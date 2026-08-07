package evidence

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	maxEvidenceWorkers = 4
	targetDeadline     = 30 * time.Second
	defaultFileBytes   = 64 << 20
)

// SemanticHasher derives a safe semantic digest from an already-normalized
// observation. It receives neither filesystem paths nor source bytes.
type SemanticHasher func(model.Observation) (string, error)

// Engine collects sealed runtime targets into public evidence records.
type Engine struct {
	Limits         TreeLimits
	FileMaxBytes   int64
	Cache          LeafCache
	SemanticHasher SemanticHasher
}

// Collection is the result of one bounded local evidence pass.
type Collection struct {
	Coverage    model.EvidenceCoverage
	Evidence    []model.ContentEvidence
	CacheWrites []CacheWrite
}

type issuedCandidate struct {
	target      model.LocalEvidenceTarget
	anchor      Anchor
	observation model.Observation
	evidenceID  string
}

type collectedCandidate struct {
	evidence model.ContentEvidence
	coverage model.EvidenceTargetResult
	writes   []CacheWrite
}

// Collect validates graph bindings before filesystem access, then performs a
// deterministic, bounded collection pass. Rejected targets deliberately do
// not receive public evidence IDs because their identity was not accepted.
func (engine Engine) Collect(ctx context.Context, env collector.Environment, inventory model.Inventory, results []model.CollectorResult) (collection Collection) {
	if ctx == nil {
		ctx = context.Background()
	}
	var allCandidates []issuedCandidate
	defer func() {
		for index := range allCandidates {
			allCandidates[index].target = model.LocalEvidenceTarget{}
		}
		collector.ClearLocalEvidenceTargets(results)
	}()

	assets, observations := graphMaps(inventory)
	for resultIndex := range results {
		for targetIndex := range results[resultIndex].LocalEvidenceTargets {
			target := results[resultIndex].LocalEvidenceTargets[targetIndex]
			anchor, accepted := verifyIssuedTarget(target)
			if !accepted || !validTargetGraph(target, assets, observations) || !validPreset(target.PresetStatus) {
				collection.Coverage.Errors = append(collection.Coverage.Errors, rejectedTargetError())
				continue
			}
			if target.TargetID == "" {
				collection.Coverage.Errors = append(collection.Coverage.Errors, rejectedTargetError())
				continue
			}
			evidenceID, ok := stableEvidenceID(target)
			if !ok {
				collection.Coverage.Errors = append(collection.Coverage.Errors, rejectedTargetError())
				continue
			}
			allCandidates = append(allCandidates, issuedCandidate{target: target, anchor: anchor, observation: observations[target.ObservationID], evidenceID: evidenceID})
		}
	}
	counts := make(map[string]int, len(allCandidates))
	for _, candidate := range allCandidates {
		counts[candidate.target.TargetID]++
	}
	candidates := make([]issuedCandidate, 0, len(allCandidates))
	for _, candidate := range allCandidates {
		if counts[candidate.target.TargetID] != 1 {
			collection.Coverage.Errors = append(collection.Coverage.Errors, rejectedTargetError())
			continue
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.target.TargetID != right.target.TargetID {
			return left.target.TargetID < right.target.TargetID
		}
		if left.target.ObservationID != right.target.ObservationID {
			return left.target.ObservationID < right.target.ObservationID
		}
		return left.evidenceID < right.evidenceID
	})
	sortCoverageErrors(collection.Coverage.Errors)
	if len(candidates) == 0 {
		collection.Coverage.Status = evidenceCoverageStatus(collection.Coverage.Errors, nil)
		return collection
	}

	completed := make([]collectedCandidate, len(candidates))
	jobs := make(chan int)
	workers := min(maxEvidenceWorkers, len(candidates))
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				completed[index] = engine.safeCollectOne(ctx, env, candidates[index])
			}
		}()
	}
	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	for _, result := range completed {
		collection.Evidence = append(collection.Evidence, result.evidence)
		collection.Coverage.Targets = append(collection.Coverage.Targets, result.coverage)
		if result.evidence.Status == model.EvidenceComplete {
			collection.CacheWrites = append(collection.CacheWrites, result.writes...)
		}
	}
	collection.Coverage.Status = evidenceCoverageStatus(collection.Coverage.Errors, collection.Evidence)
	return collection
}

func evidenceCoverageStatus(errors []model.CoverageError, records []model.ContentEvidence) model.CoverageStatus {
	if len(errors) > 0 {
		return model.CoveragePartial
	}
	for _, record := range records {
		switch record.Status {
		case model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable:
			return model.CoveragePartial
		}
	}
	if len(records) > 0 {
		allSkipped := true
		for _, record := range records {
			if record.Status != model.EvidenceSkipped {
				allSkipped = false
				break
			}
		}
		if allSkipped {
			return model.CoverageSkipped
		}
	}
	return model.CoverageComplete
}

func (engine Engine) safeCollectOne(ctx context.Context, env collector.Environment, candidate issuedCandidate) (result collectedCandidate) {
	defer func() {
		if recover() != nil {
			final, _ := finalizeRecord(candidate.target, unavailableRecord("read_unavailable", "evidence collection is unavailable"))
			result = collectedCandidate{evidence: final, coverage: model.EvidenceTargetResult{
				TargetID: candidate.target.TargetID, AssetID: candidate.target.AssetID, ObservationID: candidate.target.ObservationID,
				EvidenceID: candidate.evidenceID, Status: final.Status, Errors: append([]model.EvidenceError(nil), final.Errors...),
			}}
		}
	}()
	return engine.collectOne(ctx, env, candidate)
}

func graphMaps(inventory model.Inventory) (map[string]model.Asset, map[string]model.Observation) {
	assets := make(map[string]model.Asset, len(inventory.Assets))
	assetDuplicates := make(map[string]struct{})
	for _, asset := range inventory.Assets {
		if asset.ID == "" {
			continue
		}
		if _, duplicate := assetDuplicates[asset.ID]; duplicate {
			continue
		}
		if _, exists := assets[asset.ID]; exists {
			delete(assets, asset.ID)
			assetDuplicates[asset.ID] = struct{}{}
			continue
		}
		assets[asset.ID] = asset
	}
	observations := make(map[string]model.Observation, len(inventory.Observations))
	observationDuplicates := make(map[string]struct{})
	for _, observation := range inventory.Observations {
		if observation.ID == "" {
			continue
		}
		if _, duplicate := observationDuplicates[observation.ID]; duplicate {
			continue
		}
		if _, exists := observations[observation.ID]; exists {
			delete(observations, observation.ID)
			observationDuplicates[observation.ID] = struct{}{}
			continue
		}
		observations[observation.ID] = observation
	}
	return assets, observations
}

func validTargetGraph(target model.LocalEvidenceTarget, assets map[string]model.Asset, observations map[string]model.Observation) bool {
	if _, exists := assets[target.AssetID]; !exists {
		return false
	}
	observation, exists := observations[target.ObservationID]
	if !exists || observation.AssetID != target.AssetID {
		return false
	}
	_, err := identity.FinalizeEvidence(model.ContentEvidence{
		AssetID: target.AssetID, ObservationID: target.ObservationID, Kind: target.Kind,
		Subject: target.Subject, Status: model.EvidenceUnavailable,
	})
	return err == nil
}

func validPreset(status model.EvidenceStatus) bool {
	return status == "" || status == model.EvidenceUnsupported || status == model.EvidenceSkipped
}

func stableEvidenceID(target model.LocalEvidenceTarget) (string, bool) {
	record, err := identity.FinalizeEvidence(model.ContentEvidence{
		AssetID: target.AssetID, ObservationID: target.ObservationID, Kind: target.Kind,
		Subject: target.Subject, Status: model.EvidenceUnavailable,
	})
	return record.ID, err == nil
}

func rejectedTargetError() model.CoverageError {
	return model.CoverageError{Code: "target_rejected", Message: "evidence target was rejected"}
}

func sortCoverageErrors(errors []model.CoverageError) {
	sort.Slice(errors, func(i, j int) bool {
		if errors[i].Code != errors[j].Code {
			return errors[i].Code < errors[j].Code
		}
		return errors[i].Message < errors[j].Message
	})
}

func (engine Engine) collectOne(parent context.Context, env collector.Environment, candidate issuedCandidate) collectedCandidate {
	ctx, cancel := context.WithTimeout(parent, targetDeadline)
	defer cancel()
	target := candidate.target
	var record model.ContentEvidence
	var writes []CacheWrite
	switch target.PresetStatus {
	case model.EvidenceUnsupported, model.EvidenceSkipped:
		record.Status = target.PresetStatus
	case "":
		if target.Kind == model.EvidenceSemanticSHA256 {
			record = engine.collectSemantic(candidate)
		} else if !validTargetRuntimePath(target) {
			record = unavailableRecord("path_invalid", "evidence target path is invalid")
		} else {
			record, writes = engine.collectFilesystem(ctx, env, candidate)
		}
	default:
		record = unavailableRecord("read_unavailable", "evidence collection is unavailable")
	}
	final, err := finalizeRecord(target, record)
	if err != nil {
		final, _ = finalizeRecord(target, unavailableRecord("read_unavailable", "evidence collection is unavailable"))
	}
	result := collectedCandidate{evidence: final, writes: writes, coverage: model.EvidenceTargetResult{
		TargetID: target.TargetID, AssetID: target.AssetID, ObservationID: target.ObservationID,
		EvidenceID: candidate.evidenceID, Status: final.Status, Errors: append([]model.EvidenceError(nil), final.Errors...),
	}}
	if final.Status != model.EvidenceComplete {
		result.writes = nil
	}
	return result
}

func (engine Engine) collectSemantic(candidate issuedCandidate) model.ContentEvidence {
	if engine.SemanticHasher == nil {
		return model.ContentEvidence{Status: model.EvidenceUnsupported}
	}
	digest, err := engine.SemanticHasher(candidate.observation)
	if err != nil || !lowercaseSHA256(digest) {
		return unavailableRecord("read_unavailable", "semantic evidence is unavailable")
	}
	return model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: digest}
}

func (engine Engine) collectFilesystem(ctx context.Context, env collector.Environment, candidate issuedCandidate) (model.ContentEvidence, []CacheWrite) {
	if ctx.Err() != nil {
		return unavailableRecord("read_unavailable", "evidence collection is unavailable"), nil
	}
	if !validFilesystemAnchor(candidate.target, candidate.anchor) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if !ok || rooted == nil || !safeRootPath(candidate.target.RootPath) {
		return unavailableRecord("read_unavailable", "rooted evidence access is unavailable"), nil
	}
	root, err := rooted.OpenRoot(candidate.target.RootPath)
	if err != nil {
		return unavailableRecord("read_unavailable", "rooted evidence access is unavailable"), nil
	}
	defer root.Close()
	if !rootAnchorMatches(root, candidate.anchor) || !contentAnchorMatches(ctx, root, candidate.anchor) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}

	target := candidate.target
	var value model.ContentEvidence
	var writes []CacheWrite
	switch target.Kind {
	case model.EvidenceFileSHA256:
		digest, status, errors := HashVerifiedFile(ctx, root, target.RelativePath, engine.fileMaxBytes(candidate.anchor))
		value = model.ContentEvidence{Status: status, Algorithm: "sha256", Digest: digest.SHA256, Size: digest.Size, Errors: errors}
		if status == model.EvidenceComplete && !fileDigestMatchesAnchor(digest, candidate.anchor) {
			value = unavailableRecord("identity_changed", "evidence target identity changed")
		}
	case model.EvidenceTreeSHA256:
		digest, status, errors, treeWrites := HashTreeForTarget(ctx, target, root, target.RelativePath, engine.treeLimits(), engine.Cache)
		writes = treeWrites
		value = model.ContentEvidence{Status: status, Algorithm: "sha256", Digest: digest.Digest, Size: digest.Size, Files: digest.Files, Directories: digest.Directories, Symlinks: digest.Symlinks, Errors: errors,
			Metadata: map[string]string{metadataCache: digest.Cache}}
		if status == model.EvidenceComplete && !rootAnchorMatches(root, candidate.anchor) {
			value = unavailableRecord("identity_changed", "evidence target identity changed")
		}
	default:
		return unavailableRecord("read_unavailable", "evidence collection is unavailable"), nil
	}
	if value.Status == model.EvidenceComplete && (!rootAnchorMatches(root, candidate.anchor) || !contentAnchorMatches(ctx, root, candidate.anchor)) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}
	if value.Status != model.EvidenceComplete {
		writes = nil
	}
	return value, writes
}

func (engine Engine) fileMaxBytes(anchor Anchor) int64 {
	if anchor.MaxBytes > 0 && anchor.MaxBytes < 1<<63-1 {
		return anchor.MaxBytes
	}
	if engine.FileMaxBytes > 0 && engine.FileMaxBytes < 1<<63-1 {
		return engine.FileMaxBytes
	}
	return defaultFileBytes
}

func (engine Engine) treeLimits() TreeLimits {
	if validTreeLimits(engine.Limits) {
		return engine.Limits
	}
	return DefaultTreeLimits
}

func validTargetRuntimePath(target model.LocalEvidenceTarget) bool {
	if !safeRootPath(target.RootPath) {
		return false
	}
	if target.Kind == model.EvidenceTreeSHA256 && target.RelativePath == "" {
		return true
	}
	_, ok := filePathComponents(target.RelativePath)
	return ok
}

func validFilesystemAnchor(target model.LocalEvidenceTarget, anchor Anchor) bool {
	if !nonzeroFingerprint(anchor.Root) || !nonzeroFingerprint(anchor.AssetRoot) {
		return false
	}
	if anchor.RelativePath != "" {
		if _, ok := filePathComponents(anchor.RelativePath); !ok || !nonzeroFingerprint(anchor.Fingerprint) {
			return false
		}
	}
	if target.Kind != model.EvidenceFileSHA256 {
		return true
	}
	return anchor.RelativePath == target.RelativePath && lowercaseSHA256(anchor.Digest) && nonzeroFingerprint(anchor.Fingerprint)
}

func safeRootPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !containsNUL(path)
}

func containsNUL(value string) bool {
	for _, character := range value {
		if character == 0 {
			return true
		}
	}
	return false
}

func rootAnchorMatches(root platform.RootedDirectory, anchor Anchor) bool {
	info, err := root.Lstat(".")
	if err != nil || info == nil {
		return false
	}
	fingerprint, ok := platform.Fingerprint(info)
	if !ok {
		return false
	}
	return matchesFingerprint(anchor.Root, fingerprint) && matchesFingerprint(anchor.AssetRoot, fingerprint)
}

func contentAnchorMatches(ctx context.Context, root platform.RootedDirectory, anchor Anchor) bool {
	if anchor.RelativePath == "" {
		return true
	}
	components, ok := filePathComponents(anchor.RelativePath)
	if !ok {
		return false
	}
	parent := root
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			return false
		}
		defer parent.Close()
	}
	file, _, info, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil {
		return false
	}
	defer file.Close()
	fingerprint, ok := platform.Fingerprint(info)
	if !ok || !matchesFingerprint(anchor.Fingerprint, fingerprint) {
		return false
	}
	if anchor.RelativePath != "" && info.Size() != anchor.Size {
		return false
	}
	return anchor.RelativePath == "" || uint32(info.Mode().Perm()) == anchor.Mode
}

func matchesFingerprint(expected, actual platform.FileFingerprint) bool {
	return expected == (platform.FileFingerprint{}) || expected == actual
}

func nonzeroFingerprint(value platform.FileFingerprint) bool {
	return value != (platform.FileFingerprint{})
}

func fileDigestMatchesAnchor(digest FileDigest, anchor Anchor) bool {
	if anchor.Digest != "" && digest.SHA256 != anchor.Digest {
		return false
	}
	if digest.Size != anchor.Size {
		return false
	}
	return matchesFingerprint(anchor.Fingerprint, digest.Fingerprint)
}

func unavailableRecord(code, message string) model.ContentEvidence {
	return model.ContentEvidence{Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: code, Message: message}}}
}
