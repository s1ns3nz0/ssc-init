package evidence

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const (
	maxEvidenceWorkers = 4
	targetDeadline     = 30 * time.Second
)

// SemanticHasher is the Task 9-compatible semantic digest hook. The engine
// invokes it with a private normalized observation copy behind the shared
// callback limiter.
type SemanticHasher func(model.Observation) (string, error)

// ContextSemanticHasher is the optional context-aware semantic digest hook.
// When both hooks are installed, this hook takes precedence.
type ContextSemanticHasher func(context.Context, model.Observation) (string, error)

// Engine collects sealed runtime targets into public evidence records.
type Engine struct {
	Limits                TreeLimits
	Cache                 LeafCache
	SemanticHasher        SemanticHasher
	ContextSemanticHasher ContextSemanticHasher
	Analyzer              ContentAnalyzer
	TargetTimeout         time.Duration
	callbackLimiter       *callbackLimiter
}

// Collection is the result of one bounded local evidence pass.
type Collection struct {
	Coverage         model.EvidenceCoverage
	Evidence         []model.ContentEvidence
	CacheWrites      []CacheWrite
	AnalyzerFacts    []model.AnalyzerFact
	AnalyzerCoverage *model.AnalyzerCoverage
}

type issuedCandidate struct {
	target              model.LocalEvidenceTarget
	anchor              Anchor
	observation         model.Observation
	evidenceID          string
	targetAssetRelative string
	anchorAssetRelative string
	pathInvalid         bool
}

func (candidate *issuedCandidate) clearRuntime() {
	if candidate == nil {
		return
	}
	candidate.target = model.LocalEvidenceTarget{}
	candidate.anchor = Anchor{}
	clear(candidate.observation.Consumers)
	clear(candidate.observation.Metadata)
	candidate.observation = model.Observation{}
	candidate.evidenceID = ""
	candidate.targetAssetRelative = ""
	candidate.anchorAssetRelative = ""
	candidate.pathInvalid = false
}

type collectedCandidate struct {
	evidence model.ContentEvidence
	coverage model.EvidenceTargetResult
	writes   []CacheWrite
	facts    []model.AnalyzerFact
	analyzer model.AnalyzerCoverage
}

// Collect validates every target against its independently expected issuer
// and normalized graph before any path is examined by the filesystem.
func (engine Engine) Collect(ctx context.Context, env collector.Environment, inventory model.Inventory, results []model.CollectorResult) (collection Collection) {
	if ctx == nil {
		ctx = context.Background()
	}
	var allCandidates []issuedCandidate
	var candidates []issuedCandidate
	var proofs []*issuedTargetProof
	var issuers []*Issuer
	defer func() {
		for index := range candidates {
			candidates[index].clearRuntime()
		}
		for index := range allCandidates {
			allCandidates[index].clearRuntime()
		}
		for index, proof := range proofs {
			proof.clearRuntime()
			proofs[index] = nil
		}
		for index, issuer := range issuers {
			issuer.clearRuntime()
			issuers[index] = nil
		}
		collector.ClearLocalEvidenceTargets(results)
	}()

	assets, observations := graphMaps(inventory)
	seenProofs := make(map[*issuedTargetProof]struct{})
	seenIssuers := make(map[*Issuer]struct{})
	for resultIndex := range results {
		result := &results[resultIndex]
		expected, hasExpectedIssuer := result.LocalEvidenceIssuer.(*Issuer)
		if expected != nil {
			if _, seen := seenIssuers[expected]; !seen {
				seenIssuers[expected] = struct{}{}
				issuers = append(issuers, expected)
			}
		}
		for targetIndex := range result.LocalEvidenceTargets {
			target := result.LocalEvidenceTargets[targetIndex]
			anchor, proof, issued := verifyIssuedTarget(target, expected)
			if proof != nil {
				if proof.issuer != nil {
					if _, seen := seenIssuers[proof.issuer]; !seen {
						seenIssuers[proof.issuer] = struct{}{}
						issuers = append(issuers, proof.issuer)
					}
				}
				if _, seen := seenProofs[proof]; !seen {
					seenProofs[proof] = struct{}{}
					proofs = append(proofs, proof)
				}
			}
			detached := target
			detached.Provenance = nil
			candidate, accepted := validateIssuedCandidate(result.Collector, hasExpectedIssuer && issued, detached, anchor, assets, observations)
			target = model.LocalEvidenceTarget{}
			detached = model.LocalEvidenceTarget{}
			anchor = Anchor{}
			if !accepted {
				collection.Coverage.Errors = append(collection.Coverage.Errors, rejectedTargetError())
				continue
			}
			allCandidates = append(allCandidates, candidate)
		}
	}

	// Verification is complete. Wipe shared proofs, issuer nonces, and caller
	// backing arrays before any target work can block or panic.
	for index, proof := range proofs {
		proof.clearRuntime()
		proofs[index] = nil
	}
	for index, issuer := range issuers {
		issuer.clearRuntime()
		issuers[index] = nil
	}
	clear(seenProofs)
	clear(seenIssuers)
	seenProofs = nil
	seenIssuers = nil
	collector.ClearLocalEvidenceTargets(results)

	evidenceCounts := make(map[string]int, len(allCandidates))
	bindingCounts := make(map[struct{ targetID, observationID string }]int, len(allCandidates))
	for _, candidate := range allCandidates {
		evidenceCounts[candidate.evidenceID]++
		bindingCounts[struct{ targetID, observationID string }{candidate.target.TargetID, candidate.target.ObservationID}]++
	}
	candidates = make([]issuedCandidate, 0, len(allCandidates))
	for _, candidate := range allCandidates {
		binding := struct{ targetID, observationID string }{candidate.target.TargetID, candidate.target.ObservationID}
		if evidenceCounts[candidate.evidenceID] != 1 || bindingCounts[binding] != 1 {
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
	jobs := make(chan int, len(candidates))
	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	workers := min(maxEvidenceWorkers, len(candidates))
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				local := candidates[index]
				completed[index] = engine.safeCollectOne(ctx, env, &local)
			}
		}()
	}
	group.Wait()
	for _, result := range completed {
		collection.Evidence = append(collection.Evidence, result.evidence)
		collection.Coverage.Targets = append(collection.Coverage.Targets, result.coverage)
		if result.evidence.Status == model.EvidenceComplete {
			collection.CacheWrites = append(collection.CacheWrites, result.writes...)
		}
		collection.AnalyzerFacts = append(collection.AnalyzerFacts, result.facts...)
		if engine.Analyzer != nil {
			if collection.AnalyzerCoverage == nil {
				collection.AnalyzerCoverage = &model.AnalyzerCoverage{Status: model.CoverageComplete}
			}
			collection.AnalyzerCoverage.FilesRead += result.analyzer.FilesRead
			collection.AnalyzerCoverage.BytesRead += result.analyzer.BytesRead
			collection.AnalyzerCoverage.SkippedRules = append(collection.AnalyzerCoverage.SkippedRules, result.analyzer.SkippedRules...)
			if result.analyzer.Status != "" && result.analyzer.Status != model.CoverageComplete {
				collection.AnalyzerCoverage.Status = model.CoveragePartial
			}
		}
	}
	if collection.AnalyzerCoverage != nil {
		collection.AnalyzerCoverage.SkippedRules = uniqueSortedStrings(collection.AnalyzerCoverage.SkippedRules)
		sort.Slice(collection.AnalyzerFacts, func(i, j int) bool { return collection.AnalyzerFacts[i].ID < collection.AnalyzerFacts[j].ID })
	}
	collection.Coverage.Status = evidenceCoverageStatus(collection.Coverage.Errors, collection.Evidence)
	return collection
}

func (engine Engine) safeCollectOne(ctx context.Context, env collector.Environment, candidate *issuedCandidate) (result collectedCandidate) {
	defer func() {
		if recover() != nil {
			result = terminalUnavailable(candidate, "read_unavailable", "evidence collection is unavailable")
		}
		candidate.clearRuntime()
	}()
	return engine.collectOne(ctx, env, candidate)
}

func (engine Engine) collectOne(parent context.Context, env collector.Environment, candidate *issuedCandidate) collectedCandidate {
	timeout := engine.TargetTimeout
	if timeout <= 0 {
		timeout = targetDeadline
	}
	if timeout > targetDeadline {
		timeout = targetDeadline
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var value model.ContentEvidence
	var writes []CacheWrite
	var facts []model.AnalyzerFact
	var analyzerCoverage model.AnalyzerCoverage
	switch {
	case candidate.target.PresetStatus != "":
		value = presetRecord(candidate.target)
	case candidate.pathInvalid:
		value = unavailableRecord("path_invalid", "evidence target path is invalid")
	case candidate.target.Kind == model.EvidenceSemanticSHA256:
		value = engine.collectSemantic(ctx, candidate.observation)
	default:
		value, writes, facts, analyzerCoverage = engine.collectFilesystem(ctx, env, candidate)
	}
	final, err := finalizeRecord(candidate.target, value)
	if err != nil {
		final, _ = finalizeRecord(candidate.target, unavailableRecord("read_unavailable", "evidence collection is unavailable"))
		writes = nil
	}
	result := collectedCandidate{evidence: final, writes: writes, facts: facts, analyzer: analyzerCoverage, coverage: model.EvidenceTargetResult{
		TargetID: candidate.target.TargetID, AssetID: candidate.target.AssetID, ObservationID: candidate.target.ObservationID,
		EvidenceID: candidate.evidenceID, Status: final.Status, Errors: append([]model.EvidenceError(nil), final.Errors...),
	}}
	if final.Status != model.EvidenceComplete {
		result.writes = nil
	}
	return result
}

func uniqueSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	values = values[:0]
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func presetRecord(target model.LocalEvidenceTarget) model.ContentEvidence {
	switch target.PresetStatus {
	case model.EvidenceComplete:
		return model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: target.PresetAlgorithm, Digest: target.PresetDigest}
	case model.EvidenceOversize:
		return model.ContentEvidence{Status: model.EvidenceOversize, Errors: []model.EvidenceError{fixedFileErrors["oversize"]}}
	case model.EvidenceUnavailable:
		return model.ContentEvidence{Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{fixedFileErrors["read"]}}
	default:
		return model.ContentEvidence{Status: target.PresetStatus}
	}
}

func terminalUnavailable(candidate *issuedCandidate, code, message string) collectedCandidate {
	final, _ := finalizeRecord(candidate.target, unavailableRecord(code, message))
	return collectedCandidate{evidence: final, coverage: model.EvidenceTargetResult{
		TargetID: candidate.target.TargetID, AssetID: candidate.target.AssetID, ObservationID: candidate.target.ObservationID,
		EvidenceID: candidate.evidenceID, Status: final.Status, Errors: append([]model.EvidenceError(nil), final.Errors...),
	}}
}

type semanticResult struct {
	digest string
	err    error
}

func (engine Engine) collectSemantic(ctx context.Context, source model.Observation) model.ContentEvidence {
	contextHasher := engine.ContextSemanticHasher
	simpleHasher := engine.SemanticHasher
	if contextHasher != nil {
		simpleHasher = nil
	}
	if contextHasher == nil && simpleHasher == nil {
		if source.Collector != "mcp" {
			return model.ContentEvidence{Status: model.EvidenceUnsupported}
		}
		simpleHasher = HashMCPObservation
	}
	if ctx.Err() != nil {
		return unavailableRecord("time_limit", "evidence target deadline exceeded")
	}
	limiter := engine.callbackGate()
	if !limiter.acquire(ctx) {
		return unavailableRecord("time_limit", "evidence target deadline exceeded")
	}
	if ctx.Err() != nil {
		limiter.release()
		return unavailableRecord("time_limit", "evidence target deadline exceeded")
	}
	observation := cloneObservation(source)
	result := make(chan semanticResult, 1)
	safeContext, cancelSafe := safeCacheContext(ctx)
	go func(value model.Observation) {
		got := semanticResult{}
		defer func() {
			clear(value.Consumers)
			clear(value.Metadata)
			if recover() != nil {
				got = semanticResult{err: errors.New("semantic hasher panicked")}
			}
			limiter.release()
			result <- got
		}()
		if contextHasher != nil {
			got.digest, got.err = contextHasher(safeContext, value)
		} else {
			got.digest, got.err = simpleHasher(value)
		}
	}(observation)
	got, waitErr := awaitSemanticResult(ctx, result)
	cancelSafe()
	if waitErr != nil {
		return unavailableRecord("time_limit", "evidence target deadline exceeded")
	}
	if got.err != nil || !lowercaseSHA256(got.digest) {
		return unavailableRecord("read_unavailable", "evidence collection is unavailable")
	}
	return model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: got.digest}
}

func awaitSemanticResult(ctx context.Context, result <-chan semanticResult) (semanticResult, error) {
	select {
	case <-ctx.Done():
		return semanticResult{}, ctx.Err()
	case got := <-result:
		if ctx.Err() != nil {
			return semanticResult{}, ctx.Err()
		}
		return got, nil
	}
}

func (engine Engine) callbackGate() *callbackLimiter {
	if engine.callbackLimiter != nil {
		return engine.callbackLimiter
	}
	return processCallbackLimiter
}

func cloneObservation(source model.Observation) model.Observation {
	result := source
	result.Consumers = append([]string(nil), source.Consumers...)
	if source.Metadata != nil {
		result.Metadata = make(map[string]string, len(source.Metadata))
		for key, value := range source.Metadata {
			result.Metadata[key] = value
		}
	}
	return result
}

func evidenceCoverageStatus(coverageErrors []model.CoverageError, records []model.ContentEvidence) model.CoverageStatus {
	if len(coverageErrors) > 0 {
		return model.CoveragePartial
	}
	allSkipped := len(records) > 0
	for _, record := range records {
		switch record.Status {
		case model.EvidenceUnsupported, model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable:
			return model.CoveragePartial
		}
		if record.Status != model.EvidenceSkipped {
			allSkipped = false
		}
	}
	if allSkipped {
		return model.CoverageSkipped
	}
	return model.CoverageComplete
}

func rejectedTargetError() model.CoverageError {
	return model.CoverageError{Code: "target_rejected", Message: "evidence target was rejected"}
}

func sortCoverageErrors(values []model.CoverageError) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Code != values[j].Code {
			return values[i].Code < values[j].Code
		}
		return values[i].Message < values[j].Message
	})
}
