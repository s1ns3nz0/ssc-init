package evidence

import (
	"context"
	"os"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func (engine Engine) collectFilesystem(ctx context.Context, env collector.Environment, candidate *issuedCandidate) (model.ContentEvidence, []CacheWrite) {
	if ctx.Err() != nil {
		return unavailableRecord("time_limit", "evidence target deadline exceeded"), nil
	}
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if !ok || rooted == nil {
		return unavailableRecord("read_unavailable", "evidence collection is unavailable"), nil
	}
	root, err := rooted.OpenRoot(candidate.target.RootPath)
	if err != nil {
		return unavailableRecord("read_unavailable", "evidence collection is unavailable"), nil
	}
	defer root.Close()
	if !descriptorMatches(root, candidate.anchor.Root) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}
	assetComponents, _ := filePathComponents(candidate.anchor.AssetRelativePath)
	asset, err := platform.OpenVerifiedRoot(ctx, root, assetComponents...)
	if err != nil {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}
	defer asset.Close()
	if !descriptorMatches(asset, candidate.anchor.AssetRoot) || !verifyContentAnchor(ctx, asset, candidate) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}

	var value model.ContentEvidence
	var writes []CacheWrite
	switch candidate.target.Kind {
	case model.EvidenceFileSHA256:
		digest, status, evidenceErrors := HashVerifiedFile(ctx, asset, candidate.targetAssetRelative, candidate.anchor.MaxBytes)
		value = model.ContentEvidence{Status: status, Digest: digest.SHA256, Size: digest.Size, Errors: evidenceErrors}
		if digest.SHA256 != "" {
			value.Algorithm = "sha256"
		}
	case model.EvidenceTreeSHA256:
		target := model.LocalEvidenceTarget{ObservationID: candidate.target.ObservationID, Kind: candidate.target.Kind, Subject: candidate.target.Subject}
		digest, status, evidenceErrors, treeWrites := HashTreeForTarget(ctx, target, asset, candidate.targetAssetRelative, engine.treeLimits(), engine.boundedCache())
		value = model.ContentEvidence{Status: status, Algorithm: "sha256", Digest: digest.Digest, Size: digest.Size, Files: digest.Files, Directories: digest.Directories, Symlinks: digest.Symlinks, Errors: evidenceErrors, Metadata: map[string]string{metadataCache: digest.Cache}}
		writes = treeWrites
	default:
		return unavailableRecord("read_unavailable", "evidence collection is unavailable"), nil
	}
	if ctx.Err() != nil {
		return unavailableRecord("time_limit", "evidence target deadline exceeded"), nil
	}
	if !descriptorMatches(root, candidate.anchor.Root) || !descriptorMatches(asset, candidate.anchor.AssetRoot) || !verifyContentAnchor(ctx, asset, candidate) {
		return unavailableRecord("identity_changed", "evidence target identity changed"), nil
	}
	if value.Status != model.EvidenceComplete {
		writes = nil
	}
	return value, writes
}

func (engine Engine) boundedCache() LeafCache {
	if engine.Cache == nil || disabledLeafCache(engine.Cache) {
		return DisabledLeafCache{}
	}
	return boundedLeafCache{base: engine.Cache}
}

func (engine Engine) treeLimits() TreeLimits {
	if validTreeLimits(engine.Limits) {
		limits := engine.Limits
		if limits.MaxErrors > maxRecordErrors {
			limits.MaxErrors = maxRecordErrors
		}
		return limits
	}
	return DefaultTreeLimits
}

func descriptorMatches(root platform.RootedDirectory, expected platform.FileFingerprint) bool {
	info, err := root.Lstat(".")
	if err != nil || info == nil {
		return false
	}
	fingerprint, ok := platform.Fingerprint(info)
	return ok && fingerprint == expected
}

func verifyContentAnchor(ctx context.Context, asset platform.RootedDirectory, candidate *issuedCandidate) bool {
	if candidate.anchor.RelativePath == "" {
		return true
	}
	info, ok := anchoredFileInfo(ctx, asset, candidate.anchorAssetRelative)
	if !ok || info.Size() != candidate.anchor.Size || uint32(info.Mode().Perm()) != candidate.anchor.Mode {
		return false
	}
	fingerprint, ok := platform.Fingerprint(info)
	if !ok || fingerprint != candidate.anchor.Fingerprint {
		return false
	}
	limit := candidate.anchor.Size
	if limit < 1 {
		limit = 1
	}
	digest, status, _ := HashVerifiedFile(ctx, asset, candidate.anchorAssetRelative, limit)
	return status == model.EvidenceComplete && digest.Size == candidate.anchor.Size && digest.SHA256 == candidate.anchor.Digest && digest.Fingerprint == candidate.anchor.Fingerprint
}

func anchoredFileInfo(ctx context.Context, root platform.RootedDirectory, relativePath string) (os.FileInfo, bool) {
	components, ok := filePathComponents(relativePath)
	if !ok {
		return nil, false
	}
	parent := root
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			return nil, false
		}
		defer parent.Close()
	}
	file, _, opened, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil {
		return nil, false
	}
	defer file.Close()
	return opened, true
}

type boundedLeafCache struct {
	base LeafCache
}

type cacheLookupResult struct {
	entry CacheEntry
	found bool
	err   error
}

func (cache boundedLeafCache) Lookup(ctx context.Context, key CacheKey) (CacheEntry, bool, error) {
	if cache.base == nil {
		return CacheEntry{}, false, nil
	}
	safeContext, cancel := safeCacheContext(ctx)
	result := make(chan cacheLookupResult, 1)
	go func() {
		defer func() {
			if recover() != nil {
				result <- cacheLookupResult{err: context.Canceled}
			}
		}()
		entry, found, err := cache.base.Lookup(safeContext, key)
		result <- cacheLookupResult{entry: entry, found: found, err: err}
	}()
	select {
	case <-ctx.Done():
		cancel()
		return CacheEntry{}, false, ctx.Err()
	case got := <-result:
		cancel()
		return got.entry, got.found, got.err
	}
}

func safeCacheContext(source context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := source.Deadline(); ok {
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithCancel(context.Background())
}
