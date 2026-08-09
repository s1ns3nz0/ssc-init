package surfaces

import (
	"context"
	"path/filepath"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const maxSurfaceFileBytes = int64(4 << 20)

func issueHomeFileEvidence(ctx context.Context, env collector.Environment, result *model.CollectorResult, targetID, relative, assetID, observationID, subject string) model.EvidenceStatus {
	base := model.LocalEvidenceTarget{
		TargetID: targetID, AssetID: assetID, ObservationID: observationID,
		Kind: model.EvidenceFileSHA256, Subject: subject,
	}
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if !ok || rooted == nil {
		issueSurfacePreset(result, base, model.EvidenceUnavailable)
		return model.EvidenceUnavailable
	}
	root, err := rooted.OpenRoot(env.Home)
	if err != nil {
		issueSurfacePreset(result, base, model.EvidenceUnavailable)
		return model.EvidenceUnavailable
	}
	defer root.Close()
	rootInfo, err := root.Lstat(".")
	rootFingerprint, rootOK := platform.Fingerprint(rootInfo)
	if err != nil || rootInfo == nil || !rootInfo.IsDir() || !rootOK {
		issueSurfacePreset(result, base, model.EvidenceUnavailable)
		return model.EvidenceUnavailable
	}
	digest, status, _ := evidence.HashVerifiedFile(ctx, root, filepath.Clean(relative), maxSurfaceFileBytes)
	if status != model.EvidenceComplete {
		issueSurfacePreset(result, base, status)
		return status
	}
	base.RootPath = env.Home
	base.RelativePath = filepath.Clean(relative)
	anchor := evidence.Anchor{
		Root: rootFingerprint, AssetRoot: rootFingerprint, RelativePath: filepath.Clean(relative),
		Digest: digest.SHA256, Size: digest.Size, Mode: digest.Fingerprint.Mode & 0o777,
		Fingerprint: digest.Fingerprint, MaxBytes: maxSurfaceFileBytes,
	}
	issuer := evidence.BindCollectorResult(result)
	if issuer != nil {
		result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(base, anchor))
	}
	return model.EvidenceComplete
}

func issueSurfacePreset(result *model.CollectorResult, target model.LocalEvidenceTarget, status model.EvidenceStatus) {
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		return
	}
	target.PresetStatus = status
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(target, evidence.Anchor{}))
}
