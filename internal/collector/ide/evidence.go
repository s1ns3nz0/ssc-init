package ide

import (
	"path/filepath"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const (
	maxIDEEntrypointBytes        = 64 << 20
	invalidIDEEntrypointRelative = "invalid\x00entrypoint"
)

// ideEvidenceAnchor holds only runtime provenance for a verified extension
// directory and its manifest. It is sealed by evidence.Issuer before return.
type ideEvidenceAnchor struct {
	root, assetRoot platform.FileFingerprint
	assetRelative   string
	manifest        evidence.Anchor
}

func captureIDEManifestAnchor(root, asset platform.RootedDirectory, assetRelative, manifestRelative string, manifest ideManifestRead) (ideEvidenceAnchor, bool) {
	rootFingerprint, ok := rootedIDEFingerprint(root)
	if !ok {
		return ideEvidenceAnchor{}, false
	}
	assetFingerprint, ok := rootedIDEFingerprint(asset)
	if !ok || manifest.digest == "" || manifest.size < 0 || manifest.fingerprint == (platform.FileFingerprint{}) {
		return ideEvidenceAnchor{}, false
	}
	return ideEvidenceAnchor{
		root: rootFingerprint, assetRoot: assetFingerprint, assetRelative: filepath.ToSlash(assetRelative),
		manifest: evidence.Anchor{
			Root: rootFingerprint, AssetRoot: assetFingerprint, AssetRelativePath: filepath.ToSlash(assetRelative),
			RelativePath: filepath.FromSlash(manifestRelative), Digest: manifest.digest, Size: manifest.size,
			Mode: manifest.mode, Fingerprint: manifest.fingerprint, MaxBytes: maxManifestBytes,
		},
	}, true
}

func rootedIDEFingerprint(root platform.RootedDirectory) (platform.FileFingerprint, bool) {
	if root == nil {
		return platform.FileFingerprint{}, false
	}
	info, err := root.Lstat(".")
	if err != nil || info == nil {
		return platform.FileFingerprint{}, false
	}
	return platform.Fingerprint(info)
}

// issueIDEManifestTargets seals every target for one finalized observation.
func (c *ideCollector) issueIDEManifestTargets(rootPath string, declaration targetDeclaration, parsed manifestEvidence, observation model.Observation, result *model.CollectorResult, target *model.TargetCoverage, anchor ideEvidenceAnchor) {
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		c.addIssue(result, target, model.TargetPartial, "identity_changed", "IDE evidence issuer is unavailable", "")
		return
	}
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(model.LocalEvidenceTarget{
		TargetID: declaration.spec.ID + ".manifest", AssetID: observation.AssetID, ObservationID: observation.ID,
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, RootPath: rootPath,
		RelativePath: anchor.manifest.RelativePath,
	}, anchor.manifest))

	for _, entry := range []struct {
		value, suffix, subject string
	}{
		{parsed.main, ".entrypoint-main", model.EvidenceSubjectEntrypointMain},
		{parsed.browser, ".entrypoint-browser", model.EvidenceSubjectEntrypointBrowser},
	} {
		if entry.value == "" {
			continue
		}
		relative, valid := canonicalIDEEntrypointPath(anchor.assetRelative, entry.value)
		if !valid {
			relative = invalidIDEEntrypointRelative
		}
		entryAnchor := anchor.manifest
		entryAnchor.MaxBytes = maxIDEEntrypointBytes
		result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(model.LocalEvidenceTarget{
			TargetID: declaration.spec.ID + entry.suffix, AssetID: observation.AssetID, ObservationID: observation.ID,
			Kind: model.EvidenceFileSHA256, Subject: entry.subject, RootPath: rootPath, RelativePath: relative,
		}, entryAnchor))
	}
	tree := anchor.manifest
	tree.MaxBytes = 0
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(model.LocalEvidenceTarget{
		TargetID: declaration.spec.ID + ".payload-tree", AssetID: observation.AssetID, ObservationID: observation.ID,
		Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, RootPath: rootPath,
		RelativePath: filepath.FromSlash(anchor.assetRelative),
	}, tree))
}

func canonicalIDEEntrypointPath(assetRelative, value string) (string, bool) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) {
		return rawIDEEntrypointRelative(assetRelative, value), false
	}
	local := filepath.FromSlash(value)
	clean := filepath.Clean(local)
	if clean != local || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return rawIDEEntrypointRelative(assetRelative, value), false
	}
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			return rawIDEEntrypointRelative(assetRelative, value), false
		}
	}
	return filepath.Join(filepath.FromSlash(assetRelative), clean), true
}

func rawIDEEntrypointRelative(assetRelative, value string) string {
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.FromSlash(assetRelative) + string(filepath.Separator) + filepath.FromSlash(value)
}
