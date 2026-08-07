package ide

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const maxIDEEntrypointBytes = 64 << 20

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
func (c *ideCollector) issueIDEManifestTargets(ctx context.Context, root platform.RootedDirectory, rootPath string, declaration targetDeclaration, parsed manifestEvidence, observation model.Observation, result *model.CollectorResult, target *model.TargetCoverage, anchor ideEvidenceAnchor) {
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
		entryAnchor := anchor.manifest
		if valid {
			if captured, ok := captureIDEEntrypointAnchor(ctx, root, anchor, relative); ok {
				entryAnchor = captured
			}
		}
		result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(model.LocalEvidenceTarget{
			TargetID: declaration.spec.ID + entry.suffix, AssetID: observation.AssetID, ObservationID: observation.ID,
			Kind: model.EvidenceFileSHA256, Subject: entry.subject, RootPath: rootPath, RelativePath: relative,
		}, entryAnchor))
	}
	tree := anchor.manifest
	tree.RelativePath, tree.Digest, tree.Size, tree.Mode, tree.Fingerprint, tree.MaxBytes = "", "", 0, 0, platform.FileFingerprint{}, 0
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

func captureIDEEntrypointAnchor(ctx context.Context, root platform.RootedDirectory, base ideEvidenceAnchor, relative string) (evidence.Anchor, bool) {
	assetRelative, ok := ideRelativeToAsset(base.assetRelative, relative)
	if !ok {
		return evidence.Anchor{}, false
	}
	read, ok := readIDEEntrypoint(ctx, root, relative)
	if !ok {
		return evidence.Anchor{}, false
	}
	return evidence.Anchor{
		Root: base.root, AssetRoot: base.assetRoot, AssetRelativePath: base.assetRelative,
		RelativePath: filepath.FromSlash(relative), Digest: read.digest, Size: read.size,
		Mode: read.mode, Fingerprint: read.fingerprint, MaxBytes: maxIDEEntrypointBytes,
	}, assetRelative != ""
}

func ideRelativeToAsset(assetRelative, relative string) (string, bool) {
	asset := filepath.FromSlash(assetRelative)
	value := filepath.FromSlash(relative)
	prefix := asset + string(filepath.Separator)
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	return strings.TrimPrefix(value, prefix), true
}

type ideEntrypointRead struct {
	digest      string
	size        int64
	mode        uint32
	fingerprint platform.FileFingerprint
}

func readIDEEntrypoint(ctx context.Context, root platform.RootedDirectory, relative string) (ideEntrypointRead, bool) {
	components := strings.Split(filepath.FromSlash(relative), string(filepath.Separator))
	if len(components) == 0 || root == nil {
		return ideEntrypointRead{}, false
	}
	parent := root
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			return ideEntrypointRead{}, false
		}
		defer parent.Close()
	}
	file, _, opened, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil || opened == nil {
		return ideEntrypointRead{}, false
	}
	defer file.Close()
	if opened.Size() < 0 || opened.Size() > maxIDEEntrypointBytes {
		return ideEntrypointRead{}, false
	}
	before, ok := platform.Fingerprint(opened)
	if !ok {
		return ideEntrypointRead{}, false
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxIDEEntrypointBytes+1))
	if err != nil || int64(len(contents)) != opened.Size() || len(contents) > maxIDEEntrypointBytes {
		return ideEntrypointRead{}, false
	}
	post, err := file.Stat()
	if err != nil || post == nil || !os.SameFile(opened, post) {
		return ideEntrypointRead{}, false
	}
	after, ok := platform.Fingerprint(post)
	if !ok || after != before {
		return ideEntrypointRead{}, false
	}
	sum := sha256.Sum256(contents)
	return ideEntrypointRead{digest: hex.EncodeToString(sum[:]), size: int64(len(contents)), mode: uint32(post.Mode().Perm()), fingerprint: after}, true
}
