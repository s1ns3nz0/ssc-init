package agents

import (
	"path/filepath"
	"strings"

	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

// issueAgentEvidence issues runtime-only, descriptor-anchored targets after
// the observation ID has been finalized. The manifest digest comes from the
// exact verified bytes used by the agent manifest parser.
func (c *agentCollector) issueAgentEvidence(home string, declaration targetDeclaration, candidate markerCandidate, observation model.Observation, result *model.CollectorResult, target *model.TargetCoverage) {
	if candidate.evidence == nil || candidate.evidence.root == (platform.FileFingerprint{}) || candidate.evidence.assetRoot == (platform.FileFingerprint{}) {
		appendAgentTargetIssue(target, "identity_changed", "agent evidence anchor identity changed")
		return
	}
	anchor := evidence.Anchor{
		Root: candidate.evidence.root, AssetRoot: candidate.evidence.assetRoot, AssetRelativePath: candidate.evidence.assetPath,
		RelativePath: filepath.FromSlash(candidate.relativePath), Digest: candidate.evidence.digest,
		Size: candidate.evidence.size, Mode: candidate.evidence.mode, Fingerprint: candidate.evidence.fingerprint,
		MaxBytes: candidate.evidence.maxBytes,
	}
	assetRelative := candidate.evidence.assetPath
	if c.afterManifestRead != nil {
		c.afterManifestRead(candidate.relativePath)
	}
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		appendAgentTargetIssue(target, "identity_changed", "agent evidence issuer is unavailable")
		return
	}
	rootPath := filepath.Clean(filepath.Join(home, filepath.FromSlash(declaration.relativePath)))
	fileSubject := model.EvidenceSubjectManifest
	fileSuffix := ".manifest"
	if candidate.kind == markerSkill {
		fileSubject = model.EvidenceSubjectSkillDocument
		fileSuffix = ".skill-document"
	}
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets,
		issuer.Issue(model.LocalEvidenceTarget{
			TargetID: declaration.spec.ID + fileSuffix, AssetID: observation.AssetID, ObservationID: observation.ID,
			Kind: model.EvidenceFileSHA256, Subject: fileSubject, RootPath: rootPath,
			RelativePath: filepath.FromSlash(candidate.relativePath),
		}, anchor),
		issuer.Issue(model.LocalEvidenceTarget{
			TargetID: declaration.spec.ID + ".payload-tree", AssetID: observation.AssetID, ObservationID: observation.ID,
			Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, RootPath: rootPath,
			RelativePath: filepath.FromSlash(assetRelative),
		}, treeAgentAnchor(anchor)),
	)
}

func (walker *agentWalker) captureAgentEvidenceAnchor(candidate *markerCandidate) bool {
	if walker == nil || walker.targetRoot == nil || candidate == nil || candidate.evidence == nil || candidate.evidence.digest == "" {
		return false
	}
	rootInfo, err := walker.targetRoot.Lstat(".")
	if err != nil || rootInfo == nil {
		return false
	}
	rootFingerprint, ok := platform.Fingerprint(rootInfo)
	if !ok {
		return false
	}
	assetRelative := filepath.Dir(filepath.FromSlash(candidate.relativePath))
	if candidate.kind != markerSkill {
		assetRelative = filepath.FromSlash(candidate.pluginBase)
	}
	assetRelative = filepath.Clean(assetRelative)
	if assetRelative == "." {
		assetRelative = ""
	}
	assetRoot := walker.targetRoot
	if assetRelative != "" {
		components := strings.Split(assetRelative, string(filepath.Separator))
		assetRoot, err = platform.OpenVerifiedRoot(walker.ctx, walker.targetRoot, components...)
		if err != nil {
			return false
		}
		defer assetRoot.Close()
	}
	assetInfo, err := assetRoot.Lstat(".")
	if err != nil || assetInfo == nil {
		return false
	}
	assetFingerprint, ok := platform.Fingerprint(assetInfo)
	if !ok {
		return false
	}
	candidate.evidence.root = rootFingerprint
	candidate.evidence.assetRoot = assetFingerprint
	candidate.evidence.assetPath = filepath.ToSlash(assetRelative)
	return true
}

func treeAgentAnchor(anchor evidence.Anchor) evidence.Anchor {
	anchor.MaxBytes = 0
	return anchor
}
