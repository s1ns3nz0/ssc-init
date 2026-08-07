package evidence

import (
	"math"
	"path/filepath"
	"strings"

	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

func graphMaps(inventory model.Inventory) (map[string]model.Asset, map[string]model.Observation) {
	assets := uniqueAssets(inventory.Assets)
	observations := uniqueObservations(inventory.Observations)
	return assets, observations
}

func uniqueAssets(values []model.Asset) map[string]model.Asset {
	result := make(map[string]model.Asset, len(values))
	duplicates := make(map[string]struct{})
	for _, value := range values {
		if value.ID == "" {
			continue
		}
		if _, duplicate := duplicates[value.ID]; duplicate {
			continue
		}
		if _, exists := result[value.ID]; exists {
			delete(result, value.ID)
			duplicates[value.ID] = struct{}{}
			continue
		}
		result[value.ID] = value
	}
	return result
}

func uniqueObservations(values []model.Observation) map[string]model.Observation {
	result := make(map[string]model.Observation, len(values))
	rejected := make(map[string]struct{})
	for _, value := range values {
		if value.ID == "" {
			continue
		}
		storedID := value.ID
		if _, invalid := rejected[storedID]; invalid {
			continue
		}
		detached := cloneObservation(value)
		detached.ID = ""
		finalized, err := identity.FinalizeObservation(detached)
		if err != nil || finalized.ID != storedID {
			delete(result, storedID)
			rejected[storedID] = struct{}{}
			continue
		}
		if _, exists := result[storedID]; exists {
			delete(result, storedID)
			rejected[storedID] = struct{}{}
			continue
		}
		result[storedID] = finalized
	}
	return result
}

func validateIssuedCandidate(collectorName string, issued bool, target model.LocalEvidenceTarget, anchor Anchor, assets map[string]model.Asset, observations map[string]model.Observation) (issuedCandidate, bool) {
	if !issued || !validTargetID(target.TargetID, collectorName) {
		return issuedCandidate{}, false
	}
	if _, exists := assets[target.AssetID]; !exists {
		return issuedCandidate{}, false
	}
	observation, exists := observations[target.ObservationID]
	if !exists || observation.AssetID != target.AssetID || observation.Collector != collectorName {
		return issuedCandidate{}, false
	}
	if !validKindSubject(target.Kind, target.Subject) || !validPresetShape(target, anchor) {
		return issuedCandidate{}, false
	}
	evidence, err := identity.FinalizeEvidence(model.ContentEvidence{AssetID: target.AssetID, ObservationID: target.ObservationID, Kind: target.Kind, Subject: target.Subject, Status: model.EvidenceUnavailable})
	if err != nil {
		return issuedCandidate{}, false
	}
	if target.PresetStatus != "" || target.Kind == model.EvidenceSemanticSHA256 {
		return newIssuedCandidate(target, anchor, observation, evidence.ID), true
	}
	if !validFilesystemShape(target, anchor) {
		return issuedCandidate{}, false
	}
	anchorAssetRelative := ""
	if anchor.RelativePath != "" {
		anchorRelative, safe, bound := assetRelativePath(anchor.AssetRelativePath, anchor.RelativePath, false)
		if !safe || !bound {
			return issuedCandidate{}, false
		}
		anchorAssetRelative = anchorRelative
	}
	targetRelative, targetSafe, targetBound := assetRelativePath(anchor.AssetRelativePath, target.RelativePath, target.Kind == model.EvidenceTreeSHA256)
	if !targetSafe {
		candidate := newIssuedCandidate(target, anchor, observation, evidence.ID)
		candidate.anchorAssetRelative = anchorAssetRelative
		candidate.pathInvalid = true
		return candidate, true
	}
	if !targetBound {
		return issuedCandidate{}, false
	}
	candidate := newIssuedCandidate(target, anchor, observation, evidence.ID)
	candidate.anchorAssetRelative = anchorAssetRelative
	candidate.targetAssetRelative = targetRelative
	return candidate, true
}

func newIssuedCandidate(target model.LocalEvidenceTarget, anchor Anchor, observation model.Observation, evidenceID string) issuedCandidate {
	return issuedCandidate{target: target, anchor: anchor, observation: cloneObservation(observation), evidenceID: evidenceID}
}

func validTargetID(value, collectorName string) bool {
	if !validCollectorIdentifier(collectorName) || !validTargetIdentifier(value) || !strings.HasPrefix(value, collectorName+".") || privacy.ContainsSensitiveValue(value) {
		return false
	}
	return true
}

func validCollectorIdentifier(value string) bool {
	return validIdentifier(value, false)
}

func validTargetIdentifier(value string) bool {
	return validIdentifier(value, true)
}

func validIdentifier(value string, allowUpper bool) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	componentStart := true
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			componentStart = false
		case allowUpper && character >= 'A' && character <= 'Z':
			componentStart = false
		case character >= '0' && character <= '9' && !componentStart:
		case (character == '.' || character == '-') && !componentStart:
			componentStart = true
		default:
			return false
		}
	}
	return !componentStart
}

func validKindSubject(kind model.EvidenceKind, subject string) bool {
	switch kind {
	case model.EvidenceFileSHA256:
		return subject == model.EvidenceSubjectManifest || subject == model.EvidenceSubjectSkillDocument || subject == model.EvidenceSubjectEntrypointMain || subject == model.EvidenceSubjectEntrypointBrowser || model.ProjectEvidenceSubject(subject)
	case model.EvidenceTreeSHA256:
		return subject == model.EvidenceSubjectPayloadTree
	case model.EvidenceSemanticSHA256:
		return subject == model.EvidenceSubjectMCPDeclaration
	case model.EvidencePackageContent:
		return subject == model.EvidenceSubjectPackageContent
	case model.EvidenceContainerIdentity:
		return subject == model.EvidenceSubjectContainerImage
	default:
		return false
	}
}

func validPresetShape(target model.LocalEvidenceTarget, anchor Anchor) bool {
	if target.Kind == model.EvidencePackageContent || target.Kind == model.EvidenceContainerIdentity {
		return (target.PresetStatus == model.EvidenceUnsupported || target.PresetStatus == model.EvidenceSkipped) && target.RootPath == "" && target.RelativePath == "" && anchor == (Anchor{})
	}
	if target.PresetStatus != "" {
		return (target.PresetStatus == model.EvidenceUnsupported || target.PresetStatus == model.EvidenceSkipped) && target.RootPath == "" && target.RelativePath == "" && anchor == (Anchor{})
	}
	if target.Kind == model.EvidenceSemanticSHA256 {
		return target.RootPath == "" && target.RelativePath == "" && anchor == (Anchor{})
	}
	return true
}

func validFilesystemShape(target model.LocalEvidenceTarget, anchor Anchor) bool {
	if !safeAbsolutePath(target.RootPath) || !safeRelativePath(anchor.AssetRelativePath, true) || !nonzeroFingerprint(anchor.Root) || !nonzeroFingerprint(anchor.AssetRoot) {
		return false
	}
	if anchor.AssetRelativePath == "" {
		if anchor.AssetRoot != anchor.Root {
			return false
		}
	} else if sameFileIdentity(anchor.Root, anchor.AssetRoot) {
		return false
	}
	hasContent := anchor.RelativePath != "" || anchor.Digest != "" || anchor.Size != 0 || anchor.Mode != 0 || nonzeroFingerprint(anchor.Fingerprint)
	if hasContent {
		if !safeRelativePath(anchor.RelativePath, false) || !lowercaseSHA256(anchor.Digest) || anchor.Size < 0 || !consistentContentAnchor(anchor) {
			return false
		}
	}
	switch target.Kind {
	case model.EvidenceFileSHA256:
		return hasContent && anchor.MaxBytes > 0 && anchor.MaxBytes < math.MaxInt64
	case model.EvidenceTreeSHA256:
		return anchor.MaxBytes == 0
	default:
		return false
	}
}

func consistentContentAnchor(anchor Anchor) bool {
	return nonzeroFingerprint(anchor.Fingerprint) &&
		anchor.Fingerprint.Size == anchor.Size &&
		anchor.Fingerprint.Mode&0o777 == anchor.Mode
}

func safeAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}

func safeRelativePath(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	_, ok := filePathComponents(value)
	return ok
}

func assetRelativePath(assetPath, rootRelative string, allowAssetRoot bool) (string, bool, bool) {
	if rootRelative == "" {
		if allowAssetRoot && assetPath == "" {
			return "", true, true
		}
		return "", false, false
	}
	if !safeRelativePath(rootRelative, false) {
		return "", false, false
	}
	assetComponents, _ := filePathComponents(assetPath)
	targetComponents, _ := filePathComponents(rootRelative)
	if len(targetComponents) < len(assetComponents) {
		return "", true, false
	}
	for index := range assetComponents {
		if assetComponents[index] != targetComponents[index] {
			return "", true, false
		}
	}
	remainder := targetComponents[len(assetComponents):]
	if len(remainder) == 0 {
		return "", true, allowAssetRoot
	}
	return filepath.Join(remainder...), true, true
}

func sameFileIdentity(left, right platform.FileFingerprint) bool {
	return left.Device == right.Device && left.Inode == right.Inode
}

func nonzeroFingerprint(value platform.FileFingerprint) bool {
	return value != (platform.FileFingerprint{})
}
