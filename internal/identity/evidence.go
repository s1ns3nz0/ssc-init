package identity

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

// ErrRejectedEvidenceIdentity is returned when the stable evidence identity
// tuple is incomplete, sensitive, or outside the closed subject vocabulary.
var ErrRejectedEvidenceIdentity = errors.New("evidence identity rejected")

// FinalizeEvidence validates the stable identity tuple and assigns an ID that
// remains stable when the observed content changes.
func FinalizeEvidence(value model.ContentEvidence) (model.ContentEvidence, error) {
	if value.AssetID == "" || value.ObservationID == "" || !validEvidenceKind(value.Kind) || !validEvidenceSubject(value.Subject) || !validEvidenceStatus(value.Status) {
		return model.ContentEvidence{}, ErrRejectedEvidenceIdentity
	}
	for _, field := range []string{value.AssetID, value.ObservationID, value.Subject} {
		if privacy.ContainsSensitiveValue(field) {
			return model.ContentEvidence{}, ErrRejectedEvidenceIdentity
		}
	}
	digest := sha256.Sum256(evidenceCanonicalTuple(value))
	value.ID = fmt.Sprintf("evidence:sha256:%x", digest)
	return value, nil
}

func evidenceCanonicalTuple(value model.ContentEvidence) []byte {
	output := make([]byte, 0)
	for _, field := range []string{"ssc-init.evidence.id.v1", value.ObservationID, string(value.Kind), value.Subject} {
		output = appendLengthPrefixed(output, field)
	}
	return output
}

func validEvidenceKind(kind model.EvidenceKind) bool {
	switch kind {
	case model.EvidenceFileSHA256, model.EvidenceTreeSHA256, model.EvidenceSemanticSHA256, model.EvidencePackageContent, model.EvidenceContainerIdentity:
		return true
	default:
		return false
	}
}

func validEvidenceStatus(status model.EvidenceStatus) bool {
	switch status {
	case model.EvidenceComplete, model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable, model.EvidenceUnsupported, model.EvidenceSkipped:
		return true
	default:
		return false
	}
}

func validEvidenceSubject(subject string) bool {
	switch subject {
	case model.EvidenceSubjectManifest, model.EvidenceSubjectSkillDocument, model.EvidenceSubjectEntrypointMain, model.EvidenceSubjectEntrypointBrowser, model.EvidenceSubjectPayloadTree, model.EvidenceSubjectMCPDeclaration, model.EvidenceSubjectPackageContent, model.EvidenceSubjectContainerImage:
		return true
	default:
		return model.ProjectEvidenceSubject(subject)
	}
}
