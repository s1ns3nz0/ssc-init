package identity

import (
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

func TestFinalizeEvidenceIDIsStableAcrossContentChanges(t *testing.T) {
	base := model.ContentEvidence{
		AssetID:       "agent-skill:codex:fixture",
		ObservationID: "observation:sha256:" + strings.Repeat("a", 64),
		Kind:          model.EvidenceFileSHA256,
		Subject:       model.EvidenceSubjectSkillDocument,
		Status:        model.EvidenceComplete,
		Algorithm:     "sha256",
		Digest:        strings.Repeat("b", 64),
	}
	first, err := FinalizeEvidence(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Digest = strings.Repeat("c", 64)
	second, err := FinalizeEvidence(base)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("ids differ: %q %q", first.ID, second.ID)
	}
}

func TestFinalizeEvidenceRejectsFreeFormSubject(t *testing.T) {
	_, err := FinalizeEvidence(model.ContentEvidence{
		AssetID: "a", ObservationID: "o", Kind: model.EvidenceFileSHA256,
		Subject: "../../private", Status: model.EvidenceUnavailable,
	})
	if err == nil {
		t.Fatal("free-form subject accepted")
	}
}
