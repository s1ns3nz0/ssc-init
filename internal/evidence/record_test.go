package evidence

import (
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

func TestValidTrustedDigestRequiresCompleteLowercaseSHA256(t *testing.T) {
	valid := model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64)}
	if !validTrustedDigest(valid) {
		t.Fatal("valid complete digest rejected")
	}
	for _, candidate := range []model.ContentEvidence{
		{Status: model.EvidencePartial, Algorithm: "sha256", Digest: strings.Repeat("a", 64)},
		{Status: model.EvidenceComplete, Algorithm: "sha512", Digest: strings.Repeat("a", 64)},
		{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("A", 64)},
		{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: "not-a-digest"},
	} {
		if validTrustedDigest(candidate) {
			t.Fatalf("untrusted digest accepted: %+v", candidate)
		}
	}
}

func TestFinalizeRecordPreservesValidPartialDiagnosticDigest(t *testing.T) {
	target := recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree)
	got, err := finalizeRecord(target, model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 4, Files: 1, Directories: 2, Symlinks: 3, Metadata: map[string]string{"cache": "hit"}, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != "sha256" || got.Digest != strings.Repeat("a", 64) || validTrustedDigest(got) || got.Metadata["completeness"] != "observed-subset" || len(got.Metadata) != 1 {
		t.Fatalf("record=%+v", got)
	}
}

func TestFinalizeRecordAllowsAbsentPartialDiagnosticDigest(t *testing.T) {
	target := recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree)
	got, err := finalizeRecord(target, model.ContentEvidence{Status: model.EvidenceOversize, Size: 4, Errors: []model.EvidenceError{{Code: "byte_limit", Message: "evidence tree exceeds the byte limit"}}})
	if err != nil || got.Algorithm != "" || got.Digest != "" || got.Metadata["completeness"] != "observed-subset" {
		t.Fatalf("record=%+v err=%v", got, err)
	}
}

func TestFinalizeRecordRejectsMalformedRecordContracts(t *testing.T) {
	tests := []struct {
		name   string
		target model.LocalEvidenceTarget
		value  model.ContentEvidence
	}{
		{name: "negative-size", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Size: -1}},
		{name: "negative-files", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Files: -1}},
		{name: "malformed-partial-digest", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: "bad"}},
		{name: "algorithm-without-digest", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256"}},
		{name: "complete-errors", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence file is unavailable"}}}},
		{name: "kind-subject", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidenceUnavailable}},
		{name: "unknown-error", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "arbitrary", Message: "/private/path"}}}},
		{name: "wrong-error-message", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "path_invalid", Message: "raw path"}}}},
	}
	tooMany := model.ContentEvidence{Status: model.EvidenceUnavailable}
	for index := 0; index < maxRecordErrors+1; index++ {
		tooMany.Errors = append(tooMany.Errors, model.EvidenceError{Code: "path_invalid", Message: "evidence target path is invalid"})
	}
	tests = append(tests, struct {
		name   string
		target model.LocalEvidenceTarget
		value  model.ContentEvidence
	}{name: "too-many-errors", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: tooMany})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := finalizeRecord(test.target, test.value); err == nil {
				t.Fatalf("accepted=%+v", test.value)
			}
		})
	}
}

func TestFinalizeRecordStripsForbiddenPayloadAndSortsFixedErrors(t *testing.T) {
	for _, status := range []model.EvidenceStatus{model.EvidenceUnsupported, model.EvidenceSkipped, model.EvidenceUnavailable} {
		t.Run(string(status), func(t *testing.T) {
			target := recordTarget(model.EvidenceSemanticSHA256, model.EvidenceSubjectMCPDeclaration)
			got, err := finalizeRecord(target, model.ContentEvidence{Status: status, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1, Files: 1, Directories: 1, Symlinks: 1, Metadata: map[string]string{"cache": "hit", "raw": "/private"}, Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence collection is unavailable"}}})
			if err != nil {
				t.Fatal(err)
			}
			if got.Algorithm != "" || got.Digest != "" || got.Size != 0 || got.Files != 0 || got.Directories != 0 || got.Symlinks != 0 || got.Metadata != nil {
				t.Fatalf("record=%+v", got)
			}
			if status != model.EvidenceUnavailable && len(got.Errors) != 0 {
				t.Fatalf("preset errors=%+v", got.Errors)
			}
		})
	}
	target := recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree)
	got, err := finalizeRecord(target, model.ContentEvidence{Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}, {Code: "identity_changed", Message: "evidence tree identity changed"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Errors[0].Code != "identity_changed" || got.Errors[1].Code != "symlink_rejected" {
		t.Fatalf("errors=%+v", got.Errors)
	}
}

func TestFinalizeRecordControlsMetadataByKindAndStatus(t *testing.T) {
	tree := recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree)
	got, err := finalizeRecord(tree, model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Metadata: map[string]string{"cache": "hit", "raw": "/private"}})
	if err != nil || len(got.Metadata) != 2 || got.Metadata["cache"] != "hit" || got.Metadata["completeness"] != "complete" {
		t.Fatalf("record=%+v err=%v", got, err)
	}
	file := recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest)
	got, err = finalizeRecord(file, model.ContentEvidence{Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Metadata: map[string]string{"cache": "hit", "raw": "/private"}})
	if err != nil || len(got.Metadata) != 1 || got.Metadata["completeness"] != "complete" {
		t.Fatalf("record=%+v err=%v", got, err)
	}
}

func recordTarget(kind model.EvidenceKind, subject string) model.LocalEvidenceTarget {
	return model.LocalEvidenceTarget{AssetID: "asset", ObservationID: "observation", Kind: kind, Subject: subject}
}
