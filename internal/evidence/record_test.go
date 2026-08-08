package evidence

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
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

func TestFinalizeRecordRejectsTreeSubsetWithoutDiagnosticDigest(t *testing.T) {
	target := recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree)
	if got, err := finalizeRecord(target, model.ContentEvidence{Status: model.EvidenceOversize, Size: 4, Errors: []model.EvidenceError{{Code: "byte_limit", Message: "evidence tree exceeds the byte limit"}}}); err == nil {
		t.Fatalf("accepted=%+v", got)
	}
}

func TestFinalizeRecordEnforcesSubsetContractsByEvidenceKind(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		target  model.LocalEvidenceTarget
		value   model.ContentEvidence
		wantErr bool
	}{
		{name: "tree-partial", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: digest, Files: 1, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}}},
		{name: "tree-oversize", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidenceOversize, Algorithm: "sha256", Digest: digest, Size: 4, Errors: []model.EvidenceError{{Code: "byte_limit", Message: "evidence tree exceeds the byte limit"}}}},
		{name: "tree-missing-error", target: recordTarget(model.EvidenceTreeSHA256, model.EvidenceSubjectPayloadTree), value: model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: digest}, wantErr: true},
		{name: "file-partial-without-diagnostic", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidencePartial, Size: 3, Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence file is unavailable"}}}},
		{name: "file-oversize-without-diagnostic", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidenceOversize, Errors: []model.EvidenceError{{Code: "byte_limit", Message: "evidence file exceeds the byte limit"}}}},
		{name: "file-valid-diagnostic", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: digest, Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence file is unavailable"}}}},
		{name: "file-missing-error", target: recordTarget(model.EvidenceFileSHA256, model.EvidenceSubjectManifest), value: model.ContentEvidence{Status: model.EvidencePartial}, wantErr: true},
		{name: "semantic-partial", target: recordTarget(model.EvidenceSemanticSHA256, model.EvidenceSubjectMCPDeclaration), value: model.ContentEvidence{Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence collection is unavailable"}}}, wantErr: true},
		{name: "package-oversize", target: recordTarget(model.EvidencePackageContent, model.EvidenceSubjectPackageContent), value: model.ContentEvidence{Status: model.EvidenceOversize, Errors: []model.EvidenceError{{Code: "byte_limit", Message: "evidence file exceeds the byte limit"}}}, wantErr: true},
		{name: "container-partial", target: recordTarget(model.EvidenceContainerIdentity, model.EvidenceSubjectContainerImage), value: model.ContentEvidence{Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence collection is unavailable"}}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := finalizeRecord(test.target, test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("record=%+v err=%v wantErr=%v", got, err, test.wantErr)
			}
			if err == nil && got.Metadata["completeness"] != "observed-subset" {
				t.Fatalf("record=%+v", got)
			}
		})
	}
}

func TestFinalizeRecordAllowsPayloadFreePackageAndContainerPresets(t *testing.T) {
	for _, target := range []model.LocalEvidenceTarget{
		recordTarget(model.EvidencePackageContent, model.EvidenceSubjectPackageContent),
		recordTarget(model.EvidenceContainerIdentity, model.EvidenceSubjectContainerImage),
	} {
		for _, status := range []model.EvidenceStatus{model.EvidenceUnsupported, model.EvidenceSkipped} {
			got, err := finalizeRecord(target, model.ContentEvidence{Status: status, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1})
			if err != nil || got.Status != status || got.Algorithm != "" || got.Digest != "" || got.Size != 0 {
				t.Fatalf("record=%+v err=%v", got, err)
			}
		}
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
	got, err := finalizeRecord(target, model.ContentEvidence{Status: model.EvidencePartial, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}, {Code: "identity_changed", Message: "evidence tree identity changed"}}})
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
