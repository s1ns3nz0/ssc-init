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

func TestFinalizeRecordStripsUnsupportedPayload(t *testing.T) {
	target := model.LocalEvidenceTarget{AssetID: "asset", ObservationID: "observation", Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent}
	got, err := finalizeRecord(target, model.ContentEvidence{
		Status: model.EvidenceUnsupported, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1, Files: 1,
		Metadata: map[string]string{"cache": "hit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Algorithm != "" || got.Digest != "" || got.Size != 0 || got.Files != 0 || got.Metadata != nil {
		t.Fatalf("unsupported record retained digest payload: %+v", got)
	}
}
