package bundle

import (
	"strings"
	"testing"
)

func TestThreatIntelligenceRecordValidationAcceptsCompleteRedistributableFact(t *testing.T) {
	payload := TIPayload{Records: []TIRecord{{
		ID: "osv:GHSA-abcd-1234", AssetID: "pkg:npm/example@1.0.0", VersionRange: ">=1.0.0 <1.0.2",
		SHA256: strings.Repeat("a", 64), Verdict: "known-malicious", Confidence: "high",
		SourceURLs: []string{"https://osv.dev/vulnerability/GHSA-abcd-1234"}, RetrievedAt: "2026-08-10T00:00:00Z",
		ValidUntil: "2026-08-20T00:00:00Z", License: "CC-BY-4.0", Redistributable: true,
		CampaignIDs: []string{"campaign-1"}, AttackTechniques: []string{"T1059.007"},
	}}}
	if err := validateTIPayload(payload); err != nil {
		t.Fatal(err)
	}
}

func TestThreatIntelligenceValidationRejectsUnsafeOrIncompleteFactsWithoutEcho(t *testing.T) {
	secret := "GITHUB_TOKEN=raw-secret"
	base := TIRecord{
		ID: "record", AssetID: "pkg:npm/example@1.0.0", Verdict: "suspicious", Confidence: "medium",
		SourceURLs: []string{"https://example.invalid/advisory"}, RetrievedAt: "2026-08-10T00:00:00Z",
		ValidUntil: "2026-08-20T00:00:00Z", License: "CC0-1.0", Redistributable: true,
	}
	cases := []TIRecord{base, base, base, base, base}
	cases[0].ID = ""
	cases[1].SHA256 = "abc"
	cases[2].Verdict = "safe"
	cases[3].SourceURLs = []string{"https://user:password@example.invalid/advisory"}
	cases[4].CampaignIDs = []string{secret}
	for _, record := range cases {
		if err := validateTIPayload(TIPayload{Records: []TIRecord{record}}); err != ErrMalformed || strings.Contains(err.Error(), secret) {
			t.Fatalf("record accepted or echoed: %+v err=%v", record, err)
		}
	}
}
