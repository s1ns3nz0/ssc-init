package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingClosedVocabulariesAndJSONRoundTrip(t *testing.T) {
	finding := Finding{
		ID: "finding:sha256:" + strings.Repeat("a", 64), AssetID: "pkg:npm/example@1.0.0", AssetType: AssetPackage,
		Version: "1.0.0", SHA256: strings.Repeat("b", 64), Verdict: VerdictKnownMalicious, Severity: SeverityCritical,
		Confidence: ConfidenceHigh, Level: 1, IntelligenceIDs: []string{"osv:record-1"}, EvidenceIDs: []string{"evidence:sha256:" + strings.Repeat("c", 64)},
		DetectedAt: time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC), Action: ActionAdvisory,
		Bundles: []BundleReference{{Family: "ti", Sequence: 7, Digest: strings.Repeat("d", 64)}},
	}
	if !finding.Valid() {
		t.Fatalf("finding invalid: %+v", finding)
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Finding
	if err := json.Unmarshal(raw, &decoded); err != nil || !decoded.Valid() || decoded.ID != finding.ID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}

func TestFindingRejectsOpenVocabularyAndInvalidPrecedence(t *testing.T) {
	base := Finding{ID: "finding:1", AssetID: "asset:1", AssetType: AssetTool, Verdict: VerdictSuspicious, Severity: SeverityHigh, Confidence: ConfidenceMedium, Level: 2, DetectedAt: time.Now().UTC(), Action: ActionAdvisory}
	for _, mutate := range []func(*Finding){
		func(f *Finding) { f.Verdict = "safe" },
		func(f *Finding) { f.Severity = "urgent" },
		func(f *Finding) { f.Confidence = "certain" },
		func(f *Finding) { f.Action = "deleted" },
		func(f *Finding) { f.Level = 0 },
		func(f *Finding) { f.Level = 6 },
	} {
		candidate := base
		mutate(&candidate)
		if candidate.Valid() {
			t.Fatalf("accepted finding=%+v", candidate)
		}
	}
}
