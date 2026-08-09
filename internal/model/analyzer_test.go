package model

import "testing"

func TestAnalyzerFactAndCoverageAcceptOnlyClosedBoundedValues(t *testing.T) {
	fact := AnalyzerFact{ID: "analyzer:sha256:fixture", AssetID: "tool:fixture", RuleID: "ssc-init/dynamic-exec/js", Category: AnalyzerDynamicExecution, Confidence: ConfidenceHigh, Occurrences: 1}
	if !fact.Valid() {
		t.Fatalf("fact invalid: %+v", fact)
	}
	coverage := AnalyzerCoverage{Status: CoveragePartial, FilesRead: 1, BytesRead: 10, SkippedRules: []string{"binary", "oversize"}}
	if !coverage.Valid() {
		t.Fatalf("coverage invalid: %+v", coverage)
	}
	for _, mutate := range []func(*AnalyzerFact){func(value *AnalyzerFact) { value.Category = "free-form" }, func(value *AnalyzerFact) { value.Confidence = "certain" }, func(value *AnalyzerFact) { value.Occurrences = 0 }} {
		invalid := fact
		mutate(&invalid)
		if invalid.Valid() {
			t.Fatalf("invalid fact accepted: %+v", invalid)
		}
	}
}

func TestAnalyzerCoverageRejectsUnsortedOrUnboundedValues(t *testing.T) {
	for _, coverage := range []AnalyzerCoverage{{Status: CoverageComplete, SkippedRules: []string{"z", "a"}}, {Status: CoverageComplete, BytesRead: 1<<30 + 1}, {Status: "unknown"}} {
		if coverage.Valid() {
			t.Fatalf("invalid coverage accepted: %+v", coverage)
		}
	}
}
