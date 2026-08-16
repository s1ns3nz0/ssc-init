package audit

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestWritePrettyRendersProgressiveAuditSummary(t *testing.T) {
	var output bytes.Buffer
	stored := &Stored{SafePath: "$SSC_INIT_DATA/audit/run.zip", SHA256: strings.Repeat("a", 64), Valid: true}
	if err := WritePretty(&output, graphRecord(), stored); err != nil {
		t.Fatal(err)
	}
	assertOrderedText(t, output.String(), "SSC Init security review", "ASSESSMENT", "INTELLIGENCE", "PRIORITY FINDINGS", "NEXT STEPS", "SUMMARY", "FINDINGS", "CHANGES", "COVERAGE", "ASSETS", "AUDIT EVIDENCE")
	for _, want := range []string{"state      COMPLETE", "assets", "observations", "evidence", "findings", "changes", "state      saved", stored.SafePath, stored.SHA256} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("pretty output missing %q:\n%s", want, output.String())
		}
	}
}

func TestAssetDisplaysUsePrivateDeterministicProjectAliases(t *testing.T) {
	projectA := "project:sha256:" + strings.Repeat("a", 64)
	projectB := "project:sha256:" + strings.Repeat("b", 64)
	record := Record{Inventory: model.Inventory{Assets: []model.Asset{
		{ID: projectB, Type: model.AssetProject, Name: "project", Path: "/Users/alice/private/repo"},
		{ID: "tool:one", Type: model.AssetTool, Name: "public-tool"},
		{ID: projectA, Type: model.AssetProject, Name: "project"},
	}}}
	got := assetDisplays(record)
	if got[projectA] != "project-1" || got[projectB] != "project-2" || got["tool:one"] != "public-tool" {
		t.Fatalf("displays=%v", got)
	}
}

func TestWritePrettyLeadsWithActionAssessmentAndPriorityFinding(t *testing.T) {
	record := graphRecord()
	record.Findings[0].Verdict = model.VerdictKnownMalicious
	record.Findings[0].Severity = model.SeverityCritical
	record.Findings[0].Confidence = model.ConfidenceHigh

	var output bytes.Buffer
	if err := WritePretty(&output, record, nil); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	assertOrderedText(t, text, "SSC Init security review", "ASSESSMENT", "ACTION REQUIRED", "INTELLIGENCE", "PRIORITY FINDINGS", "KNOWN MALICIOUS", "NEXT STEPS", "SUMMARY")
	for _, want := range []string{"reason", "known-malicious", "confidence", "HIGH", "coverage", "advisory", "IMMEDIATE", "Inspect:", "Review evidence:", "Verify archive:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("action-first output missing %q:\n%s", want, text)
		}
	}
}

func TestWritePrettyExplainsVerifiedMaliciousTIAndUpdateState(t *testing.T) {
	record := graphRecord()
	record.Findings[0].Verdict = model.VerdictKnownMalicious
	record.Findings[0].Severity = model.SeverityCritical
	record.Findings[0].Confidence = model.ConfidenceHigh
	record.Findings[0].IntelligenceIDs = []string{"MAL-2026-0042"}
	record.Findings[0].Bundles = []model.BundleReference{{Family: "ti", Sequence: 42, Digest: strings.Repeat("d", 64)}}
	record.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("d", 64), KeyID: "ti-prod-1", Records: 18432, Malicious: 612, Vulnerable: 17820, RecordedAt: record.Run.FinishedAt}

	var output bytes.Buffer
	if err := WritePrettyStyled(&output, record, nil, Style{Color: true}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	assertOrderedText(t, text, "ASSESSMENT", "ACTION REQUIRED", "INTELLIGENCE", "updated", "PRIORITY FINDINGS")
	for _, want := range []string{"fresh", "sequence", "42", "records", "18432", "malicious", "612", "vulnerable", "17820", "verified malicious-package intelligence matched this exact package version", "\x1b[31m"} {
		if !strings.Contains(text, want) {
			t.Fatalf("TI output missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "\x1b[32mfresh\x1b[0m") || strings.Contains(text, "\x1b[32mNO ACTION IDENTIFIED") {
		t.Fatalf("fresh update or host safety was colored incorrectly:\n%q", text)
	}
}

func TestWritePrettyShowsDegradedAndUnavailableIntelligenceWithoutLeaking(t *testing.T) {
	for name, receipt := range map[string]*IntelligenceUpdate{
		"degraded": {Family: "ti", Status: "degraded", ErrorCode: "network-unavailable", Freshness: "stale", Sequence: 41, Digest: strings.Repeat("d", 64), KeyID: "ti-prod-1"},
		"missing":  {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "missing"},
	} {
		t.Run(name, func(t *testing.T) {
			record := graphRecord()
			receipt.RecordedAt = record.Run.FinishedAt
			record.Intelligence = receipt
			var output bytes.Buffer
			if err := WritePrettyStyled(&output, record, nil, Style{Color: true}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "\x1b[33m") {
				t.Fatalf("degraded/unavailable state lacks warning color: %q", output.String())
			}
		})
	}
}

func TestReportTextIntelligenceIsANSIFree(t *testing.T) {
	record := graphRecord()
	record.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "current", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("d", 64), KeyID: "ti-prod-1", RecordedAt: record.Run.FinishedAt}
	report, err := ReportText(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(report, []byte("\x1b[")) || !bytes.Contains(report, []byte("INTELLIGENCE")) {
		t.Fatalf("invalid archived report: %q", report)
	}
}

func TestWritePrettyStyledColorsRiskButStoredReportRemainsPlain(t *testing.T) {
	record := graphRecord()
	record.Findings[0].Verdict = model.VerdictKnownMalicious
	record.Findings[0].Severity = model.SeverityCritical

	var output bytes.Buffer
	if err := WritePrettyStyled(&output, record, &Stored{SafePath: "$SSC_INIT_DATA/audit/run.zip", SHA256: strings.Repeat("a", 64), Valid: true}, Style{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "\x1b[31mACTION REQUIRED\x1b[0m") || !strings.Contains(output.String(), "\x1b[31mKNOWN MALICIOUS\x1b[0m") || strings.Contains(output.String(), "\x1b[32msaved\x1b[0m") {
		t.Fatalf("risk and evidence states were not colored semantically:\n%q", output.String())
	}
	report, err := ReportText(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(report, []byte("\x1b[")) {
		t.Fatalf("archived report contains terminal escapes: %q", report)
	}
}

func TestWriteSectionFindingsExplainsConfidenceAndBasis(t *testing.T) {
	record := graphRecord()
	var output bytes.Buffer
	if err := WriteSection(&output, record, SectionFindings); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CONFIDENCE", "BASIS", "HIGH", "LOCAL ANALYSIS"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("finding details missing %q:\n%s", want, output.String())
		}
	}
}

func TestFindingRenderersExplainMatchedRulesWithoutExposingEvidenceIdentity(t *testing.T) {
	record := graphRecord()
	record.Findings[0].RuleIDs = []string{"ssc-init/mutable/provenance", "ssc-init/mutable/unpinned-package"}

	var summary bytes.Buffer
	if err := WritePretty(&summary, record, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "why: package version is not pinned and provenance may change") {
		t.Fatalf("priority finding does not explain its classification:\n%s", summary.String())
	}

	var details bytes.Buffer
	if err := WriteSection(&details, record, SectionFindings); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"why       package version is not pinned and provenance may change",
		"rules     mutable/provenance, mutable/unpinned-package",
		"evidence  2 linked items",
		"action    INSPECT",
	} {
		if !strings.Contains(details.String(), want) {
			t.Fatalf("detailed finding does not contain %q:\n%s", want, details.String())
		}
	}
	if strings.Contains(details.String(), "evidence:sha256:") || strings.Contains(details.String(), "asset:sha256:") {
		t.Fatalf("detailed reason exposed opaque identities:\n%s", details.String())
	}
}

func TestUnknownFindingRuleUsesNonSpeculativeFallbackReason(t *testing.T) {
	record := graphRecord()
	record.Findings[0].RuleIDs = []string{"organization/custom-review"}
	var output bytes.Buffer
	if err := WritePretty(&output, record, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "why: additional local review rule matched") || strings.Contains(output.String(), "custom-review") {
		t.Fatalf("unknown rule was omitted or exposed/speculated about:\n%s", output.String())
	}
}

func TestWriteListAndVerifyUseOnlySafeReferences(t *testing.T) {
	record := validRecord()
	report, err := ReportText(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(record, report)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	stored := Stored{
		RunID: record.Run.ID, Label: record.Run.Label, SafePath: "$SSC_INIT_DATA/audit/run.zip", SHA256: verified.ZIPSHA256,
		State: record.State, Profile: record.Profile, CreatedAt: time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC), Size: int64(len(encoded)), Valid: true,
	}
	var list, verification bytes.Buffer
	if err := WriteList(&list, []Stored{stored}); err != nil {
		t.Fatal(err)
	}
	if err := WriteVerify(&verification, verified, "$INPUT/audit.zip"); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{list.String(), verification.String()} {
		if strings.Contains(output, "/Users/") || strings.Contains(output, "/private/") {
			t.Fatalf("renderer exposed a host path:\n%s", output)
		}
	}
	if !strings.Contains(list.String(), record.Run.Label) || !strings.Contains(verification.String(), "authentication unsigned") {
		t.Fatalf("list/verify output incomplete:\n%s\n%s", list.String(), verification.String())
	}
	stored.Label = "/Users/alice/private"
	if err := WriteList(&bytes.Buffer{}, []Stored{stored}); err == nil {
		t.Fatal("WriteList accepted a private label")
	}
}

func TestWritePrettyFailureShowsOnlyClosedStageAndCode(t *testing.T) {
	record, err := BuildFailure(validRun(), StageCollect, CodeCollectorFailed)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WritePretty(&output, record, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "FAILED stage=collect code=collector_failed") || strings.Contains(output.String(), "invalid audit") {
		t.Fatalf("failure output is not closed:\n%s", output.String())
	}
}

func TestReportTextMatchesStoredReportEntry(t *testing.T) {
	record := graphRecord()
	report, err := ReportText(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(record, report)
	if err != nil {
		t.Fatal(err)
	}
	if got := unzipEntries(t, encoded)["report.txt"]; !bytes.Equal(got, report) {
		t.Fatalf("stored report differs:\n%q\n%q", got, report)
	}
}

func TestWriteSectionNeverPrintsDigestAnchoredIdentity(t *testing.T) {
	record := graphRecord()
	for _, section := range []Section{SectionFindings, SectionChanges, SectionCoverage, SectionAssets, SectionEvidence} {
		var output bytes.Buffer
		if err := WriteSection(&output, record, section); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), strings.Repeat("a", 64)) || strings.Contains(output.String(), "asset:sha256:") || strings.Contains(output.String(), "finding:sha256:") {
			t.Fatalf("section %s printed opaque identity:\n%s", section, output.String())
		}
	}
}

func assertOrderedText(t *testing.T, output string, values ...string) {
	t.Helper()
	position := -1
	for _, value := range values {
		next := strings.Index(output[position+1:], value)
		if next < 0 {
			t.Fatalf("output missing ordered value %q:\n%s", value, output)
		}
		position += next + 1
	}
}
