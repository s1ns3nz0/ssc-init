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
	assertOrderedText(t, output.String(), "SSC Init security review", "ASSESSMENT", "PRIORITY FINDINGS", "NEXT STEPS", "SUMMARY", "FINDINGS", "CHANGES", "COVERAGE", "ASSETS", "AUDIT EVIDENCE")
	for _, want := range []string{"state      COMPLETE", "assets", "observations", "evidence", "findings", "changes", "state      saved", stored.SafePath, stored.SHA256} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("pretty output missing %q:\n%s", want, output.String())
		}
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
	assertOrderedText(t, text, "SSC Init security review", "ASSESSMENT", "ACTION REQUIRED", "PRIORITY FINDINGS", "KNOWN MALICIOUS", "NEXT STEPS", "SUMMARY")
	for _, want := range []string{"reason", "known-malicious", "confidence", "HIGH", "coverage", "advisory", "IMMEDIATE", "Inspect:", "Review evidence:", "Verify archive:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("action-first output missing %q:\n%s", want, text)
		}
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
	if !strings.Contains(output.String(), "\x1b[31mACTION REQUIRED\x1b[0m") || !strings.Contains(output.String(), "\x1b[31mKNOWN MALICIOUS\x1b[0m") || !strings.Contains(output.String(), "\x1b[32msaved\x1b[0m") {
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
