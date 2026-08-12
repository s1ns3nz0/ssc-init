package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestBuildCreatesClosedCompleteAndPartialRecords(t *testing.T) {
	complete, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, validRun())
	if err != nil || complete.State != StateComplete {
		t.Fatalf("complete=%+v err=%v", complete, err)
	}
	partial, err := Build(model.ScanResult{Status: model.ScanPartial}, model.Inventory{}, model.Delta{}, nil, validRun())
	if err != nil || partial.State != StatePartial {
		t.Fatalf("partial=%+v err=%v", partial, err)
	}
}

func TestBuildFailureAcceptsOnlyClosedStageAndCode(t *testing.T) {
	if _, err := BuildFailure(validRun(), StageCollect, CodeCollectorFailed); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildFailure(validRun(), Stage("/Users/alice"), "secret=value"); err == nil {
		t.Fatal("accepted open failure values")
	}
}

func TestValidLabelRejectsPathsWhitespaceAndControls(t *testing.T) {
	for _, value := range []string{"/tmp/a", `a\\b`, "a\nb", " edge", "edge ", strings.Repeat("a", 65)} {
		if ValidLabel(value) {
			t.Fatalf("accepted label %q", value)
		}
	}
}

func TestBuildRetainsOnlyClosedCoverageErrorCodes(t *testing.T) {
	record, err := Build(model.ScanResult{
		Status:   model.ScanPartial,
		Coverage: []model.CollectorResult{{Collector: "packages", Status: model.CoveragePartial, Errors: []model.CoverageError{{Code: "read_failed", Message: "original error", Path: "/Users/alice/private"}}}},
	}, model.Inventory{Errors: []model.CoverageError{{Code: "read_failed", Message: "original error", Path: "/Users/alice/private"}}}, model.Delta{}, nil, validRun())
	if err != nil {
		t.Fatal(err)
	}
	if got := record.Coverage[0].Errors[0]; got.Message != "" || got.Path != "" {
		t.Fatalf("coverage error retained detail: %+v", got)
	}
	if got := record.Inventory.Errors[0]; got.Message != "" || got.Path != "" {
		t.Fatalf("inventory error retained detail: %+v", got)
	}
}

func validRun() Run {
	finished := time.Date(2026, 8, 12, 1, 2, 3, 0, time.FixedZone("KST", 9*60*60))
	return Run{
		ID:         "run:hex:0123456789abcdef0123456789abcdef",
		ScanID:     "scan:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DeviceID:   "device:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Label:      "baseline scan",
		Product:    "ssc-init",
		Version:    "v1.0.0",
		StartedAt:  finished.Add(-time.Minute),
		FinishedAt: finished,
	}
}
