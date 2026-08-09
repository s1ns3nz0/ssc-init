package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestSnapshotV7AnalyzerRoundTrip(t *testing.T) {
	s := openTestStore(t)
	scan, inventory := validV3Snapshot(t, "v7-analyzer-round-trip")
	scan.SchemaVersion = "ssc-init.scan.v7"
	scan.AnalyzerCoverage = &model.AnalyzerCoverage{
		Status: model.CoveragePartial, FilesRead: 2, BytesRead: 84, SkippedRules: []string{"binary"},
	}
	inventory.AnalyzerFacts = []model.AnalyzerFact{{
		ID: "analyzer:sha256:fixture", AssetID: inventory.Assets[0].ID, EvidenceID: inventory.Evidence[0].ID,
		RuleID: "ssc-init/api/process-launch", Category: model.AnalyzerProcessLaunch, Confidence: model.ConfidenceHigh, Occurrences: 2,
	}}

	if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("LatestSnapshot() ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got.Scan.AnalyzerCoverage, scan.AnalyzerCoverage) {
		t.Fatalf("coverage mismatch: got %#v want %#v", got.Scan.AnalyzerCoverage, scan.AnalyzerCoverage)
	}
	if !reflect.DeepEqual(got.Inventory.AnalyzerFacts, inventory.AnalyzerFacts) {
		t.Fatalf("facts mismatch: got %#v want %#v", got.Inventory.AnalyzerFacts, inventory.AnalyzerFacts)
	}
}

func TestSnapshotV7AnalyzerRejectsSensitiveRuleWithoutEchoingIt(t *testing.T) {
	s := openTestStore(t)
	scan, inventory := validV3Snapshot(t, "v7-analyzer-sensitive")
	scan.SchemaVersion = "ssc-init.scan.v7"
	scan.AnalyzerCoverage = &model.AnalyzerCoverage{Status: model.CoverageComplete}
	secret := "ghp_" + strings.Repeat("a", 36)
	inventory.AnalyzerFacts = []model.AnalyzerFact{{
		ID: "analyzer:sha256:fixture", AssetID: inventory.Assets[0].ID, RuleID: secret,
		Category: model.AnalyzerDynamicExecution, Confidence: model.ConfidenceHigh, Occurrences: 1,
	}}

	err := s.SaveScan(context.Background(), scan, inventory)
	if !errors.Is(err, ErrSensitiveSnapshot) || strings.Contains(err.Error(), secret) {
		t.Fatalf("SaveScan() err=%q", err)
	}
}
