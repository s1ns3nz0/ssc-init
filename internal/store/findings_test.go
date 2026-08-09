package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestV6FindingsRoundTripAndHighSeverityIncidentSurvivesSnapshotPruning(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	scan, inventory := validV3Snapshot(t, "finding-old")
	scan.SchemaVersion = "ssc-init.scan.v6"
	scan.StartedAt, scan.FinishedAt = now.Add(-91*24*time.Hour), now.Add(-90*24*time.Hour)
	inventory.Findings = []model.Finding{storeFinding(inventory.Assets[0], model.SeverityCritical, now.Add(-90*24*time.Hour))}
	if err := s.saveScanAt(context.Background(), scan, inventory, scan.FinishedAt); err != nil {
		t.Fatal(err)
	}

	latest, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(latest.Inventory.Findings, inventory.Findings) {
		t.Fatalf("round trip ok=%v err=%v findings=%+v", ok, err, latest.Inventory.Findings)
	}

	newScan, newInventory := validV3Snapshot(t, "finding-new")
	newScan.SchemaVersion, newScan.StartedAt, newScan.FinishedAt = "ssc-init.scan.v6", now.Add(-time.Minute), now
	newInventory.Findings = []model.Finding{}
	if err := s.saveScanAt(context.Background(), newScan, newInventory, now); err != nil {
		t.Fatal(err)
	}
	incidents, err := s.Incidents(context.Background())
	if err != nil || len(incidents) != 1 || incidents[0].ID != inventory.Findings[0].ID {
		t.Fatalf("incidents=%+v err=%v", incidents, err)
	}
}

func TestV6LowSeverityFindingDoesNotEnterIncidentHistory(t *testing.T) {
	s := openTestStore(t)
	scan, inventory := validV3Snapshot(t, "finding-low")
	scan.SchemaVersion = "ssc-init.scan.v6"
	inventory.Findings = []model.Finding{storeFinding(inventory.Assets[0], model.SeverityMedium, scan.FinishedAt)}
	if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	incidents, err := s.Incidents(context.Background())
	if err != nil || len(incidents) != 0 {
		t.Fatalf("incidents=%+v err=%v", incidents, err)
	}
}

func storeFinding(asset model.Asset, severity model.Severity, now time.Time) model.Finding {
	return model.Finding{ID: "finding:store", AssetID: asset.ID, AssetType: asset.Type, Version: asset.Version, SHA256: asset.SHA256, Verdict: model.VerdictKnownMalicious, Severity: severity, Confidence: model.ConfidenceHigh, Level: 1, IntelligenceIDs: []string{"ti:store"}, DetectedAt: now, Action: model.ActionAdvisory, Bundles: []model.BundleReference{{Family: "ti", Sequence: 1, Digest: strings.Repeat("a", 64)}}}
}
