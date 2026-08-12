package audit

import (
	"reflect"
	"sort"
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

func TestBuildAllowsEmptyOptionalLabelForCompletePartialAndFailure(t *testing.T) {
	run := validRun()
	run.Label = ""
	for _, status := range []model.ScanStatus{model.ScanComplete, model.ScanPartial} {
		if _, err := Build(model.ScanResult{Status: status}, model.Inventory{}, model.Delta{}, nil, run); err != nil {
			t.Fatalf("Build(%s) rejected default label: %v", status, err)
		}
	}
	if _, err := BuildFailure(run, StageCollect, CodeCollectorFailed); err != nil {
		t.Fatalf("BuildFailure rejected default label: %v", err)
	}
}

func TestBuildFailureAllowsMissingScanIDButSuccessfulRecordsRequireIt(t *testing.T) {
	run := validRun()
	run.ScanID = ""
	if _, err := BuildFailure(run, StageInitialize, CodeInitializeFailed); err != nil {
		t.Fatalf("BuildFailure rejected early failure: %v", err)
	}
	if _, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, run); err == nil {
		t.Fatal("Build accepted successful record without scan ID")
	}
}

func TestBuildNormalizesAllAuditTimestampsAndSlices(t *testing.T) {
	one := richInputRecord(time.FixedZone("west", -7*60*60))
	two := richInputRecord(time.FixedZone("east", 9*60*60))
	two.Inventory.Assets[0], two.Inventory.Assets[1] = two.Inventory.Assets[1], two.Inventory.Assets[0]
	two.Inventory.Observations[0], two.Inventory.Observations[1] = two.Inventory.Observations[1], two.Inventory.Observations[0]
	two.Findings[0].EvidenceIDs[0], two.Findings[0].EvidenceIDs[1] = two.Findings[0].EvidenceIDs[1], two.Findings[0].EvidenceIDs[0]
	first, err := Build(one.Scan, one.Inventory, one.Delta, one.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(two.Scan, two.Inventory, two.Delta, two.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("normalization differs:\nfirst=%+v\nsecond=%+v", first, second)
	}
	for _, asset := range append(append([]model.Asset(nil), first.Inventory.Assets...), first.Coverage[0].Assets...) {
		if asset.ObservedAt.Location() != time.UTC {
			t.Fatalf("asset timestamp not UTC: %v", asset.ObservedAt)
		}
	}
	for _, finding := range append(append([]model.Finding(nil), first.Inventory.Findings...), first.Findings...) {
		if finding.DetectedAt.Location() != time.UTC || !sort.StringsAreSorted(finding.EvidenceIDs) {
			t.Fatalf("finding not normalized: %+v", finding)
		}
	}
}

func TestBuildSummaryCountsInventoryEntities(t *testing.T) {
	input := richInputRecord(time.UTC)
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := record.Summary, (Summary{Assets: 2, Observations: 2, Evidence: 2, Relationships: 1, Findings: 1, Collectors: 1, EvidenceTargets: 1, Changes: 1}); got != want {
		t.Fatalf("Summary = %+v, want %+v", got, want)
	}
}

func TestBuildAcceptsLiveProducerContracts(t *testing.T) {
	run := validRun()
	run.Version = "dev"
	asset := model.Asset{
		ID:   "mcp:vscode:workspace",
		Type: model.AssetMCP,
		Name: "socket.io",
		Provenance: &model.Provenance{
			Status:    model.ProvenanceImmutable,
			Ecosystem: "npm",
			Source:    "registry",
			Integrity: "sha256:" + strings.Repeat("a", 64),
		},
	}
	scan := model.ScanResult{Status: model.ScanPartial, Coverage: []model.CollectorResult{{
		Collector: "projects", Status: model.CoveragePartial,
		Targets: []model.TargetCoverage{
			{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-a", Status: model.TargetPartial},
			{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-b", Status: model.TargetPartial},
		},
	}}}
	if _, err := Build(scan, model.Inventory{Assets: []model.Asset{asset}}, model.Delta{}, nil, run); err != nil {
		t.Fatalf("Build rejected live producer values: %v", err)
	}
}

func TestBuildAcceptsEveryLiveCoverageErrorCode(t *testing.T) {
	for _, code := range []string{"target_not_reported", "unsupported_target", "invalid_local_target", "invalid_server", "unknown_server_field", "rejected_metadata", "rejected_identity", "config_invalid", "config_unavailable", "config_oversized", "entry_limit", "root_limit", "manifest_invalid", "manifest_oversized", "legacy_manifest_partial", "legacy_transport_unknown"} {
		t.Run(code, func(t *testing.T) {
			scan := model.ScanResult{Status: model.ScanPartial, Coverage: []model.CollectorResult{{Collector: "mcp", Status: model.CoveragePartial, Errors: []model.CoverageError{{Code: code, Message: "producer detail"}}}}}
			if _, err := Build(scan, model.Inventory{}, model.Delta{}, nil, validRun()); err != nil {
				t.Fatalf("Build rejected producer error %q: %v", code, err)
			}
		})
	}
}

func TestBuildAcceptsRemovedDeltaEntitiesAbsentFromCurrentInventory(t *testing.T) {
	for _, entity := range []model.ChangeEntity{model.ChangeEntityAsset, model.ChangeEntityObservation, model.ChangeEntityEvidence} {
		t.Run(string(entity), func(t *testing.T) {
			delta := model.Delta{Changes: []model.Change{{Kind: model.ChangeRemoved, Entity: entity, EntityID: string(entity) + ":removed"}}}
			if _, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, delta, nil, validRun()); err != nil {
				t.Fatalf("Build rejected removed %s: %v", entity, err)
			}
		})
	}
}

func TestBuildAcceptsRepeatedEvidenceCoverageTargetsWithDistinctReferences(t *testing.T) {
	input := richInputRecord(time.UTC)
	input.Scan.EvidenceCoverage.Targets = append(input.Scan.EvidenceCoverage.Targets, model.EvidenceTargetResult{
		TargetID: "target:one", AssetID: "asset:two", ObservationID: "observation:two", EvidenceID: "evidence:two", Status: model.EvidenceUnavailable,
	})
	if _, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun()); err != nil {
		t.Fatalf("Build rejected repeated evidence target: %v", err)
	}
}

func TestValidateRejectsUnsortedNestedCollectorData(t *testing.T) {
	record := graphRecord()
	record.Coverage[0].Assets[0], record.Coverage[0].Assets[1] = record.Coverage[0].Assets[1], record.Coverage[0].Assets[0]
	if err := Validate(record); err == nil {
		t.Fatal("Validate accepted unsorted collector assets")
	}
}

type auditInput struct {
	Scan      model.ScanResult
	Inventory model.Inventory
	Delta     model.Delta
	Findings  []model.Finding
}

func richInputRecord(location *time.Location) auditInput {
	at := time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC).In(location)
	assetOne, assetTwo := "asset:one", "asset:two"
	observationOne, observationTwo := "observation:one", "observation:two"
	evidenceOne, evidenceTwo := "evidence:one", "evidence:two"
	finding := model.Finding{ID: "finding:one", AssetID: assetOne, AssetType: model.AssetPackage, Verdict: model.VerdictSuspicious, Severity: model.SeverityLow, Confidence: model.ConfidenceHigh, Level: 1, DetectedAt: at, Action: model.ActionAdvisory, EvidenceIDs: []string{evidenceTwo, evidenceOne}}
	assets := []model.Asset{{ID: assetTwo, Type: model.AssetTool, Name: "tool", ObservedAt: at}, {ID: assetOne, Type: model.AssetPackage, Name: "package", ObservedAt: at}}
	observations := []model.Observation{{ID: observationTwo, AssetID: assetTwo, Collector: "packages", Scope: model.ScopeUser, LocationRef: "safe-two", Consumers: []string{"z", "a"}}, {ID: observationOne, AssetID: assetOne, Collector: "packages", Scope: model.ScopeUser, LocationRef: "safe-one", Consumers: []string{"b", "a"}}}
	evidence := []model.ContentEvidence{{ID: evidenceTwo, AssetID: assetTwo, ObservationID: observationTwo, Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "read_unavailable"}, {Code: "identity_changed"}}}, {ID: evidenceOne, AssetID: assetOne, ObservationID: observationOne, Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "symlink_rejected"}, {Code: "identity_changed"}}}}
	return auditInput{
		Scan: model.ScanResult{
			Status: model.ScanComplete,
			Coverage: []model.CollectorResult{{
				Collector: "packages", Status: model.CoverageComplete, Assets: assets, Observations: observations,
				Targets: []model.TargetCoverage{{TargetID: "target:one", Status: model.TargetComplete}},
			}},
			EvidenceCoverage: model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{{
				TargetID: "target:one", AssetID: assetOne, ObservationID: observationOne, EvidenceID: evidenceOne, Status: model.EvidenceUnavailable,
			}}},
		},
		Inventory: model.Inventory{Assets: assets, Observations: observations, Evidence: evidence, Relationships: []model.Relationship{{From: assetOne, To: assetTwo, Kind: model.RelationshipUses}}, Findings: []model.Finding{finding}},
		Delta:     model.Delta{Changes: []model.Change{{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: assetOne}}},
		Findings:  []model.Finding{finding},
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
