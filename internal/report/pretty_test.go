package report_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

func prettyFixture() (model.ScanResult, model.Inventory, model.Delta) {
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v3",
		ScanID:        "00000000-0000-4000-8000-000000000001",
		Status:        "partial",
		StartedAt:     time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 8, 7, 0, 0, 1, 0, time.UTC),
		Scope: model.ScanScope{
			Platform:       "darwin",
			CatalogVersion: "ssc-init.catalog.v1",
			ProjectRoots:   []string{"$HOME/Projects"},
		},
		Coverage: []model.CollectorResult{
			{Collector: "agents", Status: model.CoveragePartial},
			{Collector: "projects", Status: model.CoverageComplete},
		},
		EvidenceCoverage: model.EvidenceCoverage{
			Status: model.CoveragePartial,
			Targets: []model.EvidenceTargetResult{
				{TargetID: "agents.claude.plugins.manifest", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", EvidenceID: "evidence:sha256:aaaa", Status: model.EvidenceComplete},
				{TargetID: "agents.claude.plugins.payload-tree", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", EvidenceID: "evidence:sha256:bbbb", Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
				{TargetID: "ide.vscode.extensions.entrypoint-main", AssetID: "ide-extension:vscode:bravo@2.0.0", ObservationID: "observation:sha256:2222", EvidenceID: "evidence:sha256:cccc", Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "path_invalid", Message: "evidence target path is invalid"}}},
			},
		},
	}
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
			{ID: "ide-extension:vscode:bravo@2.0.0", Type: model.AssetIDEExtension, Name: "bravo", Version: "2.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"},
			{ID: "observation:sha256:2222", AssetID: "ide-extension:vscode:bravo@2.0.0", Collector: "ide", Source: "ide.vscode.extensions"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 497},
			{ID: "evidence:sha256:bbbb", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial, Algorithm: "sha256", Digest: strings.Repeat("b", 64), Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
			{ID: "evidence:sha256:cccc", AssetID: "ide-extension:vscode:bravo@2.0.0", ObservationID: "observation:sha256:2222", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectEntrypointMain, Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "path_invalid", Message: "evidence target path is invalid"}}},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:bravo@2.0.0"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
	}}
	return scan, inventory, delta
}

func TestWritePrettyRendersDeterministicBaselineTables(t *testing.T) {
	scan, inventory, delta := prettyFixture()

	var first, second bytes.Buffer
	if err := report.WritePretty(&first, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if err := report.WritePretty(&second, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("pretty output is not deterministic:\n%q\n%q", first.String(), second.String())
	}

	output := first.String()
	for _, want := range []string{
		"SSC Init baseline scan",
		"ssc-init.scan.v3",
		"00000000-0000-4000-8000-000000000001",
		"COLLECTOR COVERAGE",
		"EVIDENCE COVERAGE",
		"EVIDENCE BY SOURCE",
		"ISSUES",
		"DELTA",
		"symlink_rejected",
		"path_invalid",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("pretty output missing %q:\n%s", want, output)
		}
	}
	for _, pattern := range []string{
		`(?m)agents\s+partial`,
		`(?m)projects\s+complete`,
		`(?m)agents\.claude\.plugins\s+2\s+1`,
		`(?m)ide\.vscode\.extensions\s+1\s+0`,
		`(?m)alpha\s+payload-tree\s+partial\s+symlink_rejected`,
		`(?m)bravo\s+entrypoint-main\s+unavailable\s+path_invalid`,
		`(?m)added=1\s+changed=1\s+removed=0`,
	} {
		if !regexp.MustCompile(pattern).MatchString(output) {
			t.Fatalf("pretty output missing pattern %q:\n%s", pattern, output)
		}
	}
	if strings.Contains(output, "{") || strings.Contains(output, "\"schemaVersion\"") {
		t.Fatalf("pretty output leaks JSON syntax:\n%s", output)
	}
	if strings.Contains(output, strings.Repeat("a", 64)) {
		t.Fatalf("pretty output dumps full digests:\n%s", output)
	}
}

func TestWritePrettyHandlesEmptyScanWithoutPlaceholderRows(t *testing.T) {
	scan := model.ScanResult{
		SchemaVersion:    "ssc-init.scan.v3",
		ScanID:           "00000000-0000-4000-8000-000000000002",
		Status:           "complete",
		StartedAt:        time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC),
		FinishedAt:       time.Date(2026, 8, 7, 0, 0, 1, 0, time.UTC),
		EvidenceCoverage: model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{}},
	}
	var buffer bytes.Buffer
	if err := report.WritePretty(&buffer, scan, model.Inventory{}, model.Delta{}); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "(none)") {
		t.Fatalf("empty sections must say (none):\n%s", output)
	}
	if !regexp.MustCompile(`(?m)added=0\s+changed=0\s+removed=0`).MatchString(output) {
		t.Fatalf("empty delta summary missing:\n%s", output)
	}
}

func TestWriteStatusPrettyCoversInitializedLegacyAndEmptyStates(t *testing.T) {
	scan, inventory, _ := prettyFixture()

	var initialized bytes.Buffer
	err := report.WriteStatusPretty(&initialized, report.StatusData{
		Initialized:            true,
		InventorySchemaVersion: scan.SchemaVersion,
		Scope:                  &scan.Scope,
		Coverage:               scan.Coverage,
		EvidenceCoverage:       &scan.EvidenceCoverage,
		Inventory:              &inventory,
	})
	if err != nil {
		t.Fatal(err)
	}
	output := initialized.String()
	for _, want := range []string{"SSC Init status", "initialized", "ssc-init.scan.v3", "COLLECTOR COVERAGE", "ISSUES", "symlink_rejected"} {
		if !strings.Contains(output, want) {
			t.Fatalf("status pretty missing %q:\n%s", want, output)
		}
	}

	var legacy bytes.Buffer
	if err := report.WriteStatusPretty(&legacy, report.StatusData{
		Initialized:            true,
		LegacyInventory:        true,
		InventorySchemaVersion: "ssc-init.scan.v2",
		Inventory:              &model.Inventory{Assets: inventory.Assets},
	}); err != nil {
		t.Fatal(err)
	}
	legacyOutput := legacy.String()
	if !strings.Contains(legacyOutput, "legacy inventory") {
		t.Fatalf("legacy status must be labeled:\n%s", legacyOutput)
	}
	if strings.Contains(legacyOutput, "COLLECTOR COVERAGE") || strings.Contains(legacyOutput, "EVIDENCE COVERAGE") {
		t.Fatalf("legacy status must not claim coverage:\n%s", legacyOutput)
	}

	var empty bytes.Buffer
	if err := report.WriteStatusPretty(&empty, report.StatusData{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(empty.String(), "not initialized") {
		t.Fatalf("uninitialized status must say so:\n%s", empty.String())
	}
}
