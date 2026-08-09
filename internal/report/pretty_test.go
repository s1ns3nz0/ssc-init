package report_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

func prettyFixture() (model.ScanResult, model.Inventory, model.Delta) {
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v7",
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
				{TargetID: "ide.vscode.extensions.entrypoint-main", AssetID: "ide-extension:vscode:dbaeumer.vscode-eslint@2.0.0", ObservationID: "observation:sha256:2222", EvidenceID: "evidence:sha256:cccc", Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "path_invalid", Message: "evidence target path is invalid"}}},
			},
		},
	}
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
			{ID: "ide-extension:vscode:dbaeumer.vscode-eslint@2.0.0", Type: model.AssetIDEExtension, Name: "vscode-eslint", Version: "2.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"},
			{ID: "observation:sha256:2222", AssetID: "ide-extension:vscode:dbaeumer.vscode-eslint@2.0.0", Collector: "ide", Source: "ide.vscode.extensions"},
			{ID: "observation:sha256:3333", AssetID: "pkg:pypi/charlie@3.0.0", Collector: "packages", Source: "packages.pip"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 497},
			{ID: "evidence:sha256:bbbb", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial, Algorithm: "sha256", Digest: strings.Repeat("b", 64), Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
			{ID: "evidence:sha256:cccc", AssetID: "ide-extension:vscode:dbaeumer.vscode-eslint@2.0.0", ObservationID: "observation:sha256:2222", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectEntrypointMain, Status: model.EvidenceUnavailable, Errors: []model.EvidenceError{{Code: "path_invalid", Message: "evidence target path is invalid"}}},
			{ID: "evidence:sha256:dddd", AssetID: "pkg:pypi/charlie@3.0.0", ObservationID: "observation:sha256:3333", Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:dbaeumer.vscode-eslint@2.0.0"},
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
		"ssc-init.scan.v7",
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
		`(?m)packages\.pip\s+1\s+0`,
		`(?m)alpha\s+payload-tree\s+partial\s+symlink_rejected`,
		`(?m)vscode-eslint\s+entrypoint-main\s+unavailable\s+path_invalid`,
		`(?m)^  NEW\s+ide-extension\s+vscode-eslint \(vscode\)$`,
		`(?m)^  UNVERIFIED\s+agent-plugin\s+alpha \(claude\)$`,
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
	// Unsupported evidence is a deliberate non-claim, not an anomaly: it stays
	// in the coverage counts and source totals but never floods ISSUES.
	if strings.Contains(output, "charlie") {
		t.Fatalf("unsupported evidence must not appear in ISSUES:\n%s", output)
	}
}

// The ISSUES table names an asset by its inventory record and falls back to the
// asset ID when no record resolves. For the digest-anchored types (project,
// project-config, tool-executable) that ID is "<type>:sha256:<64 hex>", and no
// human surface may ever print a digest. Graph normalization and store
// validation both reject the orphan records that reach this fallback, so this
// is defence in depth rather than a live path — but "no digest in human output"
// is a release-blocking invariant and gets a guard, not an argument.
func TestWriteStatusPrettyNeverPrintsADigestAnchoredAssetIDInIssues(t *testing.T) {
	digest := strings.Repeat("f", 64)
	inventory := model.Inventory{
		Evidence: []model.ContentEvidence{{
			ID:            "evidence:sha256:eeee",
			AssetID:       "project:sha256:" + digest,
			ObservationID: "observation:sha256:9999",
			Kind:          model.EvidenceFileSHA256,
			Subject:       model.EvidenceSubjectManifest,
			Status:        model.EvidenceUnavailable,
			Errors:        []model.EvidenceError{{Code: "path_invalid", Message: "evidence target path is invalid"}},
		}},
	}
	var buffer bytes.Buffer
	if err := report.WriteStatusPretty(&buffer, report.StatusData{
		Initialized:            true,
		InventorySchemaVersion: "ssc-init.scan.v7",
		EvidenceCoverage:       &model.EvidenceCoverage{Status: model.CoveragePartial},
		Inventory:              &inventory,
	}); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if regexp.MustCompile(`[0-9a-f]{64}`).MatchString(output) {
		t.Fatalf("status pretty printed a digest:\n%s", output)
	}
	if !regexp.MustCompile(`(?m)\(unnamed\)\s+manifest\s+unavailable\s+path_invalid`).MatchString(output) {
		t.Fatalf("unnameable issue row must read (unnamed), as removed ladder rows do:\n%s", output)
	}
}

func TestWritePrettyHandlesEmptyScanWithoutPlaceholderRows(t *testing.T) {
	scan := model.ScanResult{
		SchemaVersion:    "ssc-init.scan.v7",
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
	if !strings.Contains(output, "DELTA\n  (no changes)") {
		t.Fatalf("empty delta summary missing:\n%s", output)
	}
}

func TestWritePrettyRendersDeltaAsLadderAndAlwaysPrintsIt(t *testing.T) {
	scan, inventory, delta := prettyFixture()
	var buffer bytes.Buffer
	if err := report.WritePretty(&buffer, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !regexp.MustCompile(`(?m)^DELTA$`).MatchString(output) ||
		!regexp.MustCompile(`(?m)^  NEW\s+ide-extension\s+vscode-eslint \(vscode\)$`).MatchString(output) {
		t.Fatalf("delta ladder missing:\n%s", output)
	}
	if regexp.MustCompile(`added=\d+`).MatchString(output) {
		t.Fatalf("bare delta counts still rendered:\n%s", output)
	}

	// Unlike the hook, an interactive scan states "no changes" explicitly.
	var quiet bytes.Buffer
	if err := report.WritePretty(&quiet, scan, inventory, model.Delta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quiet.String(), "DELTA\n  (no changes)") {
		t.Fatalf("quiet delta must say so:\n%s", quiet.String())
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
	for _, want := range []string{"SSC Init status", "initialized", "ssc-init.scan.v7", "COLLECTOR COVERAGE", "ISSUES", "symlink_rejected"} {
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

// TestWritePrettyDeltaLadderIsNotCapped locks the design contract that the
// interactive ladder is uncapped: `scan --pretty` is a command the operator
// asked for, not a session interrupt, so it never truncates the diff nor
// borrows the hook's "…and N more changes" overflow line.
func TestWritePrettyDeltaLadderIsNotCapped(t *testing.T) {
	scan, _, _ := prettyFixture()
	inventory := model.Inventory{}
	delta := model.Delta{}
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("srv%02d", i)
		id := "mcp:claude-code:" + name // the prefix the mcp collector actually mints
		inventory.Assets = append(inventory.Assets, model.Asset{
			ID: id, Type: model.AssetMCP, Name: name, Source: "claude-code",
		})
		delta.Changes = append(delta.Changes, model.Change{
			Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: id,
		})
	}

	var buffer bytes.Buffer
	if err := report.WritePretty(&buffer, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()

	rows := regexp.MustCompile(`(?m)^  NEW\s+mcp-server\s+srv\d\d \(claude-code\)$`).FindAllString(output, -1)
	if len(rows) != 30 {
		t.Fatalf("interactive scan must not cap the ladder: got %d rows:\n%s", len(rows), output)
	}
	if strings.Contains(output, "more changes") {
		t.Fatalf("hook overflow line leaked into pretty:\n%s", output)
	}
}
