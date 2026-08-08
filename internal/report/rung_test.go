package report

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

var digestName = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestClassifyPairsUpgradesAndRanksRungs(t *testing.T) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
			{ID: "ide-extension:vscode:big@1.0.0", Type: model.AssetIDEExtension, Name: "big", Version: "1.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-skill:claude:docx"},
			{ID: "observation:sha256:2222", AssetID: "ide-extension:vscode:big@1.0.0"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete},
			{ID: "evidence:sha256:bbbb", ObservationID: "observation:sha256:2222", Status: model.EvidenceOversize},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:cursor:stale"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:orphan"},
	}}

	got := classify(inventory, delta)
	want := []rungRow{
		{Rung: rungNew, Type: "mcp-server", Name: "github", Host: "claude-code"},
		{Rung: rungChanged, Type: "agent-skill", Name: "docx", Host: "claude"},
		{Rung: rungUnverified, Type: "ide-extension", Name: "big", Host: "vscode"},
		{Rung: rungUpgraded, Type: "agent-plugin", Name: "superpowers", Host: "claude", From: "6.1.1", To: "6.2.0"},
		{Rung: rungRemoved, Type: "mcp-server", Name: "stale", Host: "cursor"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v\nwant=%+v", got, want)
	}
}

func TestClassifyKeepsHighestRungPerAsset(t *testing.T) {
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0"}},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete},
			{ID: "evidence:sha256:bbbb", ObservationID: "observation:sha256:1111", Status: model.EvidencePartial},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
	}}
	got := classify(inventory, delta)
	if len(got) != 1 || got[0].Rung != rungChanged {
		t.Fatalf("expected one CHANGED row, got=%+v", got)
	}
}

func TestParseAssetIDHandlesRealWorldForms(t *testing.T) {
	for _, test := range []struct{ id, wantType, wantHost, wantName, wantVersion string }{
		{"agent-plugin:claude:superpowers@6.2.0", "agent-plugin", "claude", "superpowers", "6.2.0"},
		{"agent-skill:claude:docx", "agent-skill", "claude", "docx", ""},
		{"ide-extension:vscode:usernamehw.errorlens@3.16.0", "ide-extension", "vscode", "usernamehw.errorlens", "3.16.0"},
		{"pkg:pypi/moto@5.1.22", "pkg", "", "pypi/moto", "5.1.22"},
		{"pkg:npm/@scope/server@1.0.0", "pkg", "", "npm/@scope/server", "1.0.0"},
		// mcp IDs never carry a version, so "@" belongs to the server name.
		{"mcp:claude-code:ctx@prod", "mcp", "claude-code", "ctx@prod", ""},
		{"project:sha256:77f9e938", "project", "sha256", "77f9e938", ""},
		{"opaque", "", "", "opaque", ""},
	} {
		gotType, gotHost, gotName, gotVersion := parseAssetID(test.id)
		if gotType != test.wantType || gotHost != test.wantHost || gotName != test.wantName || gotVersion != test.wantVersion {
			t.Fatalf("id=%q got=(%q,%q,%q,%q) want=(%q,%q,%q,%q)", test.id,
				gotType, gotHost, gotName, gotVersion, test.wantType, test.wantHost, test.wantName, test.wantVersion)
		}
	}
}

func TestClassifyDoesNotRenderProjectDigestAsName(t *testing.T) {
	const projectID = "project:sha256:77f9e938ae8565f4b27daf83a6a66bd5424c1665c6c0eee60951dac76e4109c8"
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: projectID, Type: model.AssetProject, Name: "project"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: projectID}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", AssetID: projectID,
			ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete}},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"}}}
	rows := classify(inventory, delta)
	if len(rows) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	if digestName.MatchString(rows[0].Name) {
		t.Fatalf("digest rendered as asset name: %+v", rows[0])
	}
	if rows[0].Host == "sha256" {
		t.Fatalf("digest algorithm rendered as host: %+v", rows[0])
	}
	if rows[0].Name != "project" || rows[0].Type != string(model.AssetProject) {
		t.Fatalf("display identity must come from the inventory: %+v", rows[0])
	}
}

func TestClassifyDoesNotRenderDigestForRemovedProjectAssets(t *testing.T) {
	const configID = "project-config:sha256:77f9e938ae8565f4b27daf83a6a66bd5424c1665c6c0eee60951dac76e4109c8"
	rows := classify(model.Inventory{}, model.Delta{Changes: []model.Change{
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: configID}}})
	if len(rows) != 1 || rows[0].Rung != rungRemoved {
		t.Fatalf("rows=%+v", rows)
	}
	if digestName.MatchString(rows[0].Name) || rows[0].Host == "sha256" {
		t.Fatalf("digest reached the removed-asset row: %+v", rows[0])
	}
	if rows[0].Type != "project-config" || rows[0].Name != "(unnamed)" || rows[0].Host != "" {
		t.Fatalf("removed digest-anchored asset must render as unnamed: %+v", rows[0])
	}
}

func TestClassifyDoesNotInventVersionsForVersionlessIDs(t *testing.T) {
	rows := classify(model.Inventory{}, model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:ctx@prod"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:ctx@dev"}}})
	if len(rows) != 2 {
		t.Fatalf("two distinct MCP servers collapsed into %d row(s): %+v", len(rows), rows)
	}
}

func TestParseAssetIDKeepsLeadingAtNames(t *testing.T) {
	_, _, name, version := parseAssetID("ide-extension:vscode:@internal")
	if name != "@internal" || version != "" {
		t.Fatalf("got name=%q version=%q", name, version)
	}
}

// ladderRows keeps the indented rung lines of a rendered report and drops
// everything around them (headers, counts, tables, the hook overflow line).
func ladderRows(output string) []string {
	labels := make(map[string]struct{}, len(rungLabels))
	for _, label := range rungLabels {
		labels[label] = struct{}{}
	}
	var rows []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if !strings.HasPrefix(line, "  ") || len(fields) == 0 {
			continue
		}
		if _, isRow := labels[fields[0]]; isRow {
			rows = append(rows, line)
		}
	}
	return rows
}

// TestRungRowRenderingIsIdenticalInHookAndPretty characterises the one format
// both surfaces share. The hook caps and the pretty ladder does not, so this
// fixture stays under the cap: below it the two must agree byte for byte.
func TestRungRowRenderingIsIdenticalInHookAndPretty(t *testing.T) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
			{ID: "ide-extension:vscode:big@1.0.0", Type: model.AssetIDEExtension, Name: "big", Version: "1.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-skill:claude:docx"},
			{ID: "observation:sha256:2222", AssetID: "ide-extension:vscode:big@1.0.0"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete},
			{ID: "evidence:sha256:bbbb", ObservationID: "observation:sha256:2222", Status: model.EvidenceOversize},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "pkg:pypi/moto@5.1.22"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:cursor:stale"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "agent-skill:claude:docx"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
	}}

	var hook, pretty bytes.Buffer
	if err := WriteHookSummary(&hook, inventory, delta); err != nil {
		t.Fatalf("hook: %v", err)
	}
	if err := WritePretty(&pretty, model.ScanResult{}, inventory, delta); err != nil {
		t.Fatalf("pretty: %v", err)
	}

	hookRows, prettyRows := ladderRows(hook.String()), ladderRows(pretty.String())
	want := []string{
		"  NEW        mcp-server    github (claude-code)",
		"  NEW        pkg           pypi/moto",
		"  CHANGED    agent-skill   docx (claude)",
		"  UNVERIFIED ide-extension big (vscode)",
		"  UPGRADED   agent-plugin  superpowers (claude)  6.1.1 → 6.2.0",
		"  REMOVED    mcp-server    stale (cursor)",
	}
	if !reflect.DeepEqual(hookRows, want) {
		t.Fatalf("hook rows drifted:\ngot=%q\nwant=%q", hookRows, want)
	}
	if !reflect.DeepEqual(prettyRows, hookRows) {
		t.Fatalf("surfaces disagree:\nhook=%q\npretty=%q", hookRows, prettyRows)
	}
	for _, row := range hookRows {
		if strings.Contains(row, "()") {
			t.Fatalf("hostless asset rendered empty parens: %q", row)
		}
	}
}

func TestClassifyIsEmptyForEmptyDelta(t *testing.T) {
	if rows := classify(model.Inventory{}, model.Delta{}); len(rows) != 0 {
		t.Fatalf("rows=%+v", rows)
	}
}
