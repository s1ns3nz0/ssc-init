package report

import (
	"bytes"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

var digestName = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestClassifyPairsUpgradesAndRanksRungs(t *testing.T) {
	// Every added asset is in the inventory: a scan diffs the snapshot it just
	// wrote, so an added asset is always present. Only the removed ones are
	// absent, and only those exercise the parseAssetID fallback.
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
			{ID: "ide-extension:vscode:big@1.0.0", Type: model.AssetIDEExtension, Name: "big", Version: "1.0.0", Source: "vscode"},
			{ID: "mcp:claude-code:github", Type: model.AssetMCP, Name: "github", Source: "claude-code"},
			{ID: "agent-plugin:claude:superpowers@6.2.0", Type: model.AssetAgentPlugin, Name: "superpowers", Version: "6.2.0", Source: "claude"},
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
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:cursor:stale"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:orphan"},
	}}

	got := classify(inventory, delta)
	want := []rungRow{
		{key: "mcp:claude-code:github", Rung: rungNew, Type: "mcp-server", Name: "github", Host: "claude-code"},
		{key: "agent-skill:claude:docx", Rung: rungChanged, Type: "agent-skill", Name: "docx", Host: "claude"},
		{key: "ide-extension:vscode:big@1.0.0", Rung: rungUnverified, Type: "ide-extension", Name: "big", Host: "vscode"},
		{key: "agent-plugin:claude:superpowers@6.2.0", Rung: rungUpgraded, Type: "agent-plugin", Name: "superpowers", Host: "claude", From: "6.1.1", To: "6.2.0"},
		{key: "mcp:cursor:stale", Rung: rungRemoved, Type: "mcp-server", Name: "stale", Host: "cursor"},
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
		// escapePURLName percent-encodes an npm scope, so a real ID carries "%40".
		{"pkg:npm/%40scope/server@1.0.0", "pkg", "", "npm/%40scope/server", "1.0.0"},
		// mcp IDs never carry a version, so "@" belongs to the server name.
		{"mcp:claude-code:ctx@prod", "mcp", "claude-code", "ctx@prod", ""},
		{"project:sha256:" + strings.Repeat("7", 64), "project", "sha256", strings.Repeat("7", 64), ""},
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
	if rows[0].Type != string(model.AssetProject) || rows[0].Name != "(unnamed)" || rows[0].Host != "" {
		t.Fatalf("removed digest-anchored asset must render as unnamed: %+v", rows[0])
	}
}

// TestClassifyDoesNotInventVersionsForVersionlessIDs deliberately keeps both
// assets out of the inventory: it asserts what the ID alone is allowed to say,
// so both rows must come from the parseAssetID fallback.
func TestClassifyDoesNotInventVersionsForVersionlessIDs(t *testing.T) {
	rows := classify(model.Inventory{}, model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:ctx@prod"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:ctx@dev"}}})
	if len(rows) != 2 {
		t.Fatalf("two distinct MCP servers collapsed into %d row(s): %+v", len(rows), rows)
	}
}

// TestParseAssetIDKeepsLeadingAtNames covers the "@" position guard on a
// synthetic ID: normalizeIdentity rejects "@" in a publisher, so no collector
// can emit this form. The guard is defensive and stays under test regardless.
func TestParseAssetIDKeepsLeadingAtNames(t *testing.T) {
	_, _, name, version := parseAssetID("ide-extension:vscode:@internal") // synthetic
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
			{ID: "mcp:claude-code:github", Type: model.AssetMCP, Name: "github", Source: "claude-code"},
			// appendPackageEvidence clears Source on a package asset and the
			// name is the bare package name; the ecosystem lives only in the ID.
			{ID: "pkg:pypi/moto@5.1.22", Type: model.AssetPackage, Name: "moto", Version: "5.1.22"},
			{ID: "agent-plugin:claude:superpowers@6.2.0", Type: model.AssetAgentPlugin, Name: "superpowers", Version: "6.2.0", Source: "claude"},
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
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "pkg:pypi/moto@5.1.22"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:cursor:stale"},
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
		// A present package prints its inventory name; only a removed one falls
		// back to the ID's more qualified "pypi/moto" (see the design document,
		// "Name vocabulary on REMOVED rows").
		"  NEW        package       moto",
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

// TestRemovedRowsUseTheSameTypeVocabularyAsAddedRows pins the TYPE column to a
// single vocabulary. A removed asset is absent from the inventory by
// definition, so its row is built from the ID prefix; four prefixes differ from
// the model.AssetType every other rung prints.
func TestRemovedRowsUseTheSameTypeVocabularyAsAddedRows(t *testing.T) {
	for _, c := range []struct {
		id    string
		asset model.Asset
	}{
		{"mcp:claude-code:srv", model.Asset{Type: model.AssetMCP, Name: "srv", Source: "claude-code"}},
		{"pkg:npm/left-pad@1.0.0", model.Asset{Type: model.AssetPackage, Name: "left-pad"}},
		{"project-config:sha256:" + strings.Repeat("b", 64),
			model.Asset{Type: model.AssetProject, Name: ".mcp.json", Source: "project-config"}},
		{"tool-executable:sha256:" + strings.Repeat("a", 64),
			model.Asset{Type: model.AssetTool, Name: "executable"}},
	} {
		c.asset.ID = c.id
		added := classify(model.Inventory{Assets: []model.Asset{c.asset}}, model.Delta{Changes: []model.Change{
			{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: c.id}}})
		removed := classify(model.Inventory{}, model.Delta{Changes: []model.Change{
			{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: c.id}}})
		if added[0].Type != removed[0].Type {
			t.Errorf("id=%q NEW prints Type=%q but REMOVED prints Type=%q", c.id, added[0].Type, removed[0].Type)
		}
	}
}

// TestRungTypesFitTheScannableColumn guards the alignment the design document
// calls a scannable column: every printed type must fit the %-13s field.
func TestRungTypesFitTheScannableColumn(t *testing.T) {
	for prefix, assetType := range assetTypeByIDPrefix {
		if len(assetType) > 13 {
			t.Errorf("prefix %q maps to %q (%d chars), overflowing the type column", prefix, assetType, len(assetType))
		}
	}
}

// halfVersionedPair is an added/removed pair sharing one type:host:name where
// only one side carries a version. internal/collector/agents appends
// "@<version>" only when a version is known, so a plugin that gains or loses
// the "version" field in its plugin.json mints exactly this shape: two genuine
// assets, one identity, one version between them.
func halfVersionedPair(addedID, removedID string) model.Delta {
	return model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: addedID},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: removedID},
	}}
}

// assertHonestPair asserts the tool reported two events rather than one
// transition. A version transition is a claim about a move from one version to
// another; with only one version in hand the tool never established it.
func assertHonestPair(t *testing.T, rows []rungRow) {
	t.Helper()
	for _, row := range rows {
		if row.Rung == rungUpgraded && (row.From == "" || row.To == "") {
			t.Fatalf("half-versioned pair rendered as a transition: %q", row.render())
		}
		if strings.Contains(row.render(), "→") && (row.From == "" || row.To == "") {
			t.Fatalf("dangling arrow: %q", row.render())
		}
	}
	if len(rows) != 2 || rows[0].Rung != rungNew || rows[1].Rung != rungRemoved {
		t.Fatalf("expected a NEW row and a REMOVED row, got %+v", rows)
	}
}

func TestClassifyDoesNotReportAVersionTransitionWhenTheVersionIsGained(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "agent-plugin:claude:superpowers@6.2.0", Type: model.AssetAgentPlugin,
			Name: "superpowers", Version: "6.2.0", Source: "claude"}}}
	assertHonestPair(t, classify(inventory, halfVersionedPair(
		"agent-plugin:claude:superpowers@6.2.0", "agent-plugin:claude:superpowers")))
}

func TestClassifyDoesNotReportAVersionTransitionWhenTheVersionIsLost(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "agent-plugin:claude:superpowers", Type: model.AssetAgentPlugin,
			Name: "superpowers", Source: "claude"}}}
	assertHonestPair(t, classify(inventory, halfVersionedPair(
		"agent-plugin:claude:superpowers", "agent-plugin:claude:superpowers@6.1.1")))
}

// TestClassifyDoesNotLetAnUpgradeMaskAnUnverifiedPayload pins "highest rung
// wins" on the case the UNVERIFIED rung exists for: new bytes arrived and the
// tool could not hash all of them. Reporting UPGRADED alone would state the
// version moved and stay silent about the payload being unverifiable.
func TestClassifyDoesNotLetAnUpgradeMaskAnUnverifiedPayload(t *testing.T) {
	const currentID = "agent-plugin:claude:demo@1.2.0"
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: currentID, Type: model.AssetAgentPlugin, Name: "demo", Version: "1.2.0", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: currentID}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", AssetID: currentID,
			ObservationID: "observation:sha256:1111", Status: model.EvidencePartial}},
	}
	rows := classify(inventory, model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: currentID},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:demo@1.1.0"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}})
	if len(rows) != 1 || rows[0].Rung != rungUnverified {
		t.Fatalf("UPGRADED masked an unverifiable payload: %+v", rows)
	}
}

// TestClassifyStillReportsAnUpgradeWhoseRecordsAreComplete guards the other
// side of the same branch. A real upgrade mints a new asset ID, hence new
// observation and evidence IDs, so every record of the upgraded asset arrives
// as *added*. Those records must not demote the asset-level UPGRADED to the
// record-level CHANGED — "same version, different bytes" would be false.
func TestClassifyStillReportsAnUpgradeWhoseRecordsAreComplete(t *testing.T) {
	const currentID = "agent-plugin:claude:demo@1.2.0"
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: currentID, Type: model.AssetAgentPlugin, Name: "demo", Version: "1.2.0", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: currentID}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", AssetID: currentID,
			ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete}},
	}
	rows := classify(inventory, model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: currentID},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:demo@1.1.0"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:1111"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}})
	want := []rungRow{{key: currentID, Rung: rungUpgraded, Type: string(model.AssetAgentPlugin),
		Name: "demo", Host: "claude", From: "1.1.0", To: "1.2.0"}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got=%+v want=%+v", rows, want)
	}
}

// TestClassifyOrdersRowsTotallyWhenDisplayColumnsCollide covers the release
// invariant "deterministic input produces byte-identical report JSON and
// snapshot state". Rows are collected from a map, so any pair the comparator
// calls equal renders in random order. Two real ID families collide on all
// four display columns: two VS Code publishers shipping the same manifest name
// (the ID keeps "publisher.name", the asset's Name does not), and one package
// name under two ecosystems (packages clear Source, so Host is empty).
func TestClassifyOrdersRowsTotallyWhenDisplayColumnsCollide(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "ide-extension:vscode:usernamehw.errorlens@2.0.0", Type: model.AssetIDEExtension,
			Name: "errorlens", Version: "2.0.0", Source: "vscode"},
		{ID: "ide-extension:vscode:otherpub.errorlens@4.0.0", Type: model.AssetIDEExtension,
			Name: "errorlens", Version: "4.0.0", Source: "vscode"},
		{ID: "pkg:npm/six@2.0.0", Type: model.AssetPackage, Name: "six", Version: "2.0.0"},
		{ID: "pkg:pypi/six@4.0.0", Type: model.AssetPackage, Name: "six", Version: "4.0.0"},
	}}
	delta := model.Delta{}
	for _, pair := range [][2]string{
		{"ide-extension:vscode:usernamehw.errorlens@2.0.0", "ide-extension:vscode:usernamehw.errorlens@1.0.0"},
		{"ide-extension:vscode:otherpub.errorlens@4.0.0", "ide-extension:vscode:otherpub.errorlens@3.0.0"},
		{"pkg:npm/six@2.0.0", "pkg:npm/six@1.0.0"},
		{"pkg:pypi/six@4.0.0", "pkg:pypi/six@3.0.0"},
	} {
		delta.Changes = append(delta.Changes,
			model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: pair[0]},
			model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: pair[1]})
	}

	seen := make(map[string]struct{})
	for iteration := 0; iteration < 200; iteration++ {
		var rendered []string
		for _, row := range classify(inventory, delta) {
			rendered = append(rendered, row.render())
		}
		seen[strings.Join(rendered, "\n")] = struct{}{}
	}
	if len(seen) != 1 {
		outputs := make([]string, 0, len(seen))
		for output := range seen {
			outputs = append(outputs, output)
		}
		sort.Strings(outputs)
		t.Fatalf("row order is not deterministic: %d distinct renderings:\n%s",
			len(seen), strings.Join(outputs, "\n---\n"))
	}
}

func TestClassifyIsEmptyForEmptyDelta(t *testing.T) {
	if rows := classify(model.Inventory{}, model.Delta{}); len(rows) != 0 {
		t.Fatalf("rows=%+v", rows)
	}
}
