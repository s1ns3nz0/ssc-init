package report_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

func hookFixture() (model.Inventory, model.Delta) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
			{ID: "ide-extension:vscode:bravo@2.0.0", Type: model.AssetIDEExtension, Name: "bravo", Version: "2.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
			{ID: "evidence:sha256:bbbb", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1},
			{ID: "evidence:sha256:cccc", AssetID: "pkg:pypi/charlie@3.0.0", ObservationID: "observation:sha256:3333", Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:bravo@2.0.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:gone"},
	}}
	return inventory, delta
}

func TestWriteHookSummaryRendersLadder(t *testing.T) {
	// An added asset is always in the inventory the scan just wrote, so every
	// added ID here has a record; only the removed predecessor is absent.
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
			{ID: "mcp:claude-code:github", Type: model.AssetMCP, Name: "github", Source: "claude-code"},
			{ID: "agent-plugin:claude:superpowers@6.2.0", Type: model.AssetAgentPlugin, Name: "superpowers", Version: "6.2.0", Source: "claude"},
		},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: "agent-skill:claude:docx"}},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete, Digest: strings.Repeat("a", 64)},
			{ID: "evidence:sha256:cccc", ObservationID: "observation:sha256:1111", Status: model.EvidenceOversize},
			{ID: "evidence:sha256:dddd", ObservationID: "observation:sha256:1111", Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}}

	var first, second bytes.Buffer
	if err := report.WriteHookSummary(&first, inventory, delta, false); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteHookSummary(&second, inventory, delta, false); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("not deterministic:\n%q\n%q", first.String(), second.String())
	}
	output := first.String()
	for _, pattern := range []string{
		`^ssc-init: 3 changes since last snapshot\n`,
		`(?m)^  NEW\s+mcp-server\s+github \(claude-code\)$`,
		`(?m)^  CHANGED\s+agent-skill\s+docx \(claude\)$`,
		`(?m)^  UPGRADED\s+agent-plugin\s+superpowers \(claude\)\s+6\.1\.1 → 6\.2\.0$`,
		`(?m)^  1 targets unverified \(standing — run: ssc-init status --pretty\)$`,
	} {
		if !regexp.MustCompile(pattern).MatchString(output) {
			t.Fatalf("missing %q in:\n%s", pattern, output)
		}
	}
	if strings.Contains(output, strings.Repeat("a", 64)) || strings.Contains(output, "evidence records") {
		t.Fatalf("leaked digest or legacy grouping:\n%s", output)
	}
}

// firstBaselineFixture is the state of a machine whose very first scan found
// one asset: the delta is all additions and covers the whole inventory.
func firstBaselineFixture() (model.Inventory, model.Delta) {
	inventory := model.Inventory{
		Assets:   []model.Asset{{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", Status: model.EvidenceComplete}},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-skill:claude:docx"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}}
	return inventory, delta
}

func TestWriteHookSummaryReportsInitialBaselineWithoutRungs(t *testing.T) {
	inventory, delta := firstBaselineFixture()
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, delta, true); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "initial baseline recorded — 1 assets, 1 evidence records, 0 unverified") {
		t.Fatalf("initial baseline line missing:\n%s", output)
	}
	if strings.Contains(output, "NEW") {
		t.Fatalf("initial baseline must not print rungs:\n%s", output)
	}
}

// TestWriteHookSummaryReportsFirstAssetAfterEmptyBaseline covers the machine
// whose first snapshot recorded nothing: the delta then looks identical to an
// initial baseline, but a previous snapshot exists, so the first tool ever
// installed is a genuine NEW and must climb the ladder.
func TestWriteHookSummaryReportsFirstAssetAfterEmptyBaseline(t *testing.T) {
	inventory, delta := firstBaselineFixture()
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, delta, false); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if strings.Contains(output, "initial baseline") {
		t.Fatalf("a recorded predecessor must not be called an initial baseline:\n%s", output)
	}
	if !regexp.MustCompile(`(?m)^  NEW\s+agent-skill\s+docx \(claude\)$`).MatchString(output) {
		t.Fatalf("first asset after an empty baseline must be NEW:\n%s", output)
	}
}

func TestWriteHookSummaryIsSilentOnEmptyDelta(t *testing.T) {
	inventory, _ := hookFixture()
	for _, firstRun := range []bool{false, true} {
		var buffer bytes.Buffer
		if err := report.WriteHookSummary(&buffer, inventory, model.Delta{}, firstRun); err != nil {
			t.Fatal(err)
		}
		if buffer.Len() != 0 {
			t.Fatalf("expected silence (firstRun=%v), got:\n%s", firstRun, buffer.String())
		}
	}
}

func TestWriteHookSummaryCapsDetailRows(t *testing.T) {
	var delta model.Delta
	var inventory model.Inventory
	for index := 0; index < 25; index++ {
		name := string(rune('a' + index))
		inventory.Assets = append(inventory.Assets, model.Asset{
			ID: "agent-skill:claude:" + name, Type: model.AssetSkill, Name: name, Source: "claude"})
		delta.Changes = append(delta.Changes,
			model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset,
				EntityID: "agent-skill:claude:" + name},
			model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset,
				EntityID: "mcp:cursor:" + name})
	}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, delta, false); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if got := strings.Count(output, "\n  NEW"); got != 20 {
		t.Fatalf("NEW rows=%d want 20 (cap must favour the highest rung):\n%s", got, output)
	}
	if strings.Contains(output, "REMOVED") || !strings.Contains(output, "…and 30 more changes") {
		t.Fatalf("cap did not prefer high rungs:\n%s", output)
	}
}

func TestWriteHookSummaryIsSilentWhenEveryChangeIsUnattributable(t *testing.T) {
	inventory := model.Inventory{
		Assets:   []model.Asset{{ID: "agent-skill:claude:docx", Name: "docx"}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:zzzz", Status: model.EvidenceOversize}},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:zzzz"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:ghost"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:gone"},
	}}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, delta, false); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("expected silence, got:\n%s", buffer.String())
	}
}
