package report

import (
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

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
		{"mcp:claude-code:@scope/server@1.0.0", "mcp", "claude-code", "@scope/server", "1.0.0"},
		{"opaque", "", "", "opaque", ""},
	} {
		gotType, gotHost, gotName, gotVersion := parseAssetID(test.id)
		if gotType != test.wantType || gotHost != test.wantHost || gotName != test.wantName || gotVersion != test.wantVersion {
			t.Fatalf("id=%q got=(%q,%q,%q,%q) want=(%q,%q,%q,%q)", test.id,
				gotType, gotHost, gotName, gotVersion, test.wantType, test.wantHost, test.wantName, test.wantVersion)
		}
	}
}

func TestClassifyIsEmptyForEmptyDelta(t *testing.T) {
	if rows := classify(model.Inventory{}, model.Delta{}); len(rows) != 0 {
		t.Fatalf("rows=%+v", rows)
	}
}
