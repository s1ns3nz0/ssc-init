package policy_test

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func changeDocument(t *testing.T) policy.Document {
	t.Helper()
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"silent-extension-change","family":"change","enabled":true,"description":"d","match":{"assetType":["ide-extension"],"rungs":["CHANGED"]}}]}`))
	if err != nil {
		t.Fatalf("change rule with a shape narrowing field was rejected: %v", err)
	}
	return document
}

func TestChangeRuleMatchesLadderRungs(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "ide-extension:vscode:esbenp.prettier-vscode@11.0.0", Type: model.AssetIDEExtension, Name: "prettier-vscode", Source: "vscode"},
		{ID: "agent-plugin:claude:helpful-utils@1.0.0", Type: model.AssetAgentPlugin, Name: "helpful-utils", Source: "claude"},
	}}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: inventory.Assets[0].ID},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: inventory.Assets[1].ID},
	}}
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: changeDocument(t)}, Inventory: inventory, Delta: delta})
	if len(result.Violations) != 1 || result.Violations[0].AssetID != inventory.Assets[0].ID {
		t.Fatalf("unexpected violations: %+v", result.Violations)
	}
}

func TestChangeRuleAgainstAnEmptyDeltaFiresNothing(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{{ID: "ide-extension:vscode:x@1", Type: model.AssetIDEExtension, Name: "x"}}}
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: changeDocument(t)}, Inventory: inventory})
	if len(result.Violations) != 0 {
		t.Fatalf("change rule fell back to the whole inventory: %+v", result.Violations)
	}
}

func TestRemovedChangeStillCarriesSafeDisplayColumns(t *testing.T) {
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"removed","family":"change","enabled":true,"description":"d","match":{"rungs":["REMOVED"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	const removed = "mcp:claude-code:old-server"
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: document}, Delta: model.Delta{Changes: []model.Change{{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: removed}}}})
	if len(result.Violations) != 1 || result.Violations[0].AssetID != removed || result.Violations[0].AssetName != "old-server" {
		t.Fatalf("removed row was lost: %+v", result.Violations)
	}
}
