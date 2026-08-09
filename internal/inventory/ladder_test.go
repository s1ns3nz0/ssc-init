package inventory_test

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestLadderRungOrderIsTheDocumentedSeverityOrder(t *testing.T) {
	want := []inventory.Rung{inventory.RungNew, inventory.RungChanged, inventory.RungUnverified, inventory.RungUpgraded, inventory.RungRemoved}
	for index, rung := range want {
		if int(rung) != index {
			t.Fatalf("%s has ordinal %d, want %d", rung.Label(), int(rung), index)
		}
		if resolved, ok := inventory.RungByLabel(rung.Label()); !ok || resolved != rung {
			t.Fatalf("documented rung label %q is not resolvable", rung.Label())
		}
	}
	if _, ok := inventory.RungByLabel("CRITICAL"); ok {
		t.Fatal("undocumented rung label accepted")
	}
}

func TestLadderPairsOneVersionedRemovalAndAdditionAsUpgrade(t *testing.T) {
	current := model.Asset{ID: "agent-plugin:claude:superpowers@6.2.0", Type: model.AssetAgentPlugin, Name: "superpowers", Source: "claude"}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: current.ID},
	}}
	rows := inventory.Ladder(model.Inventory{Assets: []model.Asset{current}}, delta)
	if len(rows) != 1 || rows[0].Rung != inventory.RungUpgraded || rows[0].From != "6.1.1" || rows[0].To != "6.2.0" || rows[0].AssetID() != current.ID {
		t.Fatalf("unexpected ladder: %+v", rows)
	}
}

func TestLadderChangedBeatsUnverifiedForTheSameExistingAsset(t *testing.T) {
	asset := model.Asset{ID: "ide-extension:vscode:publisher.extension@1.0.0", Type: model.AssetIDEExtension, Name: "extension", Source: "vscode"}
	evidence := model.ContentEvidence{ID: "evidence", AssetID: asset.ID, Status: model.EvidenceUnavailable}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: asset.ID},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: evidence.ID},
	}}
	rows := inventory.Ladder(model.Inventory{Assets: []model.Asset{asset}, Evidence: []model.ContentEvidence{evidence}}, delta)
	if len(rows) != 1 || rows[0].Rung != inventory.RungChanged {
		t.Fatalf("CHANGED did not retain the documented higher rung: %+v", rows)
	}
}
