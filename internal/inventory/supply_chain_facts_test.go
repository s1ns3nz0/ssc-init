package inventory_test

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestSupplyChainFactChangesEnterTheAssetDelta(t *testing.T) {
	before := model.Inventory{Assets: []model.Asset{{ID: "tool:test", Type: model.AssetTool, Name: "test", Signature: &model.Signature{Status: model.SignatureUnsigned}}}}
	after := model.Inventory{Assets: []model.Asset{{ID: "tool:test", Type: model.AssetTool, Name: "test", Signature: &model.Signature{Status: model.SignatureValid, Identifier: "dev.sscinit.core", TeamID: "ABCDE12345"}}}}
	delta := inventory.Diff(before, after)
	if len(delta.Changes) != 1 || delta.Changes[0].Entity != model.ChangeEntityAsset || delta.Changes[0].EntityID != "tool:test" {
		t.Fatalf("delta=%+v", delta)
	}
}
