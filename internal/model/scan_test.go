package model

import (
	"encoding/json"
	"testing"
)

func TestInventoryJSONFieldOrderIsStableV2Contract(t *testing.T) {
	inventory := Inventory{
		Assets:        []Asset{{ID: "asset", Type: AssetTool, Name: "tool"}},
		Observations:  []Observation{{ID: "observation", AssetID: "asset", Collector: "packages", Scope: ScopeToolEnvironment, LocationRef: "$HOME/bin/tool"}},
		Relationships: []Relationship{{From: "asset", To: "asset", Kind: "same-as"}},
		Errors:        []CoverageError{{Code: "partial", Message: "partial evidence"}},
	}

	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"assets":[{"id":"asset","type":"tool","name":"tool"}],"observations":[{"id":"observation","assetId":"asset","collector":"packages","scope":"tool-environment","locationRef":"$HOME/bin/tool"}],"relationships":[{"from":"asset","to":"asset","kind":"same-as"}],"errors":[{"code":"partial","message":"partial evidence"}]}`
	if string(encoded) != want {
		t.Fatalf("inventory JSON=%s\nwant=%s", encoded, want)
	}
}
