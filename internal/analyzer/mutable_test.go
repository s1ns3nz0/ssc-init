package analyzer

import (
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestMutableFactsDerivesClosedDeterministicSignals(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "pkg:npm/unpinned", Type: model.AssetPackage, Name: "unpinned"},
		{ID: "pkg:npm/latest@latest", Type: model.AssetPackage, Name: "latest", Version: "latest", Provenance: &model.Provenance{Status: model.ProvenanceMutable}},
		{ID: "tool:script", Type: model.AssetTool, Name: "script", Metadata: map[string]string{"execution_form": "remote-script", "git_ref_kind": "branch"}},
	}}
	first, second := MutableFacts(inventory), MutableFacts(inventory)
	if len(first) != 5 || !reflect.DeepEqual(first, second) {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	for _, fact := range first {
		if !fact.Valid() || fact.Category != model.AnalyzerMutableReference {
			t.Fatalf("invalid fact=%+v", fact)
		}
	}
}

func TestMutableFactsDoesNotTreatOrdinaryVersionlessToolAsMutable(t *testing.T) {
	if got := MutableFacts(model.Inventory{Assets: []model.Asset{{ID: "tool:git", Type: model.AssetTool, Name: "git"}}}); len(got) != 0 {
		t.Fatalf("facts=%+v", got)
	}
}
