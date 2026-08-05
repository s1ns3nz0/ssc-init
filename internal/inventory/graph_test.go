package inventory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

func TestBuildNormalizesDeterministicallyWithoutMutatingInput(t *testing.T) {
	results := []model.CollectorResult{
		{
			Assets: []model.Asset{
				{ID: "b", Name: "B"},
				{ID: "a", Type: model.AssetTool, Name: "Zulu", Version: "2", Metadata: map[string]string{"region": "raw-secret-west", "owner": "team"}},
			},
			Relationships: []model.Relationship{
				{From: "b", Kind: "uses", To: "a"},
				{From: "missing", Kind: "uses", To: "a"},
			},
		},
		{
			Assets: []model.Asset{
				{ID: "a", Type: model.AssetTool, Name: "Alpha", Version: "1", Metadata: map[string]string{"region": "raw-secret-east", "tier": "prod"}},
			},
			Relationships: []model.Relationship{
				{From: "b", Kind: "uses", To: "a"},
				{From: "a", Kind: "contains", To: "b"},
			},
		},
	}
	original := cloneCollectorResults(results)

	var canonical []byte
	for _, permutation := range [][]model.CollectorResult{results, {results[1], results[0]}} {
		got := Build(permutation)
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if canonical == nil {
			canonical = encoded
		} else if string(encoded) != string(canonical) {
			t.Fatalf("permutation changed output:\nfirst=%s\n got=%s", canonical, encoded)
		}

		wantAssets := []model.Asset{
			{ID: "a", Type: model.AssetTool, Name: "Alpha", Version: "1", Metadata: map[string]string{"owner": "team", "tier": "prod"}},
			{ID: "b", Name: "B"},
		}
		if !reflect.DeepEqual(got.Assets, wantAssets) {
			t.Fatalf("assets=%#v want=%#v", got.Assets, wantAssets)
		}
		wantRelationships := []model.Relationship{
			{From: "a", Kind: "contains", To: "b"},
			{From: "b", Kind: "uses", To: "a"},
		}
		if !reflect.DeepEqual(got.Relationships, wantRelationships) {
			t.Fatalf("relationships=%#v want=%#v", got.Relationships, wantRelationships)
		}
		if len(got.Errors) != 1 || got.Errors[0].Code != "metadata-conflict" {
			t.Fatalf("errors=%#v", got.Errors)
		}
		serializedError, err := json.Marshal(got.Errors[0])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(serializedError), "raw-secret") {
			t.Fatalf("conflict error leaked raw values: %s", serializedError)
		}
	}

	if !reflect.DeepEqual(results, original) {
		t.Fatalf("Build mutated its input:\n got=%#v\nwant=%#v", results, original)
	}
}

func TestBuildSortsMetadataConflictsByAssetAndKey(t *testing.T) {
	got := Build([]model.CollectorResult{{Assets: []model.Asset{
		{ID: "z", Metadata: map[string]string{"b": "1", "a": "1"}},
		{ID: "z", Metadata: map[string]string{"b": "2", "a": "2"}},
		{ID: "a", Metadata: map[string]string{"z": "1"}},
		{ID: "a", Metadata: map[string]string{"z": "2"}},
	}}})
	if len(got.Errors) != 3 {
		t.Fatalf("errors=%#v", got.Errors)
	}
	paths := got.Errors[0].Path + "," + got.Errors[1].Path + "," + got.Errors[2].Path
	if paths != "a#z,z#a,z#b" {
		t.Fatalf("conflict paths=%q", paths)
	}
}

func TestDiffIgnoresOnlyDefinedObservationTimesAndSortsByAssetID(t *testing.T) {
	previous := model.Inventory{Assets: []model.Asset{
		{ID: "d", Name: "removed"},
		{ID: "b", Name: "security-sensitive", SHA256: "old"},
		{ID: "a", Name: "stable", ObservedAt: time.Unix(1, 0), Metadata: map[string]string{model.MetadataObservedAt: "old", "risk": "low"}},
	}}
	current := model.Inventory{Assets: []model.Asset{
		{ID: "c", Name: "added"},
		{ID: "a", Name: "stable", ObservedAt: time.Unix(2, 0), Metadata: map[string]string{model.MetadataObservedAt: "new", "risk": "low"}},
		{ID: "b", Name: "security-sensitive", SHA256: "new"},
	}}

	want := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, AssetID: "b"},
		{Kind: model.ChangeAdded, AssetID: "c"},
		{Kind: model.ChangeRemoved, AssetID: "d"},
	}}
	if got := Diff(previous, current); !reflect.DeepEqual(got, want) {
		t.Fatalf("delta=%#v want=%#v", got, want)
	}
}

func TestDiffTreatsOrdinaryMetadataAsSecurityRelevant(t *testing.T) {
	previous := model.Inventory{Assets: []model.Asset{{ID: "a", Metadata: map[string]string{"risk": "low"}}}}
	current := model.Inventory{Assets: []model.Asset{{ID: "a", Metadata: map[string]string{"risk": "high"}}}}

	want := model.Delta{Changes: []model.Change{{Kind: model.ChangeChanged, AssetID: "a"}}}
	if got := Diff(previous, current); !reflect.DeepEqual(got, want) {
		t.Fatalf("delta=%#v want=%#v", got, want)
	}
}

func cloneCollectorResults(in []model.CollectorResult) []model.CollectorResult {
	out := make([]model.CollectorResult, len(in))
	for index, result := range in {
		out[index] = result
		out[index].Assets = append([]model.Asset(nil), result.Assets...)
		for assetIndex := range out[index].Assets {
			if result.Assets[assetIndex].Metadata != nil {
				out[index].Assets[assetIndex].Metadata = make(map[string]string, len(result.Assets[assetIndex].Metadata))
				for key, value := range result.Assets[assetIndex].Metadata {
					out[index].Assets[assetIndex].Metadata[key] = value
				}
			}
		}
		out[index].Relationships = append([]model.Relationship(nil), result.Relationships...)
		out[index].Errors = append([]model.CoverageError(nil), result.Errors...)
	}
	return out
}
