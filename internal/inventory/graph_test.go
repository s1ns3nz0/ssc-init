package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestV2ModelJSONNamesAndAssetChangeEntity(t *testing.T) {
	result := model.CollectorResult{
		Collector: "mcp",
		Status:    model.CoveragePartial,
		Targets: []model.TargetCoverage{{
			TargetID: "mcp.codex.user",
			Status:   model.TargetUnsupported,
		}},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{`"targets"`, `"targetId"`, `"unsupported"`} {
		if !bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("missing %s in %s", marker, encoded)
		}
	}

	delta := Diff(model.Inventory{}, model.Inventory{Assets: []model.Asset{{ID: "asset", Type: model.AssetTool, Name: "tool"}}})
	want := []model.Change{{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "asset"}}
	if !reflect.DeepEqual(delta.Changes, want) {
		t.Fatalf("changes=%+v want=%+v", delta.Changes, want)
	}
}

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

func TestNormalizeEvidenceSortsPopulatedValuesByID(t *testing.T) {
	input := []model.ContentEvidence{
		{ID: "evidence-z"},
		{ID: "evidence-a"},
		{ID: "evidence-m"},
	}
	want := []model.ContentEvidence{
		{ID: "evidence-a"},
		{ID: "evidence-m"},
		{ID: "evidence-z"},
	}
	if got := NormalizeEvidence(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence=%+v want=%+v", got, want)
	}
}

func TestBuildSortsMetadataConflictsByAssetAndKey(t *testing.T) {
	homeMarker := "/Users/alice/private-home"
	tokenMarker := "ghp_RAW_TOKEN_MARKER"
	assetA := "asset-a:" + homeMarker + ":" + tokenMarker
	assetZ := "asset-z:" + homeMarker + ":" + tokenMarker
	keyA := "metadata-a:" + homeMarker + ":" + tokenMarker
	keyB := "metadata-b:" + homeMarker + ":" + tokenMarker
	keyZ := "metadata-z:" + homeMarker + ":" + tokenMarker
	assets := []model.Asset{
		{ID: assetZ, Metadata: map[string]string{keyB: "1", keyA: "1"}},
		{ID: assetZ, Metadata: map[string]string{keyB: "2", keyA: "2"}},
		{ID: assetA, Metadata: map[string]string{keyZ: "1"}},
		{ID: assetA, Metadata: map[string]string{keyZ: "2"}},
	}
	got := Build([]model.CollectorResult{{Assets: assets}})
	if len(got.Errors) != 3 {
		t.Fatalf("errors=%#v", got.Errors)
	}
	permuted := Build([]model.CollectorResult{{Assets: []model.Asset{assets[3], assets[1], assets[2], assets[0]}}})
	if !reflect.DeepEqual(got.Errors, permuted.Errors) {
		t.Fatalf("permutation changed errors:\nfirst=%#v\n got=%#v", got.Errors, permuted.Errors)
	}
	wantPaths := []string{
		wantConflictFingerprintPath(assetA, keyZ),
		wantConflictFingerprintPath(assetZ, keyA),
		wantConflictFingerprintPath(assetZ, keyB),
	}
	for index, want := range wantPaths {
		if got.Errors[index].Path != want {
			t.Fatalf("error[%d].Path=%q want=%q", index, got.Errors[index].Path, want)
		}
	}
	encoded, err := json.Marshal(got.Errors)
	if err != nil {
		t.Fatal(err)
	}
	for _, rawMarker := range []string{"/Users/", "private-home", "ghp_", "RAW_TOKEN_MARKER", homeMarker, tokenMarker, assetA, assetZ, keyA, keyB, keyZ} {
		if strings.Contains(string(encoded), rawMarker) {
			t.Fatalf("conflict errors leaked %q: %s", rawMarker, encoded)
		}
	}
}

func TestBuildPreservesMultipleObservationsForOneAsset(t *testing.T) {
	asset := model.Asset{ID: "mcp:vscode:workspace", Type: model.AssetMCP, Name: "workspace"}
	first := model.Observation{ID: "observation:sha256:1", AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/Projects/a/.vscode/mcp.json"}
	second := model.Observation{ID: "observation:sha256:2", AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/Projects/b/.vscode/mcp.json"}
	got := Build([]model.CollectorResult{{Collector: "mcp", Assets: []model.Asset{asset, asset}, Observations: []model.Observation{second, first}}})
	if !reflect.DeepEqual(got.Observations, []model.Observation{first, second}) {
		t.Fatalf("observations=%+v", got.Observations)
	}
}

func TestBuildDropsOrphanObservationWithGenericError(t *testing.T) {
	got := Build([]model.CollectorResult{{Collector: "mcp", Observations: []model.Observation{{ID: "observation:sha256:1", AssetID: "missing"}}}})
	if len(got.Observations) != 0 || len(got.Errors) != 1 || got.Errors[0].Code != "orphan-observation" {
		t.Fatalf("inventory=%+v", got)
	}
	encoded, err := json.Marshal(got.Errors[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "missing") {
		t.Fatalf("orphan error leaked asset identity: %s", encoded)
	}
}

func TestBuildNormalizesDuplicateObservationIDConflict(t *testing.T) {
	asset := model.Asset{ID: "asset"}
	first := model.Observation{ID: "observation:sha256:1", AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/alpha"}
	second := model.Observation{ID: first.ID, AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/zulu"}

	got := Build([]model.CollectorResult{{Assets: []model.Asset{asset}, Observations: []model.Observation{second, first}}})
	if !reflect.DeepEqual(got.Observations, []model.Observation{first}) {
		t.Fatalf("observations=%+v", got.Observations)
	}
	if len(got.Errors) != 1 || got.Errors[0].Code != "observation-conflict" || got.Errors[0].Path != wantObservationConflictFingerprint(first.ID) {
		t.Fatalf("errors=%+v", got.Errors)
	}
	encoded, err := json.Marshal(got.Errors[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"alpha", "zulu", first.ID} {
		if strings.Contains(string(encoded), raw) {
			t.Fatalf("observation conflict leaked %q: %s", raw, encoded)
		}
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
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "b"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "c"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "d"},
	}}
	if got := Diff(previous, current); !reflect.DeepEqual(got, want) {
		t.Fatalf("delta=%#v want=%#v", got, want)
	}
}

func TestDiffTreatsOrdinaryMetadataAsSecurityRelevant(t *testing.T) {
	previous := model.Inventory{Assets: []model.Asset{{ID: "a", Metadata: map[string]string{"risk": "low"}}}}
	current := model.Inventory{Assets: []model.Asset{{ID: "a", Metadata: map[string]string{"risk": "high"}}}}

	want := model.Delta{Changes: []model.Change{{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "a"}}}
	if got := Diff(previous, current); !reflect.DeepEqual(got, want) {
		t.Fatalf("delta=%#v want=%#v", got, want)
	}
}

func TestDiffReportsObservationOnlyChange(t *testing.T) {
	before := model.Inventory{Observations: []model.Observation{{ID: "observation:sha256:1", AssetID: "a", Collector: "mcp", Scope: model.ScopeUser, LocationRef: "$HOME/a"}}}
	after := model.Inventory{Observations: []model.Observation{{ID: "observation:sha256:2", AssetID: "a", Collector: "mcp", Scope: model.ScopeUser, LocationRef: "$HOME/b"}}}
	got := Diff(before, after)
	want := []model.Change{
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:1"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:2"},
	}
	if !reflect.DeepEqual(got.Changes, want) {
		t.Fatalf("changes=%+v", got.Changes)
	}
}

func TestDiffReportsEvidenceDigestChange(t *testing.T) {
	before := model.Inventory{Evidence: []model.ContentEvidence{{ID: "e", Digest: strings.Repeat("a", 64)}}}
	after := model.Inventory{Evidence: []model.ContentEvidence{{ID: "e", Digest: strings.Repeat("b", 64)}}}
	got := Diff(before, after)
	want := model.Delta{Changes: []model.Change{{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "e"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}

func TestDiffOrdersAssetEvidenceObservationChanges(t *testing.T) {
	previous := model.Inventory{
		Assets:       []model.Asset{{ID: "asset-a", Name: "before"}},
		Evidence:     []model.ContentEvidence{{ID: "evidence-a", Digest: "before"}},
		Observations: []model.Observation{{ID: "observation-a", AssetID: "a", Collector: "test", Scope: model.ScopeUser, LocationRef: "$HOME/before"}},
	}
	current := model.Inventory{
		Assets:       []model.Asset{{ID: "asset-a", Name: "after"}},
		Evidence:     []model.ContentEvidence{{ID: "evidence-a", Digest: "after"}},
		Observations: []model.Observation{{ID: "observation-a", AssetID: "a", Collector: "test", Scope: model.ScopeUser, LocationRef: "$HOME/after"}},
	}
	want := []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "asset-a"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence-a"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityObservation, EntityID: "observation-a"},
	}
	if got := Diff(previous, current).Changes; !reflect.DeepEqual(got, want) {
		t.Fatalf("changes=%+v want=%+v", got, want)
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
		out[index].Observations = append([]model.Observation(nil), result.Observations...)
		for observationIndex := range out[index].Observations {
			if result.Observations[observationIndex].Consumers != nil {
				out[index].Observations[observationIndex].Consumers = append([]string(nil), result.Observations[observationIndex].Consumers...)
			}
			if result.Observations[observationIndex].Metadata != nil {
				out[index].Observations[observationIndex].Metadata = make(map[string]string, len(result.Observations[observationIndex].Metadata))
				for key, value := range result.Observations[observationIndex].Metadata {
					out[index].Observations[observationIndex].Metadata[key] = value
				}
			}
		}
		out[index].Errors = append([]model.CoverageError(nil), result.Errors...)
	}
	return out
}

func wantConflictFingerprintPath(assetID, metadataKey string) string {
	assetDigest := sha256.Sum256([]byte(assetID))
	keyDigest := sha256.Sum256([]byte(metadataKey))
	return fmt.Sprintf("asset-sha256:%x/metadata-key-sha256:%x", assetDigest, keyDigest)
}

func wantObservationConflictFingerprint(observationID string) string {
	digest := sha256.Sum256([]byte(observationID))
	return fmt.Sprintf("observation-id-sha256:%x", digest)
}
