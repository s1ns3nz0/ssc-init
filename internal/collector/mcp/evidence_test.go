package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestMCPCollectorIssuesOneSealedSemanticTargetPerFinalizedObservation(t *testing.T) {
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.user]\ncommand = \"node\"\n")
	firstProject := filepath.Join(home, "Projects", "one", ".mcp.json")
	secondProject := filepath.Join(home, "Projects", "two", ".mcp.json")
	writeMCPFile(t, firstProject, `{"mcpServers":{"shared":{"command":"node"}}}`)
	writeMCPFile(t, secondProject, `{"mcpServers":{"shared":{"command":"node"}}}`)
	result := collectMCP(t, home, sharedProjectTarget(t, home, secondProject), sharedProjectTarget(t, home, firstProject))

	if len(result.Observations) != 3 || len(result.LocalEvidenceTargets) != len(result.Observations) || result.LocalEvidenceIssuer == nil {
		t.Fatalf("observations=%+v targets=%+v issuer=%T", result.Observations, result.LocalEvidenceTargets, result.LocalEvidenceIssuer)
	}
	for _, target := range result.LocalEvidenceTargets {
		if target.TargetID == "" || target.TargetID != evidenceTargetSource(t, result.Observations, target.ObservationID)+".semantic" || target.Kind != model.EvidenceSemanticSHA256 || target.Subject != model.EvidenceSubjectMCPDeclaration || target.RootPath != "" || target.RelativePath != "" || target.PresetStatus != "" || target.AssetID == "" || target.Provenance == nil {
			t.Fatalf("target=%+v", target)
		}
	}
	assertMCPRuntimeOnly(t, result, home)

	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory.Build([]model.CollectorResult{result}), []model.CollectorResult{result})
	if collection.Coverage.Status != model.CoverageComplete || len(collection.Evidence) != 3 || len(collection.Coverage.Targets) != 3 {
		t.Fatalf("collection=%+v", collection)
	}
	for index, item := range collection.Evidence {
		if item.Status != model.EvidenceComplete || item.Kind != model.EvidenceSemanticSHA256 || item.Subject != model.EvidenceSubjectMCPDeclaration || item.AssetID == "" || item.ObservationID == "" || item.Digest == "" {
			t.Fatalf("evidence[%d]=%+v", index, item)
		}
	}
}

func TestMCPSecretValuesDoNotChangeSemanticEvidenceOrPublicModels(t *testing.T) {
	first := collectMCPSecretSemantic(t, "environment-secret-one", "header-secret-one")
	second := collectMCPSecretSemantic(t, "environment-secret-two", "header-secret-two")
	if first.digest != second.digest {
		t.Fatalf("secret-only mutation changed digest: %q %q", first.digest, second.digest)
	}
	for _, encoded := range [][]byte{first.resultJSON, first.inventoryJSON, first.collectionJSON, first.snapshotJSON, second.resultJSON, second.inventoryJSON, second.collectionJSON, second.snapshotJSON} {
		for _, marker := range []string{"environment-secret-one", "environment-secret-two", "header-secret-one", "header-secret-two", "raw-config-marker"} {
			if bytes.Contains(encoded, []byte(marker)) {
				t.Fatalf("secret marker %q persisted in %s", marker, encoded)
			}
		}
	}
}

func TestMCPSupportedSemanticMutationsChangeEndToEndDigest(t *testing.T) {
	base := `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`
	baseline := collectMCPDigest(t, base)
	cases := []struct {
		name, config string
	}{
		{"command", `{"mcpServers":{"fixture":{"command":"python","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`},
		{"args", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","strict"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`},
		{"transport", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"sse"}}}`},
		{"enabled", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":false,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`},
		{"environment key name", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"OTHER_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`},
		{"header key name", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"X-Other":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["read"],"disabledTools":["delete"],"transport":"stdio"}}}`},
		{"tool lists", `{"mcpServers":{"fixture":{"command":"node","args":["--mode","safe"],"cwd":"work","env":{"API_TOKEN":"raw-config-marker"},"headers":{"Authorization":"Bearer raw-config-marker"},"enabled":true,"enabledTools":["write"],"disabledTools":["remove"],"transport":"stdio"}}}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := collectMCPDigest(t, test.config); got == baseline {
				t.Fatalf("semantic mutation did not change digest: %s", test.name)
			}
		})
	}
	remoteOne := collectMCPDigest(t, `{"mcpServers":{"fixture":{"url":"https://example.invalid/mcp?mode=safe"}}}`)
	remoteTwo := collectMCPDigest(t, `{"mcpServers":{"fixture":{"url":"https://example.invalid/other?mode=safe"}}}`)
	if remoteOne == remoteTwo {
		t.Fatal("URL shape mutation did not change digest")
	}
}

type mcpSecretSemantic struct {
	digest         string
	resultJSON     []byte
	inventoryJSON  []byte
	collectionJSON []byte
	snapshotJSON   []byte
}

func collectMCPSecretSemantic(t *testing.T, environmentSecret, headerSecret string) mcpSecretSemantic {
	t.Helper()
	config := `{"mcpServers":{"fixture":{"command":"node","env":{"API_TOKEN":"` + environmentSecret + `"},"headers":{"Authorization":"Bearer ` + headerSecret + `"}}},"raw-config-marker":"ignored"}`
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".cursor", "mcp.json"), config)
	result := collectMCP(t, home)
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	inventoryValue := inventory.Build([]model.CollectorResult{result})
	inventoryJSON, err := json.Marshal(inventoryValue)
	if err != nil {
		t.Fatal(err)
	}
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventoryValue, []model.CollectorResult{result})
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v", collection)
	}
	collectionJSON, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}
	snapshotJSON, err := json.Marshal(model.Snapshot{Inventory: inventoryValue})
	if err != nil {
		t.Fatal(err)
	}
	return mcpSecretSemantic{digest: collection.Evidence[0].Digest, resultJSON: resultJSON, inventoryJSON: inventoryJSON, collectionJSON: collectionJSON, snapshotJSON: snapshotJSON}
}

func collectMCPDigest(t *testing.T, config string) string {
	t.Helper()
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".cursor", "mcp.json"), config)
	result := collectMCP(t, home)
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v result=%+v", collection, result)
	}
	return collection.Evidence[0].Digest
}

func evidenceTargetSource(t *testing.T, observations []model.Observation, observationID string) string {
	t.Helper()
	for _, observation := range observations {
		if observation.ID == observationID {
			return observation.Source
		}
	}
	t.Fatalf("missing observation %q", observationID)
	return ""
}

func assertMCPRuntimeOnly(t *testing.T, result model.CollectorResult, forbidden string) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(forbidden)) || bytes.Contains(encoded, []byte("semantic")) {
		t.Fatalf("runtime target data persisted: %s", encoded)
	}
	copyTargets := append([]model.LocalEvidenceTarget(nil), result.LocalEvidenceTargets...)
	sort.Slice(copyTargets, func(i, j int) bool { return copyTargets[i].ObservationID < copyTargets[j].ObservationID })
	if !reflect.DeepEqual(copyTargets, result.LocalEvidenceTargets) {
		t.Fatalf("semantic targets are not deterministic: %+v", result.LocalEvidenceTargets)
	}
}
