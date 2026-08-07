package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	remoteSSE := collectMCPDigest(t, `{"mcpServers":{"fixture":{"url":"https://example.invalid/mcp?mode=safe","transport":"sse"}}}`)
	if remoteSSE == remoteOne {
		t.Fatal("transport mutation did not change digest")
	}
}

func TestMCPCombinedCredentialSyntaxIsRedactedBeforeSemanticEvidence(t *testing.T) {
	config := func(marker string) string {
		return `{"mcpServers":{"fixture":{"command":"runner -H:` + marker + `","args":["--auth:` + marker + `","--header=` + marker + `","--env:` + marker + `","--token:` + marker + `","--client-secret=` + marker + `","-H` + marker + `","-H:` + marker + `","-e` + marker + `","-e:` + marker + `","--tokenizer"]}}}`
	}
	firstResult, firstCollection := collectMCPConfigEvidence(t, config("credential-marker-one"))
	secondResult, secondCollection := collectMCPConfigEvidence(t, config("credential-marker-two"))
	if len(firstResult.Observations) != 1 || firstResult.Observations[0].Metadata["command"] != "[redacted]" {
		t.Fatalf("observations=%+v", firstResult.Observations)
	}
	wantArgs := "--auth:[redacted]\x1f--header=[redacted]\x1f--env:[redacted]\x1f--token:[redacted]\x1f--client-secret=[redacted]\x1f-H[redacted]\x1f-H:[redacted]\x1f-e[redacted]\x1f-e:[redacted]\x1f--tokenizer"
	if got := firstResult.Observations[0].Metadata["args"]; got != wantArgs {
		t.Fatalf("args=%q want=%q", got, wantArgs)
	}
	if len(firstCollection.Evidence) != 1 || firstCollection.Evidence[0].Status != model.EvidenceComplete || len(secondCollection.Evidence) != 1 || secondCollection.Evidence[0].Status != model.EvidenceComplete || firstCollection.Evidence[0].Digest != secondCollection.Evidence[0].Digest {
		t.Fatalf("first=%+v second=%+v", firstCollection, secondCollection)
	}
	assertJSONExcludes(t, firstResult, "credential-marker-one", "credential-marker-two")
	assertJSONExcludes(t, secondResult, "credential-marker-one", "credential-marker-two")
	assertJSONExcludes(t, firstCollection, "credential-marker-one", "credential-marker-two")
}

func TestMCPPunctuationAttachedCredentialsAndCanonicalHeadersAreRedacted(t *testing.T) {
	// Keep this corpus mirrored by the defensive hasher cases in semantic_test.go.
	cases := []struct {
		name      string
		args      []string
		want      string
		forbidden []string
	}{
		{"long slash", []string{"--auth/slash-marker"}, "[redacted]", []string{"slash-marker"}},
		{"long semicolon", []string{"--header;semicolon-marker"}, "[redacted]", []string{"semicolon-marker"}},
		{"long pipe", []string{"--env|pipe-marker"}, "[redacted]", []string{"pipe-marker"}},
		{"long quote", []string{"--token'quote-marker"}, "[redacted]", []string{"quote-marker"}},
		{"long double quote", []string{`--client-secret"double-marker`}, "[redacted]", []string{"double-marker"}},
		{"short header slash", []string{"-H/short-marker"}, "[redacted]", []string{"short-marker"}},
		{"short env pipe", []string{"-e|env-marker"}, "[redacted]", []string{"env-marker"}},
		{"noncanonical placeholder", []string{"--auth/colon-marker:[redacted]"}, "[redacted]", []string{"colon-marker"}},
		{"standalone", []string{"--auth", "standalone-marker"}, "--auth\x1f[redacted]", []string{"standalone-marker"}},
		{"authorization header", []string{"Authorization: header-marker"}, "Authorization: [redacted]", []string{"header-marker"}},
		{"proxy authorization header", []string{"Proxy-Authorization: proxy-marker"}, "Proxy-Authorization: [redacted]", []string{"proxy-marker"}},
		{"split authorization header", []string{"Authorization:", "split-marker"}, "Authorization: [redacted]\x1f[redacted]", []string{"split-marker"}},
		{"split proxy authorization header", []string{"Proxy-Authorization:", "split-proxy-marker"}, "Proxy-Authorization: [redacted]\x1f[redacted]", []string{"split-proxy-marker"}},
		{"safe tokenizer", []string{"--tokenizer"}, "--tokenizer", nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			contents, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"fixture": map[string]any{"command": "runner", "args": test.args}}})
			if err != nil {
				t.Fatal(err)
			}
			result, collection := collectMCPConfigEvidence(t, string(contents))
			if len(result.Observations) != 1 {
				t.Fatalf("result=%+v", result)
			}
			if got := result.Observations[0].Metadata["args"]; got != test.want {
				t.Fatalf("args=%q want=%q", got, test.want)
			}
			if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
				t.Fatalf("collection=%+v", collection)
			}
			assertJSONExcludes(t, result, test.forbidden...)
			assertJSONExcludes(t, collection, test.forbidden...)
		})
	}
}

func TestMCPInvalidSemanticListItemsAreQuarantinedBeforeObservationFinalization(t *testing.T) {
	config := `{"mcpServers":{
"safe":{"command":"node","env":{"API_TOKEN":"secret"},"headers":{"Authorization":"secret"},"enabledTools":["read_file","tool-name","tool.name"],"disabledTools":["delete_file"]},
"bad-env":{"command":"node","env":{"BAD=actualvalue":"secret"}},
"bad-header":{"command":"node","headers":{"X-Auth:actualvalue":"secret"}},
"bad-enabled":{"command":"node","enabledTools":["bad/tool"]},
"bad-disabled":{"command":"node","disabledTools":["write:actualvalue"]}
}}`
	result, collection := collectMCPConfigEvidence(t, config)
	target := assertTarget(t, result.Targets, "mcp.cursor.user", "")
	if target.Status != model.TargetPartial || target.Assets != 1 || target.Observations != 1 || !hasErrorCode(target.Errors, "rejected_metadata") {
		t.Fatalf("target=%+v", target)
	}
	if len(result.Observations) != 1 || result.Observations[0].AssetID != "mcp:cursor:safe" {
		t.Fatalf("result=%+v", result)
	}
	metadata := result.Observations[0].Metadata
	if metadata["env_keys"] != "API_TOKEN" || metadata["header_keys"] != "Authorization" || metadata["enabled_tools"] != "read_file,tool-name,tool.name" || metadata["disabled_tools"] != "delete_file" {
		t.Fatalf("metadata=%+v", metadata)
	}
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v", collection)
	}
	assertJSONExcludes(t, result, "BAD=actualvalue", "X-Auth:actualvalue", "bad/tool", "write:actualvalue")
}

func TestMCPEmbeddedAbsolutePathsAreRedactedWithoutRejectingSafeShapes(t *testing.T) {
	config := `{"mcpServers":{"fixture":{"command":"runner --root:/private/command-marker","args":["--root:/private/argument-marker","x;/private/semicolon-marker","--root:'/private/quote-marker","x|/private/pipe-marker","[/private/bracket-marker","https://example.invalid/api/v1/mcp","https://[::1]/api/v1/mcp","$HOME/Projects/demo","config-relative/work/file","external-arg/path-sha256:` + strings.Repeat("a", 64) + `"]}}}`
	result, collection := collectMCPConfigEvidence(t, config)
	if len(result.Observations) != 1 {
		t.Fatalf("observations=%+v", result.Observations)
	}
	metadata := result.Observations[0].Metadata
	if metadata["command"] != "[redacted]" {
		t.Fatalf("command=%q", metadata["command"])
	}
	wantArgs := "[redacted]\x1f[redacted]\x1f[redacted]\x1f[redacted]\x1f[redacted]\x1fhttps://example.invalid/api/v1/mcp\x1fhttps://[::1]/api/v1/mcp\x1f$HOME/Projects/demo\x1fconfig-relative/work/file\x1fexternal-arg/path-sha256:" + strings.Repeat("a", 64)
	if metadata["args"] != wantArgs {
		t.Fatalf("args=%q want=%q", metadata["args"], wantArgs)
	}
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v", collection)
	}
	assertJSONExcludes(t, result, "/private/command-marker", "/private/argument-marker", "/private/semicolon-marker", "/private/quote-marker", "/private/pipe-marker", "/private/bracket-marker")
}

func TestMCPURLPathsAreDecodedAndSanitizedBeforeSemanticEvidence(t *testing.T) {
	config := `{"mcpServers":{
"safe":{"url":"https://alice:userinfo-marker@example.invalid/api/v1/mcp?access_token=query-marker&mode=safe#fragment-marker"},
"assignment":{"url":"https://example.invalid/password=assignment-marker"},
"colon-assignment":{"url":"https://example.invalid/password:colon-assignment-marker"},
"encoded-assignment":{"url":"https://example.invalid/password%3Dencoded-assignment-marker"},
"auth-callback":{"url":"https://example.invalid/auth/callback"},
"token-refresh":{"url":"https://example.invalid/token/refresh"},
"ordinary-escape":{"url":"https://example.invalid/api%2Dv1/mcp"},
"encoded-separator":{"url":"https://example.invalid/token%2Fencoded-segment-marker"},
"double-encoded":{"url":"https://example.invalid/password%253Ddouble-encoded-marker"},
"double-encoded-lower":{"url":"https://example.invalid/password%253ddouble-lower-marker"},
"control":{"url":"https://example.invalid/api/%0av1"},
"invalid-escape":{"url":"https://example.invalid/%zz"}
}}`
	result, collection := collectMCPConfigEvidence(t, config)
	if len(result.Observations) != 12 || len(collection.Evidence) != 12 {
		t.Fatalf("observations=%+v collection=%+v", result.Observations, collection)
	}
	for _, observation := range result.Observations {
		shape := observation.Metadata["url_shape"]
		switch observation.AssetID {
		case "mcp:cursor:safe":
			if shape != "https://example.invalid/api/v1/mcp?query_keys=access_token,mode" {
				t.Fatalf("safe shape=%q", shape)
			}
		case "mcp:cursor:auth-callback":
			if shape != "https://example.invalid/auth/callback" {
				t.Fatalf("auth callback shape=%q", shape)
			}
		case "mcp:cursor:token-refresh":
			if shape != "https://example.invalid/token/refresh" {
				t.Fatalf("token refresh shape=%q", shape)
			}
		case "mcp:cursor:ordinary-escape":
			if shape != "https://example.invalid/api%2Dv1/mcp" {
				t.Fatalf("ordinary escape shape=%q", shape)
			}
		default:
			if shape != "[redacted]" {
				t.Fatalf("asset=%q shape=%q", observation.AssetID, shape)
			}
		}
	}
	for _, item := range collection.Evidence {
		if item.Status != model.EvidenceComplete {
			t.Fatalf("evidence=%+v", item)
		}
	}
	assertJSONExcludes(t, result,
		"userinfo-marker", "query-marker", "fragment-marker", "assignment-marker",
		"colon-assignment-marker", "encoded-assignment-marker", "encoded-segment-marker", "double-encoded-marker", "double-lower-marker", "%0a", "%zz",
	)
}

func TestMCPRepresentativeSupportedTransportsProduceCompleteSemanticEvidence(t *testing.T) {
	config := `{"mcpServers":{
"stdio":{"command":"node"},
"http":{"url":"https://example.invalid/api/v1/mcp","transport":"http"},
"sse":{"url":"https://example.invalid/api/v1/sse","transport":"sse"},
"stream":{"url":"https://example.invalid/api/v1/stream","transport":"streamable-http"}
}}`
	result, collection := collectMCPConfigEvidence(t, config)
	if len(result.Observations) != 4 || len(collection.Evidence) != 4 || collection.Coverage.Status != model.CoverageComplete {
		t.Fatalf("result=%+v collection=%+v", result, collection)
	}
	for _, item := range collection.Evidence {
		if item.Status != model.EvidenceComplete {
			t.Fatalf("evidence=%+v", item)
		}
	}
}

func TestMCPCWDReferencesAreCanonicalBeforeSemanticEvidence(t *testing.T) {
	config := `{"mcpServers":{
"home":{"command":"node","cwd":"$HOME"},
"relative":{"command":"node","cwd":"work"},
"backslash":{"command":"node","cwd":"$HOME/work\\nested"},
"traversal":{"command":"node","cwd":"$HOME/../work"},
"duplicate":{"command":"node","cwd":"$HOME/work//nested"}
}}`
	result, collection := collectMCPConfigEvidence(t, config)
	if len(result.Observations) != 5 || len(collection.Evidence) != 5 {
		t.Fatalf("result=%+v collection=%+v", result, collection)
	}
	for _, observation := range result.Observations {
		want := "[redacted]"
		switch observation.AssetID {
		case "mcp:cursor:home":
			want = "$HOME"
		case "mcp:cursor:relative":
			want = "config-relative/work"
		}
		if got := observation.Metadata["cwd_ref"]; got != want {
			t.Fatalf("asset=%q cwd_ref=%q want=%q", observation.AssetID, got, want)
		}
	}
	for _, item := range collection.Evidence {
		if item.Status != model.EvidenceComplete {
			t.Fatalf("evidence=%+v", item)
		}
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

func collectMCPConfigEvidence(t *testing.T, config string) (model.CollectorResult, evidence.Collection) {
	t.Helper()
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".cursor", "mcp.json"), config)
	result := collectMCP(t, home)
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	return result, collection
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
