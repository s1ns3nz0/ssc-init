package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

func TestCatalogDeclaresOfficialMCPBoundary(t *testing.T) {
	type expectedDeclaration struct {
		id           string
		relativePath string
		host         string
		format       string
		consumers    []string
		scope        model.ObservationScope
		method       model.TargetMethod
		supported    bool
		container    string
	}
	want := []expectedDeclaration{
		{id: "mcp.claude-code.legacy-user", relativePath: ".claude/settings.json", host: "claude-code", format: "json", consumers: []string{"claude-code"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.claude-code.user", relativePath: ".claude.json", host: "claude-code", format: "json", consumers: []string{"claude-code"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.claude-desktop.user", relativePath: "Library/Application Support/Claude/claude_desktop_config.json", host: "claude-desktop", format: "json", consumers: []string{"claude-desktop"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.codex.project", relativePath: ".codex/config.toml", host: "codex", format: "toml", consumers: []string{"codex"}, scope: model.ScopeProject, method: model.TargetFile, supported: false},
		{id: "mcp.codex.user", relativePath: ".codex/config.toml", host: "codex", format: "toml", consumers: []string{"codex"}, scope: model.ScopeUser, method: model.TargetFile, supported: false},
		{id: "mcp.cursor.project", relativePath: ".cursor/mcp.json", host: "cursor", format: "json", consumers: []string{"cursor"}, scope: model.ScopeProject, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.cursor.user", relativePath: ".cursor/mcp.json", host: "cursor", format: "json", consumers: []string{"cursor"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.dev-container", scope: model.ScopeProject, method: model.TargetFile, supported: false},
		{id: "mcp.dynamic-api", scope: model.ScopeUser, method: model.TargetDynamicAPI, supported: false},
		{id: "mcp.environment-relocated", scope: model.ScopeUser, method: model.TargetFile, supported: false},
		{id: "mcp.github-copilot.user", relativePath: ".copilot/mcp-config.json", host: "github-copilot", format: "json", consumers: []string{"github-copilot"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.profile-specific", scope: model.ScopeIDEProfile, method: model.TargetFile, supported: false},
		{id: "mcp.remote-user", scope: model.ScopeUser, method: model.TargetFile, supported: false},
		{id: "mcp.service-managed", scope: model.ScopeSystem, method: model.TargetServiceAPI, supported: false},
		{id: "mcp.shared.project", relativePath: ".mcp.json", host: "shared", format: "json", consumers: []string{"claude-code", "vscode"}, scope: model.ScopeProject, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.vscode-insiders.user", relativePath: "Library/Application Support/Code - Insiders/User/mcp.json", host: "vscode-insiders", format: "json", consumers: []string{"vscode-insiders"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "servers"},
		{id: "mcp.vscode.project", relativePath: ".vscode/mcp.json", host: "vscode", format: "json", consumers: []string{"vscode"}, scope: model.ScopeProject, method: model.TargetFile, supported: true, container: "servers"},
		{id: "mcp.vscode.user", relativePath: "Library/Application Support/Code/User/mcp.json", host: "vscode", format: "json", consumers: []string{"vscode"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "servers"},
		{id: "mcp.windsurf.legacy-user", relativePath: ".windsurf/mcp.json", host: "windsurf", format: "json", consumers: []string{"windsurf"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
		{id: "mcp.windsurf.user", relativePath: ".codeium/windsurf/mcp_config.json", host: "windsurf", format: "json", consumers: []string{"windsurf"}, scope: model.ScopeUser, method: model.TargetFile, supported: true, container: "mcpServers"},
	}

	got := catalogDeclarations()
	if len(got) != len(want) {
		t.Fatalf("declarations=%d want=%d: %+v", len(got), len(want), got)
	}
	for index, expected := range want {
		declaration := got[index]
		if declaration.spec.ID != expected.id || declaration.relativePath != expected.relativePath || declaration.spec.Host != expected.host || declaration.spec.Format != expected.format || !reflect.DeepEqual(declaration.consumers, expected.consumers) || declaration.spec.Scope != expected.scope || declaration.spec.Method != expected.method || declaration.supported != expected.supported || declaration.container != expected.container {
			t.Fatalf("declaration[%d]=%+v want=%+v", index, declaration, expected)
		}
		if declaration.spec.Collector != "mcp" || declaration.spec.Platform != "darwin" {
			t.Fatalf("declaration[%d] ownership=%+v", index, declaration.spec)
		}
	}

	got[0].spec.ID = "mutated"
	got[0].consumers[0] = "mutated"
	again := catalogDeclarations()
	if again[0].spec.ID != want[0].id || !reflect.DeepEqual(again[0].consumers, want[0].consumers) {
		t.Fatalf("catalog mutated through caller: %+v", again[0])
	}
}

func TestParseJSONNormalizesOfficialContainers(t *testing.T) {
	tests := []struct {
		name string
		file string
		want ServerConfig
	}{
		{
			name: "stdio",
			file: "stdio.json",
			want: ServerConfig{
				Name: "local", Command: "node", Args: []string{"server.js", "--mode", "safe"},
				Transport: "stdio", CWD: "$HOME/Projects/demo", Enabled: boolPointer(true),
				EnvKeys: []string{"A_KEY", "Z_KEY"}, EnabledTools: []string{"read", "write"}, DisabledTools: []string{"delete"},
			},
		},
		{
			name: "http equivalent container",
			file: "http.json",
			want: ServerConfig{
				Name: "remote", URL: "https://example.invalid/mcp?mode=safe", Transport: "streamable-http",
				HeaderKeys: []string{"Authorization", "X-Client"},
			},
		},
		{
			name: "disabled",
			file: "disabled.json",
			want: ServerConfig{Name: "paused", Command: "uvx", Transport: "stdio", Enabled: boolPointer(false)},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ParseJSON(readJSONFixture(t, testCase.file))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Issues) != 0 || len(got.Servers) != 1 || !reflect.DeepEqual(got.Servers[0], testCase.want) {
				t.Fatalf("result=%+v want=%+v", got, testCase.want)
			}
		})
	}
}

func TestParseJSONOmitsSecretAndUnknownValues(t *testing.T) {
	got, err := ParseJSON(readJSONFixture(t, "secrets-unknown.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 1 {
		t.Fatalf("servers=%+v", got.Servers)
	}
	server := got.Servers[0]
	if !reflect.DeepEqual(server.EnvKeys, []string{"API_TOKEN"}) {
		t.Fatalf("env=%v", server.EnvKeys)
	}
	if !reflect.DeepEqual(server.HeaderKeys, []string{"Authorization"}) {
		t.Fatalf("headers=%v", server.HeaderKeys)
	}
	if !reflect.DeepEqual(server.UnknownFields, []string{"futureOption"}) {
		t.Fatalf("unknown=%v", server.UnknownFields)
	}
	if len(got.Issues) != 1 || got.Issues[0].Code != "unknown_server_field" {
		t.Fatalf("issues=%+v", got.Issues)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, secret := range []string{"super-secret", "Bearer secret", "unknown-secret-value"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("secret leaked: %s", encoded)
		}
	}
}

func TestParseJSONDoesNotRetainUnsafeUnknownFieldNames(t *testing.T) {
	secretField := "ghp_12345678901234567890"
	got, err := ParseJSON([]byte(`{"mcpServers":{"safe":{"command":"node","` + secretField + `":"value"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 1 || len(got.Servers[0].UnknownFields) != 0 {
		t.Fatalf("servers=%+v", got.Servers)
	}
	if len(got.Issues) != 1 || got.Issues[0].Code != "unknown_server_field" {
		t.Fatalf("issues=%+v", got.Issues)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(secretField)) {
		t.Fatalf("unsafe field name retained: %s", encoded)
	}
}

func TestParseJSONKeepsValidSiblingsAndRejectsAmbiguousTransport(t *testing.T) {
	got, err := ParseJSON(readJSONFixture(t, "malformed-siblings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 1 || got.Servers[0].Name != "safe" {
		t.Fatalf("servers=%+v", got.Servers)
	}
	if len(got.Issues) != 4 {
		t.Fatalf("issues=%+v", got.Issues)
	}
	for _, issue := range got.Issues {
		if issue.Code != "invalid_server" {
			t.Fatalf("issue=%+v", issue)
		}
	}
}

func TestParseJSONRejectsDuplicateKeysAndBoundsInput(t *testing.T) {
	deep := `{"mcpServers":{},"unrelated":` + strings.Repeat(`{"nested":`, 65) + `true` + strings.Repeat(`}`, 65) + `}`
	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{name: "duplicate", raw: []byte(`{"mcpServers":{"bad":{"env":{"TOKEN":"one","TOKEN":"two"}}}}`)},
		{name: "both containers", raw: []byte(`{"mcpServers":{},"servers":{}}`)},
		{name: "trailing value", raw: []byte(`{"mcpServers":{}} {}`)},
		{name: "deep", raw: []byte(deep)},
		{name: "oversized", raw: bytes.Repeat([]byte(" "), maxJSONConfigBytes+1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseJSON(testCase.raw); err == nil {
				t.Fatal("ParseJSON error=nil")
			}
		})
	}
}

func TestParseJSONAcceptsUnderstoodEmptyMaps(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"mcpServers":{}}`),
		[]byte(`{"servers":{},"unrelated":{"safe":true}}`),
	} {
		got, err := ParseJSON(raw)
		if err != nil || len(got.Servers) != 0 || len(got.Issues) != 0 {
			t.Fatalf("raw=%s result=%+v err=%v", raw, got, err)
		}
	}
}

func TestParseJSONContainerRejectsAnotherHostsEquivalent(t *testing.T) {
	for _, testCase := range []struct {
		expected string
		raw      []byte
	}{
		{expected: "mcpServers", raw: []byte(`{"servers":{}}`)},
		{expected: "servers", raw: []byte(`{"mcpServers":{}}`)},
		{expected: "servers", raw: []byte(`{"servers":{},"mcpServers":{}}`)},
	} {
		if _, err := parseJSONContainer(testCase.raw, testCase.expected); err == nil {
			t.Fatalf("expected=%q raw=%s error=nil", testCase.expected, testCase.raw)
		}
	}
}

func readJSONFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "json", name))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func boolPointer(value bool) *bool { return &value }
