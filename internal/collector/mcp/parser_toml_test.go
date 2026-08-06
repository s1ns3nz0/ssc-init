package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTOMLNormalizesCodexStdioServer(t *testing.T) {
	got, err := ParseTOML(readTOMLFixture(t, "stdio.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want := ServerConfig{
		Name: "local", Command: "uvx", Args: []string{"demo", "--mode=safe"},
		Transport: "stdio", CWD: "/tmp/work", Enabled: boolPointer(false),
		EnvKeys:      []string{"A_KEY", "FORWARD_TOKEN", "HOME", "Z_KEY"},
		EnabledTools: []string{"read", "write"}, DisabledTools: []string{"delete"},
	}
	assertTOMLParseResult(t, got, want)
	assertTOMLJSONExcludes(t, got, "stdio-secret-a", "stdio-secret-z")
}

func TestParseTOMLNormalizesCodexHTTPServer(t *testing.T) {
	got, err := ParseTOML(readTOMLFixture(t, "http.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want := ServerConfig{
		Name: "remote", URL: "https://example.invalid/mcp?mode=safe", Transport: "http",
		EnvKeys:    []string{"AUTH_HEADER_TOKEN", "MCP_TOKEN", "REGION_NAME"},
		HeaderKeys: []string{"Authorization", "X-Client", "X-Region"}, EnabledTools: []string{"search"},
	}
	assertTOMLParseResult(t, got, want)
	assertTOMLJSONExcludes(t, got, "http-secret-client", "http-secret-token", "Bearer")
}

func TestParseTOMLEnvVarsPreservesStringAndObjectReferences(t *testing.T) {
	got, err := ParseTOML([]byte(`
[mcp_servers.remote_stdio]
command = "runner"
env_vars = ["LOCAL_TOKEN", { name = "REMOTE_TOKEN", source = "remote" }]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := ServerConfig{
		Name: "remote_stdio", Command: "runner", Transport: "stdio",
		EnvKeys: []string{"LOCAL_TOKEN", "REMOTE_TOKEN"},
	}
	assertTOMLParseResult(t, got, want)
	assertTOMLJSONExcludes(t, got, "source", "remote\"")
}

func TestParseTOMLKeepsValidSiblingAndReportsOnlyServerUnknownFields(t *testing.T) {
	got, err := ParseTOML(readTOMLFixture(t, "siblings.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want := ServerConfig{
		Name: "safe", Command: "node", Transport: "stdio", UnknownFields: []string{"future_option"},
	}
	if len(got.Servers) != 1 || !reflect.DeepEqual(got.Servers[0], want) {
		t.Fatalf("servers=%+v want=%+v", got.Servers, want)
	}
	wantIssues := []ParseIssue{{Code: "invalid_server"}, {Code: "invalid_server"}, {Code: "unknown_server_field"}}
	if !reflect.DeepEqual(got.Issues, wantIssues) {
		t.Fatalf("issues=%+v want=%+v", got.Issues, wantIssues)
	}
	assertTOMLJSONExcludes(t, got,
		"bad-command", "bad.example.invalid", "unknown-secret-value",
		"unrelated-secret-model", "unrelated-secret-value", "telemetry",
	)
}

func TestParseTOMLIsolatesNonTableServerEntry(t *testing.T) {
	got, err := ParseTOML([]byte(`
[mcp_servers]
bad = "not-a-table"

[mcp_servers.safe]
command = "node"
`))
	if err != nil {
		t.Fatal(err)
	}
	wantServer := ServerConfig{Name: "safe", Command: "node", Transport: "stdio"}
	if len(got.Servers) != 1 || !reflect.DeepEqual(got.Servers[0], wantServer) {
		t.Fatalf("servers=%+v want=%+v", got.Servers, wantServer)
	}
	wantIssues := []ParseIssue{{Code: "invalid_server"}}
	if !reflect.DeepEqual(got.Issues, wantIssues) {
		t.Fatalf("issues=%+v want=%+v", got.Issues, wantIssues)
	}
	assertTOMLJSONExcludes(t, got, "not-a-table", "bad")
}

func TestParseTOMLIgnoresUnrelatedTopLevelTables(t *testing.T) {
	got, err := ParseTOML([]byte(`
model = "gpt-example"
[projects."/private/example"]
trust_level = "trusted"
[unrelated]
future = "must-not-persist"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 0 || len(got.Issues) != 0 {
		t.Fatalf("result=%+v", got)
	}
	assertTOMLJSONExcludes(t, got, "gpt-example", "/private/example", "must-not-persist", "projects", "unrelated")
}

func TestParseTOMLRejectsMalformedDocument(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{name: "syntax", raw: readTOMLFixture(t, "malformed.toml")},
		{name: "duplicate", raw: []byte("[mcp_servers.bad]\ncommand = \"one\"\ncommand = \"two\"\n")},
		{name: "wrong container type", raw: []byte("mcp_servers = \"not-a-table\"\n")},
		{name: "oversized", raw: bytes.Repeat([]byte(" "), maxJSONConfigBytes+1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseTOML(testCase.raw); err == nil {
				t.Fatal("ParseTOML error=nil")
			}
		})
	}
}

func TestParseTOMLRejectsInvalidKnownFieldTypesWithoutDroppingSibling(t *testing.T) {
	raw := []byte(`
[mcp_servers.bad_args]
command = "node"
args = ["safe", 7]

[mcp_servers.bad_env]
command = "node"
env = { TOKEN = 7 }

[mcp_servers.bad_env_vars]
command = "node"
env_vars = ["HOME", 7]

[mcp_servers.bad_headers]
url = "https://example.invalid/mcp"
http_headers = { Authorization = 7 }

[mcp_servers.bad_env_headers]
url = "https://example.invalid/mcp"
env_http_headers = { Authorization = 7 }

[mcp_servers.bad_enabled]
command = "node"
enabled = "false"

[mcp_servers.bad_tools]
command = "node"
enabled_tools = ["read", 7]

[mcp_servers.safe]
command = "node"
`)
	got, err := ParseTOML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 1 || got.Servers[0].Name != "safe" || len(got.Issues) != 7 {
		t.Fatalf("result=%+v", got)
	}
	for _, issue := range got.Issues {
		if issue.Code != "invalid_server" {
			t.Fatalf("issue=%+v", issue)
		}
	}
}

func assertTOMLParseResult(t *testing.T, got ParseResult, want ServerConfig) {
	t.Helper()
	if len(got.Issues) != 0 || len(got.Servers) != 1 || !reflect.DeepEqual(got.Servers[0], want) {
		t.Fatalf("result=%+v want=%+v", got, want)
	}
}

func assertTOMLJSONExcludes(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range forbidden {
		if marker != "" && bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("forbidden value %q retained: %s", marker, encoded)
		}
	}
}

func readTOMLFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "toml", name))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
