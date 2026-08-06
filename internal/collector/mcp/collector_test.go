package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/mcp"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

const maxConfigBytes = 4 << 20

func TestMCPCollectorRedactsEnvironmentValuesAndCredentials(t *testing.T) {
	env := testutil.Environment(t, "../../../testdata/home")
	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:cursor:filesystem")
	if asset.Metadata["env_keys"] != "GITHUB_TOKEN" {
		t.Fatalf("metadata=%v", asset.Metadata)
	}
	if asset.Metadata["command"] != "$HOME/.local/bin/filesystem-mcp" {
		t.Fatalf("command=%q", asset.Metadata["command"])
	}
	args := asset.Metadata["args"]
	for _, want := range []string{"--token\x1f[redacted]", "--root=$HOME/Projects", "https://example.test/rpc?api_key=%5Bredacted%5D&mode=safe"} {
		if !strings.Contains(args, want) {
			t.Fatalf("args=%q missing=%q", args, want)
		}
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, secret := range []string{"fixture-secret", "alice:"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("secret persisted: %s", encoded)
		}
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("result=%+v", got)
	}
}

func TestMCPCollectorOmitsEmptyEnvironmentKeyList(t *testing.T) {
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".claude", "settings.json"), `{
		"mcpServers": {
			"documentation": {"url": "https://docs.example.test/mcp"}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:documentation")
	if value, exists := asset.Metadata["env_keys"]; exists {
		t.Fatalf("empty env_keys metadata emitted: %q", value)
	}
}

func TestMCPCollectorSanitizesCommandAndCombinedCredentialArguments(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"command-user-marker", "command-password-marker", "command-query-marker", "command-fragment-marker",
		"combined-header-marker", "combined-token-marker", "equals-api-marker", "bearer-value-marker",
		"split-header-marker", "split-token-marker", "arg-user-marker", "arg-password-marker",
		"arg-query-marker", "arg-fragment-marker", "environment-value-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"sensitive": {
				"command": "https://command-user-marker:command-password-marker@example.test/run?token=command-query-marker&mode=safe#command-fragment-marker",
				"args": [
					"-HAuthorization: Bearer combined-header-marker",
					"--tokencombined-token-marker",
					"--api-key=equals-api-marker",
					"Bearer bearer-value-marker",
					"-H", "Authorization: Bearer split-header-marker",
					"--token", "split-token-marker",
					"--endpoint=https://arg-user-marker:arg-password-marker@example.test/mcp?access_token=arg-query-marker#arg-fragment-marker"
				],
				"env": {"TOKEN": "environment-value-marker"}
			}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:sensitive")
	if !strings.Contains(asset.Metadata["command"], "https://example.test/run") || !strings.Contains(asset.Metadata["command"], "redacted") {
		t.Fatalf("command=%q", asset.Metadata["command"])
	}
	args := asset.Metadata["args"]
	for _, want := range []string{"-H[redacted]", "--token[redacted]", "--api-key=[redacted]", "Bearer [redacted]", "--token\x1f[redacted]", "--endpoint=https://example.test/mcp"} {
		if !strings.Contains(args, want) {
			t.Fatalf("args=%q missing=%q", args, want)
		}
	}
	encoded, marshalErr := json.Marshal(asset)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, marker := range markers {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
}

func TestMCPCollectorSanitizesSemanticFlagsWithoutOverRedactingSafeNames(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"header-value-marker", "headers-equals-marker", "env-value-marker", "bearer-value-marker",
		"signature-value-marker", "github-token-value-marker", "github-token-equals-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"semantic": {
				"command": "/usr/local/bin/auth-mcp",
				"args": [
					"--header", "Authorization: Bearer header-value-marker",
					"--headers=Authorization: Bearer headers-equals-marker",
					"--env", "GITHUB_TOKEN=env-value-marker",
					"--bearer", "bearer-value-marker",
					"--signature=signature-value-marker",
					"--github-token", "github-token-value-marker",
					"--github-token=github-token-equals-marker",
					"--tokenizer-model", "safe-model", "-hostlocalhost"
				]
			}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:semantic")
	if asset.Metadata["command"] != "/usr/local/bin/auth-mcp" {
		t.Fatalf("command=%q", asset.Metadata["command"])
	}
	args := asset.Metadata["args"]
	for _, want := range []string{
		"--header\x1f[redacted]", "--headers=[redacted]", "--env\x1f[redacted]",
		"--bearer\x1f[redacted]", "--signature=[redacted]", "--github-token\x1f[redacted]",
		"--github-token=[redacted]", "--tokenizer-model\x1fsafe-model\x1f-hostlocalhost",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args=%q missing=%q", args, want)
		}
	}
	encoded, marshalErr := json.Marshal(asset)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, marker := range markers {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
}

func TestMCPCollectorSanitizesStructuredCredentialCommands(t *testing.T) {
	home := t.TempDir()
	markers := map[string]string{
		"assignment": "command-assignment-marker",
		"flag":       "command-flag-marker",
		"authHeader": "command-auth-header-marker",
		"headerFlag": "command-header-flag-marker",
		"splitText":  "command-split-text-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"assignment": {"command": "TOKEN=command-assignment-marker"},
			"flag": {"command": "--token=command-flag-marker"},
			"authHeader": {"command": "Authorization: Bearer command-auth-header-marker"},
			"headerFlag": {"command": "--header=X-Api-Key: command-header-flag-marker"},
			"splitText": {"command": "runner --token command-split-text-marker"},
			"safe": {"command": "/usr/local/bin/auth-mcp"}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for name, marker := range markers {
		asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:"+name)
		encoded, marshalErr := json.Marshal(asset)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if bytes.Contains(encoded, []byte(marker)) || !bytes.Contains(encoded, []byte("[redacted]")) {
			t.Fatalf("name=%s asset=%s", name, encoded)
		}
	}
	safe := testutil.AssertAsset(t, got.Assets, "mcp:claude:safe")
	if safe.Metadata["command"] != "/usr/local/bin/auth-mcp" {
		t.Fatalf("safe command=%q", safe.Metadata["command"])
	}
}

func TestMCPCollectorSplitsCamelCaseSensitiveNamesPrecisely(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"access-token-marker", "refresh-token-marker", "github-token-marker",
		"api-key-marker", "client-secret-marker", "authorization-marker",
		"acronym-api-key-marker", "pascal-client-secret-marker",
		"query-access-marker", "query-refresh-marker", "query-github-marker",
		"query-api-marker", "query-client-marker", "query-authorization-marker",
		"query-acronym-api-marker", "query-pascal-client-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"camel": {
				"args": [
					"--accessToken", "access-token-marker",
					"--refreshToken=refresh-token-marker",
					"--githubToken", "github-token-marker",
					"--apiKey=api-key-marker",
					"--clientSecret", "client-secret-marker",
					"--Authorization=authorization-marker",
					"--APIKey=acronym-api-key-marker",
					"--ClientSecret=pascal-client-secret-marker",
					"--tokenizerModel", "safe-tokenizer-value",
					"--authorizationHelper=safe-authorization-helper",
					"--AuthorizationHelper=safe-pascal-authorization-helper"
				],
				"url": "https://example.test/mcp?accessToken=query-access-marker&refreshToken=query-refresh-marker&githubToken=query-github-marker&apiKey=query-api-marker&clientSecret=query-client-marker&Authorization=query-authorization-marker&APIKey=query-acronym-api-marker&ClientSecret=query-pascal-client-marker&tokenizerModel=safe-query-tokenizer&authorizationHelper=safe-query-authorization&AuthorizationHelper=safe-query-pascal-authorization"
			}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:camel")
	encoded, marshalErr := json.Marshal(asset)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, marker := range markers {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
	for _, safe := range []string{
		"--tokenizerModel\x1fsafe-tokenizer-value",
		"--authorizationHelper=safe-authorization-helper",
		"--AuthorizationHelper=safe-pascal-authorization-helper",
	} {
		if !strings.Contains(asset.Metadata["args"], safe) {
			t.Fatalf("safe argument missing %q: %q", safe, asset.Metadata["args"])
		}
	}
	for _, safe := range []string{"tokenizerModel=safe-query-tokenizer", "authorizationHelper=safe-query-authorization", "AuthorizationHelper=safe-query-pascal-authorization"} {
		if !strings.Contains(asset.Metadata["url"], safe) {
			t.Fatalf("safe query missing %q: %q", safe, asset.Metadata["url"])
		}
	}
}

func TestMCPCollectorSanitizesSensitiveComponentsInsideCompounds(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"proxy-authorization-split-marker", "proxy-authorization-equals-marker",
		"auth-header-split-marker", "auth-header-equals-marker",
		"http-header-split-marker", "http-header-equals-marker",
		"query-proxy-authorization-marker", "query-auth-header-marker", "query-http-header-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"compounds": {
				"command": "/usr/local/bin/auth-mcp",
				"args": [
					"--proxyAuthorization", "proxy-authorization-split-marker",
					"--proxyAuthorization=proxy-authorization-equals-marker",
					"--authHeader", "auth-header-split-marker",
					"--authHeader=auth-header-equals-marker",
					"--http-header", "X-Api-Key: http-header-split-marker",
					"--http-header=X-Api-Key: http-header-equals-marker",
					"--tokenizerModel", "safe-tokenizer-value",
					"-hostlocalhost",
					"--authorizationHelper=safe-authorization-helper",
					"--AuthorizationHelper=safe-pascal-authorization-helper"
				],
				"url": "https://example.test/mcp?proxyAuthorization=query-proxy-authorization-marker&authHeader=query-auth-header-marker&http-header=query-http-header-marker&authorizationHelper=safe-query-authorization&AuthorizationHelper=safe-query-pascal-authorization"
			}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:compounds")
	encoded, marshalErr := json.Marshal(asset)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, marker := range markers {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
	if asset.Metadata["command"] != "/usr/local/bin/auth-mcp" {
		t.Fatalf("safe command=%q", asset.Metadata["command"])
	}
	for _, safe := range []string{
		"--tokenizerModel\x1fsafe-tokenizer-value\x1f-hostlocalhost",
		"--authorizationHelper=safe-authorization-helper",
		"--AuthorizationHelper=safe-pascal-authorization-helper",
	} {
		if !strings.Contains(asset.Metadata["args"], safe) {
			t.Fatalf("safe argument missing %q: %q", safe, asset.Metadata["args"])
		}
	}
	for _, safe := range []string{
		"authorizationHelper=safe-query-authorization",
		"AuthorizationHelper=safe-query-pascal-authorization",
	} {
		if !strings.Contains(asset.Metadata["url"], safe) {
			t.Fatalf("safe query missing %q: %q", safe, asset.Metadata["url"])
		}
	}
}

func TestMCPCollectorAllowsOnlyExactAuthorizationHelperSpellings(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"lower-split-marker", "lower-equals-marker", "lower-query-marker",
		"mixed-split-marker", "mixed-equals-marker", "mixed-query-marker",
		"upper-split-marker", "upper-equals-marker", "upper-query-marker",
	}
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{
		"mcpServers": {
			"helper-casing": {
				"args": [
					"--authorizationhelper", "lower-split-marker",
					"--authorizationhelper=lower-equals-marker",
					"--Authorizationhelper", "mixed-split-marker",
					"--Authorizationhelper=mixed-equals-marker",
					"--AUTHORIZATIONHELPER", "upper-split-marker",
					"--AUTHORIZATIONHELPER=upper-equals-marker",
					"--authorizationHelper=safe-exact-camel",
					"--AuthorizationHelper=safe-exact-pascal"
				],
				"url": "https://example.test/mcp?authorizationhelper=lower-query-marker&Authorizationhelper=mixed-query-marker&AUTHORIZATIONHELPER=upper-query-marker&authorizationHelper=safe-query-camel&AuthorizationHelper=safe-query-pascal"
			}
		}
	}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:claude:helper-casing")
	encoded, marshalErr := json.Marshal(asset)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, marker := range markers {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
	for _, safe := range []string{
		"--authorizationHelper=safe-exact-camel",
		"--AuthorizationHelper=safe-exact-pascal",
	} {
		if !strings.Contains(asset.Metadata["args"], safe) {
			t.Fatalf("safe argument missing %q: %q", safe, asset.Metadata["args"])
		}
	}
	for _, safe := range []string{
		"authorizationHelper=safe-query-camel",
		"AuthorizationHelper=safe-query-pascal",
	} {
		if !strings.Contains(asset.Metadata["url"], safe) {
			t.Fatalf("safe query missing %q: %q", safe, asset.Metadata["url"])
		}
	}
}

func TestMCPCollectorConsumesOnlyDedicatedProjectMCPAssets(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "Projects", "app", ".vscode", "mcp.json")
	writeMCPFile(t, configPath, `{"servers":{"workspace":{"url":"https://example.test/mcp"}}}`)
	projectAsset := model.Asset{
		ID:     "project-file:mcp:$HOME/Projects/app/.vscode/mcp.json",
		Type:   model.AssetProject,
		Name:   "mcp.json",
		Path:   "$HOME/Projects/app/.vscode/mcp.json",
		Source: "mcp",
	}
	wrongType := projectAsset
	wrongType.ID = "other"
	wrongType.Type = model.AssetMCP
	wrongType.Path = "$HOME/Projects/ignored/.vscode/mcp.json"
	env := testutil.Environment(t, home)

	got, err := mcp.New(projectAsset, wrongType).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "mcp:vscode:workspace")
	if asset.Metadata["url"] != "https://example.test/mcp" || len(got.Assets) != 1 || got.Status != model.CoverageComplete || len(got.Errors) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestMCPCollectorRejectsNonCanonicalProjectPathAssets(t *testing.T) {
	home := t.TempDir()
	marker := "project-path-injection-marker"
	canonicalPath := filepath.Join(home, "Projects", "app", ".vscode", "mcp.json")
	writeMCPFile(t, canonicalPath, `{"servers":{"`+marker+`":{"url":"https://example.test"}}}`)
	redacted := "$HOME/Projects/app/.vscode/mcp.json"
	assets := []model.Asset{
		{ID: "project-file:mcp:" + canonicalPath, Type: model.AssetProject, Name: "mcp.json", Path: canonicalPath, Source: "mcp"},
		{ID: "project-file:mcp:$HOME/Projects/../Projects/app/.vscode/mcp.json", Type: model.AssetProject, Name: "mcp.json", Path: "$HOME/Projects/../Projects/app/.vscode/mcp.json", Source: "mcp"},
		{ID: "project-file:mcp:$HOME/Projects/other/.vscode/mcp.json", Type: model.AssetProject, Name: "mcp.json", Path: redacted, Source: "mcp"},
		{ID: "project-file:mcp:" + redacted, Type: model.AssetProject, Name: "other.json", Path: redacted, Source: "mcp"},
	}
	env := testutil.Environment(t, home)

	got, err := mcp.New(assets...).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if len(got.Assets) != 0 || got.Status != model.CoverageComplete || bytes.Contains(encoded, []byte(marker)) || bytes.Contains(encoded, []byte(home)) {
		t.Fatalf("result=%s", encoded)
	}
}

func TestMCPCollectorRejectsSymlinkedConfigPaths(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		setup    func(*testing.T, string, string) collector.Collector
		wantPath string
	}{
		{
			name: "config file",
			setup: func(t *testing.T, home, outside string) collector.Collector {
				outsideConfig := filepath.Join(outside, "mcp.json")
				writeMCPFile(t, outsideConfig, `{"mcpServers":{"config-file-symlink-marker":{}}}`)
				if err := os.Symlink(outsideConfig, filepath.Join(home, ".claude.json")); err != nil {
					t.Fatal(err)
				}
				return mcp.New()
			},
			wantPath: "$HOME/.claude.json",
		},
		{
			name: "host root",
			setup: func(t *testing.T, home, outside string) collector.Collector {
				writeMCPFile(t, filepath.Join(outside, "mcp.json"), `{"mcpServers":{"root-symlink-marker":{}}}`)
				if err := os.Symlink(outside, filepath.Join(home, ".cursor")); err != nil {
					t.Fatal(err)
				}
				return mcp.New()
			},
			wantPath: "$HOME/.cursor/mcp.json",
		},
		{
			name: "nested project component",
			setup: func(t *testing.T, home, outside string) collector.Collector {
				writeMCPFile(t, filepath.Join(outside, ".vscode", "mcp.json"), `{"servers":{"project-symlink-marker":{}}}`)
				if err := os.MkdirAll(filepath.Join(home, "Projects"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(home, "Projects", "linked")); err != nil {
					t.Fatal(err)
				}
				path := "$HOME/Projects/linked/.vscode/mcp.json"
				return mcp.New(model.Asset{ID: "project-file:mcp:" + path, Type: model.AssetProject, Name: "mcp.json", Path: path, Source: "mcp"})
			},
			wantPath: "$HOME/Projects/linked/.vscode/mcp.json",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			outside := t.TempDir()
			collector := testCase.setup(t, home, outside)
			env := testutil.Environment(t, home)

			got, err := collector.Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			encoded, marshalErr := json.Marshal(got)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Path != testCase.wantPath || len(got.Assets) != 0 {
				t.Fatalf("result=%s", encoded)
			}
			for _, sensitive := range []string{"symlink-marker", outside} {
				if bytes.Contains(encoded, []byte(sensitive)) {
					t.Fatalf("outside data persisted: %s", encoded)
				}
			}
		})
	}
}

func TestMCPCollectorRejectsRootedIdentitySwap(t *testing.T) {
	home := t.TempDir()
	expectedPath := filepath.Join(home, "expected.json")
	replacementPath := filepath.Join(home, "replacement.json")
	writeMCPFile(t, expectedPath, `{}`)
	marker := "rooted-swap-secret-marker"
	writeMCPFile(t, replacementPath, `{"mcpServers":{"swapped":{"env":{"TOKEN":"`+marker+`"}}}}`)
	expectedInfo, err := os.Stat(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)
	env.FS = swapRootFileSystem{
		OSFileSystem: platform.OSFileSystem{},
		root: &swapRootDirectory{
			expected:    expectedInfo,
			replacement: replacementPath,
		},
	}

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 0 || bytes.Contains(encoded, []byte(marker)) {
		t.Fatalf("result=%s", encoded)
	}
}

func TestMCPCollectorFailsClosedWithoutRootedFilesystem(t *testing.T) {
	home := t.TempDir()
	marker := "path-fallback-secret-marker"
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"`+marker+`":{}}}`)
	env := testutil.Environment(t, home)
	env.FS = pathOnlyFileSystem{FileSystem: platform.OSFileSystem{}}

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 0 || bytes.Contains(encoded, []byte(marker)) {
		t.Fatalf("result=%s", encoded)
	}
}

func TestMCPCollectorRejectsDuplicateKeysAtAnyDepth(t *testing.T) {
	home := t.TempDir()
	marker := "duplicate-secret-marker"
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"bad":{"env":{"TOKEN":"`+marker+`","TOKEN":"second"}}}}`)
	env := testutil.Environment(t, home)

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	assertPartialConfigError(t, got, "config_invalid", "$HOME/.claude.json", marker, home)
}

func TestMCPCollectorRejectsMalformedAndOversizedConfigurations(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		path     string
		contents []byte
		wantCode string
		marker   string
	}{
		{name: "malformed", path: filepath.Join(".cursor", "mcp.json"), contents: []byte(`{"mcpServers":{"bad": malformed-secret-marker`), wantCode: "config_invalid", marker: "malformed-secret-marker"},
		{name: "oversized", path: filepath.Join(".windsurf", "mcp.json"), contents: bytes.Repeat([]byte("x"), maxConfigBytes+1), wantCode: "config_oversized", marker: ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, testCase.path)
			writeMCPBytes(t, path, testCase.contents)
			env := testutil.Environment(t, home)

			got, err := mcp.New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			assertPartialConfigError(t, got, testCase.wantCode, "$HOME/"+filepath.ToSlash(testCase.path), testCase.marker, home)
		})
	}
}

func TestMCPCollectorChecksSizeAfterReadAndSanitizesAccessFailures(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		readData []byte
		readErr  error
		wantCode string
	}{
		{name: "grew after pre-read check", readData: bytes.Repeat([]byte("x"), maxConfigBytes+1), wantCode: "config_oversized"},
		{name: "access failure", readErr: fs.ErrPermission, wantCode: "config_unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".claude.json")
			writeMCPFile(t, path, `{}`)
			env := testutil.Environment(t, home)
			env.FS = mcpFaultFS{FileSystem: platform.OSFileSystem{}, path: path, readData: testCase.readData, readErr: testCase.readErr}

			got, err := mcp.New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			assertPartialConfigError(t, got, testCase.wantCode, "$HOME/.claude.json", "", home)
		})
	}
}

func TestMCPCollectorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := mcp.New().Collect(ctx, testutil.Environment(t, t.TempDir()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func assertPartialConfigError(t *testing.T, got model.CollectorResult, code, path, marker, home string) {
	t.Helper()
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || len(got.Assets) != 0 {
		t.Fatalf("result=%+v", got)
	}
	if got.Errors[0].Code != code || got.Errors[0].Path != path {
		t.Fatalf("error=%+v", got.Errors[0])
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{marker, home, "permission denied", "invalid character"} {
		if sensitive != "" && strings.Contains(string(encoded), sensitive) {
			t.Fatalf("sensitive detail persisted: %s", encoded)
		}
	}
}

func writeMCPFile(t *testing.T, path, contents string) {
	t.Helper()
	writeMCPBytes(t, path, []byte(contents))
}

func writeMCPBytes(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

type mcpFaultFS struct {
	platform.FileSystem
	path     string
	readData []byte
	readErr  error
}

func (f mcpFaultFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	rooted, ok := f.FileSystem.(platform.RootedFileSystem)
	if !ok {
		return nil, fs.ErrInvalid
	}
	root, err := rooted.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &mcpFaultRoot{
		RootedDirectory: root,
		current:         name,
		target:          f.path,
		readData:        f.readData,
		readErr:         f.readErr,
	}, nil
}

type mcpFaultRoot struct {
	platform.RootedDirectory
	current  string
	target   string
	readData []byte
	readErr  error
}

func (r *mcpFaultRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &mcpFaultRoot{
		RootedDirectory: child,
		current:         filepath.Join(r.current, name),
		target:          r.target,
		readData:        r.readData,
		readErr:         r.readErr,
	}, nil
}

func (r *mcpFaultRoot) Open(name string) (platform.RootedFile, error) {
	if filepath.Join(r.current, name) != r.target {
		return r.RootedDirectory.Open(name)
	}
	if r.readErr != nil {
		return nil, r.readErr
	}
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	return &mcpFaultFile{RootedFile: file, reader: bytes.NewReader(r.readData)}, nil
}

type mcpFaultFile struct {
	platform.RootedFile
	reader *bytes.Reader
}

func (f *mcpFaultFile) Read(buffer []byte) (int, error) {
	return f.reader.Read(buffer)
}

type pathOnlyFileSystem struct {
	platform.FileSystem
}

type swapRootFileSystem struct {
	platform.OSFileSystem
	root platform.RootedDirectory
}

func (f swapRootFileSystem) OpenRoot(string) (platform.RootedDirectory, error) {
	return f.root, nil
}

type swapRootDirectory struct {
	expected    os.FileInfo
	replacement string
}

func (r *swapRootDirectory) Lstat(name string) (os.FileInfo, error) {
	if name == ".claude.json" {
		return r.expected, nil
	}
	return nil, fs.ErrNotExist
}

func (r *swapRootDirectory) OpenRoot(string) (platform.RootedDirectory, error) {
	return nil, fs.ErrNotExist
}

func (r *swapRootDirectory) Open(name string) (platform.RootedFile, error) {
	if name != ".claude.json" {
		return nil, fs.ErrNotExist
	}
	return os.Open(r.replacement)
}

func (*swapRootDirectory) Close() error { return nil }

func (f mcpFaultFS) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		return f.readData, f.readErr
	}
	return f.FileSystem.ReadFile(path)
}
