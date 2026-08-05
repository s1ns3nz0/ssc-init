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
	"time"

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
	for _, want := range []string{"--token\x1f[REDACTED]", "--root=$HOME/Projects", "https://example.test/rpc?api_key=%5BREDACTED%5D&mode=safe"} {
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
		{name: "grew after stat", readData: bytes.Repeat([]byte("x"), maxConfigBytes+1), wantCode: "config_oversized"},
		{name: "access failure", readErr: fs.ErrPermission, wantCode: "config_unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".claude.json")
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

func (f mcpFaultFS) Stat(path string) (os.FileInfo, error) {
	if path == f.path {
		return staticFileInfo{size: 2}, nil
	}
	return f.FileSystem.Stat(path)
}

func (f mcpFaultFS) ReadFile(path string) ([]byte, error) {
	if path == f.path {
		return f.readData, f.readErr
	}
	return f.FileSystem.ReadFile(path)
}

type staticFileInfo struct{ size int64 }

func (i staticFileInfo) Name() string       { return "mcp.json" }
func (i staticFileInfo) Size() int64        { return i.size }
func (i staticFileInfo) Mode() fs.FileMode  { return 0o600 }
func (i staticFileInfo) ModTime() time.Time { return time.Time{} }
func (i staticFileInfo) IsDir() bool        { return false }
func (i staticFileInfo) Sys() any           { return nil }
