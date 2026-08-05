package agents_test

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

	"github.com/ssc-init/ssc-init/internal/collector/agents"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestAgentCollectorFindsCodexPlugin(t *testing.T) {
	env := testutil.Environment(t, "../../../testdata/home")
	got, err := agents.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	asset := testutil.AssertAsset(t, got.Assets, "agent-plugin:codex:example")
	if asset.Type != model.AssetAgentPlugin || asset.Name != "example" || asset.Path != "$HOME/.codex/plugins/example" {
		t.Fatalf("asset=%+v", asset)
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("result=%+v", got)
	}
}

func TestAgentCollectorStaysWithinExplicitRootsAndFindsSkills(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "skills", "review", "SKILL.md"), "safe")
	writeAgentFile(t, filepath.Join(home, "unrelated", "plugins", "outside", ".codex-plugin", "plugin.json"), `{}`)
	env := testutil.Environment(t, home)

	got, err := agents.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "agent-skill:claude:review")
	if asset.Type != model.AssetSkill || asset.Path != "$HOME/.claude/skills/review" {
		t.Fatalf("asset=%+v", asset)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "outside") {
		t.Fatalf("scanned outside catalog: %s", encoded)
	}
}

func TestAgentCollectorFindsDirectWindsurfAsset(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".windsurf", "direct-tool", "README.md"), "safe")
	env := testutil.Environment(t, home)

	got, err := agents.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "agent-plugin:windsurf:direct-tool")
	if asset.Path != "$HOME/.windsurf/direct-tool" || asset.Type != model.AssetAgentPlugin {
		t.Fatalf("asset=%+v", asset)
	}
}

func TestAgentCollectorRejectsSymlinkedCatalogRootsAndEntries(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	marker := "outside-agent-marker"
	writeAgentFile(t, filepath.Join(outside, "plugins", marker, "plugin.json"), `{}`)
	if err := os.Symlink(outside, filepath.Join(home, ".codex")); err != nil {
		t.Fatal(err)
	}
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "safe", "plugin.json"), `{}`)
	if err := os.Symlink(filepath.Join(outside, "plugins", marker), filepath.Join(home, ".claude", "plugins", "linked")); err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)

	got, err := agents.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe")
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 2 || len(got.Assets) != 1 || bytes.Contains(encoded, []byte(marker)) || bytes.Contains(encoded, []byte(outside)) {
		t.Fatalf("result=%s", encoded)
	}
	for _, coverageErr := range got.Errors {
		if !strings.HasPrefix(coverageErr.Path, "$HOME/.codex/") {
			t.Fatalf("error=%+v", coverageErr)
		}
	}
}

func TestAgentCollectorFailsClosedWithoutRootedFilesystem(t *testing.T) {
	home := t.TempDir()
	marker := "agent-path-fallback-marker"
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", marker, "plugin.json"), `{}`)
	env := testutil.Environment(t, home)
	env.FS = pathOnlyAgentFileSystem{FileSystem: platform.OSFileSystem{}}

	got, err := agents.New().Collect(context.Background(), env)
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

func TestAgentCollectorSanitizesAccessFailures(t *testing.T) {
	home := t.TempDir()
	blocked := filepath.Join(home, ".cursor", "plugins")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)
	env.FS = agentFaultFS{FileSystem: platform.OSFileSystem{}, blocked: blocked}

	got, err := agents.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 {
		t.Fatalf("result=%+v", got)
	}
	if got.Errors[0].Path != "$HOME/.cursor/plugins" || strings.Contains(got.Errors[0].Message, home) {
		t.Fatalf("error=%+v", got.Errors[0])
	}
}

func TestAgentCollectorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := agents.New().Collect(ctx, testutil.Environment(t, t.TempDir()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func writeAgentFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

type agentFaultFS struct {
	platform.FileSystem
	blocked string
}

func (f agentFaultFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	rooted, ok := f.FileSystem.(platform.RootedFileSystem)
	if !ok {
		return nil, fs.ErrInvalid
	}
	root, err := rooted.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentFaultRoot{RootedDirectory: root, current: name, blocked: f.blocked}, nil
}

type agentFaultRoot struct {
	platform.RootedDirectory
	current string
	blocked string
}

func (r *agentFaultRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	path := filepath.Join(r.current, name)
	if path == r.blocked {
		return nil, fs.ErrPermission
	}
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentFaultRoot{RootedDirectory: child, current: path, blocked: r.blocked}, nil
}

type pathOnlyAgentFileSystem struct {
	platform.FileSystem
}

func (f agentFaultFS) ReadDir(path string) ([]fs.DirEntry, error) {
	if path == f.blocked {
		return nil, fs.ErrPermission
	}
	return f.FileSystem.ReadDir(path)
}
