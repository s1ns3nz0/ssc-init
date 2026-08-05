package agents_test

import (
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

func TestAgentCollectorSanitizesAccessFailures(t *testing.T) {
	home := t.TempDir()
	blocked := filepath.Join(home, ".cursor", "plugins")
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

func (f agentFaultFS) ReadDir(path string) ([]fs.DirEntry, error) {
	if path == f.blocked {
		return nil, fs.ErrPermission
	}
	return f.FileSystem.ReadDir(path)
}
