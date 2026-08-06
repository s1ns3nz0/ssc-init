package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/agents"
	"github.com/ssc-init/ssc-init/internal/collector/ide"
	"github.com/ssc-init/ssc-init/internal/collector/mcp"
	"github.com/ssc-init/ssc-init/internal/collector/packages"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/report"
	"github.com/ssc-init/ssc-init/internal/scan"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestBaselineFixtureNeverReadsRealHome(t *testing.T) {
	env := testutil.Environment(t, "../../testdata/home")
	env.Platform = "darwin"
	env.Scope = model.ScanScope{ProjectRoots: []string{"$HOME/Projects"}}
	env.FS = fixtureFileSystem{OSFileSystem: platform.OSFileSystem{}, root: env.Home}
	if _, ok := env.Runner.(*testutil.FakeRunner); !ok {
		t.Fatal("acceptance environment must use the fake runner")
	}
	orchestrator := collector.Orchestrator{
		Timeout:       time.Second,
		MaxConcurrent: 4,
		Collectors: []collector.Collector{
			agents.New(),
			mcp.New(),
			ide.New(),
			projects.New([]string{"$HOME/Projects"}),
			packages.New(),
		},
	}
	snapshots := newMemorySnapshots()
	service := scan.NewService(
		orchestrator,
		snapshots,
		env.Now,
		func() string { return "00000000-0000-4000-8000-000000000001" },
		env,
	)

	result, inventory, delta, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshots.saveCount() != 1 {
		t.Fatalf("saved snapshots=%d, want 1", snapshots.saveCount())
	}
	if result.Status != "complete" && result.Status != "partial" {
		t.Fatalf("status=%q", result.Status)
	}

	var output bytes.Buffer
	if err := report.WriteJSON(&output, result, inventory, delta); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output.String())
	}
	if document["schemaVersion"] != "ssc-init.scan.v2" {
		t.Fatalf("schemaVersion=%v", document["schemaVersion"])
	}
	if scope, ok := document["scope"].(map[string]any); !ok || scope["platform"] != "darwin" || scope["catalogVersion"] != collector.CatalogVersion {
		t.Fatalf("scope=%v", document["scope"])
	}
	if realHome := os.Getenv("HOME"); realHome != "" && realHome != env.Home && strings.Contains(output.String(), realHome) {
		t.Fatalf("real home leaked into fixture report: %q", realHome)
	}
}

// fixtureFileSystem rejects path-based access outside the synthetic home. Its
// rooted handles remain descriptor-anchored beneath the only allowed root.
type fixtureFileSystem struct {
	platform.OSFileSystem
	root string
}

func (f fixtureFileSystem) ReadFile(name string) ([]byte, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadFile(name)
}

func (f fixtureFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadDir(name)
}

func (f fixtureFileSystem) Stat(name string) (os.FileInfo, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.Stat(name)
}

func (f fixtureFileSystem) WalkDir(root string, walk fs.WalkDirFunc) error {
	if !f.allows(root) {
		return fs.ErrPermission
	}
	return f.OSFileSystem.WalkDir(root, walk)
}

func (f fixtureFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.OpenRoot(name)
}

func (f fixtureFileSystem) allows(name string) bool {
	relative, err := filepath.Rel(filepath.Clean(f.root), filepath.Clean(name))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
