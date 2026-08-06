package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/agents"
	"github.com/ssc-init/ssc-init/internal/collector/ide"
	"github.com/ssc-init/ssc-init/internal/collector/packages"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/report"
	"github.com/ssc-init/ssc-init/internal/scan"
	"github.com/ssc-init/ssc-init/internal/store"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestBaselineFixturePersistsWithRealStore(t *testing.T) {
	env := testutil.Environment(t, "../../testdata/home")
	env.FS = fixtureFileSystem{OSFileSystem: platform.OSFileSystem{}, root: env.Home}
	if _, ok := env.Runner.(*testutil.FakeRunner); !ok {
		t.Fatal("acceptance environment must use the fake runner")
	}
	orchestrator := collector.Orchestrator{
		Timeout:       time.Second,
		MaxConcurrent: 4,
		Collectors: []collector.Collector{
			agents.New(), ide.New(), projects.New([]string{"$HOME/Projects"}), packages.New(),
		},
	}
	databasePath := filepath.Join(privateAcceptanceTempDir(t), "state.db")
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()
	service := scan.NewService(orchestrator, snapshots, env.Now, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, delta, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	latest, initialized, err := snapshots.LatestInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !initialized || !reflect.DeepEqual(latest, inventory) {
		t.Fatalf("initialized=%v latest=%#v inventory=%#v", initialized, latest, inventory)
	}
	foundProjectMCP := false
	for _, asset := range latest.Assets {
		if asset.ID == "mcp:vscode:workspace" {
			foundProjectMCP = true
			break
		}
	}
	if !foundProjectMCP {
		t.Fatal("round-tripped inventory is missing project MCP asset mcp:vscode:workspace")
	}

	var output bytes.Buffer
	if err := report.WriteJSON(&output, result, inventory, delta); err != nil {
		t.Fatal(err)
	}
	persisted, err := json.Marshal(latest)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"persisted": persisted, "reported": output.Bytes()} {
		if bytes.Contains(content, []byte("fixture-secret")) {
			t.Fatalf("%s output retained fixture secret", name)
		}
		if realHome := os.Getenv("HOME"); realHome != "" && realHome != env.Home && strings.Contains(string(content), realHome) {
			t.Fatalf("%s output leaked real home", name)
		}
	}
}

func privateAcceptanceTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
