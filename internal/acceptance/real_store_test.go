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
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/report"
	"github.com/ssc-init/ssc-init/internal/scan"
	"github.com/ssc-init/ssc-init/internal/store"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestBaselineFixturePersistsWithRealStore(t *testing.T) {
	env := testutil.Environment(t, "../../testdata/home")
	env.Platform = "darwin"
	env.Scope = model.ScanScope{ProjectRoots: []string{"$HOME/Projects"}}
	env.FS = fixtureFileSystem{OSFileSystem: platform.OSFileSystem{}, root: env.Home}
	roots, err := projects.ResolveRoots(env.Home, env.Scope.ProjectRoots)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := env.Runner.(*testutil.FakeRunner); !ok {
		t.Fatal("acceptance environment must use the fake runner")
	}
	orchestrator := collector.Orchestrator{
		Timeout:       time.Second,
		MaxConcurrent: 4,
		Collectors: []collector.Collector{
			agents.New(), ide.New(), projects.New(roots), packages.New(),
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
	latestSnapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !initialized || !reflect.DeepEqual(latestSnapshot.Inventory, inventory) || !reflect.DeepEqual(latestSnapshot.Scan, result) {
		t.Fatalf("initialized=%v latest=%#v result=%#v inventory=%#v", initialized, latestSnapshot, result, inventory)
	}
	latest := latestSnapshot.Inventory
	projectConfigID := ""
	foundProjectMCP := false
	for _, asset := range latest.Assets {
		if asset.ID == "mcp:vscode:workspace" {
			if foundProjectMCP || asset.Type != model.AssetMCP || asset.Name != "workspace" || asset.Source != "vscode" || asset.Path != "" || asset.Metadata != nil {
				t.Fatalf("non-canonical project MCP asset: %+v", asset)
			}
			foundProjectMCP = true
		}
		if asset.Type == model.AssetProject && asset.Source == "project-config" && asset.Name == ".vscode/mcp.json" {
			if projectConfigID != "" || asset.Path != "" {
				t.Fatalf("non-canonical project config asset: %+v", asset)
			}
			projectConfigID = asset.ID
		}
	}
	if projectConfigID == "" {
		t.Fatal("round-tripped inventory is missing canonical project config evidence")
	}
	if !foundProjectMCP {
		t.Fatal("round-tripped inventory is missing Task 7 project MCP evidence")
	}
	projectID := ""
	foundProjectMCPObservation := false
	for _, observation := range latest.Observations {
		if observation.AssetID == "mcp:vscode:workspace" {
			if foundProjectMCPObservation || observation.Collector != "mcp" || observation.Host != "vscode" || !reflect.DeepEqual(observation.Consumers, []string{"vscode"}) || observation.Scope != model.ScopeProject || observation.Source != "mcp.vscode.project" || observation.LocationRef != "$HOME/Projects/sample/.vscode/mcp.json" || observation.Metadata["transport"] != "http" || observation.Metadata["url_shape"] != "https://workspace.example.test/mcp" || observation.Metadata["source_target"] != "mcp.vscode.project" {
				t.Fatalf("non-canonical project MCP observation: %+v", observation)
			}
			foundProjectMCPObservation = true
		}
		if observation.AssetID != projectConfigID {
			continue
		}
		if observation.Collector != "projects" || observation.Source != "mcp.vscode.project" || observation.LocationRef != "$HOME/Projects/sample/.vscode/mcp.json" || observation.ProjectID == "" {
			t.Fatalf("non-canonical project observation: %+v", observation)
		}
		projectID = observation.ProjectID
	}
	if projectID == "" {
		t.Fatal("round-tripped inventory is missing the project config observation")
	}
	if !foundProjectMCPObservation {
		t.Fatal("round-tripped inventory is missing Task 7 project MCP observation")
	}
	foundProject := false
	for _, asset := range latest.Assets {
		if asset.ID == projectID && asset.Type == model.AssetProject && asset.Name == "project" && asset.Path == "" {
			foundProject = true
		}
	}
	if !foundProject {
		t.Fatalf("round-tripped inventory is missing location-free project asset %q", projectID)
	}
	for _, coverage := range result.Coverage {
		if coverage.LocalTargets != nil {
			t.Fatalf("raw project local targets survived scan: %+v", coverage.LocalTargets)
		}
		if coverage.Collector == "mcp" {
			foundTarget := false
			for _, target := range coverage.Targets {
				if target.TargetID == "mcp.vscode.project" && target.InstanceRef == "$HOME/Projects/sample/.vscode/mcp.json" {
					if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
						t.Fatalf("project MCP target coverage=%+v", target)
					}
					foundTarget = true
				}
			}
			if !foundTarget {
				t.Fatalf("project MCP target coverage missing: %+v", coverage.Targets)
			}
		}
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
