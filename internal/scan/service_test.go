package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

type memorySnapshots struct {
	latest    model.Inventory
	hasLatest bool
	loadErr   error
	saveErr   error
	saved     []model.ScanResult
	inventory []model.Inventory
}

func (m *memorySnapshots) SaveScan(_ context.Context, result model.ScanResult, inventory model.Inventory) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = append(m.saved, result)
	m.inventory = append(m.inventory, inventory)
	return nil
}

func (m *memorySnapshots) LatestInventory(context.Context) (model.Inventory, bool, error) {
	return m.latest, m.hasLatest, m.loadErr
}

type fixedCollector struct {
	name   string
	result model.CollectorResult
	err    error
}

func (c fixedCollector) Name() string { return c.name }

func (c fixedCollector) Collect(context.Context, collector.Environment) (model.CollectorResult, error) {
	return c.result, c.err
}

func fixedTime() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func TestBaselinePersistsPartialScanAndDiffsPreviousInventory(t *testing.T) {
	previous := model.Inventory{
		Assets:        []model.Asset{{ID: "tool:old", Type: model.AssetTool, Name: "old"}},
		Relationships: []model.Relationship{},
	}
	snapshots := &memorySnapshots{latest: previous, hasLatest: true}
	orchestrator := collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 2, Collectors: []collector.Collector{
		fixedCollector{name: "agents", result: model.CollectorResult{Status: model.CoverageComplete, Assets: []model.Asset{{ID: "tool:new", Type: model.AssetTool, Name: "new"}}}},
		fixedCollector{name: "docker", err: context.DeadlineExceeded},
	}}
	service := NewService(orchestrator, snapshots, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	})

	result, inventory, delta, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial" || result.SchemaVersion != "ssc-init.scan.v1" {
		t.Fatalf("result=%+v", result)
	}
	if len(snapshots.saved) != 1 || snapshots.saved[0].ScanID != result.ScanID {
		t.Fatalf("saved=%+v", snapshots.saved)
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].ID != "tool:new" {
		t.Fatalf("inventory=%+v", inventory)
	}
	want := []model.Change{{Kind: model.ChangeAdded, AssetID: "tool:new"}, {Kind: model.ChangeRemoved, AssetID: "tool:old"}}
	if len(delta.Changes) != len(want) {
		t.Fatalf("delta=%+v", delta)
	}
	for i := range want {
		if delta.Changes[i] != want[i] {
			t.Fatalf("delta[%d]=%+v want=%+v", i, delta.Changes[i], want[i])
		}
	}
}

func TestBaselineRejectsInvalidInjectedIDBeforePersistence(t *testing.T) {
	snapshots := &memorySnapshots{}
	service := NewService(collector.Orchestrator{}, snapshots, fixedTime, func() string { return "not-a-uuid" })

	if _, _, _, err := service.Baseline(context.Background()); err == nil {
		t.Fatal("Baseline error=nil")
	}
	if len(snapshots.saved) != 0 {
		t.Fatal("invalid scan persisted")
	}
}

func TestBaselineDefaultIDIsRFC4122Version4(t *testing.T) {
	snapshots := &memorySnapshots{}
	service := NewService(collector.Orchestrator{}, snapshots, fixedTime, nil)

	result, _, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ScanID) != 36 || result.ScanID[14] != '4' || !strings.ContainsRune("89ab", rune(result.ScanID[19])) {
		t.Fatalf("scanId=%q", result.ScanID)
	}
}

func TestBaselineRejectsMultipleEnvironments(t *testing.T) {
	snapshots := &memorySnapshots{}
	service := NewService(collector.Orchestrator{}, snapshots, fixedTime, nil, collector.Environment{}, collector.Environment{})

	if _, _, _, err := service.Baseline(context.Background()); err == nil {
		t.Fatal("Baseline error=nil")
	}
	if len(snapshots.saved) != 0 {
		t.Fatal("invalid service persisted")
	}
}

func TestBaselineFollowsProjectMCPAssetsAndReplacesInitialMCPResult(t *testing.T) {
	home := t.TempDir()
	projectConfig := filepath.Join(home, "Projects", "sample", ".vscode", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(projectConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectConfig, []byte(`{"servers":{"fixture":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	projectAsset := model.Asset{
		ID:     "project-file:mcp:$HOME/Projects/sample/.vscode/mcp.json",
		Type:   model.AssetProject,
		Name:   "mcp.json",
		Path:   "$HOME/Projects/sample/.vscode/mcp.json",
		Source: "mcp",
	}
	orchestrator := collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 2, Collectors: []collector.Collector{
		fixedCollector{name: "projects", result: model.CollectorResult{Status: model.CoverageComplete, Assets: []model.Asset{projectAsset}}},
		fixedCollector{name: "mcp", result: model.CollectorResult{Status: model.CoverageFailed, Errors: []model.CoverageError{{Code: "stale"}}}},
	}}
	env := collector.Environment{Home: home, FS: platform.OSFileSystem{}, Runner: platform.ExecRunner{}, Now: fixedTime}
	service := NewService(orchestrator, &memorySnapshots{}, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mcpCoverage := 0
	for _, coverage := range result.Coverage {
		if coverage.Collector == "mcp" {
			mcpCoverage++
			if coverage.Status != model.CoverageComplete {
				t.Fatalf("mcp coverage=%+v", coverage)
			}
		}
	}
	if mcpCoverage != 1 {
		t.Fatalf("mcp coverage count=%d", mcpCoverage)
	}
	found := false
	for _, asset := range inventory.Assets {
		if asset.ID == "mcp:vscode:fixture" {
			found = true
		}
	}
	if !found {
		t.Fatalf("inventory=%+v", inventory)
	}
}
