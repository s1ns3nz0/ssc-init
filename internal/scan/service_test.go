package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

type memorySnapshots struct {
	latest    model.Snapshot
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
	m.latest = model.Snapshot{Scan: result, Inventory: inventory}
	m.hasLatest = true
	return nil
}

func (m *memorySnapshots) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
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
	snapshots := &memorySnapshots{latest: model.Snapshot{Inventory: previous}, hasLatest: true}
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
	if result.Status != "partial" || result.SchemaVersion != "ssc-init.scan.v2" {
		t.Fatalf("result=%+v", result)
	}
	if len(snapshots.saved) != 1 || snapshots.saved[0].ScanID != result.ScanID {
		t.Fatalf("saved=%+v", snapshots.saved)
	}
	if len(inventory.Assets) != 1 || inventory.Assets[0].ID != "tool:new" {
		t.Fatalf("inventory=%+v", inventory)
	}
	want := []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "tool:new"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "tool:old"},
	}
	if len(delta.Changes) != len(want) {
		t.Fatalf("delta=%+v", delta)
	}
	for i := range want {
		if delta.Changes[i] != want[i] {
			t.Fatalf("delta[%d]=%+v want=%+v", i, delta.Changes[i], want[i])
		}
	}
}

func TestBaselineBuildsAndPersistsV2ScopeAndDropsLocalTargets(t *testing.T) {
	projectRoots := []string{"$HOME/Projects"}
	wantScope := model.ScanScope{
		Platform:       "darwin",
		CatalogVersion: collector.CatalogVersion,
		ProjectRoots:   []string{"$HOME/Projects"},
		ExternalProbes: false,
	}
	var collectedScope model.ScanScope
	orchestrator := collector.Orchestrator{Collectors: []collector.Collector{collectorFunc{
		name: "evidence",
		fn: func(_ context.Context, env collector.Environment) (model.CollectorResult, error) {
			collectedScope = env.Scope
			return model.CollectorResult{
				Status:       model.CoverageComplete,
				LocalTargets: []model.LocalTarget{{TargetID: "private", Path: "/raw/private/path"}},
			}, nil
		},
	}}}
	home := t.TempDir()
	env := collector.Environment{
		Home:     home,
		Platform: "darwin",
		Scope:    model.ScanScope{ProjectRoots: projectRoots},
		FS:       platform.OSFileSystem{},
		Runner:   platform.ExecRunner{},
		Now:      fixedTime,
	}
	snapshots := &memorySnapshots{}
	service := NewService(orchestrator, snapshots, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)
	projectRoots[0] = "$HOME/Mutated"

	result, _, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "ssc-init.scan.v2" || !reflect.DeepEqual(result.Scope, wantScope) {
		t.Fatalf("result=%+v", result)
	}
	if !reflect.DeepEqual(collectedScope, wantScope) {
		t.Fatalf("collector scope=%+v want=%+v", collectedScope, wantScope)
	}
	if len(result.Coverage) != 2 || result.Coverage[0].Collector != "evidence" || result.Coverage[1].Collector != "mcp" {
		t.Fatalf("coverage=%+v", result.Coverage)
	}
	if len(snapshots.saved) != 1 || !reflect.DeepEqual(snapshots.saved[0].Scope, wantScope) {
		t.Fatalf("saved=%+v", snapshots.saved)
	}
	for _, coverage := range append(result.Coverage, snapshots.saved[0].Coverage...) {
		if coverage.LocalTargets != nil {
			t.Fatalf("local targets survived: %+v", coverage.LocalTargets)
		}
	}
}

type collectorFunc struct {
	name string
	fn   func(context.Context, collector.Environment) (model.CollectorResult, error)
}

func (c collectorFunc) Name() string { return c.name }

func (c collectorFunc) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	return c.fn(ctx, env)
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

func TestBaselinePersistsEmptyCoverageAsPartial(t *testing.T) {
	snapshots := &memorySnapshots{}
	service := NewService(collector.Orchestrator{}, snapshots, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	})

	result, _, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partial" || result.Coverage != nil {
		t.Fatalf("result=%+v", result)
	}
	if len(snapshots.saved) != 1 || snapshots.saved[0].Status != "partial" {
		t.Fatalf("saved=%+v", snapshots.saved)
	}
}

func TestBaselineClampsBackwardFinishedTime(t *testing.T) {
	snapshots := &memorySnapshots{}
	times := []time.Time{time.Unix(2, 0).UTC(), time.Unix(1, 0).UTC()}
	now := func() time.Time {
		value := times[0]
		times = times[1:]
		return value
	}
	service := NewService(collector.Orchestrator{}, snapshots, now, func() string {
		return "00000000-0000-4000-8000-000000000001"
	})

	result, _, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.FinishedAt.Equal(result.StartedAt) {
		t.Fatalf("started=%s finished=%s", result.StartedAt, result.FinishedAt)
	}
}

func TestBaselineRejectsZeroClockBeforePersistence(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		times []time.Time
	}{
		{name: "start", times: []time.Time{{}}},
		{name: "finish", times: []time.Time{fixedTime(), {}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			snapshots := &memorySnapshots{}
			times := append([]time.Time(nil), testCase.times...)
			now := func() time.Time {
				if len(times) == 0 {
					return time.Time{}
				}
				value := times[0]
				times = times[1:]
				return value
			}
			service := NewService(collector.Orchestrator{}, snapshots, now, func() string {
				return "00000000-0000-4000-8000-000000000001"
			})

			if _, _, _, err := service.Baseline(context.Background()); err == nil {
				t.Fatal("Baseline error=nil")
			}
			if len(snapshots.saved) != 0 {
				t.Fatalf("saved=%+v", snapshots.saved)
			}
		})
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

func TestBaselineFollowsProjectLocalTargetsAndReplacesInitialMCPResult(t *testing.T) {
	home := t.TempDir()
	projectConfig := filepath.Join(home, "Projects", "sample", ".vscode", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(projectConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectConfig, []byte(`{"servers":{"fixture":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 2, Collectors: []collector.Collector{
		projects.New(roots),
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
			if coverage.Status != model.CoveragePartial {
				t.Fatalf("mcp coverage=%+v", coverage)
			}
			for _, issue := range coverage.Errors {
				if issue.Code == "stale" {
					t.Fatalf("stale MCP result survived: %+v", coverage)
				}
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

func TestBaselineCollectsUserMCPWithoutProjectMCPAssets(t *testing.T) {
	home := t.TempDir()
	userConfig := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, []byte(`{"mcpServers":{"user-only":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	orchestrator := collector.Orchestrator{Collectors: []collector.Collector{
		fixedCollector{name: "projects", result: model.CollectorResult{Status: model.CoverageComplete}},
	}}
	env := collector.Environment{Home: home, FS: platform.OSFileSystem{}, Runner: platform.ExecRunner{}, Now: fixedTime}
	service := NewService(orchestrator, &memorySnapshots{}, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mcpResults := 0
	for _, coverage := range result.Coverage {
		if coverage.Collector == "mcp" {
			mcpResults++
		}
	}
	if mcpResults != 1 {
		t.Fatalf("mcp coverage count=%d coverage=%+v", mcpResults, result.Coverage)
	}
	found := false
	for _, asset := range inventory.Assets {
		if asset.ID == "mcp:cursor:user-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("inventory=%+v", inventory)
	}
}

func TestBaselineParsesProjectLocalTargetsAndClearsRawPaths(t *testing.T) {
	home := t.TempDir()
	projectConfig := filepath.Join(home, "Projects", "sample", ".mcp.json")
	if err := os.MkdirAll(filepath.Dir(projectConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectConfig, []byte(`{"mcpServers":{"project-only":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	userConfig := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, []byte(`{"mcpServers":{"user-only":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rawTargets := []model.LocalTarget{{
		TargetID: "mcp.shared.project", InstanceRef: "$HOME/Projects/sample/.mcp.json",
		Path: projectConfig, Format: "json", Host: "shared", Consumers: []string{"claude-code", "vscode"},
	}}
	roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := collector.Orchestrator{Collectors: []collector.Collector{
		projects.New(roots),
		fixedCollector{name: "projects", result: model.CollectorResult{
			Status: model.CoverageComplete,
		}},
		fixedCollector{name: "other", result: model.CollectorResult{Status: model.CoverageComplete, LocalTargets: rawTargets}},
	}}
	env := collector.Environment{Home: home, FS: platform.OSFileSystem{}, Runner: platform.ExecRunner{}, Now: fixedTime}
	snapshots := &memorySnapshots{}
	service := NewService(orchestrator, snapshots, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rawTargets[0], model.LocalTarget{}) {
		t.Fatalf("source local target was not cleared immediately: %+v", rawTargets[0])
	}
	foundProject := false
	foundUser := false
	for _, asset := range inventory.Assets {
		if asset.ID == "mcp:shared:project-only" {
			foundProject = true
		}
		if asset.ID == "mcp:cursor:user-only" {
			foundUser = true
		}
	}
	if !foundProject || !foundUser {
		t.Fatalf("user/project MCP behavior missing: %+v", inventory)
	}
	for _, coverage := range append(result.Coverage, snapshots.saved[0].Coverage...) {
		if coverage.LocalTargets != nil {
			t.Fatalf("raw local target survived scan: %+v", coverage.LocalTargets)
		}
	}
	encoded, marshalErr := json.Marshal(struct {
		Result    model.ScanResult
		Inventory model.Inventory
	}{result, inventory})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(projectConfig)) || bytes.Contains(encoded, []byte(home)) {
		t.Fatalf("raw target path survived: %s", encoded)
	}
}

func TestBaselineOpensExternalProjectMCPThroughFreshVerifiedRoot(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	projectConfig := filepath.Join(external, "client", ".mcp.json")
	if err := os.MkdirAll(filepath.Dir(projectConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectConfig, []byte(`{"mcpServers":{"external":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := projects.ResolveRoots(home, []string{external})
	if err != nil {
		t.Fatal(err)
	}
	rooted := &recordingRootFileSystem{}
	orchestrator := collector.Orchestrator{Collectors: []collector.Collector{
		projects.New(roots),
	}}
	env := collector.Environment{Home: home, FS: rooted, Runner: platform.ExecRunner{}, Now: fixedTime}
	snapshots := &memorySnapshots{}
	service := NewService(orchestrator, snapshots, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rooted.opened(filepath.Dir(projectConfig)) {
		t.Fatalf("external parent was not freshly rooted: opened=%q", rooted.paths())
	}
	if rooted.openCount(filepath.Dir(projectConfig)) != 1 {
		t.Fatalf("external parent open count=%d paths=%q", rooted.openCount(filepath.Dir(projectConfig)), rooted.paths())
	}
	found := false
	for _, asset := range inventory.Assets {
		if asset.ID == "mcp:shared:external" {
			found = true
		}
	}
	if !found {
		t.Fatalf("inventory=%+v", inventory)
	}
	for _, coverage := range append(result.Coverage, snapshots.saved[0].Coverage...) {
		if coverage.LocalTargets != nil {
			t.Fatalf("raw local target survived: %+v", coverage.LocalTargets)
		}
	}
	encoded, marshalErr := json.Marshal(struct {
		Result    model.ScanResult
		Inventory model.Inventory
	}{result, inventory})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(external)) || bytes.Contains(encoded, []byte(projectConfig)) {
		t.Fatalf("external path persisted: %s", encoded)
	}
}

func TestBaselineCopiesOnlyValidatedProjectLocalTargets(t *testing.T) {
	home := t.TempDir()
	configuredRoot := filepath.Join(home, "Projects")
	if err := os.MkdirAll(configuredRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	forgedPath := filepath.Join(outside, ".mcp.json")
	if err := os.WriteFile(forgedPath, []byte(`{"mcpServers":{"forged-secret-marker":{"command":"tool"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	forgedRoots, err := projects.ResolveRoots(home, []string{outside})
	if err != nil {
		t.Fatal(err)
	}
	forgedResult, err := projects.New(forgedRoots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(forgedResult.LocalTargets) != 1 || forgedResult.LocalTargets[0].Path != forgedPath {
		t.Fatalf("forged setup=%+v", forgedResult.LocalTargets)
	}
	orchestrator := collector.Orchestrator{Collectors: []collector.Collector{
		projects.New(roots),
		fixedCollector{name: "projects", result: forgedResult},
		fixedCollector{name: "other", result: forgedResult},
	}}
	rooted := &recordingRootFileSystem{}
	env := collector.Environment{Home: home, FS: rooted, Runner: platform.ExecRunner{}, Now: fixedTime}
	service := NewService(orchestrator, &memorySnapshots{}, fixedTime, func() string {
		return "00000000-0000-4000-8000-000000000001"
	}, env)

	result, inventory, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rooted.opened(filepath.Dir(forgedPath)) {
		t.Fatalf("forged external parent was opened: %q", rooted.paths())
	}
	for _, asset := range inventory.Assets {
		if strings.Contains(asset.ID, "forged-secret-marker") {
			t.Fatalf("forged target was inventoried: %+v", inventory)
		}
	}
	for _, coverage := range result.Coverage {
		if coverage.LocalTargets != nil {
			t.Fatalf("raw target survived: %+v", coverage)
		}
		if coverage.Collector == "mcp" {
			for _, target := range coverage.Targets {
				if target.TargetID == "mcp.shared.project" && target.Status != model.TargetNotPresent {
					t.Fatalf("forged target reached MCP: %+v", target)
				}
			}
		}
	}
	encoded, marshalErr := json.Marshal(struct {
		Result    model.ScanResult
		Inventory model.Inventory
	}{result, inventory})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(outside)) || bytes.Contains(encoded, []byte(forgedPath)) || bytes.Contains(encoded, []byte("forged-secret-marker")) {
		t.Fatalf("forged data persisted: %s", encoded)
	}
}

type recordingRootFileSystem struct {
	platform.OSFileSystem
	mu    sync.Mutex
	opens []string
}

func (f *recordingRootFileSystem) OpenRoot(path string) (platform.RootedDirectory, error) {
	f.mu.Lock()
	f.opens = append(f.opens, filepath.Clean(path))
	f.mu.Unlock()
	return f.OSFileSystem.OpenRoot(path)
}

func (f *recordingRootFileSystem) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.opens...)
}

func (f *recordingRootFileSystem) opened(path string) bool { return f.openCount(path) > 0 }

func (f *recordingRootFileSystem) openCount(path string) int {
	want := filepath.Clean(path)
	count := 0
	for _, opened := range f.paths() {
		if opened == want {
			count++
		}
	}
	return count
}
