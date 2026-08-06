package acceptance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/cli"
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
	"github.com/ssc-init/ssc-init/internal/store"
)

const fixtureSecretSentinel = "fixture-secret"
const unconfiguredHomeSentinel = "unconfigured-home-sentinel"

type baselineOptions struct {
	home           string
	projectRoots   []string
	externalProbes bool
	runner         platform.Runner
	inspector      platform.ExecutableInspector
	databasePath   string
	scanID         string
}

type isolatedBaseline struct {
	Scan         model.ScanResult
	Inventory    model.Inventory
	Delta        model.Delta
	Snapshot     model.Snapshot
	Report       []byte
	Home         string
	DatabasePath string
	Catalog      map[string][]model.TargetSpec
	FileSystem   *matrixFileSystem
	Runner       *matrixRunner
	Inspector    *matrixInspector
}

func TestOfficialCatalogMatrixIsTruthful(t *testing.T) {
	unconfiguredHome := t.TempDir()
	writeMatrixFile(t, filepath.Join(unconfiguredHome, ".claude.json"), `{"mcpServers":{"`+unconfiguredHomeSentinel+`":{"url":"https://unconfigured.invalid/mcp"}}}`)
	t.Setenv("HOME", unconfiguredHome)
	result := runIsolatedBaseline(t, baselineOptions{externalProbes: false})
	assertEveryApplicableTargetInstanceReportedOnce(t, result)
	assertImplementedFixtureTargetsComplete(t, result)
	assertUnsupportedDynamicTargetsVisible(t, result)
	assertNoContainerAsset(t, result.Inventory, "cache")
	assertNoRawFixtureRoot(t, result)
	assertNoSecretFixtureValue(t, result)
	assertRunnerAndInspectorUnused(t, result)
	if bytes.Contains(encodeMatrixResult(t, result), []byte(unconfiguredHomeSentinel)) {
		t.Fatal("scan read the process HOME instead of the configured isolated home")
	}
}

func TestOfficialMCPFixturesCoverBothContainersAndCodexTransports(t *testing.T) {
	result := runIsolatedBaseline(t, baselineOptions{externalProbes: false})
	want := map[string]struct {
		location   string
		transports []string
	}{
		"mcp.claude-code.legacy-user": {"$HOME/.claude/settings.json", []string{"http"}},
		"mcp.claude-code.user":        {"$HOME/.claude.json", []string{"stdio"}},
		"mcp.claude-desktop.user":     {"$HOME/Library/Application Support/Claude/claude_desktop_config.json", []string{"http"}},
		"mcp.codex.project":           {"$HOME/Projects/sample/.codex/config.toml", []string{"http", "stdio"}},
		"mcp.codex.user":              {"$HOME/.codex/config.toml", []string{"http", "stdio"}},
		"mcp.cursor.project":          {"$HOME/Projects/sample/.cursor/mcp.json", []string{"stdio"}},
		"mcp.cursor.user":             {"$HOME/.cursor/mcp.json", []string{"stdio"}},
		"mcp.github-copilot.user":     {"$HOME/.copilot/mcp-config.json", []string{"http"}},
		"mcp.shared.project":          {"$HOME/Projects/sample/.mcp.json", []string{"http"}},
		"mcp.vscode-insiders.user":    {"$HOME/Library/Application Support/Code - Insiders/User/mcp.json", []string{"stdio"}},
		"mcp.vscode.project":          {"$HOME/Projects/sample/.vscode/mcp.json", []string{"http"}},
		"mcp.vscode.user":             {"$HOME/Library/Application Support/Code/User/mcp.json", []string{"http"}},
		"mcp.windsurf.legacy-user":    {"$HOME/.windsurf/mcp.json", []string{"http"}},
		"mcp.windsurf.user":           {"$HOME/.codeium/windsurf/mcp_config.json", []string{"stdio"}},
	}
	for source, expected := range want {
		observations := matrixObservationsForSource(result.Inventory, source)
		if len(observations) != len(expected.transports) {
			t.Fatalf("source %q observations=%+v want transports=%v", source, observations, expected.transports)
		}
		gotTransports := make([]string, len(observations))
		for index, observation := range observations {
			if observation.LocationRef != expected.location {
				t.Fatalf("source %q location=%q want=%q", source, observation.LocationRef, expected.location)
			}
			gotTransports[index] = observation.Metadata["transport"]
		}
		sort.Strings(gotTransports)
		if strings.Join(gotTransports, "\x00") != strings.Join(expected.transports, "\x00") {
			t.Fatalf("source %q transports=%v want=%v", source, gotTransports, expected.transports)
		}
	}
	assertNoSecretFixtureValue(t, result)
}

func TestMissingExpansionRootsRemainExplicit(t *testing.T) {
	home := t.TempDir()
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	projectRoot := requireMatrixTarget(t, result.Scan.Coverage, "projects", "projects.root", "$HOME/Projects")
	if projectRoot.Status != model.TargetNotPresent {
		t.Fatalf("missing configured project root=%+v", projectRoot)
	}
	jetBrains := requireMatrixTarget(t, result.Scan.Coverage, "ide", "ide.jetbrains.plugins", "")
	if jetBrains.Status != model.TargetNotPresent {
		t.Fatalf("missing JetBrains expansion base=%+v", jetBrains)
	}
	for _, targetID := range []string{
		"mcp.codex.project", "mcp.cursor.project", "mcp.shared.project", "mcp.vscode.project",
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, "mcp", targetID, "")
		if target.Status != model.TargetNotPresent {
			t.Fatalf("missing project expansion base %q=%+v", targetID, target)
		}
	}
	assertRunnerAndInspectorUnused(t, result)
}

func TestSameNamedMCPServerInTwoProjectsRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	for _, project := range []string{"alpha", "beta"} {
		writeMatrixFile(t, filepath.Join(home, "Projects", project, ".mcp.json"), `{
  "mcpServers": {
    "same": {"url": "https://same-project.invalid/mcp"}
  }
}`)
	}
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	assetCount := 0
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "mcp:shared:same" {
			assetCount++
		}
	}
	observations := make([]model.Observation, 0, 2)
	for _, observation := range result.Inventory.Observations {
		if observation.AssetID == "mcp:shared:same" {
			observations = append(observations, observation)
		}
	}
	if assetCount != 1 || len(observations) != 2 {
		t.Fatalf("same-name asset count=%d observations=%+v", assetCount, observations)
	}
	locations := []string{observations[0].LocationRef, observations[1].LocationRef}
	sort.Strings(locations)
	if strings.Join(locations, "\n") != "$HOME/Projects/alpha/.mcp.json\n$HOME/Projects/beta/.mcp.json" {
		t.Fatalf("same-name locations=%v", locations)
	}
	for _, location := range locations {
		target := requireMatrixTarget(t, result.Scan.Coverage, "mcp", "mcp.shared.project", location)
		if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
			t.Fatalf("same-name project target=%+v", target)
		}
	}
}

func TestNestedPluginCacheRetainsManifestBackedPluginWithoutCacheAsset(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(
		t,
		filepath.Join(home, ".codex", "plugins", "cache", "example.invalid", "fixture-plugin", "1.2.3", ".codex-plugin", "plugin.json"),
		`{"name":"fixture-plugin","version":"1.2.3"}`,
	)
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	assertNoContainerAsset(t, result.Inventory, "cache")
	found := 0
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "agent-plugin:codex:fixture-plugin@1.2.3" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("manifest-backed nested plugin count=%d inventory=%+v", found, result.Inventory)
	}
	target := requireMatrixTarget(t, result.Scan.Coverage, "agents", "agents.codex.plugins", "")
	if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
		t.Fatalf("nested cache target=%+v", target)
	}
}

func TestSameIDEExtensionInTwoLocationsRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	manifest := `{"name":"same","publisher":"acme","version":"1.0.0","main":"dist/extension.js"}`
	for _, installation := range []string{"acme.same-1.0.0", "acme.same-copy-1.0.0"} {
		writeMatrixFile(t, filepath.Join(home, ".vscode", "extensions", installation, "package.json"), manifest)
	}
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	const assetID = "ide-extension:vscode:acme.same@1.0.0"
	assetCount := 0
	var observations []model.Observation
	for _, asset := range result.Inventory.Assets {
		if asset.ID == assetID {
			assetCount++
		}
	}
	for _, observation := range result.Inventory.Observations {
		if observation.AssetID == assetID {
			observations = append(observations, observation)
		}
	}
	if assetCount != 1 || len(observations) != 2 || observations[0].ID == observations[1].ID {
		t.Fatalf("same-extension assets=%d observations=%+v", assetCount, observations)
	}
	target := requireMatrixTarget(t, result.Scan.Coverage, "ide", "ide.vscode.extensions", "")
	if target.Status != model.TargetComplete || target.Assets != 2 || target.Observations != 2 {
		t.Fatalf("same-extension target=%+v", target)
	}
}

func TestSamePackageThroughTwoEnabledManagersRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	pythonPath := filepath.Join(home, "fake-bin", "python3")
	uvPath := filepath.Join(home, "fake-bin", "uv")
	inspector := &matrixInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {
				Command: "python3", Path: pythonPath, LocationRef: "$HOME/fake-bin/python3",
				SHA256: strings.Repeat("a", 64), Mode: 0o755,
			},
			"uv": {
				Command: "uv", Path: uvPath, LocationRef: "$HOME/fake-bin/uv",
				SHA256: strings.Repeat("b", 64), Mode: 0o755,
			},
		},
		errors: map[string]error{},
	}
	for _, capability := range packages.Capabilities() {
		if capability.Executable != "python3" && capability.Executable != "uv" {
			inspector.errors[capability.Executable] = exec.ErrNotFound
		}
	}
	runner := &matrixRunner{results: map[string]platform.CommandResult{
		matrixCommandKey(pythonPath, "-m", "pip", "list", "--format=json"): {
			Stdout: `[{"name":"shared-fixture","version":"1.0.0"}]`,
		},
		matrixCommandKey(uvPath, "tool", "list"): {Stdout: "shared-fixture v1.0.0\n"},
	}, errors: map[string]error{}}
	result := runIsolatedBaseline(t, baselineOptions{
		home: home, externalProbes: true, runner: runner, inspector: inspector,
	})

	const assetID = "pkg:pypi/shared-fixture@1.0.0"
	assetCount := 0
	var managers []string
	for _, asset := range result.Inventory.Assets {
		if asset.ID == assetID {
			assetCount++
		}
	}
	for _, observation := range result.Inventory.Observations {
		if observation.AssetID == assetID {
			managers = append(managers, observation.Metadata["manager"])
		}
	}
	sort.Strings(managers)
	if assetCount != 1 || strings.Join(managers, ",") != "pip,uv" {
		t.Fatalf("same-package assets=%d managers=%v", assetCount, managers)
	}
	for _, targetID := range []string{"packages.pip", "packages.uv"} {
		target := requireMatrixTarget(t, result.Scan.Coverage, "packages", targetID, "")
		if target.Status != model.TargetComplete || target.Assets != 2 || target.Observations != 2 {
			t.Fatalf("enabled package target %q=%+v", targetID, target)
		}
	}
	if calls := runner.callCount(); calls != 2 {
		t.Fatalf("enabled package runner calls=%d want=2", calls)
	}
	if inspect, verify := inspector.callCounts(); inspect != len(packages.Capabilities()) || verify != 2 {
		t.Fatalf("enabled package inspector calls inspect=%d verify=%d", inspect, verify)
	}
	assertNoRawFixtureRoot(t, result)
}

func TestHostileMalformedAndSymlinkSiblingsRemainPartialWithoutLosingSafeInventory(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "safe", ".codex-plugin", "plugin.json"), `{"name":"safe-fixture","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "broken", ".codex-plugin", "plugin.json"), `{`)
	const hostileIdentity = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "hostile", ".codex-plugin", "plugin.json"), `{"name":"`+hostileIdentity+`","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"safe-sibling":{"url":"https://safe-sibling.invalid/mcp"}}}`)
	outside := t.TempDir()
	writeMatrixFile(t, filepath.Join(outside, ".codex-plugin", "plugin.json"), `{"name":"outside-fixture","version":"1.0.0"}`)
	if err := os.Symlink(outside, filepath.Join(home, ".codex", "plugins", "outside-link")); err != nil {
		t.Fatal(err)
	}

	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})
	target := requireMatrixTarget(t, result.Scan.Coverage, "agents", "agents.codex.plugins", "")
	if target.Status != model.TargetPartial {
		t.Fatalf("hostile sibling target=%+v", target)
	}
	codes := make(map[string]bool)
	for _, issue := range target.Errors {
		codes[issue.Code] = true
	}
	for _, code := range []string{"identity_rejected", "manifest_invalid", "symlink_rejected"} {
		if !codes[code] {
			t.Fatalf("hostile sibling target errors=%+v missing %q", target.Errors, code)
		}
	}
	wantAssets := map[string]bool{
		"agent-plugin:codex:safe-fixture@1.0.0": false,
		"mcp:claude-code:safe-sibling":          false,
	}
	for _, asset := range result.Snapshot.Inventory.Assets {
		if _, wanted := wantAssets[asset.ID]; wanted {
			wantAssets[asset.ID] = true
		}
		if asset.Name == "outside-fixture" || strings.Contains(asset.ID, hostileIdentity) {
			t.Fatalf("hostile or symlinked asset survived: %+v", asset)
		}
	}
	for assetID, found := range wantAssets {
		if !found {
			t.Fatalf("safe sibling %q did not persist", assetID)
		}
	}
	encoded := encodeMatrixResult(t, result)
	if bytes.Contains(encoded, []byte(hostileIdentity)) {
		t.Fatal("hostile identity survived in report or snapshot")
	}
	database, err := os.ReadFile(result.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(database, []byte(hostileIdentity)) {
		t.Fatal("hostile identity survived in SQLite")
	}
}

func TestMigrationThreeLegacySnapshotSurfacesThroughStatusV2(t *testing.T) {
	databasePath := createMigrationThreeLegacyDatabase(t)
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()

	status := readMatrixStatusFromReader(t, snapshots)
	if status.SchemaVersion != "ssc-init.status.v2" || !status.Initialized || status.InventorySchemaVersion != "ssc-init.scan.v1" || !status.LegacyInventory {
		t.Fatalf("legacy status=%+v", status)
	}
	if status.Scope != nil || len(status.Coverage) != 0 || status.Inventory == nil {
		t.Fatalf("legacy status exposed v2 provenance: %+v", status)
	}
	if len(status.Inventory.Assets) != 0 || len(status.Inventory.Observations) != 0 || len(status.Inventory.Relationships) != 0 {
		t.Fatalf("legacy inventory=%+v", status.Inventory)
	}
}

func TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta(t *testing.T) {
	home := copyOfficialFixtureHome(t)
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	first := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000013",
	})
	status := readMatrixStatusFromPath(t, databasePath)
	if status.SchemaVersion != "ssc-init.status.v2" || status.InventorySchemaVersion != "ssc-init.scan.v2" || status.LegacyInventory || !status.Initialized {
		t.Fatalf("v2 status provenance=%+v", status)
	}
	if status.Scope == nil || !reflect.DeepEqual(*status.Scope, first.Scan.Scope) || !reflect.DeepEqual(status.Coverage, first.Scan.Coverage) || status.Inventory == nil || !reflect.DeepEqual(*status.Inventory, first.Inventory) {
		t.Fatalf("reopened v2 status did not preserve the full snapshot: %+v", status)
	}

	second := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000014",
	})
	if len(second.Delta.Changes) != 0 || !reflect.DeepEqual(second.Inventory, first.Inventory) || !reflect.DeepEqual(second.Scan.Scope, first.Scan.Scope) || !reflect.DeepEqual(second.Scan.Coverage, first.Scan.Coverage) {
		t.Fatalf("unchanged second scan delta=%+v", second.Delta)
	}

	oldLocation := filepath.Join(home, ".vscode", "extensions", "acme.safe-1.2.3")
	newLocation := filepath.Join(home, ".vscode", "extensions", "acme.safe-relocated-1.2.3")
	if err := os.Rename(oldLocation, newLocation); err != nil {
		t.Fatal(err)
	}
	third := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000015",
	})
	if len(third.Delta.Changes) != 2 {
		t.Fatalf("observed-location delta=%+v want one removal and one addition", third.Delta)
	}
	kinds := make([]string, 0, 2)
	for _, change := range third.Delta.Changes {
		if change.Entity != model.ChangeEntityObservation {
			t.Fatalf("observed-location mutation changed a canonical asset: %+v", change)
		}
		kinds = append(kinds, string(change.Kind))
	}
	sort.Strings(kinds)
	if strings.Join(kinds, ",") != "added,removed" {
		t.Fatalf("observed-location change kinds=%v", kinds)
	}
	latestStatus := readMatrixStatusFromPath(t, databasePath)
	if latestStatus.Inventory == nil || !reflect.DeepEqual(*latestStatus.Inventory, third.Inventory) || latestStatus.Scope == nil || !reflect.DeepEqual(*latestStatus.Scope, third.Scan.Scope) || !reflect.DeepEqual(latestStatus.Coverage, third.Scan.Coverage) {
		t.Fatalf("latest status did not use the third full snapshot: %+v", latestStatus)
	}
}

func runIsolatedBaseline(t *testing.T, options baselineOptions) isolatedBaseline {
	t.Helper()
	home := options.home
	if home == "" {
		home = copyOfficialFixtureHome(t)
	}
	home, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Clean(home)

	rootValues := options.projectRoots
	if len(rootValues) == 0 {
		rootValues = []string{"$HOME/Projects"}
	}
	roots, err := projects.ResolveRoots(home, rootValues)
	if err != nil {
		t.Fatal(err)
	}

	fileSystem := &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
	runner, runnerOK := options.runner.(*matrixRunner)
	if options.runner == nil {
		runner = &matrixRunner{failOnCall: true}
		options.runner = runner
	} else if !runnerOK {
		runner = nil
	}
	inspector, inspectorOK := options.inspector.(*matrixInspector)
	if options.inspector == nil {
		inspector = &matrixInspector{failOnCall: true}
		options.inspector = inspector
	} else if !inspectorOK {
		inspector = nil
	}

	environment := collector.Environment{
		Home: home, Platform: "darwin",
		Scope: model.ScanScope{
			Platform: "darwin", ProjectRoots: projects.RootRefs(roots),
			ExternalProbes: options.externalProbes,
		},
		FS: fileSystem, Runner: options.runner, Inspector: options.inspector,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	configured := []collector.Collector{
		agents.New(),
		ide.New(),
		projects.New(roots),
		packages.New(),
	}
	catalog := make(map[string][]model.TargetSpec, len(configured)+1)
	for _, configuredCollector := range configured {
		targeted, ok := configuredCollector.(collector.TargetedCollector)
		if !ok {
			t.Fatalf("production collector %q does not expose its target catalog", configuredCollector.Name())
		}
		catalog[configuredCollector.Name()] = targeted.Targets()
	}
	catalog["mcp"] = mcp.New().Targets()

	databasePath := options.databasePath
	if databasePath == "" {
		databasePath = filepath.Join(privateMatrixTempDir(t), "state.db")
	}
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := collector.Orchestrator{
		Timeout: time.Second, MaxConcurrent: 4, Collectors: configured,
	}
	scanID := options.scanID
	if scanID == "" {
		scanID = "00000000-0000-4000-8000-000000000013"
	}
	service := scan.NewService(
		orchestrator,
		snapshots,
		environment.Now,
		func() string { return scanID },
		environment,
	)
	scanResult, inventory, delta, err := service.Baseline(context.Background())
	if err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	if !initialized {
		_ = snapshots.Close()
		t.Fatal("baseline did not persist a snapshot")
	}
	var output bytes.Buffer
	if err := report.WriteJSON(&output, scanResult, inventory, delta); err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	if err := snapshots.Close(); err != nil {
		t.Fatal(err)
	}
	return isolatedBaseline{
		Scan: scanResult, Inventory: inventory, Delta: delta, Snapshot: snapshot,
		Report: output.Bytes(), Home: home, DatabasePath: databasePath,
		Catalog: catalog, FileSystem: fileSystem, Runner: runner, Inspector: inspector,
	}
}

func assertEveryApplicableTargetInstanceReportedOnce(t *testing.T, result isolatedBaseline) {
	t.Helper()
	coverage := make(map[string]model.CollectorResult, len(result.Scan.Coverage))
	for _, collectorResult := range result.Scan.Coverage {
		if _, duplicate := coverage[collectorResult.Collector]; duplicate {
			t.Fatalf("collector %q reported more than once", collectorResult.Collector)
		}
		coverage[collectorResult.Collector] = collectorResult
		if collectorResult.LocalTargets != nil {
			t.Fatalf("collector %q retained raw local targets", collectorResult.Collector)
		}
	}
	if len(coverage) != len(result.Catalog) {
		t.Fatalf("coverage collectors=%v catalog collectors=%v", sortedMapKeys(coverage), sortedMapKeys(result.Catalog))
	}

	wantExpanded := map[string][]string{
		"ide.jetbrains.plugins": {"Idea"},
		"mcp.codex.project":     {"$HOME/Projects/sample/.codex/config.toml"},
		"mcp.cursor.project":    {"$HOME/Projects/sample/.cursor/mcp.json"},
		"mcp.shared.project":    {"$HOME/Projects/sample/.mcp.json"},
		"mcp.vscode.project":    {"$HOME/Projects/sample/.vscode/mcp.json"},
		"projects.root":         {"$HOME/Projects"},
	}
	for collectorName, specs := range result.Catalog {
		collectorResult, ok := coverage[collectorName]
		if !ok {
			t.Fatalf("missing collector coverage %q", collectorName)
		}
		byTarget := make(map[string][]model.TargetCoverage)
		seenPairs := make(map[string]struct{})
		for _, target := range collectorResult.Targets {
			pair := target.TargetID + "\x00" + target.InstanceRef
			if _, duplicate := seenPairs[pair]; duplicate {
				t.Fatalf("duplicate target instance %q/%q", target.TargetID, target.InstanceRef)
			}
			seenPairs[pair] = struct{}{}
			byTarget[target.TargetID] = append(byTarget[target.TargetID], target)
		}
		for _, spec := range specs {
			instances := byTarget[spec.ID]
			wantRefs, expanded := wantExpanded[spec.ID]
			if !expanded {
				wantRefs = []string{""}
			}
			if len(instances) != len(wantRefs) {
				t.Fatalf("target %q instances=%+v want refs=%v", spec.ID, instances, wantRefs)
			}
			gotRefs := make([]string, len(instances))
			for index := range instances {
				gotRefs[index] = instances[index].InstanceRef
			}
			sort.Strings(gotRefs)
			sort.Strings(wantRefs)
			if strings.Join(gotRefs, "\x00") != strings.Join(wantRefs, "\x00") {
				t.Fatalf("target %q refs=%v want=%v", spec.ID, gotRefs, wantRefs)
			}
		}
	}
}

func assertImplementedFixtureTargetsComplete(t *testing.T, result isolatedBaseline) {
	t.Helper()
	for _, pair := range []struct{ collector, target, instance string }{
		{"agents", "agents.codex.plugins", ""},
		{"ide", "ide.jetbrains.plugins", "Idea"},
		{"ide", "ide.vscode.extensions", ""},
		{"mcp", "mcp.claude-code.legacy-user", ""},
		{"mcp", "mcp.claude-code.user", ""},
		{"mcp", "mcp.claude-desktop.user", ""},
		{"mcp", "mcp.codex.project", "$HOME/Projects/sample/.codex/config.toml"},
		{"mcp", "mcp.codex.user", ""},
		{"mcp", "mcp.cursor.project", "$HOME/Projects/sample/.cursor/mcp.json"},
		{"mcp", "mcp.cursor.user", ""},
		{"mcp", "mcp.github-copilot.user", ""},
		{"mcp", "mcp.shared.project", "$HOME/Projects/sample/.mcp.json"},
		{"mcp", "mcp.vscode-insiders.user", ""},
		{"mcp", "mcp.vscode.project", "$HOME/Projects/sample/.vscode/mcp.json"},
		{"mcp", "mcp.vscode.user", ""},
		{"mcp", "mcp.windsurf.legacy-user", ""},
		{"mcp", "mcp.windsurf.user", ""},
		{"projects", "projects.root", "$HOME/Projects"},
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, pair.collector, pair.target, pair.instance)
		if target.Status != model.TargetComplete || target.Assets == 0 || target.Observations == 0 {
			t.Fatalf("implemented fixture target %q/%q=%+v", pair.target, pair.instance, target)
		}
	}
}

func assertUnsupportedDynamicTargetsVisible(t *testing.T, result isolatedBaseline) {
	t.Helper()
	for _, pair := range []struct{ collector, target string }{
		{"agents", "agents.cursor.plugins"},
		{"agents", "agents.custom-roots"},
		{"agents", "agents.dynamic-api"},
		{"agents", "agents.environment-relocated"},
		{"agents", "agents.remote-host"},
		{"agents", "agents.windsurf.plugins"},
		{"ide", "ide.custom-roots"},
		{"ide", "ide.dev-container"},
		{"ide", "ide.environment-relocated"},
		{"ide", "ide.remote-ssh"},
		{"ide", "ide.remote-wsl"},
		{"ide", "ide.service-api"},
		{"mcp", "mcp.dev-container"},
		{"mcp", "mcp.dynamic-api"},
		{"mcp", "mcp.environment-relocated"},
		{"mcp", "mcp.profile-specific"},
		{"mcp", "mcp.remote-user"},
		{"mcp", "mcp.service-managed"},
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, pair.collector, pair.target, "")
		if target.Status != model.TargetUnsupported || len(target.Errors) != 1 || target.Errors[0].Code != "unsupported_target" {
			t.Fatalf("unsupported target %q=%+v", pair.target, target)
		}
	}
}

func assertNoContainerAsset(t *testing.T, inventory model.Inventory, name string) {
	t.Helper()
	for _, asset := range inventory.Assets {
		if asset.Type == model.AssetAgentPlugin && asset.Name == name {
			t.Fatalf("container %q was reported as a plugin: %+v", name, asset)
		}
	}
}

func assertNoRawFixtureRoot(t *testing.T, result isolatedBaseline) {
	t.Helper()
	encoded := encodeMatrixResult(t, result)
	if bytes.Contains(encoded, []byte(result.Home)) {
		t.Fatalf("raw fixture home leaked into persisted or reported output: %q", result.Home)
	}
	if denied := result.FileSystem.deniedPaths(); len(denied) != 0 {
		t.Fatalf("collector attempted unconfigured filesystem paths: %v", denied)
	}
}

func assertNoSecretFixtureValue(t *testing.T, result isolatedBaseline) {
	t.Helper()
	encoded := encodeMatrixResult(t, result)
	if bytes.Contains(encoded, []byte(fixtureSecretSentinel)) {
		t.Fatalf("fixture secret survived normalization: %s", encoded)
	}
	database, err := os.ReadFile(result.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(database, []byte(fixtureSecretSentinel)) {
		t.Fatal("fixture secret was persisted in SQLite")
	}
}

func assertRunnerAndInspectorUnused(t *testing.T, result isolatedBaseline) {
	t.Helper()
	if result.Runner == nil || result.Inspector == nil {
		t.Fatal("default matrix did not install fail-on-call execution fakes")
	}
	if calls := result.Runner.callCount(); calls != 0 {
		t.Fatalf("default runner calls=%d want=0", calls)
	}
	if inspect, verify := result.Inspector.callCounts(); inspect != 0 || verify != 0 {
		t.Fatalf("default inspector calls inspect=%d verify=%d want=0", inspect, verify)
	}
}

func requireMatrixTarget(t *testing.T, coverage []model.CollectorResult, collectorName, targetID, instanceRef string) model.TargetCoverage {
	t.Helper()
	for _, result := range coverage {
		if result.Collector != collectorName {
			continue
		}
		for _, target := range result.Targets {
			if target.TargetID == targetID && target.InstanceRef == instanceRef {
				return target
			}
		}
	}
	t.Fatalf("missing target %q/%q from collector %q", targetID, instanceRef, collectorName)
	return model.TargetCoverage{}
}

func matrixObservationsForSource(inventory model.Inventory, source string) []model.Observation {
	var observations []model.Observation
	for _, observation := range inventory.Observations {
		if observation.Collector == "mcp" && observation.Source == source {
			observations = append(observations, observation)
		}
	}
	return observations
}

func encodeMatrixResult(t *testing.T, result isolatedBaseline) []byte {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Scan      model.ScanResult `json:"scan"`
		Inventory model.Inventory  `json:"inventory"`
		Delta     model.Delta      `json:"delta"`
		Snapshot  model.Snapshot   `json:"snapshot"`
		Report    json.RawMessage  `json:"report"`
	}{result.Scan, result.Inventory, result.Delta, result.Snapshot, result.Report})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func copyOfficialFixtureHome(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs("../../testdata/home")
	if err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := os.CopyFS(destination, os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	return destination
}

func privateMatrixTempDir(t *testing.T) string {
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

func writeMatrixFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func matrixCommandKey(command string, args ...string) string {
	return strings.Join(append([]string{command}, args...), "\x1f")
}

type matrixStatus struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Initialized            bool                    `json:"initialized"`
	InventorySchemaVersion string                  `json:"inventorySchemaVersion"`
	LegacyInventory        bool                    `json:"legacyInventory"`
	Scope                  *model.ScanScope        `json:"scope"`
	Coverage               []model.CollectorResult `json:"coverage"`
	Inventory              *model.Inventory        `json:"inventory"`
}

func readMatrixStatusFromReader(t *testing.T, reader cli.StatusReader) matrixStatus {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := (cli.App{StatusReader: reader}).Run(context.Background(), []string{"status", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("status exit=%d stderr=%q", code, stderr.String())
	}
	var status matrixStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, stdout.String())
	}
	return status
}

func readMatrixStatusFromPath(t *testing.T, databasePath string) matrixStatus {
	t.Helper()
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	status := readMatrixStatusFromReader(t, snapshots)
	if err := snapshots.Close(); err != nil {
		t.Fatal(err)
	}
	return status
}

func createMigrationThreeLegacyDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(privateMatrixTempDir(t), "legacy.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(legacyMigrationThreeSchema); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 3; version++ {
		if _, err := database.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, "2026-08-06T00:00:00.000000000Z"); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO scans(id, schema_version, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy-migration-three", "ssc-init.scan.v1", "complete", "2026-08-06T00:00:00.000000000Z", "2026-08-06T00:00:01.000000000Z"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil, asset_count, relationship_count, error_count) VALUES (?, 1, 1, 1, 0, 0, 0)`, "legacy-migration-three"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

const legacyMigrationThreeSchema = `
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE assets (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, asset_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE relationships (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, from_id, kind, to_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE coverage (
    scan_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    result_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, collector),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE inventory_state (
    scan_id TEXT PRIMARY KEY,
    assets_nil INTEGER NOT NULL CHECK (assets_nil IN (0, 1)),
    relationships_nil INTEGER NOT NULL CHECK (relationships_nil IN (0, 1)),
    errors_nil INTEGER NOT NULL CHECK (errors_nil IN (0, 1)),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE asset_state (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_index INTEGER NOT NULL CHECK (asset_index >= 0),
    metadata_nil INTEGER NOT NULL CHECK (metadata_nil IN (0, 1)),
    PRIMARY KEY (scan_id, asset_id),
    UNIQUE (scan_id, asset_index),
    FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)
);
CREATE TABLE relationship_state (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    relationship_index INTEGER NOT NULL CHECK (relationship_index >= 0),
    PRIMARY KEY (scan_id, from_id, kind, to_id),
    UNIQUE (scan_id, relationship_index),
    FOREIGN KEY (scan_id, from_id, kind, to_id) REFERENCES relationships(scan_id, from_id, kind, to_id)
);
CREATE TABLE inventory_errors (
    scan_id TEXT NOT NULL,
    error_index INTEGER NOT NULL CHECK (error_index >= 0),
    error_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, error_index),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
ALTER TABLE inventory_state ADD COLUMN asset_count INTEGER NOT NULL DEFAULT 0 CHECK (asset_count >= 0);
ALTER TABLE inventory_state ADD COLUMN relationship_count INTEGER NOT NULL DEFAULT 0 CHECK (relationship_count >= 0);
ALTER TABLE inventory_state ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0);
UPDATE inventory_state SET
    asset_count = (SELECT count(*) FROM assets WHERE assets.scan_id = inventory_state.scan_id),
    relationship_count = (SELECT count(*) FROM relationships WHERE relationships.scan_id = inventory_state.scan_id),
    error_count = (SELECT count(*) FROM inventory_errors WHERE inventory_errors.scan_id = inventory_state.scan_id);
CREATE INDEX scans_latest_idx ON scans(finished_at DESC, id DESC);
`

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type matrixFileSystem struct {
	platform.OSFileSystem
	root string

	mu     sync.Mutex
	denied []string
}

func (f *matrixFileSystem) ReadFile(name string) ([]byte, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadFile(name)
}

func (f *matrixFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadDir(name)
}

func (f *matrixFileSystem) Stat(name string) (os.FileInfo, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.Stat(name)
}

func (f *matrixFileSystem) WalkDir(root string, walk fs.WalkDirFunc) error {
	if !f.allows(root) {
		return fs.ErrPermission
	}
	return f.OSFileSystem.WalkDir(root, walk)
}

func (f *matrixFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.OpenRoot(name)
}

func (f *matrixFileSystem) allows(name string) bool {
	relative, err := filepath.Rel(filepath.Clean(f.root), filepath.Clean(name))
	allowed := err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	if !allowed {
		f.mu.Lock()
		f.denied = append(f.denied, filepath.Clean(name))
		f.mu.Unlock()
	}
	return allowed
}

func (f *matrixFileSystem) deniedPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.denied...)
}

type matrixRunner struct {
	mu         sync.Mutex
	failOnCall bool
	calls      int
	results    map[string]platform.CommandResult
	errors     map[string]error
}

func (r *matrixRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.failOnCall {
		return platform.CommandResult{}, errors.New("matrix runner must not be called")
	}
	key := strings.Join(append([]string{command}, args...), "\x1f")
	return r.results[key], r.errors[key]
}

func (r *matrixRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type matrixInspector struct {
	mu          sync.Mutex
	failOnCall  bool
	inspectCall int
	verifyCall  int
	evidence    map[string]platform.ExecutableEvidence
	errors      map[string]error
}

func (i *matrixInspector) Inspect(_ context.Context, _ string, command string) (platform.ExecutableEvidence, error) {
	i.mu.Lock()
	i.inspectCall++
	i.mu.Unlock()
	if i.failOnCall {
		return platform.ExecutableEvidence{}, errors.New("matrix inspector must not be called")
	}
	return i.evidence[command], i.errors[command]
}

func (i *matrixInspector) Verify(platform.ExecutableEvidence) error {
	i.mu.Lock()
	i.verifyCall++
	i.mu.Unlock()
	if i.failOnCall {
		return errors.New("matrix inspector must not be called")
	}
	return nil
}

func (i *matrixInspector) callCounts() (int, int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.inspectCall, i.verifyCall
}
