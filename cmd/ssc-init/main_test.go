package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/ssc-init/ssc-init/internal/cli"
	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestDoctorCatalogMatchesConfiguredCollectorsAndPackageProbes(t *testing.T) {
	ecosystems, commands := doctorCatalog()
	wantEcosystems := []string{"agents", "cargo", "docker", "go", "homebrew", "ide", "mcp", "npm", "pip", "pipx", "projects", "uv"}
	wantCommands := []string{"brew", "cargo", "docker", "go", "npm", "pipx", "python3", "uv"}
	if !reflect.DeepEqual(ecosystems, wantEcosystems) {
		t.Fatalf("ecosystems=%v want=%v", ecosystems, wantEcosystems)
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("commands=%v want=%v", commands, wantCommands)
	}
}

func TestRunParsesExactlyOnceWithoutHostInitialization(t *testing.T) {
	oldParse, oldHost := parseOptionsForRun, hostPathsForRun
	t.Cleanup(func() {
		parseOptionsForRun = oldParse
		hostPathsForRun = oldHost
	})
	parseCalls := 0
	parseOptionsForRun = func(args []string) (cli.Options, error) {
		parseCalls++
		if !reflect.DeepEqual(args, []string{"ignored-by-injected-parser"}) {
			t.Fatalf("args=%q", args)
		}
		return cli.Options{Command: "version", JSON: true}, nil
	}
	hostPathsForRun = func() (string, platform.Paths, bool) {
		t.Fatal("version resolved host paths")
		return "", platform.Paths{}, false
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO(context.Background(), []string{"ignored-by-injected-parser"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if parseCalls != 1 {
		t.Fatalf("parse calls=%d", parseCalls)
	}
}

func TestInvalidArgumentsFailGenericallyBeforeHostResolution(t *testing.T) {
	oldParse, oldHost := parseOptionsForRun, hostPathsForRun
	t.Cleanup(func() {
		parseOptionsForRun = oldParse
		hostPathsForRun = oldHost
	})
	parseOptionsForRun = cli.ParseOptions
	hostPathsForRun = func() (string, platform.Paths, bool) {
		t.Fatal("invalid command resolved host paths")
		return "", platform.Paths{}, false
	}
	privateValue := "outside/private-value"
	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"scan", "--baseline", "--json", "--project-root", privateValue}, &stdout, &stderr)
	if code != 2 || stdout.String() != "" || stderr.String() != "invalid command arguments\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte(privateValue)) {
		t.Fatalf("private option echoed: %q", stderr.String())
	}
}

func TestStatusConstructsStoreWithoutProjectCollectors(t *testing.T) {
	oldHost, oldOpen, oldResolve := hostPathsForRun, openStoreForRun, resolveRootsForRun
	t.Cleanup(func() {
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
		resolveRootsForRun = oldResolve
	})
	home := t.TempDir()
	hostPathsForRun = func() (string, platform.Paths, bool) {
		return home, platform.PathsForHome(home), true
	}
	fakeStore := &mainSnapshotStore{}
	openStoreForRun = func(path string) (applicationStore, error) {
		if path != filepath.Join(home, "Library", "Application Support", "SSC Init", "state.db") {
			t.Fatalf("store path=%q", path)
		}
		return fakeStore, nil
	}
	resolveRootsForRun = func(string, []string) ([]projects.Root, error) {
		return nil, errors.New("status must not resolve project roots")
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO(context.Background(), []string{"status", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fakeStore.closeCalls != 1 {
		t.Fatalf("close calls=%d", fakeStore.closeCalls)
	}
}

func TestScanConfigurationCarriesResolvedScopeAndProjectCollector(t *testing.T) {
	home := t.TempDir()
	external := filepath.Join(filepath.Dir(home), "external-projects")
	options := cli.Options{
		Command: "scan", JSON: true, Baseline: true, ExternalProbes: true,
		ProjectRoots: []string{"$HOME/Projects", external},
	}
	environment, collectors, err := scanConfiguration(home, options)
	if err != nil {
		t.Fatal(err)
	}
	wantScope := model.ScanScope{
		Platform: runtime.GOOS, CatalogVersion: collector.CatalogVersion,
		ProjectRoots: []string{"$HOME/Projects", "external-root-1"}, ExternalProbes: true,
	}
	if !reflect.DeepEqual(environment.Scope, wantScope) || environment.Platform != runtime.GOOS {
		t.Fatalf("environment=%+v wantScope=%+v", environment, wantScope)
	}
	if environment.Inspector == nil {
		t.Fatal("external-probe scan did not construct an executable inspector")
	}
	wantNames := []string{"agents", "ide", "projects", "packages"}
	gotNames := make([]string, len(collectors))
	for index, configuredCollector := range collectors {
		gotNames[index] = configuredCollector.Name()
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("collectors=%q want=%q", gotNames, wantNames)
	}
	targeted, ok := collectors[2].(collector.TargetedCollector)
	if !ok || len(targeted.Targets()) != 1 || targeted.Targets()[0].ID != "projects.root" {
		t.Fatalf("project collector=%T targets=%+v", collectors[2], targeted)
	}
}

func TestScanConfigurationLeavesInspectorUnwiredWhenExternalProbesAreDisabled(t *testing.T) {
	environment, _, err := scanConfiguration(t.TempDir(), cli.Options{Command: "scan", JSON: true, Baseline: true})
	if err != nil {
		t.Fatal(err)
	}
	if environment.Scope.ExternalProbes || environment.Inspector != nil {
		t.Fatalf("environment=%+v", environment)
	}
}

type mainSnapshotStore struct {
	closeCalls int
}

func (*mainSnapshotStore) SaveScan(context.Context, model.ScanResult, model.Inventory) error {
	return nil
}

func (*mainSnapshotStore) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
	return model.Snapshot{}, false, nil
}

func (store *mainSnapshotStore) Close() error {
	store.closeCalls++
	return nil
}

var _ io.Closer = (*mainSnapshotStore)(nil)
