package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

func TestNonDarwinOperationalCommandsCreateNoState(t *testing.T) {
	oldGOOS, oldHost, oldOpen, oldResolve := runtimeGOOS, hostPathsForRun, openStoreForRun, resolveRootsForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
		resolveRootsForRun = oldResolve
	})
	runtimeGOOS = "linux"
	hostCalls, openCalls, resolveCalls := 0, 0, 0
	hostPathsForRun = func() (string, platform.Paths, bool) {
		hostCalls++
		return "", platform.Paths{}, false
	}
	openStoreForRun = func(string) (applicationStore, error) {
		openCalls++
		return nil, errors.New("store must not be opened")
	}
	resolveRootsForRun = func(string, []string) ([]projects.Root, error) {
		resolveCalls++
		return nil, errors.New("project roots must not be resolved")
	}
	hostileHome := filepath.Join(t.TempDir(), "must-remain-absent")
	t.Setenv("HOME", hostileHome)

	for _, args := range [][]string{
		{"doctor", "--json"},
		{"scan", "--baseline", "--json"},
		{"status", "--json"},
	} {
		var stdout, stderr bytes.Buffer
		code := runWithIO(context.Background(), args, &stdout, &stderr)
		if code != 2 || stdout.String() != "" || stderr.String() != "unsupported operating system\n" {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	if hostCalls != 0 || openCalls != 0 || resolveCalls != 0 {
		t.Fatalf("host calls=%d store calls=%d root-resolution calls=%d", hostCalls, openCalls, resolveCalls)
	}
	if _, err := os.Stat(hostileHome); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hostile HOME was touched: err=%v", err)
	}
}

func TestVersionOnNonDarwinDoesNotInitializeHost(t *testing.T) {
	oldGOOS, oldHost := runtimeGOOS, hostPathsForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		hostPathsForRun = oldHost
	})
	runtimeGOOS = "linux"
	hostCalls := 0
	hostPathsForRun = func() (string, platform.Paths, bool) {
		hostCalls++
		return "", platform.Paths{}, false
	}

	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"version", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.String() != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("version output is not JSON: %v", err)
	}
	if payload["product"] != "SSC Init" || payload["command"] != "ssc-init" || payload["version"] != version {
		t.Fatalf("payload=%v", payload)
	}
	if hostCalls != 0 {
		t.Fatalf("host calls=%d", hostCalls)
	}
}

func TestNonDarwinInvalidCommandsRemainUsageErrorsWithoutHostInitialization(t *testing.T) {
	oldGOOS, oldHost := runtimeGOOS, hostPathsForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		hostPathsForRun = oldHost
	})
	runtimeGOOS = "linux"
	hostCalls := 0
	hostPathsForRun = func() (string, platform.Paths, bool) {
		hostCalls++
		return "", platform.Paths{}, false
	}

	for _, args := range [][]string{
		nil,
		{"unknown", "--json"},
		{"scan", "--baseline"},
	} {
		var stdout, stderr bytes.Buffer
		code := runWithIO(context.Background(), args, &stdout, &stderr)
		if code != 2 || stdout.String() != "" || stderr.String() != "invalid command arguments\n" {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	if hostCalls != 0 {
		t.Fatalf("host calls=%d", hostCalls)
	}
}

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

func TestHookRunsBaselineScanAndPersistsSnapshot(t *testing.T) {
	oldHost, oldOpen := hostPathsForRun, openStoreForRun
	t.Cleanup(func() {
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
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

	var stdout, stderr bytes.Buffer
	if code := runWithIO(context.Background(), []string{"hook"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if fakeStore.saveCalls != 1 {
		t.Fatalf("baseline scanner was not reached: save calls=%d", fakeStore.saveCalls)
	}
	if fakeStore.closeCalls != 1 {
		t.Fatalf("close calls=%d", fakeStore.closeCalls)
	}
}

func TestHookOnUnsupportedOperatingSystemIsAUsageError(t *testing.T) {
	oldGOOS, oldHost, oldOpen := runtimeGOOS, hostPathsForRun, openStoreForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
	})
	runtimeGOOS = "linux"
	hostPathsForRun = func() (string, platform.Paths, bool) {
		t.Fatal("hook resolved host paths on an unsupported operating system")
		return "", platform.Paths{}, false
	}
	openStoreForRun = func(string) (applicationStore, error) {
		t.Fatal("hook opened the store on an unsupported operating system")
		return nil, errors.New("store must not be opened")
	}

	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"hook"}, &stdout, &stderr)
	if code != 2 || stdout.String() != "" || stderr.String() != "unsupported operating system\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestHookHostInitializationFailuresStayAdvisory(t *testing.T) {
	oldHost, oldOpen := hostPathsForRun, openStoreForRun
	t.Cleanup(func() {
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
	})
	home := t.TempDir()

	for _, testCase := range []struct {
		name  string
		hosts func() (string, platform.Paths, bool)
		open  func(string) (applicationStore, error)
	}{
		{
			name:  "host paths unavailable",
			hosts: func() (string, platform.Paths, bool) { return "", platform.Paths{}, false },
			open: func(string) (applicationStore, error) {
				t.Fatal("hook opened the store without host paths")
				return nil, errors.New("store must not be opened")
			},
		},
		{
			name:  "store unavailable",
			hosts: func() (string, platform.Paths, bool) { return home, platform.PathsForHome(home), true },
			open:  func(string) (applicationStore, error) { return nil, errors.New("store unavailable") },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			hostPathsForRun = testCase.hosts
			openStoreForRun = testCase.open
			var stdout, stderr bytes.Buffer
			code := runWithIO(context.Background(), []string{"hook"}, &stdout, &stderr)
			if code != 0 || stdout.String() != "" || stderr.String() != "ssc-init hook: baseline scan failed\n" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
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

func TestDefaultStoreSupportsAutomaticEvidenceCacheWiring(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	opened, err := openStoreForRun(filepath.Join(parent, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, ok := opened.(evidence.LeafCache); !ok {
		t.Fatalf("store %T does not provide the evidence leaf cache", opened)
	}
	if _, ok := opened.(evidence.CacheWriter); !ok {
		t.Fatalf("store %T does not provide the evidence cache writer", opened)
	}
}

type mainSnapshotStore struct {
	closeCalls int
	saveCalls  int
}

func (store *mainSnapshotStore) SaveScan(context.Context, model.ScanResult, model.Inventory) error {
	store.saveCalls++
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
