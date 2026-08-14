package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/audit"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

func TestColorEnabledRequiresTerminalAndHonorsNoColor(t *testing.T) {
	oldTerminal := terminalForColor
	oldNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	t.Cleanup(func() {
		terminalForColor = oldTerminal
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", oldNoColor)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	terminalForColor = func(*os.File) bool { return true }
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if !colorEnabled(file) {
		t.Fatal("terminal output did not enable color")
	}
	t.Setenv("NO_COLOR", "1")
	if colorEnabled(file) {
		t.Fatal("NO_COLOR did not disable terminal color")
	}
	if colorEnabled(&bytes.Buffer{}) {
		t.Fatal("redirected output enabled color")
	}
}

func TestProductionTIUpdaterUsesOnlyReviewedCompiledFeedIdentity(t *testing.T) {
	manager := &bundle.Manager{}
	updater := productionTIUpdater(manager, time.Now)
	if updater.Manager != manager || updater.Base == nil || updater.Base.String() != "https://github.com/s1ns3nz0/ssc-init-ti/" || updater.RepositoryID != productionTIRepositoryID {
		t.Fatalf("updater=%+v", updater)
	}
	if productionTIRepositoryID != "1333823234" {
		t.Fatalf("repository id=%q", productionTIRepositoryID)
	}
	keys := bundle.ProductionKeys()
	if len(keys[bundle.FamilyTI]) != 1 {
		t.Fatalf("production TI trust=%v", keys)
	}
}

func TestAuditVerifyIsOfflineAndStatusAuditAvoidsStore(t *testing.T) {
	oldGOOS, oldHost, oldOpen := runtimeGOOS, hostPathsForRun, openStoreForRun
	t.Cleanup(func() {
		runtimeGOOS, hostPathsForRun, openStoreForRun = oldGOOS, oldHost, oldOpen
	})
	runtimeGOOS = "darwin"
	home := t.TempDir()
	paths := platform.PathsForHome(home)
	finished := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
	record, err := audit.Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, audit.Run{
		ID: "run:hex:0123456789abcdef0123456789abcdef", ScanID: "scan:sha256:" + strings.Repeat("a", 64), DeviceID: "device:sha256:" + strings.Repeat("b", 64), Label: "audit mac", Product: "ssc-init", Version: "dev", StartedAt: finished.Add(-time.Second), FinishedAt: finished,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := audit.Encode(record, []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "audit.zip")
	if err := os.WriteFile(external, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	hostCalls, storeCalls := 0, 0
	hostPathsForRun = func() (string, platform.Paths, bool) {
		hostCalls++
		return home, paths, true
	}
	openStoreForRun = func(string) (applicationStore, error) {
		storeCalls++
		return nil, errors.New("store must remain closed")
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO(context.Background(), []string{"audit", "verify", external, "--pretty"}, &stdout, &stderr); code != 0 || hostCalls != 0 || storeCalls != 0 || strings.Contains(stdout.String(), external) {
		t.Fatalf("verify code=%d hosts=%d stores=%d out=%q err=%q", code, hostCalls, storeCalls, stdout.String(), stderr.String())
	}
	manager := &audit.Manager{Root: paths.Install().AuditDir, Home: home, Now: func() time.Time { return finished }, Random: strings.NewReader(strings.Repeat("r", 512)), Render: func(audit.Record) ([]byte, error) { return []byte("report\n"), nil }}
	if _, err := manager.Save(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithIO(context.Background(), []string{"status", "--pretty"}, &stdout, &stderr); code != 0 || hostCalls != 1 || storeCalls != 0 || !strings.Contains(stdout.String(), "SSC Init security review") {
		t.Fatalf("status code=%d hosts=%d stores=%d out=%q err=%q", code, hostCalls, storeCalls, stdout.String(), stderr.String())
	}
}

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
		{"install", "--from", "/tmp/ssc-init", "--version", "v0.1.0", "--sha256", strings.Repeat("a", 64), "--json"},
		{"rollback", "--json"},
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
	oldHost, oldOpen, oldDiscover := hostPathsForRun, openStoreForRun, discoverRootsForRun
	t.Cleanup(func() {
		hostPathsForRun = oldHost
		openStoreForRun = oldOpen
		discoverRootsForRun = oldDiscover
	})
	home := t.TempDir()

	for _, testCase := range []struct {
		name     string
		hosts    func() (string, platform.Paths, bool)
		open     func(string) (applicationStore, error)
		discover func(context.Context, collector.Environment) (projects.Discovery, error)
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
			name:  "scan configuration unavailable",
			hosts: func() (string, platform.Paths, bool) { return home, platform.PathsForHome(home), true },
			open: func(string) (applicationStore, error) {
				t.Fatal("hook opened the store without a scan configuration")
				return nil, errors.New("store must not be opened")
			},
			discover: func(context.Context, collector.Environment) (projects.Discovery, error) {
				return projects.Discovery{}, errors.New("project roots unavailable")
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
			discoverRootsForRun = oldDiscover
			if testCase.discover != nil {
				discoverRootsForRun = testCase.discover
			}
			var stdout, stderr bytes.Buffer
			code := runWithIO(context.Background(), []string{"hook"}, &stdout, &stderr)
			wantStderr := "ssc-init hook: baseline scan failed\n"
			if testCase.name == "host paths unavailable" {
				wantStderr += "ssc-init hook: audit evidence unavailable\n"
			}
			if code != 0 || stdout.String() != "" || stderr.String() != wantStderr {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestScanExplicitRootCarriesResolvedScopeAndProjectCollector(t *testing.T) {
	oldDiscover := discoverRootsForRun
	t.Cleanup(func() { discoverRootsForRun = oldDiscover })
	discoverRootsForRun = func(context.Context, collector.Environment) (projects.Discovery, error) {
		t.Fatal("explicit project root invoked automatic discovery")
		return projects.Discovery{}, errors.New("automatic discovery must not run")
	}
	home := t.TempDir()
	external := filepath.Join(filepath.Dir(home), "external-projects")
	options := cli.Options{
		Command: "scan", JSON: true, Baseline: true, ExternalProbes: true,
		ProjectRoots: []string{"$HOME/Projects", external},
	}
	environment, collectors, err := scanConfiguration(context.Background(), home, options)
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
	if environment.Inspector == nil || environment.SignatureInspector == nil {
		t.Fatal("external-probe scan did not construct executable and signature inspectors")
	}
	wantNames := []string{"agents", "ide", "projects", "surfaces", "packages", "runtime"}
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

func TestScanExplicitRootResolutionFailureRemainsUsageError(t *testing.T) {
	oldGOOS, oldParse, oldHost := runtimeGOOS, parseOptionsForRun, hostPathsForRun
	oldResolve, oldDiscover, oldOpen := resolveRootsForRun, discoverRootsForRun, openStoreForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		parseOptionsForRun = oldParse
		hostPathsForRun = oldHost
		resolveRootsForRun = oldResolve
		discoverRootsForRun = oldDiscover
		openStoreForRun = oldOpen
	})
	runtimeGOOS = "darwin"
	parseOptionsForRun = func([]string) (cli.Options, error) {
		return cli.Options{Command: "scan", JSON: true, Baseline: true, ProjectRoots: []string{"invalid-root"}}, nil
	}
	home := t.TempDir()
	hostPathsForRun = func() (string, platform.Paths, bool) {
		return home, platform.PathsForHome(home), true
	}
	resolveRootsForRun = func(string, []string) ([]projects.Root, error) {
		return nil, errors.New("invalid explicit root")
	}
	discoverRootsForRun = func(context.Context, collector.Environment) (projects.Discovery, error) {
		t.Fatal("explicit root failure invoked automatic discovery or its runner")
		return projects.Discovery{}, errors.New("automatic discovery must not run")
	}
	openStoreForRun = func(string) (applicationStore, error) {
		t.Fatal("invalid explicit root opened the store")
		return nil, errors.New("store must not be opened")
	}
	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"ignored-by-injected-parser"}, &stdout, &stderr)
	if code != 2 || stdout.String() != "" || stderr.String() != "invalid command arguments\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestScanConfigurationAutomaticDiscoveryFinalizesScopeAndCoverage(t *testing.T) {
	oldDiscover, oldResolve := discoverRootsForRun, resolveRootsForRun
	t.Cleanup(func() {
		discoverRootsForRun = oldDiscover
		resolveRootsForRun = oldResolve
	})
	home := t.TempDir()
	project := filepath.Join(home, "work", "automatic")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := projects.ResolveRoots(home, []string{project})
	if err != nil {
		t.Fatal(err)
	}
	wantCoverage := model.TargetCoverage{
		TargetID: "projects.discovery.vscode",
		Status:   model.TargetComplete,
	}
	resolveRootsForRun = func(string, []string) ([]projects.Root, error) {
		t.Fatal("automatic discovery invoked explicit root resolution")
		return nil, errors.New("explicit root resolution must not run")
	}
	discoverRootsForRun = func(ctx context.Context, environment collector.Environment) (projects.Discovery, error) {
		if err := ctx.Err(); err != nil {
			return projects.Discovery{}, err
		}
		if environment.Home != home || environment.FS == nil || environment.Runner == nil || environment.Now == nil {
			t.Fatalf("incomplete discovery environment=%+v", environment)
		}
		if len(environment.Scope.ProjectRoots) != 0 {
			t.Fatalf("scope finalized before discovery: %+v", environment.Scope)
		}
		return projects.Discovery{Roots: roots, Coverage: []model.TargetCoverage{wantCoverage}}, nil
	}

	environment, collectors, err := scanConfiguration(context.Background(), home, cli.Options{Command: "scan", JSON: true, Baseline: true})
	if err != nil {
		t.Fatal(err)
	}
	wantScope := model.ScanScope{
		Platform: runtime.GOOS, CatalogVersion: collector.CatalogVersion,
		ProjectRoots: []string{"$HOME/work/automatic"},
	}
	if !reflect.DeepEqual(environment.Scope, wantScope) {
		t.Fatalf("scope=%+v want=%+v", environment.Scope, wantScope)
	}
	result, err := collectors[2].Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) < 1 || !reflect.DeepEqual(result.Targets[0], wantCoverage) {
		t.Fatalf("project targets=%+v want discovery first=%+v", result.Targets, wantCoverage)
	}
}

func TestScanAutomaticDiscoveryCancellationDoesNotOpenStore(t *testing.T) {
	oldGOOS, oldParse, oldHost := runtimeGOOS, parseOptionsForRun, hostPathsForRun
	oldDiscover, oldOpen := discoverRootsForRun, openStoreForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		parseOptionsForRun = oldParse
		hostPathsForRun = oldHost
		discoverRootsForRun = oldDiscover
		openStoreForRun = oldOpen
	})
	runtimeGOOS = "darwin"
	parseOptionsForRun = func([]string) (cli.Options, error) {
		return cli.Options{Command: "scan", JSON: true, Baseline: true}, nil
	}
	home := t.TempDir()
	hostPathsForRun = func() (string, platform.Paths, bool) {
		return home, platform.PathsForHome(home), true
	}
	discoverRootsForRun = func(ctx context.Context, _ collector.Environment) (projects.Discovery, error) {
		return projects.Discovery{}, ctx.Err()
	}
	openStoreForRun = func(string) (applicationStore, error) {
		t.Fatal("canceled discovery opened the store")
		return nil, errors.New("store must not be opened")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := runWithIO(ctx, []string{"ignored-by-injected-parser"}, &stdout, &stderr)
	if code != 1 || stdout.String() != "" || stderr.String() != "failed to initialize SSC Init\naudit evidence unavailable\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestScanAutomaticDiscoveryOperationalFailureDoesNotOpenStore(t *testing.T) {
	oldGOOS, oldParse, oldHost := runtimeGOOS, parseOptionsForRun, hostPathsForRun
	oldDiscover, oldOpen := discoverRootsForRun, openStoreForRun
	t.Cleanup(func() {
		runtimeGOOS = oldGOOS
		parseOptionsForRun = oldParse
		hostPathsForRun = oldHost
		discoverRootsForRun = oldDiscover
		openStoreForRun = oldOpen
	})
	runtimeGOOS = "darwin"
	parseOptionsForRun = func([]string) (cli.Options, error) {
		return cli.Options{Command: "scan", JSON: true, Baseline: true}, nil
	}
	home := t.TempDir()
	hostPathsForRun = func() (string, platform.Paths, bool) {
		return home, platform.PathsForHome(home), true
	}
	discoverRootsForRun = func(context.Context, collector.Environment) (projects.Discovery, error) {
		return projects.Discovery{}, errors.New("metadata unavailable")
	}
	openStoreForRun = func(string) (applicationStore, error) {
		t.Fatal("failed discovery opened the store")
		return nil, errors.New("store must not be opened")
	}
	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"ignored-by-injected-parser"}, &stdout, &stderr)
	if code != 1 || stdout.String() != "" || stderr.String() != "failed to initialize SSC Init\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestScanConfigurationLeavesInspectorUnwiredWhenExternalProbesAreDisabled(t *testing.T) {
	environment, _, err := scanConfiguration(context.Background(), t.TempDir(), cli.Options{Command: "scan", JSON: true, Baseline: true})
	if err != nil {
		t.Fatal(err)
	}
	if environment.Scope.ExternalProbes || environment.Inspector != nil || environment.SignatureInspector != nil {
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

// installHome is a resolved temporary home; macOS temp directories live under
// the /var -> /private/var symlink.
func installHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home
}

// universalCore builds a minimal fat Mach-O carrying one arm64 and one x86_64
// slice. It is a valid shape rather than runnable code, which is exactly what a
// health-check failure needs: staging accepts it and exec refuses it.
func universalCore() []byte {
	const sliceSize = 4096
	cpuTypes := []uint32{0x0100000c, 0x01000007}
	image := make([]byte, sliceSize*(len(cpuTypes)+1))
	binary.BigEndian.PutUint32(image[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(image[4:], uint32(len(cpuTypes)))
	for index, cpuType := range cpuTypes {
		entry := image[8+20*index:]
		offset := sliceSize * (index + 1)
		binary.BigEndian.PutUint32(entry[0:], cpuType)
		binary.BigEndian.PutUint32(entry[8:], uint32(offset))
		binary.BigEndian.PutUint32(entry[12:], sliceSize)
		binary.BigEndian.PutUint32(entry[16:], 12)
		binary.LittleEndian.PutUint32(image[offset:], 0xfeedfacf)
		image[offset+sliceSize-1] = byte(index + 1)
	}
	return image
}

func writeCoreSource(t *testing.T, content []byte) (string, string) {
	t.Helper()
	source := filepath.Join(t.TempDir(), "ssc-init-darwin-universal")
	if err := os.WriteFile(source, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return source, hex.EncodeToString(sum[:])
}

func TestInstallRejectsADigestMismatchWithoutStagingAnything(t *testing.T) {
	home := installHome(t)
	source, _ := writeCoreSource(t, universalCore())

	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{
		"install", "--from", source, "--version", "v0.1.0",
		"--sha256", strings.Repeat("a", 64), "--json",
	}, &stdout, &stderr)
	if code != 3 || stdout.String() != "" || stderr.String() != "core verification failed\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	layout := platform.PathsForHome(home).Install()
	for _, absent := range []string{
		filepath.Join(layout.VersionsDir, "v0.1.0"),
		layout.CurrentFile,
		layout.StateDatabase,
	} {
		if _, err := os.Lstat(absent); !os.IsNotExist(err) {
			t.Fatalf("failed install left %s behind: %v", filepath.Base(absent), err)
		}
	}
}

// The staged core is a valid universal shape that cannot execute, so the real
// health check — which runs the freshly hashed binary's own doctor — fails. The
// version stays installed for a retry and no version becomes active.
func TestInstallKeepsNoVersionActiveWhenTheStagedCoreFailsItsHealthCheck(t *testing.T) {
	home := installHome(t)
	source, digest := writeCoreSource(t, universalCore())

	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{
		"install", "--from", source, "--version", "v0.1.0", "--sha256", digest, "--json",
	}, &stdout, &stderr)
	if code != 4 || stdout.String() != "" || stderr.String() != "staged core failed its health check\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	layout := platform.PathsForHome(home).Install()
	if _, err := os.Stat(filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)); err != nil {
		t.Fatalf("a health-check failure discarded the staged version: %v", err)
	}
	if _, err := os.Lstat(layout.CurrentFile); !os.IsNotExist(err) {
		t.Fatalf("a core that failed its health check became active: %v", err)
	}
}

// The install lock is advisory and cross-process, so contention is a distinct,
// retryable outcome rather than a generic failure.
func TestInstallCommandsReportABusyInstallRootWithTheirOwnExitCode(t *testing.T) {
	home := installHome(t)
	layout := platform.PathsForHome(home).Install()
	if err := os.MkdirAll(layout.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	guard, err := os.OpenFile(filepath.Join(layout.Root, ".lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"rollback", "--json"}, &stdout, &stderr)
	if code != 5 || stdout.String() != "" || stderr.String() != "another installation is already in progress\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRollbackWithoutAnInstallFailsWithoutCreatingState(t *testing.T) {
	home := installHome(t)
	var stdout, stderr bytes.Buffer
	code := runWithIO(context.Background(), []string{"rollback", "--json"}, &stdout, &stderr)
	if code != 1 || stdout.String() != "" || stderr.String() != "rollback failed\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(platform.PathsForHome(home).Install().StateDatabase); !os.IsNotExist(err) {
		t.Fatalf("rollback created shared state: %v", err)
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
