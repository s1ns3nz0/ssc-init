package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	runtimecollector "github.com/s1ns3nz0/ssc-init/internal/collector/runtime"
	"github.com/s1ns3nz0/ssc-init/internal/collector/surfaces"
	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/install"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

var version = "dev"

type applicationStore interface {
	scan.SnapshotStore
	Close() error
}

var (
	runtimeGOOS        = runtime.GOOS
	parseOptionsForRun = cli.ParseOptions
	hostPathsForRun    = hostPaths
	resolveRootsForRun = projects.ResolveRoots
	// The local-policy build always opens the store with documented retention
	// defaults. Only a future verified, signed organization bundle may wire
	// store.Options here; local policy is deliberately outside this seam.
	openStoreForRun  = func(path string) (applicationStore, error) { return store.Open(path) }
	bundleKeysForRun = bundle.KeyRegistry{}
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	return runWithIO(ctx, args, os.Stdout, os.Stderr)
}

func runWithIO(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, err := parseOptionsForRun(args)
	if err != nil {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	if operationalCommand(options.Command) && !platform.OperationallySupported(runtimeGOOS) {
		fmt.Fprintln(stderr, "unsupported operating system")
		return 2
	}
	app := cli.App{Version: version}
	switch options.Command {
	case "version":
		return app.RunOptions(ctx, options, stdout, stderr)
	case "doctor":
		home, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		ecosystems, commands := doctorCatalog()
		app.Doctor = doctor.New(doctor.Config{
			Product:          "SSC Init",
			Version:          version,
			Paths:            paths,
			DatabasePath:     filepath.Join(paths.DataDir, "state.db"),
			Ecosystems:       ecosystems,
			OptionalCommands: commands,
			InstallReporter:  func() (doctor.Install, error) { return doctor.InstallReport(home) },
		})
		return app.RunOptions(ctx, options, stdout, stderr)
	case "status":
		_, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		snapshots, err := openStoreForRun(filepath.Join(paths.DataDir, "state.db"))
		if err != nil {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		defer snapshots.Close()
		app.StatusReader = snapshots
		return app.RunOptions(ctx, options, stdout, stderr)
	case "findings":
		home, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		snapshots, err := openStoreForRun(filepath.Join(paths.DataDir, "state.db"))
		if err != nil {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		defer snapshots.Close()
		statusReader, ok := snapshots.(cli.StatusReader)
		if !ok {
			return 1
		}
		managers := make(map[bundle.Family]*bundle.Manager, 2)
		for _, family := range []bundle.Family{bundle.FamilyTI, bundle.FamilyPolicy} {
			layout, layoutErr := bundle.LayoutFor(home, family)
			if layoutErr != nil {
				return 1
			}
			managers[family] = &bundle.Manager{Layout: layout, Family: family, Verifier: bundle.Verifier{Keys: bundleKeysForRun}, Now: func() time.Time { return time.Now().UTC() }}
		}
		app.StatusReader = statusReader
		app.FindingService = finding.Service{TI: managers[bundle.FamilyTI], Policy: managers[bundle.FamilyPolicy], Now: time.Now}
		return app.RunOptions(ctx, options, stdout, stderr)
	case "scan":
		home, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		environment, configuredCollectors, err := scanConfiguration(home, options)
		if err != nil {
			fmt.Fprintln(stderr, "invalid command arguments")
			return 2
		}
		snapshots, err := openStoreForRun(filepath.Join(paths.DataDir, "state.db"))
		if err != nil {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		defer snapshots.Close()

		orchestrator := collector.Orchestrator{
			Timeout:       30 * time.Second,
			MaxConcurrent: 4,
			Collectors:    configuredCollectors,
		}
		app.BaselineScanner = scan.NewService(orchestrator, snapshots, environment.Now, nil, environment)
		policyContents, policyErr := os.ReadFile(paths.Install().PolicyFile)
		if policyErr == nil {
			app.PolicyDocument, app.PolicyLoadError = policy.Load(policyContents)
			if app.PolicyLoadError == nil {
				if policyStore, ok := snapshots.(cli.PolicyStore); ok {
					app.PolicyStore = policyStore
					app.Now = environment.Now
				} else {
					app.PolicyLoadError = errors.New("policy state is unavailable")
				}
			}
		} else if !errors.Is(policyErr, os.ErrNotExist) {
			app.PolicyLoadError = errors.New("policy document is unavailable")
		}
		return app.RunOptions(ctx, options, stdout, stderr)
	case "install", "rollback":
		home, _, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		manager := install.New(home)
		manager.Health = coreHealthCheck
		app.Installer = coreInstaller{manager: manager}
		return app.RunOptions(ctx, options, stdout, stderr)
	case "policy":
		home, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		app.Home = home
		app.PolicyPath = paths.Install().PolicyFile
		if options.PolicyCommand == "check" {
			policyPath := app.PolicyPath
			if options.PolicyPath != "" {
				policyPath = options.PolicyPath
				if strings.HasPrefix(policyPath, "$HOME/") {
					policyPath = filepath.Join(home, strings.TrimPrefix(policyPath, "$HOME/"))
				}
			}
			contents, err := os.ReadFile(policyPath)
			if err != nil {
				fmt.Fprintln(stderr, "failed to load policy document")
				return 1
			}
			app.PolicyDocument, app.PolicyLoadError = policy.Load(contents)
			if app.PolicyLoadError != nil {
				return app.RunOptions(ctx, options, stdout, stderr)
			}
		}
		if options.PolicyCommand == "pin" || options.PolicyCommand == "check" {
			snapshots, err := openStoreForRun(filepath.Join(paths.DataDir, "state.db"))
			if err != nil {
				fmt.Fprintln(stderr, "failed to initialize SSC Init")
				return 1
			}
			defer snapshots.Close()
			policyStore, ok := snapshots.(cli.PolicyStore)
			if !ok {
				fmt.Fprintln(stderr, "failed to initialize SSC Init")
				return 1
			}
			app.StatusReader = snapshots
			app.PolicyStore = policyStore
			app.Now = time.Now
		}
		return app.RunOptions(ctx, options, stdout, stderr)
	case "bundle":
		home, _, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "failed to initialize SSC Init")
			return 1
		}
		app.BundleManagers = make(map[bundle.Family]cli.BundleManager, 2)
		for _, family := range []bundle.Family{bundle.FamilyTI, bundle.FamilyPolicy} {
			layout, err := bundle.LayoutFor(home, family)
			if err != nil {
				fmt.Fprintln(stderr, "failed to initialize SSC Init")
				return 1
			}
			manager := &bundle.Manager{Layout: layout, Family: family, Verifier: bundle.Verifier{Keys: bundleKeysForRun}, Now: func() time.Time { return time.Now().UTC() }}
			app.BundleManagers[family] = manager
		}
		return app.RunOptions(ctx, options, stdout, stderr)
	case "hook":
		home, paths, ok := hostPathsForRun()
		if !ok {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		environment, configuredCollectors, err := scanConfiguration(home, options)
		if err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		snapshots, err := openStoreForRun(filepath.Join(paths.DataDir, "state.db"))
		if err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		defer snapshots.Close()

		orchestrator := collector.Orchestrator{
			Timeout:       30 * time.Second,
			MaxConcurrent: 4,
			Collectors:    configuredCollectors,
		}
		app.BaselineScanner = scan.NewService(orchestrator, snapshots, environment.Now, nil, environment)
		return app.RunOptions(ctx, options, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
}

const (
	// coreHealthCheckTimeout bounds the one process this product ever starts, so
	// a wedged staged core cannot hang an install.
	coreHealthCheckTimeout = 30 * time.Second
	// maxHealthReportBytes bounds what that process may return before anything
	// parses it. A doctor report is a few kilobytes.
	maxHealthReportBytes = 64 << 10
)

// coreInstaller composes the design §11 update — stage and verify, health
// check, atomic switch — behind the cli.Installer seam. Staging and activation
// are one command on purpose: staging a second version before the first is
// switched to would leave the un-activated one for the next prune, and joining
// them makes that unreachable.
type coreInstaller struct {
	manager install.Manager
}

func (i coreInstaller) Install(ctx context.Context, sourcePath, version, digest string) (cli.InstallOutcome, error) {
	if err := i.manager.Stage(ctx, sourcePath, version, digest); err != nil {
		return cli.InstallOutcome{}, classifyInstallError(err)
	}
	if err := i.manager.Activate(ctx, version); err != nil {
		return cli.InstallOutcome{}, classifyInstallError(err)
	}
	return i.outcome()
}

func (i coreInstaller) Rollback(ctx context.Context) (cli.InstallOutcome, error) {
	if err := i.manager.Rollback(ctx); err != nil {
		return cli.InstallOutcome{}, classifyInstallError(err)
	}
	return i.outcome()
}

// outcome reads the pointers back rather than reporting what was requested, so
// the payload describes the installation as it now is.
func (i coreInstaller) outcome() (cli.InstallOutcome, error) {
	current, installed, err := i.manager.Current()
	if err != nil {
		return cli.InstallOutcome{}, classifyInstallError(err)
	}
	if !installed {
		return cli.InstallOutcome{}, errors.New("no core version is active")
	}
	previous, rollbackAvailable, err := i.manager.Previous()
	if err != nil {
		// The switch already happened. An unreadable rollback target only means
		// rollback is unavailable, which is exactly what the payload reports.
		previous, rollbackAvailable = "", false
	}
	return cli.InstallOutcome{
		Version:           current,
		PreviousVersion:   previous,
		RollbackAvailable: rollbackAvailable,
	}, nil
}

// classifyInstallError maps the install manager's value-free sentinels onto the
// three conditions the command surface reports with their own exit codes.
// Those sentinels are deliberately unexported, so their exact messages are the
// only stable handle; each match below is pinned by a test that provokes the
// real condition rather than the literal. An unrecognised error stays a generic
// failure instead of being reported as a verification result it may not be.
func classifyInstallError(err error) error {
	switch err.Error() {
	case "another installation is already in progress":
		return cli.ErrInstallBusy
	case "staged core failed its health check":
		return cli.ErrInstallHealth
	case "core binary digest does not match the expected digest",
		"core binary is not a macos universal executable",
		"core binary does not provide both required architectures",
		"core binary source cannot be read",
		"core binary source is not a regular file",
		"core binary source exceeds the install size limit",
		"expected core digest is not a sha-256 digest",
		"unsupported core version",
		"requested core version is not installed",
		"installed core has no usable install manifest":
		return cli.ErrInstallVerification
	}
	return err
}

// coreHealthCheck runs the freshly staged core's own `doctor --json` and
// requires a ready installation before that version may become active
// (design §11).
//
// Executing here does not weaken the "default scans execute no process"
// invariant, and that is not left to be re-derived. The executable is not a
// discovered asset: it is the file this tool copied itself and verified against
// the caller-supplied SHA-256 moments earlier. It runs only on an explicit
// `install` or `rollback`, and no scan, hook, status, or doctor path reaches
// this function. The exec is bounded accordingly — argv only so no shell parses
// the path, its own 30s deadline, no stdin, a bounded read of stdout, and an
// environment reduced to HOME and a fixed PATH so the core under test cannot be
// steered by whatever the calling adapter's environment happens to carry.
func coreHealthCheck(ctx context.Context, executablePath string) error {
	ctx, cancel := context.WithTimeout(ctx, coreHealthCheckTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, executablePath, "doctor", "--json")
	command.Stdin = nil
	command.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin"}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return errors.New("staged core cannot be run")
	}
	if err := command.Start(); err != nil {
		return errors.New("staged core cannot be run")
	}
	report, readErr := io.ReadAll(io.LimitReader(stdout, maxHealthReportBytes))
	if waitErr := command.Wait(); waitErr != nil || readErr != nil {
		return errors.New("staged core failed to report its health")
	}
	var result struct {
		SchemaVersion string `json:"schemaVersion"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(report, &result); err != nil {
		return errors.New("staged core produced an unreadable health report")
	}
	if !strings.HasPrefix(result.SchemaVersion, "ssc-init.doctor.") || result.Status != "ready" {
		return errors.New("staged core reported a degraded installation")
	}
	return nil
}

func operationalCommand(command string) bool {
	switch command {
	case "bundle", "doctor", "findings", "hook", "install", "policy", "rollback", "scan", "status":
		return true
	default:
		return false
	}
}

func scanConfiguration(home string, options cli.Options) (collector.Environment, []collector.Collector, error) {
	roots, err := resolveRootsForRun(home, options.ProjectRoots)
	if err != nil {
		return collector.Environment{}, nil, err
	}
	environment := collector.Environment{
		Home:     home,
		Platform: runtime.GOOS,
		Scope: model.ScanScope{
			Platform: runtime.GOOS, CatalogVersion: collector.CatalogVersion,
			ProjectRoots: projects.RootRefs(roots), ExternalProbes: options.ExternalProbes,
		},
		FS: platform.OSFileSystem{},
		Runner: platform.ExecRunner{
			Timeout:        5 * time.Second,
			MaxOutputBytes: 4 << 20,
		},
		Now: func() time.Time { return time.Now().UTC() },
	}
	if options.ExternalProbes {
		environment.Inspector = platform.NewExecutableInspector(16, 64<<20)
		environment.SignatureInspector = platform.NewSignatureInspector(environment.Runner)
	}
	configuredCollectors := []collector.Collector{
		agents.New(),
		ide.New(),
		projects.New(roots),
		surfaces.New(),
		packages.New(),
		runtimecollector.New(),
	}
	return environment, configuredCollectors, nil
}

func hostPaths() (string, platform.Paths, bool) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", platform.Paths{}, false
	}
	return home, platform.PathsForHome(home), true
}

func doctorCatalog() ([]string, []string) {
	ecosystems := []string{"agents", "ide", "mcp", "projects"}
	commands := make([]string, 0)
	for _, capability := range packages.Capabilities() {
		ecosystems = append(ecosystems, capability.Ecosystem)
		commands = append(commands, capability.Executable)
	}
	return uniqueSortedStrings(ecosystems), uniqueSortedStrings(commands)
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
