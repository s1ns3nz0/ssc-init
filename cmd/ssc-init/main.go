package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/ssc-init/ssc-init/internal/cli"
	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/agents"
	"github.com/ssc-init/ssc-init/internal/collector/ide"
	"github.com/ssc-init/ssc-init/internal/collector/packages"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/doctor"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/scan"
	"github.com/ssc-init/ssc-init/internal/store"
)

var version = "dev"

type applicationStore interface {
	scan.SnapshotStore
	Close() error
}

var (
	parseOptionsForRun = cli.ParseOptions
	hostPathsForRun    = hostPaths
	resolveRootsForRun = projects.ResolveRoots
	openStoreForRun    = func(path string) (applicationStore, error) { return store.Open(path) }
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
	app := cli.App{Version: version}
	switch options.Command {
	case "version":
		return app.RunOptions(ctx, options, stdout, stderr)
	case "doctor":
		_, paths, ok := hostPathsForRun()
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
		return app.RunOptions(ctx, options, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
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
	configuredCollectors := []collector.Collector{
		agents.New(),
		ide.New(),
		projects.New(roots),
		packages.New(),
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
