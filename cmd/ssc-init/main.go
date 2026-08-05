package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ssc-init/ssc-init/internal/cli"
	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/agents"
	"github.com/ssc-init/ssc-init/internal/collector/ide"
	"github.com/ssc-init/ssc-init/internal/collector/packages"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/doctor"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/scan"
	"github.com/ssc-init/ssc-init/internal/store"
)

var version = "dev"

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	app := cli.App{Version: version}
	if exactArgs(args, "doctor", "--json") {
		_, paths, ok := hostPaths()
		if !ok {
			fmt.Fprintln(os.Stderr, "failed to initialize SSC Init")
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
		return app.Run(ctx, args, os.Stdout, os.Stderr)
	}
	if exactArgs(args, "scan", "--baseline", "--json") || exactArgs(args, "status", "--json") {
		home, paths, ok := hostPaths()
		if !ok {
			fmt.Fprintln(os.Stderr, "failed to initialize SSC Init")
			return 1
		}
		snapshots, err := store.Open(filepath.Join(paths.DataDir, "state.db"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to initialize SSC Init")
			return 1
		}
		defer snapshots.Close()

		environment := collector.Environment{
			Home: home,
			FS:   platform.OSFileSystem{},
			Runner: platform.ExecRunner{
				Timeout:        5 * time.Second,
				MaxOutputBytes: 4 << 20,
			},
			Now: func() time.Time { return time.Now().UTC() },
		}
		orchestrator := collector.Orchestrator{
			Timeout:       30 * time.Second,
			MaxConcurrent: 4,
			Collectors: []collector.Collector{
				agents.New(),
				ide.New(),
				projects.New([]string{"$HOME/Projects"}),
				packages.New(),
			},
		}
		app.StatusReader = snapshots
		app.BaselineScanner = scan.NewService(orchestrator, snapshots, environment.Now, nil, environment)
	}
	return app.Run(ctx, args, os.Stdout, os.Stderr)
}

func hostPaths() (string, platform.Paths, bool) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", platform.Paths{}, false
	}
	return home, platform.PathsForHome(home), true
}

func exactArgs(args []string, want ...string) bool {
	if len(args) != len(want) {
		return false
	}
	for index := range want {
		if args[index] != want[index] {
			return false
		}
	}
	return true
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
