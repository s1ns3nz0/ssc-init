package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// App holds CLI configuration.
type App struct {
	Version string
}

// Run executes the CLI with the development version.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return (App{Version: "dev"}).Run(ctx, args, stdout, stderr)
}

// Run executes the CLI command represented by args.
func (a App) Run(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		_ = json.NewEncoder(stdout).Encode(map[string]string{
			"product": "SSC Init",
			"command": "ssc-init",
			"version": a.Version,
		})
		return 0
	}

	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	fmt.Fprintf(stderr, "unknown command: %s\n", command)
	return 2
}
