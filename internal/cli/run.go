package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ssc-init/ssc-init/internal/doctor"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/report"
)

// BaselineScanner performs and persists one baseline scan.
type BaselineScanner interface {
	Baseline(context.Context) (model.ScanResult, model.Inventory, model.Delta, error)
}

// StatusReader loads the latest persisted inventory, if one exists.
type StatusReader interface {
	LatestInventory(context.Context) (model.Inventory, bool, error)
}

// Doctor performs read-only runtime diagnostics.
type Doctor interface {
	Check(context.Context) doctor.Result
}

// App holds CLI configuration.
type App struct {
	Version         string
	BaselineScanner BaselineScanner
	StatusReader    StatusReader
	Doctor          Doctor
}

// Run executes the CLI with the development version.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return (App{Version: "dev"}).Run(ctx, args, stdout, stderr)
}

// Run executes the CLI command represented by args.
func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		if err := writeJSON(stdout, map[string]string{
			"product": "SSC Init",
			"command": "ssc-init",
			"version": a.Version,
		}); err != nil {
			fmt.Fprintln(stderr, "failed to write version output")
			return 1
		}
		return 0
	}
	if len(args) == 3 && args[0] == "scan" && args[1] == "--baseline" && args[2] == "--json" {
		if a.BaselineScanner == nil {
			fmt.Fprintln(stderr, "baseline scan is unavailable")
			return 1
		}
		scan, inventory, delta, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "baseline scan failed")
			return 1
		}
		if err := report.WriteJSON(stdout, scan, inventory, delta); err != nil {
			fmt.Fprintln(stderr, "failed to write baseline output")
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "status" && args[1] == "--json" {
		if a.StatusReader == nil {
			fmt.Fprintln(stderr, "status is unavailable")
			return 1
		}
		inventory, initialized, err := a.StatusReader.LatestInventory(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "failed to read status")
			return 1
		}
		status := statusPayload{SchemaVersion: "ssc-init.status.v1", Initialized: initialized}
		if initialized {
			status.Inventory = &inventory
		}
		if err := writeJSON(stdout, status); err != nil {
			fmt.Fprintln(stderr, "failed to write status output")
			return 1
		}
		return 0
	}
	if len(args) == 2 && args[0] == "doctor" && args[1] == "--json" {
		if a.Doctor == nil {
			fmt.Fprintln(stderr, "doctor is unavailable")
			return 1
		}
		result := a.Doctor.Check(ctx)
		if result.Fatal {
			fmt.Fprintln(stderr, "doctor check failed")
			return 1
		}
		if err := writeJSON(stdout, result); err != nil {
			fmt.Fprintln(stderr, "failed to write doctor output")
			return 1
		}
		return 0
	}

	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	fmt.Fprintf(stderr, "unknown command: %s\n", command)
	return 2
}

// statusPayload deliberately reports inventory initialization only. The
// SnapshotStore does not expose the status of the scan that created it.
type statusPayload struct {
	SchemaVersion string           `json:"schemaVersion"`
	Initialized   bool             `json:"initialized"`
	Inventory     *model.Inventory `json:"inventory,omitempty"`
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
