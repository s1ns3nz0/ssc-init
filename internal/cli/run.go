package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

// BaselineScanner performs and persists one baseline scan.
type BaselineScanner interface {
	Baseline(context.Context) (model.ScanResult, model.Inventory, model.Delta, error)
}

// StatusReader loads the latest persisted scan and inventory, if one exists.
type StatusReader interface {
	LatestSnapshot(context.Context) (model.Snapshot, bool, error)
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
	options, err := ParseOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	return a.RunOptions(ctx, options, stdout, stderr)
}

// RunOptions executes one command that has already passed ParseOptions.
func (a App) RunOptions(ctx context.Context, options Options, stdout, stderr io.Writer) int {
	switch options.Command {
	case "version":
		if err := writeJSON(stdout, map[string]string{
			"product": "SSC Init",
			"command": "ssc-init",
			"version": a.Version,
		}); err != nil {
			fmt.Fprintln(stderr, "failed to write version output")
			return 1
		}
		return 0
	case "scan":
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
	case "status":
		if a.StatusReader == nil {
			fmt.Fprintln(stderr, "status is unavailable")
			return 1
		}
		snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "failed to read status")
			return 1
		}
		status := statusPayload{SchemaVersion: "ssc-init.status.v3", Initialized: initialized}
		if initialized {
			status.InventorySchemaVersion = snapshot.Scan.SchemaVersion
			status.Inventory = &snapshot.Inventory
			if snapshot.Scan.SchemaVersion == "ssc-init.scan.v3" {
				scope := snapshot.Scan.Scope
				status.Scope = &scope
				status.Coverage = snapshot.Scan.Coverage
				evidenceCoverage := snapshot.Scan.EvidenceCoverage
				status.EvidenceCoverage = &evidenceCoverage
			} else {
				// v1/v2 snapshots predate content evidence. They keep their
				// persisted inventory but never claim scope, coverage, or any
				// evidence coverage they could not have collected.
				status.LegacyInventory = true
			}
		}
		if err := writeJSON(stdout, status); err != nil {
			fmt.Fprintln(stderr, "failed to write status output")
			return 1
		}
		return 0
	case "doctor":
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
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
}

type statusPayload struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Initialized            bool                    `json:"initialized"`
	InventorySchemaVersion string                  `json:"inventorySchemaVersion,omitempty"`
	LegacyInventory        bool                    `json:"legacyInventory,omitempty"`
	Scope                  *model.ScanScope        `json:"scope,omitempty"`
	Coverage               []model.CollectorResult `json:"coverage,omitempty"`
	EvidenceCoverage       *model.EvidenceCoverage `json:"evidenceCoverage,omitempty"`
	Inventory              *model.Inventory        `json:"inventory,omitempty"`
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
