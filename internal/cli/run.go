package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

// BaselineScanner performs and persists one baseline scan. The reported bool
// is true when no previous snapshot existed, which only the scanner knows.
type BaselineScanner interface {
	Baseline(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error)
}

// StatusReader loads the latest persisted scan and inventory, if one exists.
type StatusReader interface {
	LatestSnapshot(context.Context) (model.Snapshot, bool, error)
}

type PolicyStore interface {
	Pins(context.Context) ([]policy.Pin, error)
	SavePins(context.Context, []policy.Pin, time.Time) error
	Exceptions(context.Context) ([]policy.Exception, error)
	RecordDecisions(context.Context, []policy.Violation, time.Time) error
	Decisions(context.Context) ([]policy.Decision, error)
}

// Doctor performs read-only runtime diagnostics.
type Doctor interface {
	Check(context.Context) doctor.Result
}

// InstallOutcome is the state of the shared installation after one install or
// rollback: version strings and booleans only, never a path.
type InstallOutcome struct {
	Version           string
	PreviousVersion   string
	RollbackAvailable bool
}

// Installer stages, verifies, health-checks, and activates core versions
// (design §5.3, §11). Install composes staging and activation in one call
// deliberately: staging a second version before the first is switched to would
// leave the un-activated one to be pruned, and one command makes that
// unreachable.
type Installer interface {
	Install(ctx context.Context, sourcePath, version, digest string) (InstallOutcome, error)
	Rollback(ctx context.Context) (InstallOutcome, error)
}

// Install and rollback failure sentinels. They are the classification an
// adapter acts on; the messages below are the only thing ever printed, so no
// supplied path, version, or digest can be echoed back.
var (
	// ErrInstallVerification reports a core refused by digest, universal-binary,
	// or manifest verification. Nothing was activated.
	ErrInstallVerification = errors.New("core verification failed")
	// ErrInstallHealth reports a staged core that failed its health check. The
	// version that was already active stays active.
	ErrInstallHealth = errors.New("staged core failed its health check")
	// ErrInstallBusy reports another process holding the install lock. The
	// command did nothing and is safe to retry.
	ErrInstallBusy = errors.New("another installation is already in progress")
)

// Install and rollback exit codes, which are part of the command contract: an
// adapter tells "these bytes are bad" (3) from "the new core is bad" (4) from
// "someone else is installing right now" (5) without parsing any message. 0 is
// success, 1 is any other failure, and 2 stays the usage error every command
// shares.
const (
	exitInstallVerification = 3
	exitInstallHealth       = 4
	exitInstallBusy         = 5
)

// App holds CLI configuration.
type App struct {
	Version         string
	BaselineScanner BaselineScanner
	StatusReader    StatusReader
	Doctor          Doctor
	Installer       Installer
	Home            string
	PolicyPath      string
	PolicyStore     PolicyStore
	PolicySources   policy.Sources
	PolicyDocument  policy.Document
	PolicyLoadError error
	Now             func() time.Time
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
		scan, inventory, delta, _, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "baseline scan failed")
			return 1
		}
		if options.Pretty {
			if err := report.WritePretty(stdout, scan, inventory, delta); err != nil {
				fmt.Fprintln(stderr, "failed to write baseline output")
				return 1
			}
			return 0
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
		status := statusPayload{SchemaVersion: "ssc-init.status.v5", Initialized: initialized}
		if initialized {
			status.InventorySchemaVersion = snapshot.Scan.SchemaVersion
			status.Inventory = &snapshot.Inventory
			if snapshot.Scan.SchemaVersion == "ssc-init.scan.v5" {
				scope := snapshot.Scan.Scope
				status.Scope = &scope
				status.Coverage = snapshot.Scan.Coverage
				evidenceCoverage := snapshot.Scan.EvidenceCoverage
				status.EvidenceCoverage = &evidenceCoverage
			} else {
				// Earlier snapshots predate the complete v4 external-fact contract. They keep their
				// persisted inventory but never claim scope, coverage, or any
				// evidence coverage they could not have collected.
				status.LegacyInventory = true
			}
		}
		if options.Pretty {
			err := report.WriteStatusPretty(stdout, report.StatusData{
				Initialized:            status.Initialized,
				LegacyInventory:        status.LegacyInventory,
				InventorySchemaVersion: status.InventorySchemaVersion,
				Scope:                  status.Scope,
				Coverage:               status.Coverage,
				EvidenceCoverage:       status.EvidenceCoverage,
				Inventory:              status.Inventory,
			})
			if err != nil {
				fmt.Fprintln(stderr, "failed to write status output")
				return 1
			}
			return 0
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
	case "install", "rollback":
		if a.Installer == nil {
			fmt.Fprintln(stderr, options.Command+" is unavailable")
			return 1
		}
		var outcome InstallOutcome
		var err error
		if options.Command == "install" {
			outcome, err = a.Installer.Install(ctx, options.InstallSource, options.InstallVersion, options.InstallDigest)
		} else {
			outcome, err = a.Installer.Rollback(ctx)
		}
		if err != nil {
			switch {
			case errors.Is(err, ErrInstallBusy):
				fmt.Fprintln(stderr, ErrInstallBusy.Error())
				return exitInstallBusy
			case errors.Is(err, ErrInstallHealth):
				fmt.Fprintln(stderr, ErrInstallHealth.Error())
				return exitInstallHealth
			case errors.Is(err, ErrInstallVerification):
				fmt.Fprintln(stderr, ErrInstallVerification.Error())
				return exitInstallVerification
			}
			fmt.Fprintln(stderr, options.Command+" failed")
			return 1
		}
		if err := writeJSON(stdout, installPayload{
			SchemaVersion:     "ssc-init.install.v1",
			Command:           options.Command,
			Version:           outcome.Version,
			PreviousVersion:   outcome.PreviousVersion,
			RollbackAvailable: outcome.RollbackAvailable,
		}); err != nil {
			fmt.Fprintln(stderr, "failed to write "+options.Command+" output")
			return 1
		}
		return 0
	case "policy":
		if options.PolicyCommand == "pin" {
			return a.runPolicyPin(ctx, options, stdout, stderr)
		}
		if options.PolicyCommand == "check" {
			return a.runPolicyCheck(ctx, options, stdout, stderr)
		}
		if options.PolicyCommand != "init" {
			fmt.Fprintln(stderr, "invalid command arguments")
			return 2
		}
		path := a.PolicyPath
		if options.PolicyPath != "" {
			path = options.PolicyPath
			if strings.HasPrefix(path, "$HOME/") {
				path = filepath.Join(a.Home, strings.TrimPrefix(path, "$HOME/"))
			}
		}
		if path == "" || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
			fmt.Fprintln(stderr, "failed to initialize policy")
			return 1
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "policy document already exists or cannot be created")
			return 1
		}
		writeErr := func() error {
			defer file.Close()
			_, err := file.Write(policy.Starter())
			return err
		}()
		if writeErr != nil {
			_ = os.Remove(path)
			fmt.Fprintln(stderr, "failed to write policy document")
			return 1
		}
		fmt.Fprintf(stdout, "ssc-init: wrote policy to %s\n", platform.SafeLocationRef(a.Home, path, "policy"))
		return 0
	case "hook":
		if a.BaselineScanner == nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		_, inventory, delta, firstRun, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		var policyResult policy.Result
		if a.PolicyLoadError != nil {
			fmt.Fprintln(stderr, "ssc-init hook: policy document could not be loaded")
		} else if a.PolicyStore != nil {
			policyResult, err = a.evaluatePolicy(ctx, inventory, delta)
			if err != nil {
				fmt.Fprintln(stderr, "ssc-init hook: policy evaluation failed")
				policyResult = policy.Result{}
			}
		}
		if err := report.WriteHookSummary(stdout, inventory, delta, firstRun, policyResult); err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		return 0
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
}

func (a App) evaluatePolicy(ctx context.Context, inventory model.Inventory, delta model.Delta) (policy.Result, error) {
	pins, err := a.PolicyStore.Pins(ctx)
	if err != nil {
		return policy.Result{}, err
	}
	exceptions, err := a.PolicyStore.Exceptions(ctx)
	if err != nil {
		return policy.Result{}, err
	}
	decisions, err := a.PolicyStore.Decisions(ctx)
	if err != nil {
		return policy.Result{}, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	sources := a.PolicySources
	sources.Document = a.PolicyDocument
	if err := policy.VerifyExceptions(sources.Document, sources.Intelligence, now); err != nil {
		return policy.Result{}, err
	}
	result := policy.Evaluate(policy.Input{Sources: sources, Inventory: inventory, Delta: delta, Pins: pins, Exceptions: exceptions, Now: now})
	standing := map[string]bool{}
	for _, decision := range decisions {
		standing[decision.RuleID+"\x00"+decision.AssetID] = true
	}
	for index := range result.Violations {
		result.Violations[index].Standing = standing[result.Violations[index].RuleID+"\x00"+result.Violations[index].AssetID]
	}
	if err := a.PolicyStore.RecordDecisions(ctx, result.Violations, now); err != nil {
		return policy.Result{}, err
	}
	return result, nil
}

func (a App) runPolicyPin(ctx context.Context, options Options, stdout, stderr io.Writer) int {
	if a.PolicySources.Bundle != nil {
		fmt.Fprintln(stderr, "pins are authored in the organization bundle")
		return 1
	}
	if a.StatusReader == nil || a.PolicyStore == nil {
		fmt.Fprintln(stderr, "policy state is unavailable")
		return 1
	}
	snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
	if err != nil || !initialized {
		fmt.Fprintln(stderr, "latest snapshot is unavailable")
		return 1
	}
	assetExists := map[string]bool{}
	for _, asset := range snapshot.Inventory.Assets {
		assetExists[asset.ID] = true
	}
	if options.PolicyAssetID != "" && !assetExists[options.PolicyAssetID] {
		fmt.Fprintln(stderr, "requested asset is not present in the latest snapshot")
		return 1
	}
	observationAssets := map[string]string{}
	for _, observation := range snapshot.Inventory.Observations {
		observationAssets[observation.ID] = observation.AssetID
	}
	pins := []policy.Pin{}
	for _, evidence := range snapshot.Inventory.Evidence {
		if evidence.Status != model.EvidenceComplete || evidence.Digest == "" {
			continue
		}
		assetID := evidence.AssetID
		if assetID == "" {
			assetID = observationAssets[evidence.ObservationID]
		}
		if options.PolicyAssetID != "" && assetID != options.PolicyAssetID {
			continue
		}
		pins = append(pins, policy.Pin{AssetID: assetID, Kind: string(evidence.Kind), Subject: evidence.Subject, Digest: evidence.Digest})
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if err := a.PolicyStore.SavePins(ctx, pins, now); err != nil {
		fmt.Fprintln(stderr, "failed to save policy pins")
		return 1
	}
	fmt.Fprintln(stdout, "ssc-init: pinning records what is on this machine now.")
	fmt.Fprintln(stdout, "  A pin protects against future change, not against what is already there —")
	fmt.Fprintln(stdout, "  pinning a compromised machine approves the compromise.")
	fmt.Fprintf(stdout, "  pinned %d evidence subjects\n", len(pins))
	return 0
}

type policyCheckPayload struct {
	SchemaVersion string             `json:"schemaVersion"`
	Capability    string             `json:"capability"`
	Levels        []policy.Level     `json:"levels"`
	Snapshot      policySnapshotRef  `json:"snapshot"`
	Violations    []policy.Violation `json:"violations"`
	Applied       []policy.Applied   `json:"exceptionsApplied,omitempty"`
	Expired       []policy.Applied   `json:"exceptionsExpired,omitempty"`
}

type policySnapshotRef struct {
	ScanID     string    `json:"scanId"`
	FinishedAt time.Time `json:"finishedAt"`
}

func (a App) runPolicyCheck(ctx context.Context, options Options, stdout, stderr io.Writer) int {
	if a.PolicyLoadError != nil {
		fmt.Fprintf(stderr, "invalid policy document: %v\n", a.PolicyLoadError)
		return 2
	}
	if a.StatusReader == nil || a.PolicyStore == nil {
		fmt.Fprintln(stderr, "policy state is unavailable")
		return 1
	}
	snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
	if err != nil || !initialized {
		fmt.Fprintln(stderr, "latest snapshot is unavailable")
		return 1
	}
	pins, err := a.PolicyStore.Pins(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "failed to read policy pins")
		return 1
	}
	exceptions, err := a.PolicyStore.Exceptions(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "failed to read policy exceptions")
		return 1
	}
	decisions, err := a.PolicyStore.Decisions(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "failed to read policy decisions")
		return 1
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	sources := a.PolicySources
	sources.Document = a.PolicyDocument
	if err := policy.VerifyExceptions(sources.Document, sources.Intelligence, now); err != nil {
		fmt.Fprintf(stderr, "invalid policy document: %v\n", err)
		return 2
	}
	result := policy.Evaluate(policy.Input{Sources: sources, Inventory: snapshot.Inventory, Pins: pins, Exceptions: exceptions, Now: now})
	standing := map[string]bool{}
	for _, decision := range decisions {
		standing[decision.RuleID+"\x00"+decision.AssetID] = true
	}
	for index := range result.Violations {
		result.Violations[index].Standing = standing[result.Violations[index].RuleID+"\x00"+result.Violations[index].AssetID]
	}
	if err := a.PolicyStore.RecordDecisions(ctx, result.Violations, now); err != nil {
		fmt.Fprintln(stderr, "failed to record policy decisions")
		return 1
	}
	payload := policyCheckPayload{SchemaVersion: "ssc-init.policy-check.v1", Capability: "advisory", Levels: result.Levels,
		Snapshot: policySnapshotRef{ScanID: snapshot.Scan.ScanID, FinishedAt: snapshot.Scan.FinishedAt}, Violations: result.Violations,
		Applied: result.Applied, Expired: result.Expired}
	if options.Pretty {
		if err := report.WritePolicy(stdout, result); err != nil {
			fmt.Fprintln(stderr, "failed to write policy output")
			return 1
		}
	} else if err := writeJSON(stdout, payload); err != nil {
		fmt.Fprintln(stderr, "failed to write policy output")
		return 1
	}
	if len(result.Violations) > 0 {
		return 3
	}
	return 0
}

// installPayload is the ssc-init.install.v1 contract. Its shape is fixed —
// every field is always present — and it carries no path: an absent rollback
// target is an empty version string with rollbackAvailable false.
type installPayload struct {
	SchemaVersion     string `json:"schemaVersion"`
	Command           string `json:"command"`
	Version           string `json:"version"`
	PreviousVersion   string `json:"previousVersion"`
	RollbackAvailable bool   `json:"rollbackAvailable"`
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
