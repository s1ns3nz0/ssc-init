package cli

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/adapter"
	"github.com/s1ns3nz0/ssc-init/internal/audit"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
	"github.com/s1ns3nz0/ssc-init/internal/quarantine"
	"github.com/s1ns3nz0/ssc-init/internal/report"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/schedule"
	"golang.org/x/sys/unix"
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

type AuditManager interface {
	List(context.Context) ([]audit.Stored, error)
	Open(context.Context, string) (audit.Verified, error)
	Export(context.Context, string, string, bool) (audit.Stored, error)
}

type AuditService interface {
	Complete(context.Context, audit.Run, model.ScanResult, model.Inventory, model.Delta, []model.Finding) audit.Outcome
	Fail(context.Context, audit.Run, audit.Stage, string) audit.Outcome
}

type intelligenceAuditService interface {
	CompleteWithIntelligence(context.Context, audit.Run, model.ScanResult, model.Inventory, model.Delta, []model.Finding, *audit.IntelligenceUpdate) audit.Outcome
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

type BundleManager interface {
	Install(context.Context, string, string) (bundle.Verified, error)
	Status(context.Context) (bundle.Status, error)
	Rollback(context.Context) error
}

type FindingService interface {
	Evaluate(context.Context, model.Inventory) (finding.Result, error)
}

// TIUpdater is deliberately narrower than bundle.Updater so no CLI command can
// supply a repository, URL, credential, or trust root.
type TIUpdater interface {
	Update(context.Context) bundle.UpdateResult
}

type WebhookDeliverer interface {
	Deliver(context.Context, string, []byte) error
}

type QuarantineManager interface {
	Preview(context.Context, model.Inventory, quarantine.Selection) (quarantine.Proposal, error)
	Apply(context.Context, model.Inventory, quarantine.Selection, string) (quarantine.Record, error)
	PreviewRestore(quarantine.Record) (quarantine.Proposal, error)
	ApplyRestore(context.Context, quarantine.Record, string) (quarantine.Record, error)
}

type QuarantineReader interface {
	QuarantineRecords(context.Context) ([]quarantine.Record, error)
}

type ScheduleManager interface {
	Preview() (schedule.Preview, error)
	Install(context.Context) (schedule.Result, error)
	Remove(context.Context) (schedule.Result, error)
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
	Version          string
	Color            bool
	BaselineScanner  BaselineScanner
	StatusReader     StatusReader
	Doctor           Doctor
	Installer        Installer
	Home             string
	PolicyPath       string
	PolicyStore      PolicyStore
	PolicySources    policy.Sources
	PolicyDocument   policy.Document
	PolicyLoadError  error
	Now              func() time.Time
	BundleManagers   map[bundle.Family]BundleManager
	FindingService   FindingService
	TIUpdater        TIUpdater
	DeviceID         string
	Webhook          WebhookDeliverer
	AdapterInput     io.Reader
	Quarantine       QuarantineManager
	QuarantineReader QuarantineReader
	Schedule         ScheduleManager
	AuditManager     AuditManager
	AuditService     AuditService
	Random           io.Reader
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
		var update bundle.UpdateResult
		if options.UpdateTI {
			if a.TIUpdater == nil {
				fmt.Fprintln(stderr, "threat intelligence update is unavailable")
				return 1
			}
			update = a.TIUpdater.Update(ctx)
			if update.ErrorCode == bundle.UpdateErrorCancellation {
				fmt.Fprintln(stderr, "threat intelligence update cancelled")
				return 1
			}
		}
		var run audit.Run
		var runErr error
		if a.AuditService != nil {
			run, runErr = a.newAuditRun(options.ScanLabel)
		}
		scan, inventory, delta, _, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "baseline scan failed")
			stage, code := auditFailureForScanError(err)
			if !a.archiveFailure(ctx, run, runErr, stage, code) {
				fmt.Fprintln(stderr, "audit evidence unavailable")
			}
			return 1
		}
		var findings []model.Finding
		if a.FindingService != nil {
			if evaluated, evaluationErr := a.FindingService.Evaluate(ctx, inventory); evaluationErr == nil {
				findings = evaluated.Findings
			}
		}
		var outcome audit.Outcome
		if a.AuditService != nil && runErr == nil {
			if options.UpdateTI {
				if service, ok := a.AuditService.(intelligenceAuditService); ok {
					outcome = service.CompleteWithIntelligence(ctx, run, scan, inventory, delta, findings, auditReceipt(update))
				} else {
					outcome = a.AuditService.Complete(ctx, run, scan, inventory, delta, findings)
				}
			} else {
				outcome = a.AuditService.Complete(ctx, run, scan, inventory, delta, findings)
			}
		}
		exitCode := findingExitCode(findings)
		if options.Pretty {
			if outcome.Record.SchemaVersion != "" {
				if err := audit.WritePrettyStyled(stdout, outcome.Record, outcome.Stored, audit.Style{Color: a.Color}); err != nil {
					fmt.Fprintln(stderr, "failed to write baseline output")
					return 1
				}
				return exitCode
			}
			if err := report.WritePretty(stdout, scan, inventory, delta); err != nil {
				fmt.Fprintln(stderr, "failed to write baseline output")
				return 1
			}
			return exitCode
		}
		if err := report.WriteJSON(stdout, scan, inventory, delta); err != nil {
			fmt.Fprintln(stderr, "failed to write baseline output")
			return 1
		}
		return exitCode
	case "audit":
		return a.runAudit(ctx, options, stdout, stderr)
	case "status":
		if options.Pretty && a.AuditManager != nil {
			listed, listErr := a.AuditManager.List(ctx)
			if listErr == nil {
				for _, stored := range listed {
					if !stored.Valid {
						continue
					}
					verified, err := a.AuditManager.Open(ctx, stored.RunID)
					if err != nil {
						fmt.Fprintln(stderr, "audit archive is invalid")
						return 1
					}
					if err := audit.WritePrettyStyled(stdout, verified.Record, &stored, audit.Style{Color: a.Color}); err != nil {
						fmt.Fprintln(stderr, "failed to write status output")
						return 1
					}
					return 0
				}
			}
		}
		if a.StatusReader == nil {
			fmt.Fprintln(stderr, "status is unavailable")
			return 1
		}
		snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "failed to read status")
			return 1
		}
		status := statusPayload{SchemaVersion: "ssc-init.status.v7", Initialized: initialized}
		if initialized {
			status.InventorySchemaVersion = snapshot.Scan.SchemaVersion
			status.Inventory = &snapshot.Inventory
			if snapshot.Scan.SchemaVersion == "ssc-init.scan.v7" {
				scope := snapshot.Scan.Scope
				status.Scope = &scope
				status.Coverage = snapshot.Scan.Coverage
				evidenceCoverage := snapshot.Scan.EvidenceCoverage
				status.EvidenceCoverage = &evidenceCoverage
				status.AnalyzerCoverage = snapshot.Scan.AnalyzerCoverage
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
				AnalyzerCoverage:       status.AnalyzerCoverage,
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
	case "findings":
		if a.StatusReader == nil || a.FindingService == nil {
			fmt.Fprintln(stderr, "findings are unavailable")
			return 1
		}
		snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
		if err != nil || !initialized {
			fmt.Fprintln(stderr, "failed to evaluate findings")
			return 1
		}
		result, err := a.FindingService.Evaluate(ctx, snapshot.Inventory)
		if err != nil {
			fmt.Fprintln(stderr, "failed to evaluate findings")
			return 1
		}
		data := report.FindingData{DeviceID: a.DeviceID, Intelligence: result.Intelligence, Policy: result.Policy, Findings: result.Findings, Assets: snapshot.Inventory.Assets}
		if options.WebhookURL != "" {
			if a.Webhook == nil {
				fmt.Fprintln(stderr, "webhook delivery is unavailable")
				return 1
			}
			var body bytes.Buffer
			if report.WriteFindingsJSON(&body, data, false) != nil || a.Webhook.Deliver(ctx, options.WebhookURL, body.Bytes()) != nil {
				fmt.Fprintln(stderr, "webhook delivery failed")
				return 1
			}
		}
		var writeErr error
		if options.Pretty {
			writeErr = report.WriteFindingsPretty(stdout, data, a.Color)
		} else {
			writeErr = report.WriteFindingsJSON(stdout, data, false)
		}
		if writeErr != nil {
			fmt.Fprintln(stderr, "failed to write findings output")
			return 1
		}
		code := 0
		for _, item := range result.Findings {
			if item.Action == model.ActionAdvisory || item.Action == model.ActionBlocked || item.Action == model.ActionPaused {
				code = 3
			}
			if item.Verdict == model.VerdictKnownMalicious || item.Level == 2 {
				return 4
			}
		}
		return code
	case "adapter":
		if options.AdapterCommand != "evaluate" || a.AdapterInput == nil || a.StatusReader == nil || a.FindingService == nil {
			fmt.Fprintln(stderr, "adapter evaluation failed")
			return 1
		}
		invocation, err := decodeAdapterInvocation(a.AdapterInput)
		if err != nil {
			fmt.Fprintln(stderr, "adapter evaluation failed")
			return 1
		}
		snapshot, initialized, err := a.StatusReader.LatestSnapshot(ctx)
		if err != nil || !initialized {
			fmt.Fprintln(stderr, "adapter evaluation failed")
			return 1
		}
		result, err := a.FindingService.Evaluate(ctx, snapshot.Inventory)
		if err != nil {
			fmt.Fprintln(stderr, "adapter evaluation failed")
			return 1
		}
		evaluation, err := adapter.EvaluateInventory(invocation, result, snapshot.Inventory)
		if err != nil || writeJSON(stdout, evaluation) != nil {
			fmt.Fprintln(stderr, "adapter evaluation failed")
			return 1
		}
		return 0
	case "quarantine":
		if a.Quarantine == nil || a.QuarantineReader == nil {
			fmt.Fprintln(stderr, "quarantine operation failed")
			return 1
		}
		var output any
		var operationErr error
		if options.QuarantineCommand == "preview" || options.QuarantineCommand == "apply" {
			if a.StatusReader == nil {
				fmt.Fprintln(stderr, "quarantine operation failed")
				return 1
			}
			snapshot, initialized, loadErr := a.StatusReader.LatestSnapshot(ctx)
			if loadErr != nil || !initialized {
				fmt.Fprintln(stderr, "quarantine operation failed")
				return 1
			}
			selection := quarantine.Selection{AssetID: options.QuarantineAssetID, ObservationID: options.QuarantineObservationID, EvidenceID: options.QuarantineEvidenceID}
			if options.QuarantineCommand == "preview" {
				output, operationErr = a.Quarantine.Preview(ctx, snapshot.Inventory, selection)
			} else {
				output, operationErr = a.Quarantine.Apply(ctx, snapshot.Inventory, selection, options.QuarantineApprovalID)
			}
		} else {
			records, loadErr := a.QuarantineReader.QuarantineRecords(ctx)
			if loadErr != nil {
				fmt.Fprintln(stderr, "quarantine operation failed")
				return 1
			}
			record, found := quarantineRecordByID(records, options.QuarantineRecordID)
			if !found {
				fmt.Fprintln(stderr, "quarantine operation failed")
				return 1
			}
			if options.QuarantineCommand == "restore-preview" {
				output, operationErr = a.Quarantine.PreviewRestore(record)
			} else {
				output, operationErr = a.Quarantine.ApplyRestore(ctx, record, options.QuarantineApprovalID)
			}
		}
		if operationErr != nil || writeJSON(stdout, output) != nil {
			fmt.Fprintln(stderr, "quarantine operation failed")
			return 1
		}
		return 0
	case "schedule":
		if a.Schedule == nil {
			fmt.Fprintln(stderr, "schedule operation failed")
			return 1
		}
		var output any
		var operationErr error
		switch options.ScheduleCommand {
		case "preview":
			output, operationErr = a.Schedule.Preview()
		case "install":
			output, operationErr = a.Schedule.Install(ctx)
		case "remove":
			output, operationErr = a.Schedule.Remove(ctx)
		default:
			operationErr = errors.New("invalid schedule command")
		}
		if operationErr != nil || writeJSON(stdout, output) != nil {
			fmt.Fprintln(stderr, "schedule operation failed")
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
	case "bundle":
		family := bundle.Family(options.BundleFamily)
		if options.BundleCommand == "update" {
			if family != bundle.FamilyTI || a.TIUpdater == nil {
				fmt.Fprintln(stderr, "bundle update is unavailable")
				return 1
			}
			result := a.TIUpdater.Update(ctx)
			if options.Pretty {
				if _, err := fmt.Fprintf(stdout, "THREAT INTELLIGENCE UPDATE\n  status      %s\n  freshness   %s\n  sequence    %d\n", result.Status, result.Freshness, result.Sequence); err != nil {
					fmt.Fprintln(stderr, "failed to write bundle output")
					return 1
				}
			} else if err := writeJSON(stdout, bundleUpdatePayload{SchemaVersion: "ssc-init.bundle-update.v1", UpdateResult: result}); err != nil {
				fmt.Fprintln(stderr, "failed to write bundle output")
				return 1
			}
			if result.ErrorCode == bundle.UpdateErrorCancellation {
				return 1
			}
			return 0
		}
		manager := a.BundleManagers[family]
		if manager == nil {
			fmt.Fprintln(stderr, "bundle state is unavailable")
			return 1
		}
		var status bundle.Status
		var err error
		switch options.BundleCommand {
		case "install":
			_, err = manager.Install(ctx, options.BundleSource, options.BundleSignature)
			if err == nil {
				status, err = manager.Status(ctx)
			}
		case "status":
			status, err = manager.Status(ctx)
		case "rollback":
			err = manager.Rollback(ctx)
			if err == nil {
				status, err = manager.Status(ctx)
			}
		default:
			fmt.Fprintln(stderr, "invalid command arguments")
			return 2
		}
		if err != nil {
			fmt.Fprintln(stderr, "bundle "+options.BundleCommand+" failed")
			return 1
		}
		if err := writeJSON(stdout, bundlePayload{SchemaVersion: "ssc-init.bundle-status.v1", Command: options.BundleCommand, Status: status}); err != nil {
			fmt.Fprintln(stderr, "failed to write bundle output")
			return 1
		}
		return 0
	case "hook":
		if a.BaselineScanner == nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		previousIDs := map[string]struct{}{}
		if a.FindingService != nil && a.StatusReader != nil {
			if previous, ok, loadErr := a.StatusReader.LatestSnapshot(ctx); loadErr == nil && ok {
				if evaluated, evaluationErr := a.FindingService.Evaluate(ctx, previous.Inventory); evaluationErr == nil {
					for _, item := range evaluated.Findings {
						previousIDs[item.ID] = struct{}{}
					}
				}
			}
		}
		var run audit.Run
		var runErr error
		if a.AuditService != nil {
			run, runErr = a.newAuditRun("")
		}
		scanResult, inventory, delta, firstRun, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			stage, code := auditFailureForScanError(err)
			if !a.archiveFailure(ctx, run, runErr, stage, code) {
				fmt.Fprintln(stderr, "ssc-init hook: audit evidence unavailable")
			}
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
		var newFindings []model.Finding
		var allFindings []model.Finding
		if a.FindingService != nil {
			if evaluated, evaluationErr := a.FindingService.Evaluate(ctx, inventory); evaluationErr == nil {
				allFindings = evaluated.Findings
				for _, item := range evaluated.Findings {
					if _, standing := previousIDs[item.ID]; !standing {
						newFindings = append(newFindings, item)
					}
				}
			} else {
				fmt.Fprintln(stderr, "ssc-init hook: finding evaluation failed")
			}
		}
		if a.AuditService != nil && runErr == nil {
			_ = a.AuditService.Complete(ctx, run, scanResult, inventory, delta, allFindings)
		}
		if err := report.WriteHookSummaryFindings(stdout, inventory, delta, firstRun, newFindings, policyResult); err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		return 0
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
}

func (a App) newAuditRun(label string) (audit.Run, error) {
	random := a.Random
	if random == nil {
		random = cryptorand.Reader
	}
	identifier := make([]byte, 16)
	if _, err := io.ReadFull(random, identifier); err != nil {
		return audit.Run{}, errors.New("audit run identity unavailable")
	}
	now := a.Now
	if now == nil {
		now = time.Now
	}
	return audit.Run{ID: "run:hex:" + hex.EncodeToString(identifier), DeviceID: a.DeviceID, Label: label, Product: "ssc-init", Version: a.Version, StartedAt: now().UTC()}, nil
}

func (a App) archiveFailure(ctx context.Context, run audit.Run, runErr error, stage audit.Stage, code string) bool {
	if a.AuditService == nil {
		return true
	}
	if runErr != nil {
		return false
	}
	outcome := a.AuditService.Fail(ctx, run, stage, code)
	return outcome.Stored != nil && outcome.ArchiveErrorCode == ""
}

func auditFailureForScanError(err error) (audit.Stage, string) {
	if stage, ok := scan.FailureStageOf(err); ok {
		switch stage {
		case scan.FailureInitialize:
			return audit.StageInitialize, audit.CodeInitializeFailed
		case scan.FailureAnalyze:
			return audit.StageAnalyze, audit.CodeAnalyzerFailed
		case scan.FailurePersist:
			return audit.StagePersist, audit.CodePersistenceFailed
		}
	}
	return audit.StageCollect, audit.CodeCollectorFailed
}

func (a App) runAudit(ctx context.Context, options Options, stdout, stderr io.Writer) int {
	if options.AuditCommand == "verify" {
		return runAuditVerify(options, stdout, stderr)
	}
	if a.AuditManager == nil {
		fmt.Fprintln(stderr, "audit evidence is unavailable")
		return 1
	}
	switch options.AuditCommand {
	case "list":
		records, err := a.AuditManager.List(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "audit evidence is unavailable")
			return 1
		}
		if options.Pretty {
			if err := audit.WriteList(stdout, records); err != nil {
				fmt.Fprintln(stderr, "failed to write audit output")
				return 1
			}
		} else if err := writeJSON(stdout, records); err != nil {
			fmt.Fprintln(stderr, "failed to write audit output")
			return 1
		}
		return 0
	case "show":
		verified, err := a.AuditManager.Open(ctx, options.AuditRunID)
		if err != nil {
			fmt.Fprintln(stderr, "audit archive is invalid")
			return 1
		}
		if options.JSON {
			if err := writeJSON(stdout, verified.Record); err != nil {
				fmt.Fprintln(stderr, "failed to write audit output")
				return 1
			}
			return 0
		}
		if options.AuditSection != "" {
			if err := audit.WriteSectionStyled(stdout, verified.Record, audit.Section(options.AuditSection), audit.Style{Color: a.Color}); err != nil {
				fmt.Fprintln(stderr, "failed to write audit output")
				return 1
			}
			return 0
		}
		var stored *audit.Stored
		if verified.SafePath != "" {
			stored = &audit.Stored{SafePath: verified.SafePath, SHA256: verified.ZIPSHA256, Valid: true}
		}
		if err := audit.WritePrettyStyled(stdout, verified.Record, stored, audit.Style{Color: a.Color}); err != nil {
			fmt.Fprintln(stderr, "failed to write audit output")
			return 1
		}
		return 0
	case "export":
		stored, err := a.AuditManager.Export(ctx, options.AuditRunID, options.AuditOutput, options.AuditRedacted)
		if err != nil {
			fmt.Fprintln(stderr, "audit export failed")
			return 1
		}
		fmt.Fprintln(stdout, "SSC Init audit export")
		fmt.Fprintf(stdout, "  state      exported\n  profile    %s\n  sha256     %s\n", stored.Profile, stored.SHA256)
		return 0
	default:
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
}

func runAuditVerify(options Options, stdout, stderr io.Writer) int {
	file, err := os.OpenFile(options.AuditOutput, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		fmt.Fprintln(stderr, "audit archive is invalid")
		return 1
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintln(stderr, "audit archive is invalid")
		return 1
	}
	verified, err := audit.Verify(file, info.Size())
	if err != nil {
		fmt.Fprintln(stderr, "audit archive is invalid")
		return 1
	}
	if options.Pretty {
		if err := audit.WriteVerify(stdout, verified, "$INPUT/audit.zip"); err != nil {
			fmt.Fprintln(stderr, "failed to write audit output")
			return 1
		}
	} else if err := writeJSON(stdout, map[string]any{"valid": true, "manifest": verified.Manifest, "record": verified.Record, "zipSha256": verified.ZIPSHA256}); err != nil {
		fmt.Fprintln(stderr, "failed to write audit output")
		return 1
	}
	return 0
}

func decodeAdapterInvocation(input io.Reader) (adapter.Invocation, error) {
	const maxAdapterInput = 64 << 10
	encoded, err := io.ReadAll(io.LimitReader(input, maxAdapterInput+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maxAdapterInput {
		return adapter.Invocation{}, errors.New("invalid adapter input")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var invocation adapter.Invocation
	if err := decoder.Decode(&invocation); err != nil || !invocation.Valid() {
		return adapter.Invocation{}, errors.New("invalid adapter input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return adapter.Invocation{}, errors.New("invalid adapter input")
	}
	return invocation, nil
}

func quarantineRecordByID(records []quarantine.Record, id string) (quarantine.Record, bool) {
	for _, record := range records {
		if record.ID == id {
			return record, true
		}
	}
	return quarantine.Record{}, false
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
	criticalDecision := false
	if a.FindingService != nil {
		evaluated, evaluationErr := a.FindingService.Evaluate(ctx, snapshot.Inventory)
		if evaluationErr != nil {
			fmt.Fprintln(stderr, "failed to evaluate verified findings")
			return 1
		}
		assets := make(map[string]model.Asset, len(snapshot.Inventory.Assets))
		for _, asset := range snapshot.Inventory.Assets {
			assets[asset.ID] = asset
		}
		for _, item := range evaluated.Findings {
			if item.Level > 3 || item.Action == model.ActionAllowed || item.Action == model.ActionExcepted {
				continue
			}
			ruleID := "verified-finding"
			if len(item.RuleIDs) > 0 {
				ruleID = item.RuleIDs[0]
			} else if len(item.IntelligenceIDs) > 0 {
				ruleID = item.IntelligenceIDs[0]
			}
			asset := assets[item.AssetID]
			result.Violations = append(result.Violations, policy.Violation{RuleID: ruleID, Level: item.Level, AssetID: item.AssetID, AssetType: string(item.AssetType), AssetName: asset.Name})
			if item.Verdict == model.VerdictKnownMalicious || item.Level == 2 {
				criticalDecision = true
			}
		}
	}
	sort.Slice(result.Violations, func(i, j int) bool {
		if result.Violations[i].RuleID != result.Violations[j].RuleID {
			return result.Violations[i].RuleID < result.Violations[j].RuleID
		}
		return result.Violations[i].AssetID < result.Violations[j].AssetID
	})
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
		if criticalDecision {
			return 4
		}
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

type bundlePayload struct {
	SchemaVersion string        `json:"schemaVersion"`
	Command       string        `json:"command"`
	Status        bundle.Status `json:"status"`
}

type bundleUpdatePayload struct {
	SchemaVersion string `json:"schemaVersion"`
	bundle.UpdateResult
}

func findingExitCode(findings []model.Finding) int {
	for _, item := range findings {
		if item.Verdict == model.VerdictKnownMalicious || item.Verdict == model.VerdictBehaviorMalicious || item.Level == 2 {
			return 4
		}
	}
	if len(findings) > 0 {
		return 3
	}
	return 0
}

func auditReceipt(result bundle.UpdateResult) *audit.IntelligenceUpdate {
	return &audit.IntelligenceUpdate{Status: string(result.Status), ErrorCode: string(result.ErrorCode), Freshness: string(result.Freshness), Sequence: result.Sequence, Digest: result.Digest, KeyID: result.KeyID}
}

type statusPayload struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Initialized            bool                    `json:"initialized"`
	InventorySchemaVersion string                  `json:"inventorySchemaVersion,omitempty"`
	LegacyInventory        bool                    `json:"legacyInventory,omitempty"`
	Scope                  *model.ScanScope        `json:"scope,omitempty"`
	Coverage               []model.CollectorResult `json:"coverage,omitempty"`
	EvidenceCoverage       *model.EvidenceCoverage `json:"evidenceCoverage,omitempty"`
	AnalyzerCoverage       *model.AnalyzerCoverage `json:"analyzerCoverage,omitempty"`
	Inventory              *model.Inventory        `json:"inventory,omitempty"`
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
