package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
)

type failingWriter struct {
	err error
}

type fakeFindingService struct{ result finding.Result }

func (f fakeFindingService) Evaluate(context.Context, model.Inventory) (finding.Result, error) {
	return f.result, nil
}

type fakeWebhook struct {
	destination string
	body        []byte
}

func (f *fakeWebhook) Deliver(_ context.Context, destination string, body []byte) error {
	f.destination = destination
	f.body = append([]byte(nil), body...)
	return nil
}

func TestRunFindingsUsesLatestSnapshotAndClosedExitCodes(t *testing.T) {
	asset := model.Asset{ID: "tool:bad", Type: model.AssetTool, Name: "bad"}
	item := model.Finding{ID: "finding:test", AssetID: asset.ID, AssetType: asset.Type, Verdict: model.VerdictKnownMalicious, Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Level: 1, IntelligenceIDs: []string{"ti:test"}, DetectedAt: time.Unix(1, 0).UTC(), Action: model.ActionAdvisory, Bundles: []model.BundleReference{{Family: "ti", Sequence: 1, Digest: strings.Repeat("a", 64)}}}
	app := App{DeviceID: "device:sha256:" + strings.Repeat("b", 64), StatusReader: &cliMemorySnapshots{latest: model.Snapshot{Inventory: model.Inventory{Assets: []model.Asset{asset}}}, hasLatest: true}, FindingService: fakeFindingService{result: finding.Result{Intelligence: "fresh", Policy: "inactive", Findings: []model.Finding{item}}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"findings", "--json"}, &out, &errOut); code != 4 || errOut.Len() != 0 || !strings.Contains(out.String(), `"schemaVersion":"ssc-init.findings.v1"`) {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestRunFindingsWebhookIsExplicitAndReceivesCanonicalPayload(t *testing.T) {
	delivery := &fakeWebhook{}
	app := App{DeviceID: "device:sha256:" + strings.Repeat("b", 64), StatusReader: &cliMemorySnapshots{latest: model.Snapshot{}, hasLatest: true}, FindingService: fakeFindingService{result: finding.Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{}}}, Webhook: delivery}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"findings", "--json", "--webhook", "https://example.com/hook"}, &out, &errOut); code != 0 || delivery.destination == "" || !bytes.Equal(delivery.body, out.Bytes()) {
		t.Fatalf("code=%d destination=%q body=%q out=%q err=%q", code, delivery.destination, delivery.body, out.Bytes(), errOut.String())
	}
}

func TestRunBundleCommandsUseLocalManagerAndEmitPathFreeStatus(t *testing.T) {
	manager := &fakeBundleManager{status: bundle.Status{Family: bundle.FamilyTI, Freshness: bundle.FreshnessFresh, Sequence: 9, Version: "2026.08.10"}}
	app := App{BundleManagers: map[bundle.Family]BundleManager{bundle.FamilyTI: manager}}
	privateBundle, privateSignature := "/Users/private/bundle.json", "/Users/private/bundle.sig"
	var out, errOut bytes.Buffer
	code := app.Run(context.Background(), []string{"bundle", "install", "--family", "ti", "--from", privateBundle, "--signature", privateSignature, "--json"}, &out, &errOut)
	if code != 0 || errOut.Len() != 0 || manager.source != privateBundle || manager.signature != privateSignature {
		t.Fatalf("code=%d stdout=%q stderr=%q manager=%+v", code, out.String(), errOut.String(), manager)
	}
	if strings.Contains(out.String(), "/Users/private") || !strings.Contains(out.String(), `"schemaVersion":"ssc-init.bundle-status.v1"`) || !strings.Contains(out.String(), `"freshness":"fresh"`) {
		t.Fatalf("bundle output=%q", out.String())
	}
}

type fakeBundleManager struct {
	status            bundle.Status
	source, signature string
}

func (m *fakeBundleManager) Install(_ context.Context, source, signature string) (bundle.Verified, error) {
	m.source, m.signature = source, signature
	return bundle.Verified{}, nil
}

func (m *fakeBundleManager) Status(context.Context) (bundle.Status, error) { return m.status, nil }
func (m *fakeBundleManager) Rollback(context.Context) error                { return nil }

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"version", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}

	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["product"] != "SSC Init" || got["command"] != "ssc-init" {
		t.Fatalf("got=%v", got)
	}
}

func TestPolicyInitWritesStarterOnceWithPrivatePermissions(t *testing.T) {
	home := t.TempDir()
	policyPath := filepath.Join(home, "Library", "Application Support", "SSC Init", "policy.json")
	app := App{PolicyPath: policyPath, Home: home}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "init"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	info, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if strings.Contains(out.String(), home) || !strings.Contains(out.String(), "$HOME") {
		t.Fatalf("location was not redacted: %q", out.String())
	}
	before, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := app.Run(context.Background(), []string{"policy", "init"}, &out, &errOut); code != 1 {
		t.Fatalf("overwrite code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	after, err := os.ReadFile(policyPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing policy changed: %v", err)
	}
}

type memoryPolicyStore struct {
	pins      []policy.Pin
	saved     []policy.Pin
	decisions []policy.Decision
	recorded  []policy.Violation
}

func (store *memoryPolicyStore) Pins(context.Context) ([]policy.Pin, error) {
	return append([]policy.Pin(nil), store.pins...), nil
}

func (store *memoryPolicyStore) SavePins(_ context.Context, pins []policy.Pin, _ time.Time) error {
	store.saved = append([]policy.Pin(nil), pins...)
	return nil
}

func (store *memoryPolicyStore) Exceptions(context.Context) ([]policy.Exception, error) {
	return nil, nil
}

func (store *memoryPolicyStore) RecordDecisions(_ context.Context, violations []policy.Violation, _ time.Time) error {
	store.recorded = append([]policy.Violation(nil), violations...)
	return nil
}
func (store *memoryPolicyStore) Decisions(context.Context) ([]policy.Decision, error) {
	return append([]policy.Decision(nil), store.decisions...), nil
}

func policySnapshot() *cliMemorySnapshots {
	return &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{Inventory: model.Inventory{
		Assets:   []model.Asset{{ID: "agent-plugin:claude:x@1.0.0", Type: model.AssetAgentPlugin, Name: "x"}},
		Evidence: []model.ContentEvidence{{AssetID: "agent-plugin:claude:x@1.0.0", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidenceComplete, Digest: strings.Repeat("a", 64)}},
	}}}
}

func TestPolicyPinEchoesTheTrustOnFirstUseCaveat(t *testing.T) {
	store := &memoryPolicyStore{}
	app := App{StatusReader: policySnapshot(), PolicyStore: store, Now: func() time.Time { return time.Unix(1, 0) }}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "pin"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	for _, phrase := range []string{"records what is on this machine now", "pinning a compromised machine approves the compromise"} {
		if !strings.Contains(out.String(), phrase) {
			t.Fatalf("missing caveat %q: %s", phrase, out.String())
		}
	}
	if len(store.saved) != 1 || store.saved[0].Digest != strings.Repeat("a", 64) {
		t.Fatalf("saved pins=%+v", store.saved)
	}
}

func TestPolicyPinUpdateRejectsAnUnknownAsset(t *testing.T) {
	store := &memoryPolicyStore{}
	app := App{StatusReader: policySnapshot(), PolicyStore: store}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "pin", "--update", "unknown-secret-asset"}, &out, &errOut); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if len(store.saved) != 0 || strings.Contains(errOut.String(), "unknown-secret-asset") {
		t.Fatalf("unknown asset was saved or echoed: %q %+v", errOut.String(), store.saved)
	}
}

func TestPolicyPinRefusesUnderAnOrganizationBundle(t *testing.T) {
	store := &memoryPolicyStore{}
	app := App{StatusReader: policySnapshot(), PolicyStore: store, PolicySources: policy.Sources{Bundle: &policy.Bundle{}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "pin"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "pins are authored in the organization bundle") {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestPolicyCheckExitsThreeOnViolationAndNamesInertLevels(t *testing.T) {
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"unpinned","family":"pin","enabled":true,"description":"d"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	snapshots := policySnapshot()
	snapshots.latest.Scan.ScanID = "scan-1"
	snapshots.latest.Scan.FinishedAt = time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)
	store := &memoryPolicyStore{}
	app := App{StatusReader: snapshots, PolicyStore: store, PolicyDocument: document, Now: func() time.Time { return time.Date(2026, 8, 9, 2, 0, 0, 0, time.UTC) }}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "check", "--json"}, &out, &errOut); code != 3 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	var payload struct {
		SchemaVersion string             `json:"schemaVersion"`
		Capability    string             `json:"capability"`
		Levels        []policy.Level     `json:"levels"`
		Violations    []policy.Violation `json:"violations"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != "ssc-init.policy-check.v1" || payload.Capability != "advisory" || len(payload.Levels) != 5 || payload.Levels[0].Active || payload.Levels[0].Reason != "no evidence available" {
		t.Fatalf("payload header=%+v", payload)
	}
	if len(payload.Violations) != 1 || payload.Violations[0].RuleID != "unpinned" || len(store.recorded) != 1 {
		t.Fatalf("violations=%+v recorded=%+v", payload.Violations, store.recorded)
	}
}

func TestPolicyCheckConsumesVerifiedLevelOneFinding(t *testing.T) {
	document, err := policy.Load(policy.Starter())
	if err != nil {
		t.Fatal(err)
	}
	snapshots := policySnapshot()
	snapshots.latest.Scan.ScanID = "scan-verified"
	store := &memoryPolicyStore{}
	asset := snapshots.latest.Inventory.Assets[0]
	verified := model.Finding{ID: "finding:verified", AssetID: asset.ID, AssetType: asset.Type, Verdict: model.VerdictKnownMalicious, Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Level: 1, IntelligenceIDs: []string{"ti:verified"}, DetectedAt: time.Unix(1, 0).UTC(), Action: model.ActionAdvisory}
	app := App{StatusReader: snapshots, PolicyStore: store, PolicyDocument: document, FindingService: fakeFindingService{result: finding.Result{Findings: []model.Finding{verified}}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "check", "--json"}, &out, &errOut); code != 4 || len(store.recorded) != 1 || store.recorded[0].Level != 1 {
		t.Fatalf("code=%d recorded=%+v err=%q", code, store.recorded, errOut.String())
	}
}

func TestPolicyCheckExitsTwoOnAnUnloadableDocument(t *testing.T) {
	app := App{PolicyLoadError: errors.New("rules[0].family: unknown rule family")}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "check"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "rules[0].family") {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestPolicyCheckTouchesNoCollectorRoot(t *testing.T) {
	root := t.TempDir()
	plugin := filepath.Join(root, "plugin.json")
	if err := os.WriteFile(plugin, []byte(`{"secret":"must-not-be-read"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wantTime := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(plugin, wantTime, wantTime); err != nil {
		t.Fatal(err)
	}
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	snapshots := policySnapshot()
	app := App{Home: root, StatusReader: snapshots, PolicyStore: &memoryPolicyStore{}, PolicyDocument: document}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"policy", "check"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	info, err := os.Stat(plugin)
	if err != nil {
		t.Fatal(err)
	}
	if snapshots.latestCalls != 1 || !info.ModTime().Equal(wantTime) {
		t.Fatalf("latest calls=%d plugin mtime=%s", snapshots.latestCalls, info.ModTime())
	}
}

func TestHookEvaluatesPolicyAndAlwaysExitsZero(t *testing.T) {
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"unpinned","family":"pin","enabled":true,"description":"d"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	inventory := policySnapshot().latest.Inventory
	store := &memoryPolicyStore{}
	app := App{
		BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
			return model.ScanResult{}, inventory, model.Delta{}, false, nil
		}),
		PolicyStore: store, PolicyDocument: document, Now: func() time.Time { return time.Unix(1, 0) },
	}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "POLICY (1 violations)") || len(store.recorded) != 1 {
		t.Fatalf("stdout=%q recorded=%+v", out.String(), store.recorded)
	}
}

func TestHookPolicyLoadFailureKeepsTheLadderAdvisory(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{{ID: "agent-skill:claude:x", Type: model.AssetSkill, Name: "x", Source: "claude"}}}
	delta := model.Delta{Changes: []model.Change{{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-skill:claude:x"}}}
	app := App{
		BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
			return model.ScanResult{}, inventory, delta, false, nil
		}),
		PolicyLoadError: errors.New("invalid"),
	}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out.String(), "NEW") || errOut.String() != "ssc-init hook: policy document could not be loaded\n" {
		t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRunVersionReturnsErrorWhenOutputFails(t *testing.T) {
	var errOut bytes.Buffer
	code := Run(context.Background(), []string{"version", "--json"}, failingWriter{err: errors.New("disk full")}, &errOut)
	if code == 0 {
		t.Fatal("code=0")
	}
	if !strings.Contains(errOut.String(), "failed to write version output") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestCurrentStatusContractIsV4(t *testing.T) {
	app := App{StatusReader: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{Scan: model.ScanResult{SchemaVersion: "ssc-init.scan.v6"}, Inventory: model.Inventory{Assets: []model.Asset{}, Evidence: []model.ContentEvidence{}, Relationships: []model.Relationship{}}}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"status", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"schemaVersion":"ssc-init.status.v6"`) || strings.Contains(out.String(), `"legacyInventory":true`) {
		t.Fatalf("status=%s", out.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"wat"}, &out, &errOut); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if errOut.String() != "invalid command arguments\n" {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

type baselineScannerFunc func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error)

func (f baselineScannerFunc) Baseline(ctx context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
	return f(ctx)
}

func TestRunOptionsUsesAlreadyParsedCommand(t *testing.T) {
	called := false
	app := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
		called = true
		return model.ScanResult{}, model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}, model.Delta{Changes: []model.Change{}}, true, nil
	})}
	var out, errOut bytes.Buffer
	options := Options{
		Command:        "scan",
		JSON:           true,
		Baseline:       true,
		ExternalProbes: true,
		ProjectRoots:   []string{"/Volumes/private-value-must-not-be-parsed"},
	}
	if code := app.RunOptions(context.Background(), options, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	if !called {
		t.Fatal("baseline scanner was not called")
	}
}

type cliMemorySnapshots struct {
	latest      model.Snapshot
	hasLatest   bool
	loadErr     error
	saved       []model.ScanResult
	inventory   []model.Inventory
	latestCalls int
}

func (m *cliMemorySnapshots) SaveScan(_ context.Context, result model.ScanResult, inventory model.Inventory) error {
	m.saved = append(m.saved, result)
	m.inventory = append(m.inventory, inventory)
	m.latest = model.Snapshot{Scan: result, Inventory: inventory}
	m.hasLatest = true
	return nil
}

func (m *cliMemorySnapshots) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
	m.latestCalls++
	return m.latest, m.hasLatest, m.loadErr
}

type cliCollector struct {
	name   string
	result model.CollectorResult
	err    error
}

type cliTargetedCollector struct {
	cliCollector
	specs []model.TargetSpec
}

func (c cliTargetedCollector) Targets() []model.TargetSpec { return c.specs }

func (c cliCollector) Name() string { return c.name }
func (c cliCollector) Collect(context.Context, collector.Environment) (model.CollectorResult, error) {
	return c.result, c.err
}

type fakeDoctor struct{ result doctor.Result }

func (d fakeDoctor) Check(context.Context) doctor.Result { return d.result }

func TestScanAndStatusPrettyRenderHumanTablesWithoutJSON(t *testing.T) {
	scanResult := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v6",
		ScanID:        "00000000-0000-4000-8000-000000000009",
		Status:        "partial",
		Coverage:      []model.CollectorResult{{Collector: "agents", Status: model.CoveragePartial}},
		EvidenceCoverage: model.EvidenceCoverage{Status: model.CoveragePartial, Targets: []model.EvidenceTargetResult{
			{TargetID: "agents.claude.plugins.manifest", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", EvidenceID: "evidence:sha256:aaaa", Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
		}},
	}
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial,
			Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}}},
	}
	app := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
		return scanResult, inventory, model.Delta{}, true, nil
	})}

	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"scan", "--baseline", "--pretty"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	scanOutput := out.String()
	for _, want := range []string{"SSC Init baseline scan", "COLLECTOR COVERAGE", "alpha", "symlink_rejected", "DELTA"} {
		if !strings.Contains(scanOutput, want) {
			t.Fatalf("scan pretty missing %q:\n%s", want, scanOutput)
		}
	}
	if strings.Contains(scanOutput, "\"schemaVersion\"") {
		t.Fatalf("scan pretty leaked JSON:\n%s", scanOutput)
	}

	snapshots := &cliMemorySnapshots{latest: model.Snapshot{Scan: scanResult, Inventory: inventory}, hasLatest: true}
	statusApp := App{StatusReader: snapshots}
	out.Reset()
	if code := statusApp.Run(context.Background(), []string{"status", "--pretty"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	statusOutput := out.String()
	for _, want := range []string{"SSC Init status", "initialized", "ssc-init.scan.v6", "COLLECTOR COVERAGE", "symlink_rejected"} {
		if !strings.Contains(statusOutput, want) {
			t.Fatalf("status pretty missing %q:\n%s", want, statusOutput)
		}
	}

	legacySnapshots := &cliMemorySnapshots{latest: model.Snapshot{Scan: model.ScanResult{SchemaVersion: "ssc-init.scan.v2"}, Inventory: inventory}, hasLatest: true}
	out.Reset()
	if code := (App{StatusReader: legacySnapshots}).Run(context.Background(), []string{"status", "--pretty"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	legacyOutput := out.String()
	if !strings.Contains(legacyOutput, "legacy inventory") || strings.Contains(legacyOutput, "COLLECTOR COVERAGE") {
		t.Fatalf("legacy status pretty wrong:\n%s", legacyOutput)
	}

	out.Reset()
	if code := (App{StatusReader: &cliMemorySnapshots{}}).Run(context.Background(), []string{"status", "--pretty"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "not initialized") {
		t.Fatalf("uninitialized status pretty wrong:\n%s", out.String())
	}
}

func TestBaselineJSONReportsPartialCoverageAndPersists(t *testing.T) {
	snapshots := &cliMemorySnapshots{}
	orchestrator := collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 2, Collectors: []collector.Collector{
		cliTargetedCollector{
			cliCollector: cliCollector{name: "agents", result: model.CollectorResult{
				Status: model.CoverageComplete,
				Assets: []model.Asset{{ID: "tool:new", Type: model.AssetTool, Name: "new"}},
				Targets: []model.TargetCoverage{{
					TargetID: "agents.user", Status: model.TargetComplete, Assets: 1,
				}},
				LocalTargets: []model.LocalTarget{{TargetID: "agents.user", Path: "/raw/private/target"}},
			}},
			specs: []model.TargetSpec{{
				ID: "agents.user", Collector: "agents", Platform: "darwin",
				Scope: model.ScopeUser, Method: model.TargetDirectory,
			}},
		},
		cliCollector{name: "docker", err: errors.New("daemon unavailable")},
	}}
	scanner := scan.NewService(orchestrator, snapshots, func() time.Time {
		return time.Unix(1_700_000_000, 0).UTC()
	}, func() string { return "00000000-0000-4000-8000-000000000001" })
	app := App{Version: "test", BaselineScanner: scanner, StatusReader: snapshots, Doctor: fakeDoctor{}}
	var out, errOut bytes.Buffer

	code := app.Run(context.Background(), []string{"scan", "--baseline", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	wantOutput := `{"schemaVersion":"ssc-init.scan.v6",` +
		`"scanId":"00000000-0000-4000-8000-000000000001",` +
		`"status":"partial",` +
		`"startedAt":"2023-11-14T22:13:20Z",` +
		`"finishedAt":"2023-11-14T22:13:20Z",` +
		`"scope":{"platform":"","catalogVersion":"ssc-init.catalog.v1","projectRoots":null,"externalProbes":false},` +
		`"coverage":[` +
		`{"collector":"agents","status":"complete","assets":[{"id":"tool:new","type":"tool","name":"new"}],` +
		`"targets":[{"targetId":"agents.user","status":"complete","assets":1,"observations":0}]},` +
		`{"collector":"docker","status":"failed","errors":[{"code":"collector_error","message":"collector failed"}]}` +
		`],` +
		`"evidenceCoverage":{"status":"complete","targets":[]},` +
		`"inventory":{"assets":[{"id":"tool:new","type":"tool","name":"new"}],"observations":[],"evidence":[],"relationships":[]},` +
		`"delta":{"changes":[{"kind":"added","entity":"asset","entityId":"tool:new"}]}}` + "\n"
	if out.String() != wantOutput {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), wantOutput)
	}
	if strings.Contains(out.String(), "/raw/private/target") {
		t.Fatalf("local target leaked: %s", out.String())
	}
	if len(snapshots.saved) != 1 {
		t.Fatal("scan not persisted")
	}
	if snapshots.latest.Scan.SchemaVersion != "ssc-init.scan.v6" || len(snapshots.latest.Inventory.Assets) != 1 {
		t.Fatalf("snapshot=%+v", snapshots.latest)
	}
}

func TestStatusJSONHasStableEmptyV1V2V3AndV4Shapes(t *testing.T) {
	legacyInventory := model.Inventory{
		Assets:        []model.Asset{{ID: "tool:legacy", Type: model.AssetTool, Name: "legacy"}},
		Relationships: []model.Relationship{},
	}
	emptyInventory := model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}
	v4Inventory := model.Inventory{
		Assets: []model.Asset{}, Evidence: []model.ContentEvidence{}, Relationships: []model.Relationship{},
	}
	scanScope := model.ScanScope{
		Platform: "darwin", CatalogVersion: collector.CatalogVersion,
		ProjectRoots: []string{"$HOME/Projects"}, ExternalProbes: false,
	}
	for _, tc := range []struct {
		name      string
		snapshots *cliMemorySnapshots
		want      string
	}{
		{
			name:      "empty",
			snapshots: &cliMemorySnapshots{},
			want:      "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":false}\n",
		},
		{
			name: "v1 legacy inventory",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v1",
					Scope:         scanScope,
					Coverage:      []model.CollectorResult{{Collector: "must-not-be-synthesized", Status: model.CoverageComplete}},
				},
				Inventory: legacyInventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v1\",\"legacyInventory\":true,\"inventory\":{\"assets\":[{\"id\":\"tool:legacy\",\"type\":\"tool\",\"name\":\"legacy\"}],\"evidence\":null,\"relationships\":[]}}\n",
		},
		{
			name: "v2 legacy inventory",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v2",
					Scope:         scanScope,
					Coverage:      []model.CollectorResult{{Collector: "must-not-be-synthesized", Status: model.CoverageComplete}},
					EvidenceCoverage: model.EvidenceCoverage{
						Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{},
					},
				},
				Inventory: emptyInventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v2\",\"legacyInventory\":true,\"inventory\":{\"assets\":[],\"evidence\":null,\"relationships\":[]}}\n",
		},
		{
			name: "v3 legacy evidence inventory",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan:      model.ScanResult{SchemaVersion: "ssc-init.scan.v3"},
				Inventory: v4Inventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v3\",\"legacyInventory\":true,\"inventory\":{\"assets\":[],\"evidence\":[],\"relationships\":[]}}\n",
		},
		{
			name: "v4 legacy provenance",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan:      model.ScanResult{SchemaVersion: "ssc-init.scan.v4"},
				Inventory: v4Inventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v4\",\"legacyInventory\":true,\"inventory\":{\"assets\":[],\"evidence\":[],\"relationships\":[]}}\n",
		},
		{
			name: "v5 developer surfaces",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v6",
					Scope:         scanScope,
					Coverage:      []model.CollectorResult{{Collector: "agents", Status: model.CoverageComplete}},
					EvidenceCoverage: model.EvidenceCoverage{
						Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{},
					},
				},
				Inventory: v4Inventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v6\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v6\",\"scope\":{\"platform\":\"darwin\",\"catalogVersion\":\"ssc-init.catalog.v1\",\"projectRoots\":[\"$HOME/Projects\"],\"externalProbes\":false},\"coverage\":[{\"collector\":\"agents\",\"status\":\"complete\"}],\"evidenceCoverage\":{\"status\":\"complete\",\"targets\":[]},\"inventory\":{\"assets\":[],\"evidence\":[],\"relationships\":[]}}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := App{StatusReader: tc.snapshots}
			var out, errOut bytes.Buffer
			if code := app.Run(context.Background(), []string{"status", "--json"}, &out, &errOut); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, errOut.String())
			}
			if out.String() != tc.want {
				t.Fatalf("output=%s want=%s", out.String(), tc.want)
			}
		})
	}
}

func TestDoctorJSONUsesInjectedReadOnlyChecker(t *testing.T) {
	app := App{Doctor: fakeDoctor{result: doctor.Result{SchemaVersion: "ssc-init.doctor.v2", Status: "ready"}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"doctor", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"schemaVersion":"ssc-init.doctor.v2"`) {
		t.Fatalf("stdout=%q", out.String())
	}
}

// The values an install carries are the ones an error must never echo.
const (
	secretSource  = "/Volumes/private-drop/ssc-init-darwin-universal"
	secretVersion = "v9.9.9"
)

var secretDigest = strings.Repeat("b", 64)

type stubInstaller struct {
	installArgs   [][3]string
	rollbackCalls int
	outcome       InstallOutcome
	err           error
}

func (s *stubInstaller) Install(_ context.Context, sourcePath, version, digest string) (InstallOutcome, error) {
	s.installArgs = append(s.installArgs, [3]string{sourcePath, version, digest})
	return s.outcome, s.err
}

func (s *stubInstaller) Rollback(context.Context) (InstallOutcome, error) {
	s.rollbackCalls++
	return s.outcome, s.err
}

func TestInstallAndRollbackEmitTheInstallContract(t *testing.T) {
	installer := &stubInstaller{outcome: InstallOutcome{
		Version: "v0.2.0", PreviousVersion: "v0.1.0", RollbackAvailable: true,
	}}
	app := App{Installer: installer}

	var out, errOut bytes.Buffer
	code := app.Run(context.Background(), []string{
		"install", "--from", secretSource, "--version", "v0.2.0", "--sha256", secretDigest, "--json",
	}, &out, &errOut)
	if code != 0 || errOut.String() != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	want := `{"schemaVersion":"ssc-init.install.v1","command":"install","version":"v0.2.0","previousVersion":"v0.1.0","rollbackAvailable":true}` + "\n"
	if out.String() != want {
		t.Fatalf("stdout=%q want=%q", out.String(), want)
	}
	if len(installer.installArgs) != 1 || installer.installArgs[0] != [3]string{secretSource, "v0.2.0", secretDigest} {
		t.Fatalf("installer received %+v", installer.installArgs)
	}

	out.Reset()
	installer.outcome = InstallOutcome{Version: "v0.1.0", PreviousVersion: "v0.2.0", RollbackAvailable: true}
	if code := app.Run(context.Background(), []string{"rollback", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	want = `{"schemaVersion":"ssc-init.install.v1","command":"rollback","version":"v0.1.0","previousVersion":"v0.2.0","rollbackAvailable":true}` + "\n"
	if out.String() != want {
		t.Fatalf("stdout=%q want=%q", out.String(), want)
	}
	if installer.rollbackCalls != 1 {
		t.Fatalf("rollback calls=%d", installer.rollbackCalls)
	}
}

// A first install has no rollback target: the shape stays fixed and the absent
// target is reported as an empty version and rollbackAvailable false.
func TestInstallReportsAFirstInstallWithoutARollbackTarget(t *testing.T) {
	app := App{Installer: &stubInstaller{outcome: InstallOutcome{Version: "v0.1.0"}}}
	var out, errOut bytes.Buffer
	code := app.Run(context.Background(), []string{
		"install", "--from", secretSource, "--version", "v0.1.0", "--sha256", secretDigest, "--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	want := `{"schemaVersion":"ssc-init.install.v1","command":"install","version":"v0.1.0","previousVersion":"","rollbackAvailable":false}` + "\n"
	if out.String() != want {
		t.Fatalf("stdout=%q want=%q", out.String(), want)
	}
}

// The payload reports version strings and booleans only: no absolute path, no
// home directory, and never the supplied source or digest.
func TestInstallPayloadCarriesNoPathOrSuppliedValue(t *testing.T) {
	app := App{Installer: &stubInstaller{outcome: InstallOutcome{
		Version: "v0.2.0", PreviousVersion: "v0.1.0", RollbackAvailable: true,
	}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{
		"install", "--from", secretSource, "--version", "v0.2.0", "--sha256", secretDigest, "--json",
	}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	payload := out.String()
	for _, forbidden := range []string{"/", secretSource, secretDigest, "$HOME", "Application Support"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload leaks %q: %s", forbidden, payload)
		}
	}
}

// Each install failure mode gets its own exit code so an adapter can tell "these
// bytes are bad" from "the new core is bad" from "someone else is installing"
// without parsing a message. The messages themselves stay fixed and value-free.
func TestInstallFailuresExitDistinctlyWithFixedValueFreeMessages(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		err    error
		code   int
		stderr string
	}{
		{"verification", ErrInstallVerification, 3, "core verification failed\n"},
		{"health", ErrInstallHealth, 4, "staged core failed its health check\n"},
		{"busy", ErrInstallBusy, 5, "another installation is already in progress\n"},
		{"unclassified", errors.New("mounting /Volumes/private-drop failed"), 1, "install failed\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			app := App{Installer: &stubInstaller{err: testCase.err}}
			var out, errOut bytes.Buffer
			code := app.Run(context.Background(), []string{
				"install", "--from", secretSource, "--version", secretVersion, "--sha256", secretDigest, "--json",
			}, &out, &errOut)
			if code != testCase.code {
				t.Fatalf("code=%d want=%d", code, testCase.code)
			}
			if out.String() != "" {
				t.Fatalf("failed install wrote a payload: %q", out.String())
			}
			if errOut.String() != testCase.stderr {
				t.Fatalf("stderr=%q want=%q", errOut.String(), testCase.stderr)
			}
			for _, forbidden := range []string{secretSource, secretVersion, secretDigest, "/Volumes"} {
				if strings.Contains(errOut.String(), forbidden) {
					t.Fatalf("stderr leaks %q: %q", forbidden, errOut.String())
				}
			}
		})
	}
}

func TestRollbackFailuresExitDistinctly(t *testing.T) {
	for _, testCase := range []struct {
		err    error
		code   int
		stderr string
	}{
		{ErrInstallBusy, 5, "another installation is already in progress\n"},
		{ErrInstallVerification, 3, "core verification failed\n"},
		{errors.New("no previous known-good core version is available"), 1, "rollback failed\n"},
	} {
		app := App{Installer: &stubInstaller{err: testCase.err}}
		var out, errOut bytes.Buffer
		code := app.Run(context.Background(), []string{"rollback", "--json"}, &out, &errOut)
		if code != testCase.code || out.String() != "" || errOut.String() != testCase.stderr {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
		}
	}
}

func TestInstallAndRollbackFailWhenOutputCannotBeWritten(t *testing.T) {
	app := App{Installer: &stubInstaller{outcome: InstallOutcome{Version: "v0.1.0"}}}
	var errOut bytes.Buffer
	code := app.Run(context.Background(), []string{
		"install", "--from", secretSource, "--version", "v0.1.0", "--sha256", secretDigest, "--json",
	}, failingWriter{err: errors.New("disk full")}, &errOut)
	if code != 1 || errOut.String() != "failed to write install output\n" {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestOperationalCommandsFailGenericallyWhenDependencyMissing(t *testing.T) {
	installArgs := []string{"install", "--from", secretSource, "--version", "v0.1.0", "--sha256", secretDigest, "--json"}
	for _, args := range [][]string{{"scan", "--baseline", "--json"}, {"status", "--json"}, {"doctor", "--json"}, installArgs, {"rollback", "--json"}} {
		var out, errOut bytes.Buffer
		code := (App{}).Run(context.Background(), args, &out, &errOut)
		if code != 1 || strings.Contains(errOut.String(), "<nil>") {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, errOut.String())
		}
	}
}

// TestHookPassesFirstRunToTheRenderer proves the scanner's first-run signal —
// not a guess made from the delta — decides between the initial-baseline line
// and the ladder. Both cases send an identical all-additions delta.
func TestHookPassesFirstRunToTheRenderer(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
	}}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-skill:claude:docx"},
	}}
	scanner := func(firstRun bool) App {
		return App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
			return model.ScanResult{}, inventory, delta, firstRun, nil
		})}
	}

	var out, errOut bytes.Buffer
	if code := scanner(true).Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("first run: code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "initial baseline recorded") || strings.Contains(out.String(), "NEW") {
		t.Fatalf("first run must report an initial baseline without rungs:\n%s", out.String())
	}

	out.Reset()
	if code := scanner(false).Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("later run: code=%d stderr=%q", code, errOut.String())
	}
	if strings.Contains(out.String(), "initial baseline") ||
		!regexp.MustCompile(`(?m)^  NEW\s+agent-skill\s+docx \(claude\)$`).MatchString(out.String()) {
		t.Fatalf("a run with a predecessor must climb the ladder:\n%s", out.String())
	}
}

func TestHookIsAdvisoryAcrossDriftCleanAndFailure(t *testing.T) {
	drift := model.Delta{Changes: []model.Change{{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:alpha@1.0.0"}}}
	scan := model.ScanResult{SchemaVersion: "ssc-init.scan.v6"}
	// A scan diffs the snapshot it just wrote, so the added asset is in the
	// inventory it hands the renderer. A second asset keeps the delta from
	// looking like an initial baseline.
	drifted := model.Inventory{Assets: []model.Asset{
		{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
		{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
	}}

	var out, errOut bytes.Buffer
	app := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
		return scan, drifted, drift, false, nil
	})}
	if code := app.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("drift: code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "ssc-init: 1 changes since last snapshot") ||
		!regexp.MustCompile(`(?m)^  NEW\s+agent-plugin\s+alpha \(claude\)$`).MatchString(out.String()) {
		t.Fatalf("drift output wrong:\n%s", out.String())
	}

	out.Reset()
	clean := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
		return scan, model.Inventory{}, model.Delta{}, false, nil
	})}
	if code := clean.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("clean: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	failing := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, errors.New("store locked at /private/path")
	})}
	out.Reset()
	errOut.Reset()
	if code := failing.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("failure must stay advisory: code=%d", code)
	}
	if out.Len() != 0 || errOut.String() != "ssc-init hook: baseline scan failed\n" {
		t.Fatalf("failure output wrong: stdout=%q stderr=%q", out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := (App{}).Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("nil scanner must stay advisory: code=%d", code)
	}
	if out.Len() != 0 || errOut.String() != "ssc-init hook: baseline scan failed\n" {
		t.Fatalf("nil scanner output wrong: stdout=%q stderr=%q", out.String(), errOut.String())
	}

	errOut.Reset()
	if code := app.Run(context.Background(), []string{"hook"}, failingWriter{err: errors.New("broken pipe")}, &errOut); code != 0 {
		t.Fatalf("write failure must stay advisory: code=%d", code)
	}
	if errOut.String() != "ssc-init hook: baseline scan failed\n" {
		t.Fatalf("write failure output wrong: stderr=%q", errOut.String())
	}
}
