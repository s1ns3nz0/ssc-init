package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/doctor"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
)

type failingWriter struct {
	err error
}

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
	latest    model.Snapshot
	hasLatest bool
	loadErr   error
	saved     []model.ScanResult
	inventory []model.Inventory
}

func (m *cliMemorySnapshots) SaveScan(_ context.Context, result model.ScanResult, inventory model.Inventory) error {
	m.saved = append(m.saved, result)
	m.inventory = append(m.inventory, inventory)
	m.latest = model.Snapshot{Scan: result, Inventory: inventory}
	m.hasLatest = true
	return nil
}

func (m *cliMemorySnapshots) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
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
		SchemaVersion: "ssc-init.scan.v3",
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
	for _, want := range []string{"SSC Init status", "initialized", "ssc-init.scan.v3", "COLLECTOR COVERAGE", "symlink_rejected"} {
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
	wantOutput := `{"schemaVersion":"ssc-init.scan.v3",` +
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
	if snapshots.latest.Scan.SchemaVersion != "ssc-init.scan.v3" || len(snapshots.latest.Inventory.Assets) != 1 {
		t.Fatalf("snapshot=%+v", snapshots.latest)
	}
}

func TestStatusJSONHasStableEmptyV1V2AndV3Shapes(t *testing.T) {
	legacyInventory := model.Inventory{
		Assets:        []model.Asset{{ID: "tool:legacy", Type: model.AssetTool, Name: "legacy"}},
		Relationships: []model.Relationship{},
	}
	emptyInventory := model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}
	v3Inventory := model.Inventory{
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
			want:      "{\"schemaVersion\":\"ssc-init.status.v3\",\"initialized\":false}\n",
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
			want: "{\"schemaVersion\":\"ssc-init.status.v3\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v1\",\"legacyInventory\":true,\"inventory\":{\"assets\":[{\"id\":\"tool:legacy\",\"type\":\"tool\",\"name\":\"legacy\"}],\"evidence\":null,\"relationships\":[]}}\n",
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
			want: "{\"schemaVersion\":\"ssc-init.status.v3\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v2\",\"legacyInventory\":true,\"inventory\":{\"assets\":[],\"evidence\":null,\"relationships\":[]}}\n",
		},
		{
			name: "v3 provenance",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v3",
					Scope:         scanScope,
					Coverage:      []model.CollectorResult{{Collector: "agents", Status: model.CoverageComplete}},
					EvidenceCoverage: model.EvidenceCoverage{
						Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{},
					},
				},
				Inventory: v3Inventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v3\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v3\",\"scope\":{\"platform\":\"darwin\",\"catalogVersion\":\"ssc-init.catalog.v1\",\"projectRoots\":[\"$HOME/Projects\"],\"externalProbes\":false},\"coverage\":[{\"collector\":\"agents\",\"status\":\"complete\"}],\"evidenceCoverage\":{\"status\":\"complete\",\"targets\":[]},\"inventory\":{\"assets\":[],\"evidence\":[],\"relationships\":[]}}\n",
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
	app := App{Doctor: fakeDoctor{result: doctor.Result{SchemaVersion: "ssc-init.doctor.v1", Status: "ready"}}}
	var out, errOut bytes.Buffer
	if code := app.Run(context.Background(), []string{"doctor", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"schemaVersion":"ssc-init.doctor.v1"`) {
		t.Fatalf("stdout=%q", out.String())
	}
}

func TestOperationalCommandsFailGenericallyWhenDependencyMissing(t *testing.T) {
	for _, args := range [][]string{{"scan", "--baseline", "--json"}, {"status", "--json"}, {"doctor", "--json"}} {
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
	scan := model.ScanResult{SchemaVersion: "ssc-init.scan.v3"}
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
