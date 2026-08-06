package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/doctor"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/scan"
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
	if !strings.Contains(errOut.String(), "unknown command: wat") {
		t.Fatalf("stderr=%q", errOut.String())
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
	env := collector.Environment{
		Platform: "darwin",
		Scope: model.ScanScope{
			ProjectRoots: []string{"$HOME/Projects"},
		},
	}
	scanner := scan.NewService(orchestrator, snapshots, func() time.Time {
		return time.Unix(1_700_000_000, 0).UTC()
	}, func() string { return "00000000-0000-4000-8000-000000000001" }, env)
	app := App{Version: "test", BaselineScanner: scanner, StatusReader: snapshots, Doctor: fakeDoctor{}}
	var out, errOut bytes.Buffer

	code := app.Run(context.Background(), []string{"scan", "--baseline", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if strings.Contains(out.String(), "/raw/private/target") {
		t.Fatalf("local target leaked: %s", out.String())
	}
	if len(snapshots.saved) != 1 {
		t.Fatal("scan not persisted")
	}
	if snapshots.latest.Scan.SchemaVersion != "ssc-init.scan.v2" || len(snapshots.latest.Inventory.Assets) != 1 {
		t.Fatalf("snapshot=%+v", snapshots.latest)
	}
}

func TestStatusJSONHasStableEmptyV1AndV2Shapes(t *testing.T) {
	legacyInventory := model.Inventory{
		Assets:        []model.Asset{{ID: "tool:legacy", Type: model.AssetTool, Name: "legacy"}},
		Relationships: []model.Relationship{},
	}
	emptyInventory := model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}
	v2Scope := model.ScanScope{
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
			want:      "{\"schemaVersion\":\"ssc-init.status.v2\",\"initialized\":false}\n",
		},
		{
			name: "v1 legacy inventory",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v1",
					Scope:         v2Scope,
					Coverage:      []model.CollectorResult{{Collector: "must-not-be-synthesized", Status: model.CoverageComplete}},
				},
				Inventory: legacyInventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v2\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v1\",\"legacyInventory\":true,\"inventory\":{\"assets\":[{\"id\":\"tool:legacy\",\"type\":\"tool\",\"name\":\"legacy\"}],\"relationships\":[]}}\n",
		},
		{
			name: "v2 provenance",
			snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Snapshot{
				Scan: model.ScanResult{
					SchemaVersion: "ssc-init.scan.v2",
					Scope:         v2Scope,
					Coverage:      []model.CollectorResult{{Collector: "agents", Status: model.CoverageComplete}},
				},
				Inventory: emptyInventory,
			}},
			want: "{\"schemaVersion\":\"ssc-init.status.v2\",\"initialized\":true,\"inventorySchemaVersion\":\"ssc-init.scan.v2\",\"scope\":{\"platform\":\"darwin\",\"catalogVersion\":\"ssc-init.catalog.v1\",\"projectRoots\":[\"$HOME/Projects\"],\"externalProbes\":false},\"coverage\":[{\"collector\":\"agents\",\"status\":\"complete\"}],\"inventory\":{\"assets\":[],\"relationships\":[]}}\n",
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
