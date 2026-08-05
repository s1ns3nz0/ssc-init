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
	latest    model.Inventory
	hasLatest bool
	saved     []model.ScanResult
}

func (m *cliMemorySnapshots) SaveScan(_ context.Context, result model.ScanResult, _ model.Inventory) error {
	m.saved = append(m.saved, result)
	return nil
}

func (m *cliMemorySnapshots) LatestInventory(context.Context) (model.Inventory, bool, error) {
	return m.latest, m.hasLatest, nil
}

type cliCollector struct {
	name   string
	result model.CollectorResult
	err    error
}

func (c cliCollector) Name() string { return c.name }
func (c cliCollector) Collect(context.Context, collector.Environment) (model.CollectorResult, error) {
	return c.result, c.err
}

type fakeDoctor struct{ result doctor.Result }

func (d fakeDoctor) Check(context.Context) doctor.Result { return d.result }

func TestBaselineJSONReportsPartialCoverageAndPersists(t *testing.T) {
	snapshots := &cliMemorySnapshots{}
	orchestrator := collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 2, Collectors: []collector.Collector{
		cliCollector{name: "agents", result: model.CollectorResult{Status: model.CoverageComplete}},
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
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(want) {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if len(snapshots.saved) != 1 {
		t.Fatal("scan not persisted")
	}
}

func TestStatusJSONHasStableEmptyAndInitializedShapes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		snapshots   *cliMemorySnapshots
		initialized bool
	}{
		{name: "empty", snapshots: &cliMemorySnapshots{}, initialized: false},
		{name: "initialized", snapshots: &cliMemorySnapshots{hasLatest: true, latest: model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}}, initialized: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := App{StatusReader: tc.snapshots}
			var out, errOut bytes.Buffer
			if code := app.Run(context.Background(), []string{"status", "--json"}, &out, &errOut); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, errOut.String())
			}
			var got struct {
				SchemaVersion string           `json:"schemaVersion"`
				Initialized   bool             `json:"initialized"`
				Inventory     *model.Inventory `json:"inventory"`
			}
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != "ssc-init.status.v1" || got.Initialized != tc.initialized {
				t.Fatalf("status=%+v", got)
			}
			if (got.Inventory != nil) != tc.initialized {
				t.Fatalf("inventory=%+v initialized=%v", got.Inventory, tc.initialized)
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
