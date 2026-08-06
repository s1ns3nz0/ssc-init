package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
)

func TestMigrationFourAddsScopeAndObservationSchema(t *testing.T) {
	path := createDatabaseAtMigration(t, 3)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, table := range []string{"observations", "observation_state"} {
		assertTableExists(t, s.db, table)
	}
	assertColumnExists(t, s.db, "scans", "scope_json")
	assertColumnExists(t, s.db, "inventory_state", "observations_nil")
	assertColumnExists(t, s.db, "inventory_state", "observation_count")
}

func TestMigrationFourRollsBackAsOneTransaction(t *testing.T) {
	path := createDatabaseAtMigration(t, 3)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE observations (conflict TEXT)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(path); err == nil {
		reopened.Close()
		t.Fatal("conflicting migration unexpectedly opened")
	}

	db, err = sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var applied int
	if err := db.QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 3 {
		t.Fatalf("applied migration=%d want=3", applied)
	}
	assertColumnMissing(t, db, "scans", "scope_json")
	assertColumnMissing(t, db, "inventory_state", "observations_nil")
}

func TestMigrationFourPreservesLegacyV1Snapshot(t *testing.T) {
	path := createDatabaseAtMigration(t, 3)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scans(id, schema_version, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy", "ssc-init.scan.v1", "complete", formatTime(time.Unix(1, 0)), formatTime(time.Unix(2, 0))); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil, asset_count, relationship_count, error_count) VALUES (?, 1, 1, 1, 0, 0, 0)`, "legacy"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, ok, err := s.LatestSnapshot(context.Background())
	want := model.Snapshot{
		Scan: model.ScanResult{
			SchemaVersion: "ssc-init.scan.v1",
			ScanID:        "legacy",
			Status:        "complete",
			StartedAt:     time.Unix(1, 0).UTC(),
			FinishedAt:    time.Unix(2, 0).UTC(),
		},
		Inventory: model.Inventory{},
	}
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ok=%v\n got=%#v\nwant=%#v\nerr=%v", ok, got, want, err)
	}
}

func TestObservationAndScopeRoundTrip(t *testing.T) {
	s := openTestStore(t)
	scan := testScan("v2", time.Unix(2, 0).UTC())
	scan.SchemaVersion = "ssc-init.scan.v2"
	scan.Scope = model.ScanScope{Platform: "darwin", CatalogVersion: "ssc-init.catalog.v1", ProjectRoots: []string{"$HOME/Projects"}}
	scan.Coverage = []model.CollectorResult{{
		Collector: "packages",
		Status:    model.CoveragePartial,
		Targets: []model.TargetCoverage{{
			TargetID:     "packages.user-bin",
			InstanceRef:  "$HOME/bin",
			Status:       model.TargetComplete,
			Assets:       1,
			Observations: 2,
		}},
	}}
	first, err := identity.FinalizeObservation(model.Observation{
		AssetID: "a", Collector: "packages", Scope: model.ScopeToolEnvironment, LocationRef: "$HOME/bin/a",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := identity.FinalizeObservation(model.Observation{
		AssetID: "a", Collector: "packages", Scope: model.ScopeToolEnvironment, LocationRef: "$HOME/bin/alias-a", Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	second.Consumers = []string{}
	inventory := model.Inventory{
		Assets:        []model.Asset{{ID: "a", Type: model.AssetTool, Name: "a"}},
		Observations:  []model.Observation{second, first},
		Relationships: []model.Relationship{},
		Errors:        []model.CoverageError{},
	}
	if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	snapshot, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(snapshot, model.Snapshot{Scan: scan, Inventory: inventory}) {
		t.Fatalf("snapshot=%#v want=%#v", snapshot, model.Snapshot{Scan: scan, Inventory: inventory})
	}
}

func TestObservationInventoryShapeRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name         string
		observations []model.Observation
	}{
		{name: "nil"},
		{name: "empty", observations: []model.Observation{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			inventory := model.Inventory{Observations: tt.observations}
			if err := s.SaveScan(context.Background(), testScan("shape-"+tt.name, time.Unix(2, 0).UTC()), inventory); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.LatestSnapshot(context.Background())
			if err != nil || !ok || !reflect.DeepEqual(got.Inventory, inventory) {
				t.Fatalf("ok=%v got=%#v want=%#v err=%v", ok, got.Inventory, inventory, err)
			}
		})
	}
}

func TestSaveAndLoadLatestInventory(t *testing.T) {
	s, err := Open(filepath.Join(privateTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	want := model.Inventory{Assets: []model.Asset{{
		ID:       "mcp:cursor:fs",
		Type:     model.AssetMCP,
		Metadata: map[string]string{"env_keys": "TOKEN"},
	}}}
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v1",
		ScanID:        "scan-1",
		Status:        "complete",
		StartedAt:     time.Unix(1, 0).UTC(),
		FinishedAt:    time.Unix(2, 0).UTC(),
	}
	if err := s.SaveScan(context.Background(), scan, want); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ok=%v got=%+v err=%v", ok, got, err)
	}
	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestLatestInventoryEmptyStore(t *testing.T) {
	s := openTestStore(t)

	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || ok || !reflect.DeepEqual(got, model.Inventory{}) {
		t.Fatalf("ok=%v got=%+v err=%v", ok, got, err)
	}
}

func TestFullInventoryRoundTripPreservesShapeAndErrors(t *testing.T) {
	s := openTestStore(t)
	want := model.Inventory{
		Assets: []model.Asset{
			{ID: "asset-nil-metadata", Type: model.AssetProject, Name: "project", ObservedAt: time.Unix(12, 34).UTC()},
			{ID: "asset-empty-metadata", Type: model.AssetTool, Name: "tool", Metadata: map[string]string{}},
		},
		Relationships: []model.Relationship{
			{From: "asset-nil-metadata", To: "asset-empty-metadata", Kind: "contains"},
			{From: "asset-empty-metadata", To: "asset-nil-metadata", Kind: "uses"},
		},
		Errors: []model.CoverageError{{Code: "metadata-conflict", Message: "conflicting metadata values omitted", Path: "fingerprint"}},
	}
	scan := testScan("full", time.Unix(20, 0).UTC())
	scan.Coverage = []model.CollectorResult{{
		Collector: "projects",
		Status:    model.CoveragePartial,
		Errors:    []model.CoverageError{{Code: "read-failed", Message: "sanitized", Path: "safe/path"}},
	}}
	if err := s.SaveScan(context.Background(), scan, want); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ok=%v\n got=%#v\nwant=%#v\nerr=%v", ok, got, want, err)
	}
	var coverageJSON []byte
	if err := s.db.QueryRow(`SELECT result_json FROM coverage WHERE scan_id = ? AND collector = ?`, "full", "projects").Scan(&coverageJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(coverageJSON), `"message":"sanitized"`) {
		t.Fatalf("coverage JSON = %s", coverageJSON)
	}
}

func TestRoundTripPreservesNilAndEmptyInventorySlices(t *testing.T) {
	tests := []struct {
		name string
		want model.Inventory
	}{
		{name: "nil", want: model.Inventory{}},
		{name: "empty", want: model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}, Errors: []model.CoverageError{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			if err := s.SaveScan(context.Background(), testScan(tt.name, time.Unix(2, 0).UTC()), tt.want); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.LatestInventory(context.Background())
			if err != nil || !ok || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ok=%v got=%#v want=%#v err=%v", ok, got, tt.want, err)
			}
		})
	}
}

func TestDuplicateScanIsImmutable(t *testing.T) {
	s := openTestStore(t)
	scan := testScan("same", time.Unix(2, 0).UTC())
	original := model.Inventory{Assets: []model.Asset{{ID: "original", Type: model.AssetTool}}}
	if err := s.SaveScan(context.Background(), scan, original); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(context.Background(), scan, model.Inventory{Assets: []model.Asset{{ID: "replacement", Type: model.AssetTool}}}); err == nil {
		t.Fatal("duplicate scan unexpectedly succeeded")
	}
	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got, original) {
		t.Fatalf("ok=%v got=%#v err=%v", ok, got, err)
	}
}

func TestRowFailureRollsBackEveryTable(t *testing.T) {
	s := openTestStore(t)
	scan := testScan("rollback", time.Unix(2, 0).UTC())
	duplicateAssets := model.Inventory{Assets: []model.Asset{{ID: "duplicate"}, {ID: "duplicate"}}}
	if err := s.SaveScan(context.Background(), scan, duplicateAssets); err == nil {
		t.Fatal("duplicate asset unexpectedly succeeded")
	}
	for _, table := range []string{"scans", "assets", "asset_state", "relationships", "relationship_state", "coverage", "inventory_state", "inventory_errors"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after rollback", table, count)
		}
	}
}

func TestLatestInventoryBreaksFinishedAtTieByID(t *testing.T) {
	s := openTestStore(t)
	finished := time.Unix(30, 0).UTC()
	for _, id := range []string{"scan-a", "scan-z", "scan-m"} {
		want := model.Inventory{Assets: []model.Asset{{ID: id, Type: model.AssetTool}}}
		if err := s.SaveScan(context.Background(), testScan(id, finished), want); err != nil {
			t.Fatal(err)
		}
	}
	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || !ok || len(got.Assets) != 1 || got.Assets[0].ID != "scan-z" {
		t.Fatalf("ok=%v got=%#v err=%v", ok, got, err)
	}
}

func TestLatestInventoryOrdersFractionalFinishedTimesChronologically(t *testing.T) {
	s := openTestStore(t)
	base := time.Unix(30, 0).UTC()
	if err := s.SaveScan(context.Background(), testScan("whole-second", base), model.Inventory{Assets: []model.Asset{{ID: "older"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScan(context.Background(), testScan("fractional", base.Add(500*time.Millisecond)), model.Inventory{Assets: []model.Asset{{ID: "newer"}}}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LatestInventory(context.Background())
	if err != nil || !ok || len(got.Assets) != 1 || got.Assets[0].ID != "newer" {
		t.Fatalf("ok=%v got=%#v err=%v", ok, got, err)
	}
}

func TestCancelledContextStopsSaveAndLoad(t *testing.T) {
	s := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.SaveScan(ctx, testScan("cancelled", time.Unix(2, 0).UTC()), model.Inventory{}); !errorsIsContext(err) {
		t.Fatalf("SaveScan error = %v", err)
	}
	if _, _, err := s.LatestInventory(ctx); !errorsIsContext(err) {
		t.Fatalf("LatestInventory error = %v", err)
	}
}

func TestCorruptAssetJSONReturnsError(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveScan(context.Background(), testScan("corrupt", time.Unix(2, 0).UTC()), model.Inventory{Assets: []model.Asset{{ID: "asset"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE assets SET asset_json = ? WHERE scan_id = ?`, []byte(`{"id":`), "corrupt"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LatestInventory(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestLatestSnapshotRejectsNonObjectScopeJSON(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveScan(context.Background(), testScan("corrupt-scope", time.Unix(2, 0).UTC()), model.Inventory{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE scans SET scope_json = 'null' WHERE id = 'corrupt-scope'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LatestSnapshot(context.Background()); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("error=%v", err)
	}
}

func TestCorruptSnapshotStateReturnsError(t *testing.T) {
	t.Run("missing asset state", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.SaveScan(context.Background(), testScan("missing-state", time.Unix(2, 0).UTC()), model.Inventory{Assets: []model.Asset{{ID: "asset"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DELETE FROM asset_state WHERE scan_id = ?`, "missing-state"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LatestInventory(context.Background()); err == nil {
			t.Fatal("missing asset state unexpectedly loaded")
		}
	})
	t.Run("nil shape with rows", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.SaveScan(context.Background(), testScan("bad-shape", time.Unix(2, 0).UTC()), model.Inventory{Assets: []model.Asset{{ID: "asset"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`UPDATE inventory_state SET assets_nil = 1 WHERE scan_id = ?`, "bad-shape"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LatestInventory(context.Background()); err == nil {
			t.Fatal("inconsistent nil shape unexpectedly loaded")
		}
	})
}

func TestObservationCorruptionReturnsError(t *testing.T) {
	mutations := []struct {
		name       string
		statements []string
		want       string
	}{
		{name: "missing state", statements: []string{`DELETE FROM observation_state WHERE scan_id = 'corrupt-observation'`}, want: "missing observation state"},
		{name: "mismatched JSON id", statements: []string{`UPDATE observations SET observation_json = replace(observation_json, 'observation:sha256:', 'wrong:sha256:') WHERE scan_id = 'corrupt-observation'`}, want: "does not match row"},
		{name: "orphan asset id", statements: []string{`PRAGMA foreign_keys=OFF`, `UPDATE observations SET asset_id = 'missing' WHERE scan_id = 'corrupt-observation'`, `PRAGMA foreign_keys=ON`}, want: "missing asset"},
		{name: "invalid index", statements: []string{`UPDATE observation_state SET observation_index = 1 WHERE scan_id = 'corrupt-observation'`}, want: "got index 1, want 0"},
		{name: "row count mismatch", statements: []string{`UPDATE inventory_state SET observation_count = 2 WHERE scan_id = 'corrupt-observation'`}, want: "observation row count mismatch"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			s := openTestStore(t)
			observation, err := identity.FinalizeObservation(model.Observation{
				AssetID: "asset", Collector: "packages", Scope: model.ScopeUser, LocationRef: "$HOME/.tool",
			})
			if err != nil {
				t.Fatal(err)
			}
			inventory := model.Inventory{
				Assets:       []model.Asset{{ID: "asset", Type: model.AssetTool}},
				Observations: []model.Observation{observation},
			}
			if err := s.SaveScan(context.Background(), testScan("corrupt-observation", time.Unix(2, 0).UTC()), inventory); err != nil {
				t.Fatal(err)
			}
			for _, statement := range mutation.statements {
				if _, err := s.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := s.LatestSnapshot(context.Background()); err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("error=%v want substring %q", err, mutation.want)
			}
		})
	}
}

func TestObservationAndTargetValidationHappensBeforeTransaction(t *testing.T) {
	validObservation, err := identity.FinalizeObservation(model.Observation{
		AssetID: "asset", Collector: "packages", Scope: model.ScopeUser, LocationRef: "$HOME/.tool", Consumers: []string{"codex", "vscode"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		mutate    func(*model.ScanResult, *model.Inventory)
		wantError string
	}{
		{name: "duplicate id", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations = append(inventory.Observations, inventory.Observations[0])
		}, wantError: "duplicate inventory observation id"},
		{name: "missing asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].AssetID = "missing"
		}, wantError: "references missing asset"},
		{name: "invalid scope", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Scope = "invalid"
		}, wantError: "invalid observation scope"},
		{name: "unsorted consumers", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Consumers = []string{"vscode", "codex"}
		}, wantError: "sorted and unique"},
		{name: "duplicate consumers", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Consumers = []string{"codex", "codex"}
		}, wantError: "sorted and unique"},
		{name: "sensitive observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Source = "SERVICE_TOKEN=raw-value"
		}, wantError: ErrSensitiveSnapshot.Error()},
		{name: "invalid target status", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.Coverage = []model.CollectorResult{{Collector: "packages", Status: model.CoverageComplete, Targets: []model.TargetCoverage{{TargetID: "target", Status: "invalid"}}}}
		}, wantError: "invalid target status"},
		{name: "negative target assets", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.Coverage = []model.CollectorResult{{Collector: "packages", Status: model.CoverageComplete, Targets: []model.TargetCoverage{{TargetID: "target", Status: model.TargetComplete, Assets: -1}}}}
		}, wantError: "invalid target counts"},
		{name: "negative target observations", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.Coverage = []model.CollectorResult{{Collector: "packages", Status: model.CoverageComplete, Targets: []model.TargetCoverage{{TargetID: "target", Status: model.TargetComplete, Observations: -1}}}}
		}, wantError: "invalid target counts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			scan := testScan("invalid-observation", time.Unix(2, 0).UTC())
			inventory := model.Inventory{Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{validObservation}}
			tt.mutate(&scan, &inventory)
			if err := s.SaveScan(context.Background(), scan, inventory); err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error=%v want substring %q", err, tt.wantError)
			}
			assertNoSnapshotRows(t, s)
		})
	}
}

func TestObservationSnapshotRowFailureRollsBackEveryTable(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_inventory_state BEFORE INSERT ON inventory_state BEGIN SELECT RAISE(ABORT, 'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: "asset", Collector: "packages", Scope: model.ScopeUser, LocationRef: "$HOME/.tool",
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := testScan("atomic", time.Unix(2, 0).UTC())
	scan.Coverage = []model.CollectorResult{{Collector: "packages", Status: model.CoverageComplete}}
	inventory := model.Inventory{
		Assets:        []model.Asset{{ID: "asset"}},
		Observations:  []model.Observation{observation},
		Relationships: []model.Relationship{{From: "asset", Kind: "uses", To: "asset"}},
		Errors:        []model.CoverageError{{Code: "safe", Message: "safe"}},
	}
	if err := s.SaveScan(context.Background(), scan, inventory); err == nil {
		t.Fatal("forced row failure unexpectedly succeeded")
	}
	assertNoSnapshotRows(t, s)
}

func TestOpenAppliesMigrationsAndPragmas(t *testing.T) {
	s := openTestStore(t)
	var migrationsApplied int
	if err := s.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&migrationsApplied); err != nil {
		t.Fatal(err)
	}
	if migrationsApplied != len(migrations) {
		t.Fatalf("migrations = %d, want %d", migrationsApplied, len(migrations))
	}
	var foreignKeys, busyTimeout int
	var journalMode string
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 || busyTimeout != 5000 || journalMode != "wal" {
		t.Fatalf("foreign_keys=%d busy_timeout=%d journal_mode=%q", foreignKeys, busyTimeout, journalMode)
	}
	if _, err := s.db.Exec(`INSERT INTO assets(scan_id, asset_id, asset_json) VALUES ('missing', 'asset', '{}')`); err == nil {
		t.Fatal("foreign key violation unexpectedly succeeded")
	}
}

func TestOpenCreatesPrivateParentsAndDatabase(t *testing.T) {
	root := privateTempDir(t)
	parent := filepath.Join(root, "one", "two")
	path := filepath.Join(parent, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, directory := range []string{filepath.Join(root, "one"), parent} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode=%04o", directory, info.Mode().Perm())
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode=%04o", info.Mode().Perm())
	}
}

func TestOpenRefusesInsecureExistingParent(t *testing.T) {
	parent := canonicalTempDir(t)
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(filepath.Join(parent, "state.db"))
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error = %v", err)
	}
	info, statErr := os.Stat(parent)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("Open changed existing parent mode to %04o", info.Mode().Perm())
	}
}

func TestOpenRefusesSymlinkDatabaseAndParent(t *testing.T) {
	root := privateTempDir(t)
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Run("database", func(t *testing.T) {
		target := filepath.Join(realParent, "target.db")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(realParent, "link.db")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("parent", func(t *testing.T) {
		link := filepath.Join(root, "linked-parent")
		if err := os.Symlink(realParent, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(filepath.Join(link, "state.db")); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestOpenRefusesNonRegularDatabase(t *testing.T) {
	parent := privateTempDir(t)
	path := filepath.Join(parent, "state.db")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenEscapesFilenameQueryCharacters(t *testing.T) {
	parent := privateTempDir(t)
	path := filepath.Join(parent, "state.db?_pragma=foreign_keys(0)#fragment")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	var foreignKeys int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys=%d", foreignKeys)
	}
}

func TestOpenDetectsInjectedPathReplacement(t *testing.T) {
	parent := privateTempDir(t)
	path := filepath.Join(parent, "state.db")
	testHookAfterDatabaseGuard = func(path string) error {
		if err := os.Rename(path, path+".guarded"); err != nil {
			return err
		}
		return os.WriteFile(path, nil, 0o600)
	}
	t.Cleanup(func() { testHookAfterDatabaseGuard = nil })
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "pathname changed") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("replacement pathname was incorrectly removed: %v", err)
	}
}

func TestSQLiteFilesRemainPrivate(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveScan(context.Background(), testScan("sidecars", time.Unix(2, 0).UTC()), model.Inventory{Assets: []model.Asset{{ID: "asset"}}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.Path(), s.Path() + "-wal", s.Path() + "-shm"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%04o", path, info.Mode().Perm())
		}
	}
}

func TestSaveRejectsSensitiveSnapshotsWithoutRows(t *testing.T) {
	markers := []string{
		"ghp_123456789012345678901234567890123456",
		"xoxb-1234567890-abcdefghij",
		"sk-123456789012345678901234567890",
		"AKIA1234567890ABCDEF",
		"npm_123456789012345678901234567890",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
		"-----BEGIN PRIVATE KEY-----",
		"https://user:password@example.test/path",
		"https://example.test/path?access_token=raw-value",
		"Authorization: Bearer abcdefghijklmnop",
		"SERVICE_TOKEN=raw-value",
	}
	for index, marker := range markers {
		t.Run(fmt.Sprintf("marker-%d", index), func(t *testing.T) {
			s := openTestStore(t)
			scan := testScan("sensitive", time.Unix(2, 0).UTC())
			inventory := model.Inventory{Assets: []model.Asset{{ID: "asset", Name: marker}}}
			if err := s.SaveScan(context.Background(), scan, inventory); !errors.Is(err, ErrSensitiveSnapshot) || err.Error() != ErrSensitiveSnapshot.Error() {
				t.Fatalf("error = %v", err)
			}
			assertNoSnapshotRows(t, s)
		})
	}
	t.Run("sensitive metadata key", func(t *testing.T) {
		s := openTestStore(t)
		inventory := model.Inventory{Assets: []model.Asset{{ID: "asset", Metadata: map[string]string{"raw_token": "value"}}}}
		if err := s.SaveScan(context.Background(), testScan("metadata", time.Unix(2, 0).UTC()), inventory); !errors.Is(err, ErrSensitiveSnapshot) {
			t.Fatalf("error = %v", err)
		}
		assertNoSnapshotRows(t, s)
	})
}

func TestSecretValidationURIAndSafeListBoundaries(t *testing.T) {
	t.Run("safe username-only URIs and key lists", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("safe-boundaries", time.Unix(2, 0).UTC())
		scan.Coverage = []model.CollectorResult{{
			Collector: "mcp", Status: model.CoverageComplete,
			Assets: []model.Asset{{ID: "coverage", Source: "ssh://git@github.com/repo"}},
		}}
		inventory := model.Inventory{Assets: []model.Asset{{
			ID: "inventory", Source: "https://user@example.test/path", Metadata: map[string]string{"env_keys": "GITHUB_TOKEN,HOME"},
		}}}
		if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
			t.Fatal(err)
		}
	})
	for _, tt := range []struct {
		name     string
		coverage string
		metadata string
	}{
		{name: "fragment access token", coverage: "https://example.test/callback#access_token=raw-value"},
		{name: "fragment bearer", coverage: "https://example.test/callback#authorization=Bearer%20abcdefghijklmnop"},
		{name: "malformed safe list assignment", metadata: "GITHUB_TOKEN=raw-secret"},
		{name: "token marker in safe list", metadata: "ghp_123456789012345678901234567890123456"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			scan := testScan("unsafe-boundary", time.Unix(2, 0).UTC())
			inventory := model.Inventory{Assets: []model.Asset{{ID: "inventory", Metadata: map[string]string{"env_keys": tt.metadata}}}}
			if tt.coverage != "" {
				scan.Coverage = []model.CollectorResult{{Collector: "mcp", Status: model.CoverageComplete, Assets: []model.Asset{{ID: "coverage", Source: tt.coverage}}}}
				inventory.Assets[0].Metadata = nil
			}
			if err := s.SaveScan(context.Background(), scan, inventory); !errors.Is(err, ErrSensitiveSnapshot) {
				t.Fatalf("error = %v", err)
			}
			assertNoSnapshotRows(t, s)
		})
	}
}

func TestRedactionPlaceholderSemantics(t *testing.T) {
	placeholders := []string{"[redacted]", "[REDACTED]", "redacted", "REDACTED"}
	for _, placeholder := range placeholders {
		t.Run("safe-"+strings.ReplaceAll(placeholder, "[", "bracket-"), func(t *testing.T) {
			s := openTestStore(t)
			scan := testScan("safe-placeholder", time.Unix(2, 0).UTC())
			scan.Coverage = []model.CollectorResult{{
				Collector: "mcp", Status: model.CoverageComplete,
				Assets: []model.Asset{{ID: "query", Source: "https://example.test/?access_token=" + url.QueryEscape(placeholder)}},
			}}
			inventory := model.Inventory{Assets: []model.Asset{
				{ID: "fragment", Source: "https://example.test/#access_token=" + url.QueryEscape(placeholder)},
				{ID: "metadata", Metadata: map[string]string{"raw_token": placeholder}},
				{ID: "safe-list", Metadata: map[string]string{"env_keys": placeholder}},
			}}
			if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
				t.Fatalf("placeholder %q rejected: %v", placeholder, err)
			}
		})
	}
	for _, nearMiss := range []string{"REDACTED-secret", "[REDACTED]-secret", "prefix-redacted", "raw-secret"} {
		t.Run("reject-"+nearMiss, func(t *testing.T) {
			s := openTestStore(t)
			inventory := model.Inventory{Assets: []model.Asset{{ID: "asset", Metadata: map[string]string{"raw_token": nearMiss}}}}
			if err := s.SaveScan(context.Background(), testScan("near-miss", time.Unix(2, 0).UTC()), inventory); !errors.Is(err, ErrSensitiveSnapshot) {
				t.Fatalf("near miss %q error = %v", nearMiss, err)
			}
			assertNoSnapshotRows(t, s)
		})
	}
}

func TestConcurrentCloseAndOperations(t *testing.T) {
	s := openTestStore(t)
	var sequence atomic.Int64
	var wg sync.WaitGroup
	errorsOut := make(chan error, 256)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 20; attempt++ {
				id := fmt.Sprintf("scan-%d", sequence.Add(1))
				err := s.SaveScan(context.Background(), testScan(id, time.Unix(sequence.Load()+10, 0).UTC()), model.Inventory{Assets: []model.Asset{{ID: id}}})
				if err != nil && !errors.Is(err, ErrStoreClosed) {
					errorsOut <- err
				}
				if _, _, err := s.LatestInventory(context.Background()); err != nil && !errors.Is(err, ErrStoreClosed) {
					errorsOut <- err
				}
			}
		}()
	}
	for closer := 0; closer < 8; closer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Close(); err != nil {
				errorsOut <- err
			}
		}()
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Errorf("concurrent operation: %v", err)
	}
	if err := s.SaveScan(context.Background(), testScan("after-close", time.Unix(100, 0).UTC()), model.Inventory{}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("SaveScan after close error = %v", err)
	}
	if _, _, err := s.LatestInventory(context.Background()); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("LatestInventory after close error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("repeated Close error = %v", err)
	}
}

func TestSaveRejectsInvalidShapeWithoutRows(t *testing.T) {
	s := openTestStore(t)
	invalid := model.Inventory{
		Assets:        []model.Asset{{ID: "asset"}},
		Relationships: []model.Relationship{{From: "asset", Kind: "uses", To: "missing"}},
	}
	if err := s.SaveScan(context.Background(), testScan("invalid", time.Unix(2, 0).UTC()), invalid); err == nil {
		t.Fatal("invalid relationship unexpectedly saved")
	}
	assertNoSnapshotRows(t, s)
}

func TestLatestInventoryRejectsDeletedSnapshotRows(t *testing.T) {
	deletions := []struct {
		name       string
		statements []string
	}{
		{name: "asset", statements: []string{`DELETE FROM asset_state WHERE asset_id = 'b'`, `DELETE FROM assets WHERE asset_id = 'b'`}},
		{name: "relationship", statements: []string{`DELETE FROM relationship_state WHERE relationship_index = 1`, `DELETE FROM relationships WHERE kind = 'second'`}},
		{name: "error", statements: []string{`DELETE FROM inventory_errors WHERE error_index = 1`}},
	}
	for _, deletion := range deletions {
		t.Run(deletion.name, func(t *testing.T) {
			s := openTestStore(t)
			inventory := model.Inventory{
				Assets: []model.Asset{{ID: "a"}, {ID: "b"}},
				Relationships: []model.Relationship{
					{From: "a", Kind: "first", To: "b"},
					{From: "b", Kind: "second", To: "a"},
				},
				Errors: []model.CoverageError{{Code: "one", Message: "one"}, {Code: "two", Message: "two"}},
			}
			if err := s.SaveScan(context.Background(), testScan("counts", time.Unix(2, 0).UTC()), inventory); err != nil {
				t.Fatal(err)
			}
			for _, statement := range deletion.statements {
				if _, err := s.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := s.LatestInventory(context.Background()); err == nil || !strings.Contains(err.Error(), "count mismatch") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOpenRejectsMalformedMigrationHistoryAndSchema(t *testing.T) {
	tests := []struct {
		name   string
		mutate string
	}{
		{name: "negative", mutate: `UPDATE schema_migrations SET version = -1 WHERE version = 1`},
		{name: "gap", mutate: `DELETE FROM schema_migrations WHERE version = 2`},
		{name: "future", mutate: `UPDATE schema_migrations SET version = 99 WHERE version = 3`},
		{name: "missing table", mutate: `DROP TABLE coverage`},
		{name: "extra column", mutate: `ALTER TABLE coverage ADD COLUMN unexpected TEXT`},
		{name: "wrong index order", mutate: `DROP INDEX scans_latest_idx; CREATE INDEX scans_latest_idx ON scans(id, finished_at)`},
		{name: "unexpected observation index", mutate: `CREATE INDEX unexpected_observation_idx ON observations(asset_id)`},
		{name: "unexpected trigger", mutate: `CREATE TRIGGER unexpected_scan_trigger AFTER INSERT ON scans BEGIN SELECT 1; END`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "state.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tt.mutate); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path); err == nil {
				reopened.Close()
				t.Fatal("malformed migration state unexpectedly opened")
			}
		})
	}
	for _, tt := range []struct {
		name, table, old, replacement string
	}{
		{name: "wrong type", table: "assets", old: "asset_json BLOB NOT NULL", replacement: "asset_json TEXT NOT NULL"},
		{name: "wrong nullability", table: "scans", old: "status TEXT NOT NULL", replacement: "status TEXT"},
		{name: "wrong default", table: "inventory_state", old: "asset_count INTEGER NOT NULL DEFAULT 0", replacement: "asset_count INTEGER NOT NULL DEFAULT 1"},
		{name: "wrong primary key order", table: "relationships", old: "PRIMARY KEY (scan_id, from_id, kind, to_id)", replacement: "PRIMARY KEY (from_id, scan_id, kind, to_id)"},
		{name: "wrong foreign key", table: "coverage", old: "REFERENCES scans(id)", replacement: "REFERENCES scans(status)"},
		{name: "wrong check", table: "asset_state", old: "CHECK (asset_index >= 0)", replacement: "CHECK (asset_index >= -1)"},
		{name: "wrong observation default", table: "inventory_state", old: "observations_nil INTEGER NOT NULL DEFAULT 1", replacement: "observations_nil INTEGER NOT NULL DEFAULT 0"},
		{name: "wrong observation check", table: "observation_state", old: "CHECK (consumers_nil IN (0, 1))", replacement: "CHECK (consumers_nil IN (0, 2))"},
		{name: "wrong observation foreign key", table: "observations", old: "FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)", replacement: "FOREIGN KEY (scan_id, asset_id) REFERENCES assets(asset_id, scan_id)"},
		{name: "split composite foreign key", table: "asset_state", old: "FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)", replacement: "FOREIGN KEY (asset_id) REFERENCES assets(asset_id), FOREIGN KEY (scan_id) REFERENCES assets(scan_id)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "state.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`PRAGMA writable_schema=ON`); err != nil {
				t.Fatal(err)
			}
			result, err := s.db.Exec(`UPDATE sqlite_master SET sql = replace(sql, ?, ?) WHERE type = 'table' AND name = ?`, tt.old, tt.replacement, tt.table)
			if err != nil {
				t.Fatal(err)
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				t.Fatalf("affected=%d", affected)
			}
			if _, err := s.db.Exec(`PRAGMA writable_schema=OFF`); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path); err == nil {
				reopened.Close()
				t.Fatal("incompatible schema unexpectedly opened")
			}
		})
	}
}

func assertNoSnapshotRows(t *testing.T, s *Store) {
	t.Helper()
	for _, table := range []string{"scans", "assets", "observations", "observation_state", "relationships", "coverage", "inventory_errors", "inventory_state"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s contains %d rows", table, count)
		}
	}
}

func createDatabaseAtMigration(t *testing.T, version int) string {
	t.Helper()
	if version < 1 || version > len(migrations) {
		t.Fatalf("invalid migration version %d", version)
	}
	path := filepath.Join(privateTempDir(t), "state.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	for index, statement := range migrations[:version] {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		if _, err := tx.Exec(statement); err != nil {
			_ = tx.Rollback()
			db.Close()
			t.Fatalf("apply migration %d: %v", index+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, index+1, formatTime(time.Unix(int64(index+1), 0))); err != nil {
			_ = tx.Rollback()
			db.Close()
			t.Fatalf("record migration %d: %v", index+1, err)
		}
		if err := tx.Commit(); err != nil {
			db.Close()
			t.Fatalf("commit migration %d: %v", index+1, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("table %q does not exist", table)
	}
}

func assertColumnExists(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	if !columnExists(t, db, table, column) {
		t.Fatalf("column %q does not exist in table %q", column, table)
	}
}

func assertColumnMissing(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	if columnExists(t, db, table, column) {
		t.Fatalf("column %q unexpectedly exists in table %q", column, table)
	}
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info("` + strings.ReplaceAll(table, `"`, `""`) + `")`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(privateTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil && err != sql.ErrConnDone {
			t.Errorf("close store: %v", err)
		}
	})
	return s
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := canonicalTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

// canonicalTempDir resolves macOS's system /var alias in test fixtures. The
// production path traversal intentionally never follows aliases.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func testScan(id string, finishedAt time.Time) model.ScanResult {
	return model.ScanResult{
		SchemaVersion: "ssc-init.scan.v1",
		ScanID:        id,
		Status:        "complete",
		StartedAt:     finishedAt.Add(-time.Second),
		FinishedAt:    finishedAt,
	}
}

func errorsIsContext(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
