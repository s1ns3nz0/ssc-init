package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

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
	parent := t.TempDir()
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
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
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
