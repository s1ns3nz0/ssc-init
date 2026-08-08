package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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

	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
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

func TestMigration5AddsEvidenceAndContentCacheSchema(t *testing.T) {
	path := createDatabaseAtMigration(t, 4)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var applied int
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(migrations) {
		t.Fatalf("applied migration=%d want=%d", applied, len(migrations))
	}
	for _, table := range []string{"evidence", "evidence_state", "evidence_coverage", "content_cache"} {
		assertTableExists(t, s.db, table)
	}
	for table, columns := range map[string][]string{
		"evidence":          {"scan_id", "evidence_id", "asset_id", "observation_id", "evidence_json"},
		"evidence_state":    {"scan_id", "evidence_id", "evidence_index", "metadata_nil", "errors_nil"},
		"evidence_coverage": {"scan_id", "result_json"},
		"content_cache":     {"cache_key", "algorithm", "format", "digest", "size", "last_used_at"},
		"inventory_state":   {"evidence_nil", "evidence_count"},
	} {
		for _, column := range columns {
			assertColumnExists(t, s.db, table, column)
		}
	}
}

func TestMigration5RollsBackAsOneTransaction(t *testing.T) {
	path := createDatabaseAtMigration(t, 4)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE content_cache (conflict TEXT)`); err != nil {
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
	if applied != 4 {
		t.Fatalf("applied migration=%d want=4", applied)
	}
	assertColumnMissing(t, db, "inventory_state", "evidence_nil")
	assertColumnMissing(t, db, "inventory_state", "evidence_count")
	for _, table := range []string{"evidence", "evidence_state", "evidence_coverage"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("table %q unexpectedly exists after rollback", table)
		}
	}
}

func TestMigration5PreservesLegacyV2Snapshot(t *testing.T) {
	path := createDatabaseAtMigration(t, 4)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scans(id, schema_version, status, started_at, finished_at, scope_json) VALUES (?, ?, ?, ?, ?, '{}')`,
		"legacy-v2", "ssc-init.scan.v2", "complete", formatTime(time.Unix(1, 0)), formatTime(time.Unix(2, 0))); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil, asset_count, relationship_count, error_count, observations_nil, observation_count) VALUES (?, 1, 1, 1, 0, 0, 0, 1, 0)`, "legacy-v2"); err != nil {
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
			SchemaVersion: "ssc-init.scan.v2",
			ScanID:        "legacy-v2",
			Status:        "complete",
			StartedAt:     time.Unix(1, 0).UTC(),
			FinishedAt:    time.Unix(2, 0).UTC(),
		},
		Inventory: model.Inventory{},
	}
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ok=%v\n got=%#v\nwant=%#v\nerr=%v", ok, got, want, err)
	}
	if got.Inventory.Evidence != nil {
		t.Fatal("legacy snapshot loaded a non-nil evidence slice")
	}
	if !reflect.DeepEqual(got.Scan.EvidenceCoverage, model.EvidenceCoverage{}) {
		t.Fatalf("legacy snapshot implied evidence coverage: %#v", got.Scan.EvidenceCoverage)
	}
}

func TestEvidenceSchemaRejectsIncompatibleShapes(t *testing.T) {
	for _, tt := range []struct {
		name, table, old, replacement string
	}{
		{name: "split evidence asset foreign key", table: "evidence",
			old:         "FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)",
			replacement: "FOREIGN KEY (asset_id) REFERENCES assets(asset_id), FOREIGN KEY (scan_id) REFERENCES assets(scan_id)"},
		{name: "reordered evidence observation foreign key", table: "evidence",
			old:         "FOREIGN KEY (scan_id, observation_id) REFERENCES observations(scan_id, observation_id)",
			replacement: "FOREIGN KEY (scan_id, observation_id) REFERENCES observations(observation_id, scan_id)"},
		{name: "cross-scan evidence asset foreign key", table: "evidence",
			old:         "FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)",
			replacement: "FOREIGN KEY (observation_id, asset_id) REFERENCES assets(scan_id, asset_id)"},
		{name: "wrong evidence index check", table: "evidence_state",
			old:         "CHECK (evidence_index >= 0)",
			replacement: "CHECK (evidence_index >= -1)"},
		{name: "wrong evidence unique index", table: "evidence_state",
			old:         "UNIQUE (scan_id, evidence_index)",
			replacement: "UNIQUE (evidence_index)"},
		{name: "wrong evidence state foreign key", table: "evidence_state",
			old:         "REFERENCES evidence(scan_id, evidence_id)",
			replacement: "REFERENCES evidence(evidence_id, scan_id)"},
		{name: "wrong coverage foreign key", table: "evidence_coverage",
			old:         "REFERENCES scans(id)",
			replacement: "REFERENCES scans(status)"},
		{name: "wrong evidence nil default", table: "inventory_state",
			old:         "evidence_nil INTEGER NOT NULL DEFAULT 1",
			replacement: "evidence_nil INTEGER NOT NULL DEFAULT 0"},
		{name: "wrong evidence count check", table: "inventory_state",
			old:         "CHECK (evidence_count >= 0)",
			replacement: "CHECK (evidence_count >= -1)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertRewrittenSchemaRejected(t, tt.table, tt.old, tt.replacement)
		})
	}
}

func TestContentCacheSchemaRejectsIncompatibleShapes(t *testing.T) {
	for _, tt := range []struct {
		name, table, old, replacement string
	}{
		{name: "wrong key type", table: "content_cache",
			old:         "cache_key BLOB PRIMARY KEY",
			replacement: "cache_key TEXT PRIMARY KEY"},
		{name: "wrong key length check", table: "content_cache",
			old:         "CHECK (length(cache_key) = 32)",
			replacement: "CHECK (length(cache_key) = 31)"},
		{name: "wrong size check", table: "content_cache",
			old:         "CHECK (size >= 0)",
			replacement: "CHECK (size >= -1)"},
		{name: "wrong nullability", table: "content_cache",
			old:         "digest TEXT NOT NULL",
			replacement: "digest TEXT"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertRewrittenSchemaRejected(t, tt.table, tt.old, tt.replacement)
		})
	}
}

func assertRewrittenSchemaRejected(t *testing.T, table, old, replacement string) {
	t.Helper()
	path := filepath.Join(privateTempDir(t), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`PRAGMA writable_schema=ON`); err != nil {
		t.Fatal(err)
	}
	result, err := s.db.Exec(`UPDATE sqlite_master SET sql = replace(sql, ?, ?) WHERE type = 'table' AND name = ?`, old, replacement, table)
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

func TestLatestSnapshotPreservesCoverageNilAndEmptyShapes(t *testing.T) {
	s := openTestStore(t)
	nilShape, err := identity.FinalizeObservation(model.Observation{
		AssetID: "nil-shape", Collector: "packages", Scope: model.ScopeUser, LocationRef: "$HOME/bin/nil-shape",
	})
	if err != nil {
		t.Fatal(err)
	}
	emptyShape, err := identity.FinalizeObservation(model.Observation{
		AssetID: "empty-shape", Collector: "packages", Scope: model.ScopeUser, LocationRef: "$HOME/bin/empty-shape",
		Consumers: []string{}, Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	emptyShape.Consumers = []string{}
	emptyShape.Metadata = map[string]string{}

	scan := testScan("coverage-shapes", time.Unix(2, 0).UTC())
	scan.Coverage = []model.CollectorResult{
		{Collector: "agents", Status: model.CoverageComplete},
		{
			Collector: "packages",
			Status:    model.CoveragePartial,
			Assets: []model.Asset{
				{ID: "nil-shape", Type: model.AssetTool},
				{ID: "empty-shape", Type: model.AssetTool, Metadata: map[string]string{}},
			},
			Relationships: []model.Relationship{},
			Errors:        []model.CoverageError{},
			Targets: []model.TargetCoverage{
				{TargetID: "nil-errors", Status: model.TargetComplete},
				{TargetID: "empty-errors", Status: model.TargetComplete, Errors: []model.CoverageError{}},
			},
			Observations: []model.Observation{nilShape, emptyShape},
			LocalTargets: []model.LocalTarget{{TargetID: "must-not-persist", Path: "$HOME/private-runtime-path"}},
		},
		{
			Collector:     "projects",
			Status:        model.CoverageComplete,
			Assets:        []model.Asset{},
			Relationships: []model.Relationship{},
			Errors:        []model.CoverageError{},
			Targets:       []model.TargetCoverage{},
			Observations:  []model.Observation{},
			LocalTargets:  []model.LocalTarget{},
		},
	}
	wantScan := scan
	wantScan.Coverage = append([]model.CollectorResult(nil), scan.Coverage...)
	wantScan.Coverage[1].LocalTargets = nil
	wantScan.Coverage[2].LocalTargets = nil
	if err := s.SaveScan(context.Background(), scan, model.Inventory{}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got.Scan, wantScan) {
		t.Fatalf("ok=%v\n got=%#v\nwant=%#v\nerr=%v", ok, got.Scan, wantScan, err)
	}
	var encoded []byte
	if err := s.db.QueryRow(`SELECT result_json FROM coverage WHERE scan_id = ? AND collector = ?`, scan.ScanID, "packages").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("must-not-persist")) || bytes.Contains(encoded, []byte("private-runtime-path")) {
		t.Fatalf("coverage JSON persisted local target: %s", encoded)
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

func TestCoverageAllowsOnlyIdenticalSameIDCandidateAssets(t *testing.T) {
	t.Run("identical candidates", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("identical-candidates", time.Unix(2, 0).UTC())
		candidate := model.Asset{ID: "mcp:shared:same", Type: model.AssetMCP, Name: "same", Source: "shared"}
		scan.Coverage = []model.CollectorResult{{
			Collector: "mcp", Status: model.CoverageComplete,
			Assets: []model.Asset{candidate, candidate},
		}}
		if err := s.SaveScan(context.Background(), scan, model.Inventory{Assets: []model.Asset{candidate}}); err != nil {
			t.Fatal(err)
		}
		latest, ok, err := s.LatestSnapshot(context.Background())
		if err != nil || !ok || !reflect.DeepEqual(latest.Scan, scan) {
			t.Fatalf("ok=%v latest=%#v scan=%#v err=%v", ok, latest, scan, err)
		}
	})

	t.Run("conflicting candidates", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("conflicting-candidates", time.Unix(2, 0).UTC())
		scan.Coverage = []model.CollectorResult{{
			Collector: "mcp", Status: model.CoverageComplete,
			Assets: []model.Asset{
				{ID: "mcp:shared:same", Type: model.AssetMCP, Name: "same", Source: "shared"},
				{ID: "mcp:shared:same", Type: model.AssetMCP, Name: "different", Source: "shared"},
			},
		}}
		if err := s.SaveScan(context.Background(), scan, model.Inventory{}); err == nil {
			t.Fatal("conflicting same-ID coverage candidates unexpectedly persisted")
		}
		if _, ok, err := s.LatestSnapshot(context.Background()); err != nil || ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
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
	for _, table := range []string{"scans", "assets", "asset_state", "relationships", "relationship_state", "coverage", "evidence", "evidence_state", "evidence_coverage", "inventory_state", "inventory_errors"} {
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

func TestSaveScanRejectsUndocumentedStatus(t *testing.T) {
	t.Run("save", func(t *testing.T) {
		s := openTestStore(t)
		scan, inventory := validV3Snapshot(t, "undocumented-status")
		scan.Status = "ok"
		if err := s.SaveScan(context.Background(), scan, inventory); err == nil {
			t.Fatal("SaveScan accepted an undocumented status")
		}
		assertNoSnapshotRows(t, s)
	})
	t.Run("load", func(t *testing.T) {
		s := openTestStore(t)
		saveValidV3Snapshot(t, s, "undocumented-status")
		if _, err := s.db.Exec(`UPDATE scans SET status = 'ok'`); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := s.LatestSnapshot(context.Background()); err == nil || ok {
			t.Fatalf("LatestSnapshot accepted an undocumented status: ok=%v error=%v", ok, err)
		}
	})
}

func TestValidateSnapshotRejectsRawAbsolutePersistedPathFields(t *testing.T) {
	for _, testCase := range persistedRawPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			scan, inventory := persistenceSafePathFixture()
			testCase.mutate(&scan, &inventory, persistedRawPathSentinel)
			err := validateSnapshot(scan, inventory)
			if err == nil {
				t.Fatal("raw absolute path unexpectedly validated")
			}
			if strings.Contains(err.Error(), persistedRawPathSentinel) {
				t.Fatalf("validation error exposed raw path: %v", err)
			}
		})
	}
}

func TestValidateSnapshotRejectsCanonicalEncodedPathCorpus(t *testing.T) {
	for _, testCase := range canonicalEncodedPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			scan, inventory := persistenceSafePathFixture()
			inventory.Assets[0].Metadata["entry_point"] = testCase.value

			if err := validateSnapshot(scan, inventory); !errors.Is(err, errUnsafeSnapshotPath) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidateSnapshotMetadataPathKeyBoundaries(t *testing.T) {
	for _, key := range []string{
		"args", "command", "command_basename", "cwd_ref", "entry_point", "manifest_path",
		"path", "probe_source", "ref", "root_ref", "runtime_source", "symlink_chain",
	} {
		t.Run("path-"+key, func(t *testing.T) {
			scan, inventory := persistenceSafePathFixture()
			inventory.Assets[0].Metadata[key] = persistedRawPathSentinel
			if err := validateSnapshot(scan, inventory); !errors.Is(err, errUnsafeSnapshotPath) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, key := range []string{"path_id", "ref_target", "command_type", "entry_point_name", "symlink_kind", "args_id"} {
		t.Run("opaque-"+key, func(t *testing.T) {
			scan, inventory := persistenceSafePathFixture()
			inventory.Assets[0].Metadata[key] = persistedRawPathSentinel
			if err := validateSnapshot(scan, inventory); err != nil {
				t.Fatalf("opaque metadata value rejected: %v", err)
			}
		})
	}
}

func TestSaveRejectsCanonicalEncodedPathCorpusAtomicallyWithoutPersistingBytes(t *testing.T) {
	for _, testCase := range canonicalEncodedPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			s := openTestStore(t)
			scan, inventory := persistenceSafePathFixture()
			inventory.Assets[0].Metadata["entry_point"] = testCase.value

			if err := s.SaveScan(context.Background(), scan, inventory); !errors.Is(err, errUnsafeSnapshotPath) {
				t.Fatalf("error = %v", err)
			}
			assertNoSnapshotRows(t, s)
			assertSQLiteFilesExclude(t, s.Path(), testCase.value)
		})
	}
}

func TestLatestSnapshotRejectsCorruptedCanonicalEncodedPathCorpus(t *testing.T) {
	for _, testCase := range canonicalEncodedPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			s := openTestStore(t)
			scan, inventory := persistenceSafePathFixture()
			if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
				t.Fatal(err)
			}

			inventory.Assets[0].Metadata["entry_point"] = testCase.value
			corruptPersistedPathCase(t, s, "inventory-asset", scan, inventory)
			if _, ok, err := s.LatestSnapshot(context.Background()); err == nil || ok {
				t.Fatalf("ok=%v error=%v", ok, err)
			}
		})
	}
}

func TestSaveRejectsRawAbsolutePersistedPathFieldsAtomicallyWithoutPersistingBytes(t *testing.T) {
	for _, testCase := range persistedRawPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			s := openTestStore(t)
			scan, inventory := persistenceSafePathFixture()
			testCase.mutate(&scan, &inventory, persistedRawPathSentinel)

			err := s.SaveScan(context.Background(), scan, inventory)
			if err == nil {
				t.Fatal("raw absolute path unexpectedly saved")
			}
			if strings.Contains(err.Error(), persistedRawPathSentinel) {
				t.Fatalf("save error exposed raw path: %v", err)
			}
			assertNoSnapshotRows(t, s)
			assertSQLiteFilesExclude(t, s.Path(), persistedRawPathSentinel)
		})
	}
}

func TestLatestSnapshotRejectsManuallyCorruptedRawAbsolutePersistedPathFields(t *testing.T) {
	for _, testCase := range persistedRawPathCases() {
		t.Run(testCase.name, func(t *testing.T) {
			s := openTestStore(t)
			scan, inventory := persistenceSafePathFixture()
			if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&scan, &inventory, persistedRawPathSentinel)
			corruptPersistedPathCase(t, s, testCase.storage, scan, inventory)

			_, ok, err := s.LatestSnapshot(context.Background())
			if err == nil || ok {
				t.Fatalf("ok=%v error=%v", ok, err)
			}
			if strings.Contains(err.Error(), persistedRawPathSentinel) {
				t.Fatalf("load error exposed raw path: %v", err)
			}
		})
	}
}

func TestValidateSnapshotAllowsApprovedReferencesAndLegitimateNonPathValues(t *testing.T) {
	digestRef := "external-ide/path-sha256:" + strings.Repeat("a", 64)
	for _, testCase := range []struct {
		name   string
		mutate func(*model.ScanResult, *model.Inventory)
	}{
		{name: "home project root", mutate: func(scan *model.ScanResult, _ *model.Inventory) { scan.Scope.ProjectRoots[0] = "$HOME/Projects" }},
		{name: "generic external project root", mutate: func(scan *model.ScanResult, _ *model.Inventory) { scan.Scope.ProjectRoots[0] = "external-root-1" }},
		{name: "home location reference", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].LocationRef = "$HOME/.tool"
		}},
		{name: "hashed location reference", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].LocationRef = digestRef
		}},
		{name: "generic probe reference", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].LocationRef = "probe-target:packages.pip"
		}},
		{name: "relative manifest path", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["manifest_path"] = "extension/package.json"
		}},
		{name: "relative entrypoint", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "dist/extension.js"
		}},
		{name: "URL entrypoint", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "https://example.test/Volumes/extension.js;mode=/Volumes/safe"
		}},
		{name: "HTTP percent-encoded path", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "https://example.test/%2FVolumes/safe?root=%2FVolumes%2Fsafe"
		}},
		{name: "embedded HTTP command argument", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["command"] = `runner --url="https://example.test/Volumes/safe?root=/Volumes/safe"`
		}},
		{name: "npm PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0"
		}},
		{name: "scoped npm PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:npm/%40scope/tool@2.0.0"
		}},
		{name: "pypi PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:pypi/requests@2.32.3"
		}},
		{name: "cargo PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:cargo/ripgrep@14.1.0"
		}},
		{name: "brew PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:brew/openssl%403@3.3.2"
		}},
		{name: "docker PURL metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:docker/library/alpine@3.20"
		}},
		{name: "command basename", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["command"] = "python3"
		}},
		{name: "safe JSON args", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["args"] = `["--root","$HOME/Projects","https://example.test/Volumes/safe","pkg:npm/example@1.0.0"]`
		}},
		{name: "safe nested JSON refs", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["args"] = `{"config":{"entry":"dist/extension.js","ref":"external-ide/path-sha256:` + strings.Repeat("b", 64) + `"}}`
		}},
		{name: "HTTPS location reference", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].LocationRef = "https://example.test/Volumes/tool?root=/Volumes/safe"
		}},
		{name: "PURL with qualifiers and subpath", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0?arch=arm64&os=darwin#dist/bin"
		}},
		{name: "safe JSON object keys and values", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["args"] = `{"dist/config.json":{"nested":"relative/value"}}`
		}},
		{name: "safe literal percent", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "100%"
		}},
		{name: "safe malformed percent literal", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["entry_point"] = "%ZZ"
		}},
		{name: "probe source identifier metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["probe_source_id"] = "/Volumes/opaque-identifier"
		}},
		{name: "source target metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["source_target"] = "/Volumes/opaque-identifier"
		}},
		{name: "source type metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["artifact_source_type"] = "/Volumes/opaque-identifier"
		}},
		{name: "source kind metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["runtime_source_kind"] = "/Volumes/opaque-identifier"
		}},
		{name: "source name metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["package_source_name"] = "/Volumes/opaque-identifier"
		}},
		{name: "unrelated build source metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["build_source"] = "/Volumes/opaque-identifier"
		}},
		{name: "probe source label metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Observations[0].Metadata["probe_source_label"] = "/Volumes/opaque-identifier"
		}},
		{name: "unrelated metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Assets[0].Metadata["publisher"] = "/Volumes/private-is-a-publisher"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scan, inventory := persistenceSafePathFixture()
			testCase.mutate(&scan, &inventory)
			if err := validateSnapshot(scan, inventory); err != nil {
				t.Fatalf("safe reference rejected: %v", err)
			}
		})
	}
}

func TestApprovedPackageReferenceRequiresConformantLocalPURLGrammar(t *testing.T) {
	for _, testCase := range []struct {
		value string
		want  bool
	}{
		{value: "pkg:npm/example@1.0.0", want: true},
		{value: "pkg:npm/%40scope/tool@2.0.0", want: true},
		{value: "pkg:pypi/requests@2.32.3", want: true},
		{value: "pkg:cargo/ripgrep@14.1.0", want: true},
		{value: "pkg:brew/openssl%403@3.3.2", want: true},
		{value: "pkg:docker/library/alpine@3.20", want: true},
		{value: "pkg:npm/example@1.0.0?arch=arm64&os=darwin#dist/bin", want: true},
		{value: "pkg:NPM/example@1.0.0"},
		{value: "pkg:npm//example@1.0.0"},
		{value: "pkg:npm/example@"},
		{value: "pkg:npm/example@1.0.0?arch="},
		{value: "pkg:npm/example@1.0.0?arch=arm64&arch=x86_64"},
		{value: "pkg:npm/example@1.0.0#dist/../private"},
		{value: "pkg:npm/example%2Fprivate@1.0.0"},
		{value: "pkg:npm/example@feature%2Fbranch"},
		{value: "pkg:npm/example@1.0.0?arch=arm%2F64"},
		{value: "pkg:npm/example@1.0.0?root=/Volumes/private"},
		{value: "pkg:npm/example@1.0.0?root=%2FVolumes%2Fprivate"},
		{value: "pkg:npm/example@1.0.0#/Volumes/private"},
		{value: "pkg:npm/example@%2FVolumes%2Fprivate"},
		{value: "pkg:npm/%252FVolumes%252Fprivate@1.0.0"},
		{value: "pkg:npm/example@1.0.0#%252e%252e/Volumes/private"},
		{value: "pkg:npm/%FF@1.0.0"},
		{value: "pkg:npm/example@%00"},
		{value: "pkg:npm/example@1.0.0?arch=%1F"},
		{value: "pkg:npm/example@1.0.0#file:/Volumes/private"},
		{value: "pkg:npm/%25ZZfile%3Arelative@1.0.0"},
		{value: "pkg:npm/example@1.0.0|/Volumes/private"},
		{value: "pkg:npm/%GGexample@1.0.0"},
	} {
		if got := approvedPackageReference(testCase.value); got != testCase.want {
			t.Errorf("approvedPackageReference(%q)=%v want %v", testCase.value, got, testCase.want)
		}
	}
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
	for _, table := range []string{"scans", "assets", "observations", "observation_state", "evidence", "evidence_state", "evidence_coverage", "relationships", "coverage", "inventory_errors", "inventory_state", "asset_history"} {
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

const persistedRawPathSentinel = "/Volumes/ssc-init-final-review-private-marker"

type canonicalEncodedPathCase struct {
	name  string
	value string
}

func canonicalEncodedPathCases() []canonicalEncodedPathCase {
	return []canonicalEncodedPathCase{
		{name: "mixed malformed encoded absolute", value: "%ZZ%2FVolumes%2Fprivate"},
		{name: "mixed malformed encoded file URI", value: "%ZZfile%3A%2F%2FVolumes%2Fprivate"},
		{name: "mixed malformed double-encoded absolute", value: "prefix=%ZZ%252FVolumes%252Fprivate"},
		{name: "PURL double-encoded name absolute", value: "pkg:npm/%252FVolumes%252Fprivate@1.0.0"},
		{name: "PURL double-encoded subpath traversal", value: "pkg:npm/example@1.0.0#%252e%252e/Volumes/private"},
		{name: "PURL invalid UTF-8 name", value: "pkg:npm/%FF@1.0.0"},
		{name: "PURL NUL version", value: "pkg:npm/example@%00"},
		{name: "PURL control qualifier", value: "pkg:npm/example@1.0.0?arch=%1F"},
		{name: "PURL local file subpath", value: "pkg:npm/example@1.0.0#file:/Volumes/private"},
		{name: "terminal malformed escape masks absolute", value: "prefix=%25ZZ%2FVolumes%2Fprivate"},
		{name: "terminal malformed escape masks PURL local file", value: "pkg:npm/%25ZZfile%3Arelative@1.0.0"},
		{name: "final round malformed escape masks absolute", value: "%252525ZZ%25252FVolumes%25252Fprivate"},
	}
}

type persistedPathCase struct {
	name    string
	storage string
	mutate  func(*model.ScanResult, *model.Inventory, string)
}

func persistedRawPathCases() []persistedPathCase {
	cases := []persistedPathCase{
		{name: "scope project root", storage: "scope", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) { scan.Scope.ProjectRoots[0] = raw }},
		{name: "inventory asset path", storage: "inventory-asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) { inventory.Assets[0].Path = raw }},
		{name: "inventory asset manifest metadata", storage: "inventory-asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Assets[0].Metadata["manifest_path"] = raw
		}},
		{name: "inventory asset entrypoint metadata", storage: "inventory-asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Assets[0].Metadata["entry_point"] = raw
		}},
		{name: "inventory observation location", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].LocationRef = raw
		}},
		{name: "inventory observation root metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["root_ref"] = raw
		}},
		{name: "inventory observation cwd metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["cwd_ref"] = raw
		}},
		{name: "inventory observation symlink metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["symlink_chain"] = "$HOME/bin/tool\x1f" + raw
		}},
		{name: "inventory observation command metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["command"] = "runner " + raw
		}},
		{name: "inventory observation args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = "--root=" + raw
		}},
		{name: "inventory observation command basename metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["command_basename"] = raw
		}},
		{name: "inventory observation probe source metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["probe_source"] = raw
		}},
		{name: "inventory observation command prefix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["command_alias"] = raw
		}},
		{name: "inventory observation command suffix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["resolved_command"] = raw
		}},
		{name: "inventory observation args suffix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["runtime_args"] = `["--root","` + raw + `"]`
		}},
		{name: "inventory observation source suffix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["runtime_source"] = raw
		}},
		{name: "inventory observation path prefix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["path_hint"] = raw
		}},
		{name: "inventory observation ref prefix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["ref_value"] = raw
		}},
		{name: "inventory observation entrypoint suffix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["extension_entry_point"] = raw
		}},
		{name: "inventory observation symlink suffix metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["runtime_symlink"] = raw
		}},
		{name: "inventory observation JSON args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = `["--root","` + raw + `"]`
		}},
		{name: "inventory observation JSON string args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = `"` + raw + `"`
		}},
		{name: "inventory observation nested JSON args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = `{"config":{"argv":["--root","` + raw + `"]}}`
		}},
		{name: "inventory observation JSON object key args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = `{"` + raw + `":"safe"}`
		}},
		{name: "inventory observation nested JSON object key args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["args"] = `{"config":{"` + raw + `":"safe"}}`
		}},
		{name: "inventory observation deeply nested JSON args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, _ string) {
			inventory.Observations[0].Metadata["args"] = strings.Repeat("[", 65) + `"safe"` + strings.Repeat("]", 65)
		}},
		{name: "inventory observation oversized args metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, _ string) {
			inventory.Observations[0].Metadata["args"] = strings.Repeat("a", (64<<10)+1)
		}},
		{name: "inventory observation punctuated command metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["command"] = `("--root":"` + raw + `")`
		}},
		{name: "inventory observation malformed PURL metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["entry_point"] = "pkg:" + raw
		}},
		{name: "inventory observation PURL suffix path metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0|" + raw
		}},
		{name: "inventory observation PURL qualifier path metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0?root=" + raw
		}},
		{name: "inventory observation PURL encoded qualifier path metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0?root=" + strings.ReplaceAll(raw, "/", "%2F")
		}},
		{name: "inventory observation PURL subpath path metadata", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].Metadata["entry_point"] = "pkg:npm/example@1.0.0#" + raw
		}},
		{name: "inventory observation file URI location", storage: "inventory-observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Observations[0].LocationRef = "file://" + raw
		}},
		{name: "inventory asset localhost file URI path", storage: "inventory-asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
			inventory.Assets[0].Path = "file://localhost" + raw
		}},
		{name: "inventory error path", storage: "inventory-error", mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) { inventory.Errors[0].Path = raw }},
		{name: "coverage asset path", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) { scan.Coverage[0].Assets[0].Path = raw }},
		{name: "coverage asset metadata", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Assets[0].Metadata["manifest_path"] = raw
		}},
		{name: "coverage observation location", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Observations[0].LocationRef = raw
		}},
		{name: "coverage observation metadata", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Observations[0].Metadata["cwd_ref"] = raw
		}},
		{name: "coverage result error path", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) { scan.Coverage[0].Errors[0].Path = raw }},
		{name: "coverage target instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = raw
		}},
		{name: "coverage target short file URI instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = "file:" + raw
		}},
		{name: "coverage target uppercase file URI instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = "FILE://" + raw
		}},
		{name: "coverage target encoded file URI instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = "file:" + strings.ReplaceAll(raw, "/", "%2F")
		}},
		{name: "coverage target encoded file scheme instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = "file%3A%2F%2F" + strings.TrimPrefix(strings.ReplaceAll(raw, "/", "%2F"), "%2F")
		}},
		{name: "coverage target mixed-case encoded file scheme instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = "f%69le%3a%2F%2f" + strings.TrimPrefix(strings.ReplaceAll(raw, "/", "%2F"), "%2F")
		}},
		{name: "coverage target double-encoded file URI instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			doubleEncoded := strings.ReplaceAll(strings.ReplaceAll(raw, "%", "%25"), "/", "%252F")
			scan.Coverage[0].Targets[0].InstanceRef = "file%253A%252F%252F" + strings.TrimPrefix(doubleEncoded, "%252F")
		}},
		{name: "coverage target encoded absolute instance", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].InstanceRef = strings.ReplaceAll(raw, "/", "%2F")
		}},
		{name: "coverage target error path", storage: "coverage", mutate: func(scan *model.ScanResult, _ *model.Inventory, raw string) {
			scan.Coverage[0].Targets[0].Errors[0].Path = raw
		}},
	}

	for _, punctuation := range []struct {
		name   string
		prefix string
		suffix string
	}{
		{name: "question mark", prefix: "?"},
		{name: "hash", prefix: "#"},
		{name: "ampersand", prefix: "&"},
		{name: "backslash", prefix: `\`},
		{name: "pipe", prefix: "|"},
		{name: "comma", prefix: ","},
		{name: "colon", prefix: ":"},
		{name: "equals", prefix: "="},
		{name: "brackets", prefix: "[", suffix: "]"},
		{name: "parentheses", prefix: "(", suffix: ")"},
		{name: "braces", prefix: "{", suffix: "}"},
		{name: "closing brace", prefix: "}"},
		{name: "angle brackets", prefix: "<", suffix: ">"},
		{name: "at sign", prefix: "@"},
		{name: "single quotes", prefix: `'`, suffix: `'`},
		{name: "quotes", prefix: `"`, suffix: `"`},
	} {
		punctuation := punctuation
		cases = append(cases, persistedPathCase{
			name:    "inventory observation command punctuation " + punctuation.name,
			storage: "inventory-observation",
			mutate: func(_ *model.ScanResult, inventory *model.Inventory, raw string) {
				inventory.Observations[0].Metadata["command"] = "runner" + punctuation.prefix + raw + punctuation.suffix
			},
		})
	}
	return cases
}

func persistenceSafePathFixture() (model.ScanResult, model.Inventory) {
	scan := testScan("path-validation", time.Unix(2, 0).UTC())
	scan.Scope = model.ScanScope{
		Platform: "darwin", CatalogVersion: "ssc-init.catalog.v1", ProjectRoots: []string{"$HOME/Projects"},
	}
	scan.Coverage = []model.CollectorResult{{
		Collector: "packages", Status: model.CoverageComplete,
		Assets: []model.Asset{{ID: "coverage-asset", Type: model.AssetTool, Name: "coverage", Metadata: map[string]string{"manifest_path": "bin/tool"}}},
		Observations: []model.Observation{{
			ID: "coverage-observation", AssetID: "coverage-asset", Collector: "packages",
			Scope: model.ScopeToolEnvironment, LocationRef: "$HOME/bin/coverage", Metadata: map[string]string{"cwd_ref": "config-relative/work"},
		}},
		Errors: []model.CoverageError{{Code: "coverage-warning", Message: "coverage warning", Path: "relative/evidence"}},
		Targets: []model.TargetCoverage{{
			TargetID: "packages.pip", InstanceRef: "probe-target:packages.pip", Status: model.TargetPartial,
			Assets: 1, Observations: 1, Errors: []model.CoverageError{{Code: "target-warning", Message: "target warning", Path: "$HOME/bin/python3"}},
		}},
	}}
	inventory := model.Inventory{
		Assets: []model.Asset{{ID: "inventory-asset", Type: model.AssetTool, Name: "inventory", Metadata: map[string]string{"manifest_path": "bin/tool"}}},
		Observations: []model.Observation{{
			ID: "inventory-observation", AssetID: "inventory-asset", Collector: "packages",
			Scope: model.ScopeToolEnvironment, LocationRef: "$HOME/bin/inventory", Metadata: map[string]string{"cwd_ref": "config-relative/work"},
		}},
		Errors: []model.CoverageError{{Code: "inventory-warning", Message: "inventory warning", Path: "relative/evidence"}},
	}
	return scan, inventory
}

func corruptPersistedPathCase(t *testing.T, s *Store, storage string, scan model.ScanResult, inventory model.Inventory) {
	t.Helper()
	var statement string
	var encoded []byte
	var err error
	switch storage {
	case "scope":
		statement = `UPDATE scans SET scope_json = ? WHERE id = ?`
		encoded, err = json.Marshal(scan.Scope)
	case "inventory-asset":
		statement = `UPDATE assets SET asset_json = ? WHERE scan_id = ?`
		encoded, err = json.Marshal(inventory.Assets[0])
	case "inventory-observation":
		statement = `UPDATE observations SET observation_json = ? WHERE scan_id = ?`
		encoded, err = json.Marshal(inventory.Observations[0])
	case "inventory-error":
		statement = `UPDATE inventory_errors SET error_json = ? WHERE scan_id = ?`
		encoded, err = json.Marshal(inventory.Errors[0])
	case "coverage":
		statement = `UPDATE coverage SET result_json = ? WHERE scan_id = ?`
		encoded, err = encodeCoverage(scan.Coverage[0])
	default:
		t.Fatalf("unknown storage %q", storage)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(statement, encoded, scan.ScanID); err != nil {
		t.Fatal(err)
	}
}

func assertSQLiteFilesExclude(t *testing.T, databasePath, forbidden string) {
	t.Helper()
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		contents, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte(forbidden)) {
			t.Fatalf("raw path persisted in %s", filepath.Base(path))
		}
	}
}

func saveSnapshotAt(t *testing.T, s *Store, scanID string, finishedAt, now time.Time) {
	t.Helper()
	scan, inventory := validV3Snapshot(t, scanID)
	scan.StartedAt, scan.FinishedAt = finishedAt.Add(-time.Second), finishedAt
	if err := s.saveScanAt(context.Background(), scan, inventory, now); err != nil {
		t.Fatal(err)
	}
}

func snapshotCount(t *testing.T, s *Store) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM scans`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// scanChildTables reads every table carrying a scan_id column straight from
// the live schema, so a table added later cannot silently escape the orphan
// assertion below.
func scanChildTables(t *testing.T, s *Store) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT m.name FROM sqlite_master m JOIN pragma_table_info(m.name) c
WHERE m.type = 'table' AND c.name = 'scan_id' ORDER BY m.name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(tables) < 12 {
		t.Fatalf("schema exposed %d scan_id tables, want at least 12: %v", len(tables), tables)
	}
	return tables
}

func TestSaveScanPrunesSnapshotsBeyondRetention(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index, age := range []time.Duration{90 * 24 * time.Hour, 60 * 24 * time.Hour, time.Hour} {
		saveSnapshotAt(t, s, fmt.Sprintf("retention-%d", index), now.Add(-age), now)
	}
	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}
	snapshot, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("load surviving snapshot: ok=%v err=%v", ok, err)
	}
	if snapshot.Scan.ScanID != "retention-2" {
		t.Fatalf("retention kept scan %q, want %q", snapshot.Scan.ScanID, "retention-2")
	}
}

func TestSaveScanKeepsNewestSnapshotBeyondRetention(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "retention-ancient", now.Add(-365*24*time.Hour), now)
	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}
	snapshot, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("retention deleted the only snapshot: ok=%v err=%v", ok, err)
	}
	if snapshot.Scan.ScanID != "retention-ancient" {
		t.Fatalf("retention kept scan %q, want %q", snapshot.Scan.ScanID, "retention-ancient")
	}
}

func TestSaveScanRetentionLeavesNoOrphanRows(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index, age := range []time.Duration{200 * 24 * time.Hour, 90 * 24 * time.Hour, 31 * 24 * time.Hour, time.Hour} {
		saveSnapshotAt(t, s, fmt.Sprintf("orphan-%d", index), now.Add(-age), now)
	}
	for _, table := range scanChildTables(t, s) {
		var orphans int
		if err := s.db.QueryRow(`SELECT count(*) FROM "` + table + `" WHERE scan_id NOT IN (SELECT id FROM scans)`).Scan(&orphans); err != nil {
			t.Fatal(err)
		}
		if orphans != 0 {
			t.Fatalf("table %s kept %d orphan rows", table, orphans)
		}
	}
	var rows int
	if err := s.db.QueryRow(`SELECT count(*) FROM evidence`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 4 {
		t.Fatalf("evidence table holds %d rows, want 4 (one surviving snapshot)", rows)
	}
}

// TestSaveScanKeepsSnapshotsInsideRetentionWindow pins the window itself. The
// tests above only exercise snapshots that survive by being newest, so without
// this one a zero-length retention window would still pass the suite.
func TestSaveScanKeepsSnapshotsInsideRetentionWindow(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index, age := range []time.Duration{29 * 24 * time.Hour, 15 * 24 * time.Hour, 24 * time.Hour, 0} {
		saveSnapshotAt(t, s, fmt.Sprintf("window-%d", index), now.Add(-age), now)
	}
	if remaining := snapshotCount(t, s); remaining != 4 {
		t.Fatalf("retention kept %d snapshots inside the 30-day window, want 4", remaining)
	}
}

func TestSaveScanKeepsSnapshotExactlyAtRetentionEdge(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "edge-old", now.Add(-defaultSnapshotRetention), now)
	saveSnapshotAt(t, s, "edge-new", now, now)
	if remaining := snapshotCount(t, s); remaining != 2 {
		t.Fatalf("retention kept %d snapshots, want 2 (edge snapshot must be retained)", remaining)
	}
}

// TestSaveScanPruneRollsBackWithTheInsert catches a prune hoisted ahead of the
// insert: the pruning clock would then not see the new baseline.
func TestSaveScanPruneRollsBackWithTheInsert(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "atomic-old", now.Add(-90*24*time.Hour), now.Add(-90*24*time.Hour))
	saveSnapshotAt(t, s, "atomic-mid", now.Add(-60*24*time.Hour), now.Add(-60*24*time.Hour))
	before := snapshotCount(t, s)
	scan, inventory := validV3Snapshot(t, "atomic-mid") // duplicate id: save must fail
	scan.StartedAt, scan.FinishedAt = now.Add(-time.Second), now
	if err := s.saveScanAt(context.Background(), scan, inventory, now); err == nil {
		t.Fatal("expected duplicate scan id to fail")
	}
	if after := snapshotCount(t, s); after != before {
		t.Fatalf("failed save pruned snapshots anyway: %d -> %d", before, after)
	}
}

// TestSaveScanFailedPruneRollsBackTheInsert catches the opposite hoist: a prune
// moved after the commit would leave a store pruned but without the baseline it
// was pruned for. A trigger fails the prune's final DELETE, so the save must
// report failure and leave the previous snapshot as the newest one.
func TestSaveScanFailedPruneRollsBackTheInsert(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "blocked-old", now.Add(-90*24*time.Hour), now.Add(-90*24*time.Hour))
	if _, err := s.db.Exec(`CREATE TRIGGER block_prune BEFORE DELETE ON scans BEGIN SELECT raise(ABORT, 'prune blocked'); END`); err != nil {
		t.Fatal(err)
	}
	scan, inventory := validV3Snapshot(t, "blocked-new")
	scan.StartedAt, scan.FinishedAt = now.Add(-time.Second), now
	if err := s.saveScanAt(context.Background(), scan, inventory, now); err == nil {
		t.Fatal("expected a blocked prune to fail the save")
	}
	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("failed prune left %d snapshots, want 1 (the insert must roll back with it)", remaining)
	}
	var surviving string
	if err := s.db.QueryRow(`SELECT id FROM scans`).Scan(&surviving); err != nil {
		t.Fatal(err)
	}
	if surviving != "blocked-old" {
		t.Fatalf("failed save persisted scan %q", surviving)
	}
}

// bulkySnapshot pads a valid v3 snapshot with filler assets so each saved
// snapshot occupies enough database pages for a file-size change to be
// observable at page granularity.
func bulkySnapshot(t *testing.T, scanID string, finishedAt time.Time) (model.ScanResult, model.Inventory) {
	t.Helper()
	scan, inventory := validV3Snapshot(t, scanID)
	scan.StartedAt, scan.FinishedAt = finishedAt.Add(-time.Second), finishedAt
	filler := strings.Repeat("f", 512)
	for index := 0; index < 200; index++ {
		inventory.Assets = append(inventory.Assets, model.Asset{
			ID:       fmt.Sprintf("filler-%s-%d", scanID, index),
			Type:     model.AssetAgentPlugin,
			Name:     fmt.Sprintf("filler-%d", index),
			Metadata: map[string]string{"note": filler},
		})
	}
	return scan, inventory
}

// storeDiskBytes reports the store's full on-disk footprint, which is what the
// design's storage budget bounds: the main database plus its write-ahead log.
func storeDiskBytes(t *testing.T, s *Store) int64 {
	t.Helper()
	var total int64
	for _, suffix := range []string{"", "-wal"} {
		info, err := os.Stat(s.Path() + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	return total
}

func TestSaveScanRetentionReclaimsFileSpace(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var peak int64
	for index := 0; index < 20; index++ {
		scan, inventory := bulkySnapshot(t, fmt.Sprintf("reclaim-%d", index), now.Add(-time.Duration(29-index)*24*time.Hour))
		if err := s.saveScanAt(context.Background(), scan, inventory, now); err != nil {
			t.Fatal(err)
		}
		if size := storeDiskBytes(t, s); size > peak {
			peak = size
		}
	}
	later := now.Add(60 * 24 * time.Hour)
	scan, inventory := bulkySnapshot(t, "reclaim-fresh", later)
	if err := s.saveScanAt(context.Background(), scan, inventory, later); err != nil {
		t.Fatal(err)
	}
	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}
	if size := storeDiskBytes(t, s); size >= peak {
		t.Fatalf("store occupies %d bytes after pruning 20 snapshots, want less than the %d byte peak", size, peak)
	}
}

// assetHistoryRow reads one history row. Absence is reported rather than
// fatal so pruning assertions can distinguish "deleted" from "never written".
func assetHistoryRow(t *testing.T, s *Store, assetID string) (firstSeen, lastSeen, digest, changedAt string, ok bool) {
	t.Helper()
	err := s.db.QueryRow(`SELECT first_seen_at, last_seen_at, content_digest, content_changed_at FROM asset_history WHERE asset_id = ?`, assetID).
		Scan(&firstSeen, &lastSeen, &digest, &changedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return firstSeen, lastSeen, digest, changedAt, true
}

// saveHistorySnapshot saves a valid v3 snapshot carrying one extra evidence-free
// asset, so a later snapshot can drop that asset and leave only its history.
func saveHistorySnapshot(t *testing.T, s *Store, scanID, extraAssetID, digest string, finishedAt, now time.Time) {
	t.Helper()
	scan, inventory := validV3Snapshot(t, scanID)
	scan.StartedAt, scan.FinishedAt = finishedAt.Add(-time.Second), finishedAt
	if digest != "" {
		for index, evidence := range inventory.Evidence {
			if evidence.Status == model.EvidenceComplete {
				inventory.Evidence[index].Digest = digest
			}
		}
	}
	if extraAssetID != "" {
		inventory.Assets = append(inventory.Assets, model.Asset{ID: extraAssetID, Type: model.AssetPackage, Name: "extra"})
	}
	if err := s.saveScanAt(context.Background(), scan, inventory, now); err != nil {
		t.Fatal(err)
	}
}

func TestSaveScanRecordsAssetHistoryAcrossDigestTransitions(t *testing.T) {
	s := openTestStore(t)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "history-1", "", strings.Repeat("a", 64), first, first)
	firstSeen, lastSeen, digest, changedAt, ok := assetHistoryRow(t, s, "asset-one")
	if !ok {
		t.Fatal("first scan recorded no asset history")
	}
	if firstSeen != formatTime(first) || lastSeen != formatTime(first) || changedAt != formatTime(first) {
		t.Fatalf("first=%q last=%q changed=%q, want all %q", firstSeen, lastSeen, changedAt, formatTime(first))
	}
	if digest == "" {
		t.Fatal("asset with complete evidence recorded no content digest")
	}

	unchanged := first.Add(24 * time.Hour)
	saveHistorySnapshot(t, s, "history-2", "", strings.Repeat("a", 64), unchanged, unchanged)
	gotFirst, gotLast, gotDigest, gotChanged, _ := assetHistoryRow(t, s, "asset-one")
	if gotFirst != formatTime(first) {
		t.Fatalf("first seen moved to %q, want %q", gotFirst, formatTime(first))
	}
	if gotLast != formatTime(unchanged) {
		t.Fatalf("last seen = %q, want %q", gotLast, formatTime(unchanged))
	}
	if gotDigest != digest || gotChanged != formatTime(first) {
		t.Fatalf("unchanged content reported a transition: digest=%q changed=%q", gotDigest, gotChanged)
	}

	changed := first.Add(48 * time.Hour)
	saveHistorySnapshot(t, s, "history-3", "", strings.Repeat("c", 64), changed, changed)
	gotFirst, gotLast, gotDigest, gotChanged, _ = assetHistoryRow(t, s, "asset-one")
	if gotFirst != formatTime(first) {
		t.Fatalf("first seen moved to %q, want %q", gotFirst, formatTime(first))
	}
	if gotLast != formatTime(changed) || gotChanged != formatTime(changed) {
		t.Fatalf("last=%q changed=%q, want %q", gotLast, gotChanged, formatTime(changed))
	}
	if gotDigest == digest {
		t.Fatal("content digest did not follow the evidence digest")
	}
}

func TestAssetHistorySurvivesSnapshotPruning(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	aged := now.Add(-31 * 24 * time.Hour)
	saveHistorySnapshot(t, s, "history-aged", "removed-asset", "", aged, aged)
	saveHistorySnapshot(t, s, "history-fresh", "", "", now, now)

	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}
	var assetRows int
	if err := s.db.QueryRow(`SELECT count(*) FROM assets WHERE asset_id = ?`, "removed-asset").Scan(&assetRows); err != nil {
		t.Fatal(err)
	}
	if assetRows != 0 {
		t.Fatalf("pruned snapshot left %d asset rows", assetRows)
	}
	firstSeen, lastSeen, _, _, ok := assetHistoryRow(t, s, "removed-asset")
	if !ok {
		t.Fatal("history did not survive the pruning of the snapshot that produced it")
	}
	if firstSeen != formatTime(aged) || lastSeen != formatTime(aged) {
		t.Fatalf("first=%q last=%q, want %q", firstSeen, lastSeen, formatTime(aged))
	}
}

func TestSaveScanPrunesAssetHistoryBeyondNinetyDays(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ancient := now.Add(-100 * 24 * time.Hour)
	recent := now.Add(-80 * 24 * time.Hour)
	saveHistorySnapshot(t, s, "history-ancient", "ancient-asset", "", ancient, ancient)
	saveHistorySnapshot(t, s, "history-recent", "recent-asset", "", recent, recent)
	saveHistorySnapshot(t, s, "history-now", "", "", now, now)

	if _, _, _, _, ok := assetHistoryRow(t, s, "ancient-asset"); ok {
		t.Fatal("history last seen 100 days ago survived the 90 day window")
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "recent-asset"); !ok {
		t.Fatal("history last seen 80 days ago was pruned inside the 90 day window")
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "asset-one"); !ok {
		t.Fatal("history for a currently present asset was pruned")
	}
}

// saveHistorySnapshotWithoutCompleteEvidence saves a snapshot in which
// asset-one's complete evidence and its coverage target are dropped, leaving
// the asset present but carrying only non-complete evidence: exactly the shape
// a target that became unreadable on a later scan produces.
func saveHistorySnapshotWithoutCompleteEvidence(t *testing.T, s *Store, scanID string, finishedAt, now time.Time) {
	t.Helper()
	scan, inventory := validV3Snapshot(t, scanID)
	scan.StartedAt, scan.FinishedAt = finishedAt.Add(-time.Second), finishedAt
	kept := make([]model.ContentEvidence, 0, len(inventory.Evidence))
	removed := ""
	for _, evidence := range inventory.Evidence {
		if evidence.AssetID == "asset-one" && evidence.Status == model.EvidenceComplete {
			removed = evidence.ID
			continue
		}
		kept = append(kept, evidence)
	}
	if removed == "" {
		t.Fatal("fixture carries no complete evidence for asset-one")
	}
	inventory.Evidence = kept
	targets := make([]model.EvidenceTargetResult, 0, len(scan.EvidenceCoverage.Targets))
	for _, target := range scan.EvidenceCoverage.Targets {
		if target.EvidenceID == removed {
			continue
		}
		targets = append(targets, target)
	}
	scan.EvidenceCoverage.Targets = targets
	if err := s.saveScanAt(context.Background(), scan, inventory, now); err != nil {
		t.Fatal(err)
	}
}

// TestSaveScanEmptyDigestNeverOverwritesKnownDigest pins two rules the upsert
// promises in its comment: a scan that produces no trusted digest for an asset
// neither erases the last known digest nor forges a content change, and only
// complete evidence is a trusted digest, so the asset's surviving partial
// evidence must not stand in for the complete evidence it lost.
func TestSaveScanEmptyDigestNeverOverwritesKnownDigest(t *testing.T) {
	s := openTestStore(t)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "digest-known", "", strings.Repeat("a", 64), first, first)
	_, _, digest, changedAt, ok := assetHistoryRow(t, s, "asset-one")
	if !ok || digest == "" {
		t.Fatalf("first scan recorded no digest: ok=%v digest=%q", ok, digest)
	}
	if changedAt != formatTime(first) {
		t.Fatalf("changed at = %q, want %q", changedAt, formatTime(first))
	}

	later := first.Add(24 * time.Hour)
	saveHistorySnapshotWithoutCompleteEvidence(t, s, "digest-unreadable", later, later)
	_, lastSeen, gotDigest, gotChanged, _ := assetHistoryRow(t, s, "asset-one")
	if lastSeen != formatTime(later) {
		t.Fatalf("last seen = %q, want %q", lastSeen, formatTime(later))
	}
	if gotDigest != digest {
		t.Fatalf("digest = %q, want the last known digest %q", gotDigest, digest)
	}
	if gotChanged != formatTime(first) {
		t.Fatalf("changed at = %q, want %q: a scan without a trusted digest forged a content change", gotChanged, formatTime(first))
	}
}

// TestSaveScanBackdatedScanDoesNotRewriteAssetHistory pins the history record
// to scan order: a snapshot saved out of order and finished before the newest
// stored one must not become the reported content digest, and must not date a
// content change backwards. Written against literal times rather than the
// upsert's shape so it survives a rewrite of the statement.
func TestSaveScanBackdatedScanDoesNotRewriteAssetHistory(t *testing.T) {
	s := openTestStore(t)
	newest := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "history-newest", "", strings.Repeat("a", 64), newest, newest)
	_, _, digest, _, ok := assetHistoryRow(t, s, "asset-one")
	if !ok || digest == "" {
		t.Fatalf("first scan recorded no digest: ok=%v digest=%q", ok, digest)
	}

	backdated := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "history-backdated", "", strings.Repeat("c", 64), backdated, newest)
	firstSeen, lastSeen, gotDigest, gotChanged, _ := assetHistoryRow(t, s, "asset-one")
	if firstSeen != formatTime(backdated) {
		t.Fatalf("first seen = %q, want the earliest sighting %q", firstSeen, formatTime(backdated))
	}
	if lastSeen != formatTime(newest) {
		t.Fatalf("last seen = %q, want the newest sighting %q", lastSeen, formatTime(newest))
	}
	if gotDigest != digest {
		t.Fatalf("digest = %q, want the newest snapshot's digest %q", gotDigest, digest)
	}
	if gotChanged != formatTime(newest) {
		t.Fatalf("changed at = %q, want %q: a backdated scan dated a content change before the change it reports", gotChanged, formatTime(newest))
	}
}

// TestSaveScanAssetHistoryRetentionEdge pins the history window to 90 days at
// its own edge. Every bound is a literal duration: a test written in terms of
// the retention constant pins nothing, because the constant is what a mistake
// would change.
func TestSaveScanAssetHistoryRetentionEdge(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		assetID string
		age     time.Duration
		kept    bool
	}{
		{assetID: "edge-91d", age: 91 * 24 * time.Hour},
		{assetID: "edge-90d-1ns", age: 90*24*time.Hour + time.Nanosecond},
		{assetID: "edge-90d", age: 90 * 24 * time.Hour, kept: true},
		{assetID: "edge-89d", age: 89 * 24 * time.Hour, kept: true},
	}
	for _, tt := range cases {
		at := now.Add(-tt.age)
		saveHistorySnapshot(t, s, "retention-"+tt.assetID, tt.assetID, "", at, at)
	}
	saveHistorySnapshot(t, s, "retention-now", "", "", now, now)

	for _, tt := range cases {
		_, _, _, _, ok := assetHistoryRow(t, s, tt.assetID)
		if ok != tt.kept {
			t.Fatalf("history last seen %v ago: kept=%v, want kept=%v", tt.age, ok, tt.kept)
		}
	}
}

// TestSaveScanKeepsAssetHistoryForRetainedSnapshots covers the interaction
// between the two windows: the newest snapshot is retained regardless of age,
// so the assets it still names must keep their history too.
func TestSaveScanKeepsAssetHistoryForRetainedSnapshots(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ancient := now.Add(-365 * 24 * time.Hour)
	saveHistorySnapshot(t, s, "history-only", "", "", ancient, now)
	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "asset-one"); !ok {
		t.Fatal("retained snapshot lost the history of an asset it still names")
	}
}

func TestSaveRejectsSensitiveAssetHistoryWithoutRows(t *testing.T) {
	s := openTestStore(t)
	inventory := model.Inventory{Assets: []model.Asset{{ID: "ghp_123456789012345678901234567890123456", Name: "asset"}}}
	if err := s.SaveScan(context.Background(), testScan("sensitive-history", time.Unix(2, 0).UTC()), inventory); !errors.Is(err, ErrSensitiveSnapshot) {
		t.Fatalf("error = %v", err)
	}
	assertNoSnapshotRows(t, s)
	var rows int
	if err := s.db.QueryRow(`SELECT count(*) FROM asset_history`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("asset_history contains %d rows", rows)
	}
}

func TestMigration6AddsAssetHistoryAndPreservesExistingSnapshots(t *testing.T) {
	path := createDatabaseAtMigration(t, 5)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	earlier, later := time.Unix(100, 0).UTC(), time.Unix(200, 0).UTC()
	for _, existing := range []struct {
		scanID     string
		finishedAt time.Time
		assetIDs   []string
	}{
		{"legacy-old", earlier, []string{"legacy-asset", "legacy-gone"}},
		{"legacy-new", later, []string{"legacy-asset"}},
	} {
		if _, err := db.Exec(`INSERT INTO scans(id, schema_version, status, started_at, finished_at, scope_json) VALUES (?, 'ssc-init.scan.v3', 'complete', ?, ?, '{}')`,
			existing.scanID, formatTime(existing.finishedAt.Add(-time.Second)), formatTime(existing.finishedAt)); err != nil {
			db.Close()
			t.Fatal(err)
		}
		for index, assetID := range existing.assetIDs {
			if _, err := db.Exec(`INSERT INTO assets(scan_id, asset_id, asset_json) VALUES (?, ?, ?)`, existing.scanID, assetID, `{"id":"`+assetID+`"}`); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO asset_state(scan_id, asset_id, asset_index, metadata_nil) VALUES (?, ?, ?, 1)`, existing.scanID, assetID, index); err != nil {
				db.Close()
				t.Fatal(err)
			}
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var applied int
	if err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(migrations) {
		t.Fatalf("applied migration=%d want=%d", applied, len(migrations))
	}
	assertTableExists(t, s.db, "asset_history")
	var snapshots, assets int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM assets)`).Scan(&snapshots, &assets); err != nil {
		t.Fatal(err)
	}
	if snapshots != 2 || assets != 3 {
		t.Fatalf("migration lost data: scans=%d assets=%d, want 2 and 3", snapshots, assets)
	}
	firstSeen, lastSeen, digest, changedAt, ok := assetHistoryRow(t, s, "legacy-asset")
	if !ok {
		t.Fatal("migration did not backfill history from existing snapshots")
	}
	if firstSeen != formatTime(earlier) || lastSeen != formatTime(later) || changedAt != formatTime(earlier) || digest != "" {
		t.Fatalf("backfilled first=%q last=%q changed=%q digest=%q", firstSeen, lastSeen, changedAt, digest)
	}
	if firstSeen, lastSeen, _, _, ok = assetHistoryRow(t, s, "legacy-gone"); !ok || firstSeen != formatTime(earlier) || lastSeen != formatTime(earlier) {
		t.Fatalf("backfilled removed asset ok=%v first=%q last=%q", ok, firstSeen, lastSeen)
	}
}

func TestMigration6RollsBackAsOneTransaction(t *testing.T) {
	path := createDatabaseAtMigration(t, 5)
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE asset_history (conflict TEXT)`); err != nil {
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
	if applied != 5 {
		t.Fatalf("applied migration=%d want=5", applied)
	}
}

func TestAssetHistorySchemaRejectsIncompatibleShapes(t *testing.T) {
	for _, tt := range []struct {
		name, table, old, replacement string
	}{
		{name: "wrong key column", table: "asset_history",
			old: "asset_id TEXT PRIMARY KEY", replacement: "asset_id TEXT NOT NULL PRIMARY KEY"},
		{name: "nullable first seen", table: "asset_history",
			old: "first_seen_at TEXT NOT NULL", replacement: "first_seen_at TEXT"},
		{name: "scan scoped history", table: "asset_history",
			old: "content_changed_at TEXT NOT NULL", replacement: "content_changed_at TEXT NOT NULL, scan_id TEXT REFERENCES scans(id)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertRewrittenSchemaRejected(t, tt.table, tt.old, tt.replacement)
		})
	}
}

func openTestStoreWithOptions(t *testing.T, options Options) *Store {
	t.Helper()
	s, err := OpenWithOptions(filepath.Join(privateTempDir(t), "state.db"), options)
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

// TestOpenZeroOptionsRetainsTheDocumentedDefaults is the trap this seam exists
// to avoid: an Options value whose windows are left unset must mean the
// documented 30 and 90 days, never "retain nothing". A zero window would keep
// only the newest snapshot and delete every asset's history on the next save.
func TestOpenZeroOptionsRetainsTheDocumentedDefaults(t *testing.T) {
	s := openTestStoreWithOptions(t, Options{})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "zero-aged", "aged-asset", "", now.Add(-29*24*time.Hour), now)
	saveSnapshotAt(t, s, "zero-new", now, now)

	if remaining := snapshotCount(t, s); remaining != 2 {
		t.Fatalf("zero options kept %d snapshots, want 2 (29 days is inside the 30 day default)", remaining)
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "aged-asset"); !ok {
		t.Fatal("zero options pruned history 29 days old, want the 90 day default")
	}
}

func TestOpenShortRetentionPrunesMoreThanTheDefault(t *testing.T) {
	s := openTestStoreWithOptions(t, Options{SnapshotRetention: 24 * time.Hour, AssetHistoryRetention: 24 * time.Hour})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "short-aged", "aged-asset", "", now.Add(-48*time.Hour), now)
	saveSnapshotAt(t, s, "short-new", now, now)

	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("one day retention kept %d snapshots, want 1", remaining)
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "aged-asset"); ok {
		t.Fatal("one day history retention kept a row last seen two days ago")
	}
}

func TestOpenLongRetentionKeepsWhatTheDefaultWouldPrune(t *testing.T) {
	s := openTestStoreWithOptions(t, Options{SnapshotRetention: 365 * 24 * time.Hour, AssetHistoryRetention: 365 * 24 * time.Hour})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "long-aged", "aged-asset", "", now.Add(-200*24*time.Hour), now)
	saveSnapshotAt(t, s, "long-new", now, now)

	if remaining := snapshotCount(t, s); remaining != 2 {
		t.Fatalf("one year retention kept %d snapshots, want 2", remaining)
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "aged-asset"); !ok {
		t.Fatal("one year history retention pruned a row last seen 200 days ago")
	}
}

// TestOpenTinyRetentionKeepsTheNewestSnapshot pins the one rule no window may
// override: without the newest snapshot there is no baseline to diff against.
func TestOpenTinyRetentionKeepsTheNewestSnapshot(t *testing.T) {
	s := openTestStoreWithOptions(t, Options{SnapshotRetention: time.Nanosecond, AssetHistoryRetention: time.Nanosecond})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "tiny-old", now.Add(-time.Hour), now)
	saveSnapshotAt(t, s, "tiny-new", now, now)

	if remaining := snapshotCount(t, s); remaining != 1 {
		t.Fatalf("one nanosecond retention kept %d snapshots, want 1", remaining)
	}
	snapshot, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("load surviving snapshot: ok=%v err=%v", ok, err)
	}
	if snapshot.Scan.ScanID != "tiny-new" {
		t.Fatalf("retention kept scan %q, want %q", snapshot.Scan.ScanID, "tiny-new")
	}
}

// TestOpenKeepsWorkingWithoutOptions guards the existing constructor: it must
// stay equivalent to the zero value rather than becoming a second policy.
func TestOpenKeepsWorkingWithoutOptions(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "plain-aged", now.Add(-29*24*time.Hour), now)
	saveSnapshotAt(t, s, "plain-new", now, now)
	if remaining := snapshotCount(t, s); remaining != 2 {
		t.Fatalf("Open kept %d snapshots, want 2", remaining)
	}
}

// TestOpenNegativeRetentionRetainsTheDocumentedDefaults covers the other way a
// window can arrive meaning nothing: a negative window would put the cutoff in
// the future and prune snapshots that have not aged at all.
func TestOpenNegativeRetentionRetainsTheDocumentedDefaults(t *testing.T) {
	s := openTestStoreWithOptions(t, Options{SnapshotRetention: -time.Hour, AssetHistoryRetention: -time.Hour})
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveHistorySnapshot(t, s, "negative-aged", "aged-asset", "", now.Add(-29*24*time.Hour), now)
	saveSnapshotAt(t, s, "negative-new", now, now)

	if remaining := snapshotCount(t, s); remaining != 2 {
		t.Fatalf("negative retention kept %d snapshots, want 2 (the default window)", remaining)
	}
	if _, _, _, _, ok := assetHistoryRow(t, s, "aged-asset"); !ok {
		t.Fatal("negative retention pruned history inside the 90 day default")
	}
}
