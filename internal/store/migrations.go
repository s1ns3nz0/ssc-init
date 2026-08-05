package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var migrations = []string{
	`CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE assets (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, asset_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE relationships (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, from_id, kind, to_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE coverage (
    scan_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    result_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, collector),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);`,
	`CREATE TABLE inventory_state (
    scan_id TEXT PRIMARY KEY,
    assets_nil INTEGER NOT NULL CHECK (assets_nil IN (0, 1)),
    relationships_nil INTEGER NOT NULL CHECK (relationships_nil IN (0, 1)),
    errors_nil INTEGER NOT NULL CHECK (errors_nil IN (0, 1)),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE asset_state (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_index INTEGER NOT NULL CHECK (asset_index >= 0),
    metadata_nil INTEGER NOT NULL CHECK (metadata_nil IN (0, 1)),
    PRIMARY KEY (scan_id, asset_id),
	UNIQUE (scan_id, asset_index),
    FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)
);
CREATE TABLE relationship_state (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    relationship_index INTEGER NOT NULL CHECK (relationship_index >= 0),
    PRIMARY KEY (scan_id, from_id, kind, to_id),
	UNIQUE (scan_id, relationship_index),
    FOREIGN KEY (scan_id, from_id, kind, to_id) REFERENCES relationships(scan_id, from_id, kind, to_id)
);
CREATE TABLE inventory_errors (
    scan_id TEXT NOT NULL,
    error_index INTEGER NOT NULL CHECK (error_index >= 0),
    error_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, error_index),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);`,
	`ALTER TABLE inventory_state ADD COLUMN asset_count INTEGER NOT NULL DEFAULT 0 CHECK (asset_count >= 0);
ALTER TABLE inventory_state ADD COLUMN relationship_count INTEGER NOT NULL DEFAULT 0 CHECK (relationship_count >= 0);
ALTER TABLE inventory_state ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0);
UPDATE inventory_state SET
    asset_count = (SELECT count(*) FROM assets WHERE assets.scan_id = inventory_state.scan_id),
    relationship_count = (SELECT count(*) FROM relationships WHERE relationships.scan_id = inventory_state.scan_id),
    error_count = (SELECT count(*) FROM inventory_errors WHERE inventory_errors.scan_id = inventory_state.scan_id);
CREATE INDEX scans_latest_idx ON scans(finished_at DESC, id DESC);`,
}

func applyMigrations(db *sql.DB) error {
	var hasMigrations int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&hasMigrations); err != nil {
		return fmt.Errorf("inspect schema migrations: %w", err)
	}
	applied := 0
	if hasMigrations != 0 {
		rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
		if err != nil {
			return fmt.Errorf("read schema migration history: %w", err)
		}
		for rows.Next() {
			var version int
			if err := rows.Scan(&version); err != nil {
				rows.Close()
				return fmt.Errorf("scan schema migration history: %w", err)
			}
			if version != applied+1 || version < 1 || version > len(migrations) {
				rows.Close()
				return fmt.Errorf("invalid schema migration history at version %d", version)
			}
			applied = version
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close schema migration history: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate schema migration history: %w", err)
		}
	}
	for version := applied + 1; version <= len(migrations); version++ {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin schema migration %d: %w", version, err)
		}
		if _, err := tx.Exec(migrations[version-1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply schema migration %d: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record schema migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit schema migration %d: %w", version, err)
		}
	}
	return verifySchema(db)
}

var requiredColumns = map[string][]string{
	"schema_migrations":  {"version", "applied_at"},
	"scans":              {"id", "schema_version", "status", "started_at", "finished_at"},
	"assets":             {"scan_id", "asset_id", "asset_json"},
	"relationships":      {"scan_id", "from_id", "kind", "to_id"},
	"coverage":           {"scan_id", "collector", "result_json"},
	"inventory_state":    {"scan_id", "assets_nil", "relationships_nil", "errors_nil", "asset_count", "relationship_count", "error_count"},
	"asset_state":        {"scan_id", "asset_id", "asset_index", "metadata_nil"},
	"relationship_state": {"scan_id", "from_id", "kind", "to_id", "relationship_index"},
	"inventory_errors":   {"scan_id", "error_index", "error_json"},
}

func verifySchema(db *sql.DB) error {
	for table, expected := range requiredColumns {
		rows, err := db.Query(`PRAGMA table_info("` + table + `")`)
		if err != nil {
			return fmt.Errorf("inspect required table %s: %w", table, err)
		}
		columns := make(map[string]struct{})
		primaryKeyColumns := make(map[string]int)
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, columnType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				return fmt.Errorf("scan required table %s: %w", table, err)
			}
			columns[name] = struct{}{}
			if primaryKey > 0 {
				primaryKeyColumns[name] = primaryKey
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close required table %s inspection: %w", table, err)
		}
		for _, column := range expected {
			if _, ok := columns[column]; !ok {
				return fmt.Errorf("required schema column %s.%s is missing", table, column)
			}
		}
		if len(primaryKeyColumns) == 0 {
			return fmt.Errorf("required primary key for %s is missing", table)
		}
	}
	for _, table := range []string{"scans", "assets", "relationships", "coverage", "inventory_state", "asset_state", "relationship_state", "inventory_errors"} {
		rows, err := db.Query(`PRAGMA index_list("` + table + `")`)
		if err != nil {
			return fmt.Errorf("inspect required indices for %s: %w", table, err)
		}
		foundPrimaryKey := false
		for rows.Next() {
			var sequence, unique, partial int
			var name, origin string
			if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
				rows.Close()
				return fmt.Errorf("scan required indices for %s: %w", table, err)
			}
			if origin == "pk" {
				foundPrimaryKey = true
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate required indices for %s: %w", table, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close required indices for %s: %w", table, err)
		}
		if !foundPrimaryKey {
			return fmt.Errorf("required primary-key index for %s is missing", table)
		}
	}
	var indexSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'scans_latest_idx'`).Scan(&indexSQL); err != nil || indexSQL == "" {
		return errors.New("required schema index scans_latest_idx is missing")
	}
	rows, err := db.Query(`PRAGMA index_info("scans_latest_idx")`)
	if err != nil {
		return fmt.Errorf("inspect scans_latest_idx columns: %w", err)
	}
	var indexColumns []string
	for rows.Next() {
		var sequence, cid int
		var name string
		if err := rows.Scan(&sequence, &cid, &name); err != nil {
			rows.Close()
			return fmt.Errorf("scan scans_latest_idx columns: %w", err)
		}
		indexColumns = append(indexColumns, name)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close scans_latest_idx inspection: %w", err)
	}
	if len(indexColumns) != 2 || indexColumns[0] != "finished_at" || indexColumns[1] != "id" {
		return errors.New("required schema index scans_latest_idx has invalid columns")
	}
	return nil
}
