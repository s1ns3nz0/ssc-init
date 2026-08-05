package store

import (
	"database/sql"
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
}

func applyMigrations(db *sql.DB) error {
	var hasMigrations int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&hasMigrations); err != nil {
		return fmt.Errorf("inspect schema migrations: %w", err)
	}
	applied := 0
	if hasMigrations != 0 {
		if err := db.QueryRow(`SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&applied); err != nil {
			return fmt.Errorf("read schema migration version: %w", err)
		}
	}
	if applied > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than supported version %d", applied, len(migrations))
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
	return nil
}
