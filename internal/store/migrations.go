package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
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

type columnSpec struct {
	name, typeName, defaultSQL string
	notNull, primaryKey        int
	hasDefault                 bool
}

var requiredColumns = map[string][]columnSpec{
	"schema_migrations":  {{"version", "INTEGER", "", 0, 1, false}, {"applied_at", "TEXT", "", 1, 0, false}},
	"scans":              {{"id", "TEXT", "", 0, 1, false}, {"schema_version", "TEXT", "", 1, 0, false}, {"status", "TEXT", "", 1, 0, false}, {"started_at", "TEXT", "", 1, 0, false}, {"finished_at", "TEXT", "", 1, 0, false}},
	"assets":             {{"scan_id", "TEXT", "", 1, 1, false}, {"asset_id", "TEXT", "", 1, 2, false}, {"asset_json", "BLOB", "", 1, 0, false}},
	"relationships":      {{"scan_id", "TEXT", "", 1, 1, false}, {"from_id", "TEXT", "", 1, 2, false}, {"kind", "TEXT", "", 1, 3, false}, {"to_id", "TEXT", "", 1, 4, false}},
	"coverage":           {{"scan_id", "TEXT", "", 1, 1, false}, {"collector", "TEXT", "", 1, 2, false}, {"result_json", "BLOB", "", 1, 0, false}},
	"inventory_state":    {{"scan_id", "TEXT", "", 0, 1, false}, {"assets_nil", "INTEGER", "", 1, 0, false}, {"relationships_nil", "INTEGER", "", 1, 0, false}, {"errors_nil", "INTEGER", "", 1, 0, false}, {"asset_count", "INTEGER", "0", 1, 0, true}, {"relationship_count", "INTEGER", "0", 1, 0, true}, {"error_count", "INTEGER", "0", 1, 0, true}},
	"asset_state":        {{"scan_id", "TEXT", "", 1, 1, false}, {"asset_id", "TEXT", "", 1, 2, false}, {"asset_index", "INTEGER", "", 1, 0, false}, {"metadata_nil", "INTEGER", "", 1, 0, false}},
	"relationship_state": {{"scan_id", "TEXT", "", 1, 1, false}, {"from_id", "TEXT", "", 1, 2, false}, {"kind", "TEXT", "", 1, 3, false}, {"to_id", "TEXT", "", 1, 4, false}, {"relationship_index", "INTEGER", "", 1, 0, false}},
	"inventory_errors":   {{"scan_id", "TEXT", "", 1, 1, false}, {"error_index", "INTEGER", "", 1, 2, false}, {"error_json", "BLOB", "", 1, 0, false}},
}

func verifySchema(db *sql.DB) error {
	for table, expected := range requiredColumns {
		rows, err := db.Query(`PRAGMA table_info("` + table + `")`)
		if err != nil {
			return fmt.Errorf("inspect required table %s: %w", table, err)
		}
		var actual []columnSpec
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, columnType string
			var defaultValue sql.NullString
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				rows.Close()
				return fmt.Errorf("scan required table %s: %w", table, err)
			}
			actual = append(actual, columnSpec{name: name, typeName: normalizeType(columnType), defaultSQL: defaultValue.String, notNull: notNull, primaryKey: primaryKey, hasDefault: defaultValue.Valid})
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close required table %s inspection: %w", table, err)
		}
		if len(actual) != len(expected) {
			return fmt.Errorf("required schema table %s has unexpected column count", table)
		}
		for index := range expected {
			if actual[index] != expected[index] {
				return fmt.Errorf("required schema table %s has incompatible column %d", table, index)
			}
		}
		if err := verifyTableChecksAndTriggers(db, table); err != nil {
			return err
		}
	}
	if err := verifyForeignKeys(db); err != nil {
		return err
	}
	if err := verifyIndices(db); err != nil {
		return err
	}
	return nil
}

func normalizeType(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(value), " "))
}

var requiredChecks = map[string][]string{
	"inventory_state":    {"check(assets_nilin(0,1))", "check(relationships_nilin(0,1))", "check(errors_nilin(0,1))", "check(asset_count>=0)", "check(relationship_count>=0)", "check(error_count>=0)"},
	"asset_state":        {"check(asset_index>=0)", "check(metadata_nilin(0,1))"},
	"relationship_state": {"check(relationship_index>=0)"},
	"inventory_errors":   {"check(error_index>=0)"},
}

func verifyTableChecksAndTriggers(db *sql.DB, table string) error {
	var createSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&createSQL); err != nil {
		return fmt.Errorf("read required table %s definition: %w", table, err)
	}
	normalized := strings.ToLower(strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "", `"`, "", "`", "", "[", "", "]", "").Replace(createSQL))
	expected := requiredChecks[table]
	if strings.Count(normalized, "check(") != len(expected) {
		return fmt.Errorf("required schema table %s has incompatible checks", table)
	}
	for _, check := range expected {
		if !strings.Contains(normalized, check) {
			return fmt.Errorf("required schema table %s has incompatible checks", table)
		}
	}
	var triggerCount int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?`, table).Scan(&triggerCount); err != nil || triggerCount != 0 {
		return fmt.Errorf("required schema table %s has unexpected triggers", table)
	}
	return nil
}

type foreignKeySpec struct{ table, from, to, onUpdate, onDelete, match string }

var requiredForeignKeys = map[string][]foreignKeySpec{
	"assets":             {{"scans", "scan_id", "id", "NO ACTION", "NO ACTION", "NONE"}},
	"relationships":      {{"scans", "scan_id", "id", "NO ACTION", "NO ACTION", "NONE"}},
	"coverage":           {{"scans", "scan_id", "id", "NO ACTION", "NO ACTION", "NONE"}},
	"inventory_state":    {{"scans", "scan_id", "id", "NO ACTION", "NO ACTION", "NONE"}},
	"asset_state":        {{"assets", "scan_id", "scan_id", "NO ACTION", "NO ACTION", "NONE"}, {"assets", "asset_id", "asset_id", "NO ACTION", "NO ACTION", "NONE"}},
	"relationship_state": {{"relationships", "scan_id", "scan_id", "NO ACTION", "NO ACTION", "NONE"}, {"relationships", "from_id", "from_id", "NO ACTION", "NO ACTION", "NONE"}, {"relationships", "kind", "kind", "NO ACTION", "NO ACTION", "NONE"}, {"relationships", "to_id", "to_id", "NO ACTION", "NO ACTION", "NONE"}},
	"inventory_errors":   {{"scans", "scan_id", "id", "NO ACTION", "NO ACTION", "NONE"}},
}

func verifyForeignKeys(db *sql.DB) error {
	for table := range requiredColumns {
		rows, err := db.Query(`PRAGMA foreign_key_list("` + table + `")`)
		if err != nil {
			return fmt.Errorf("inspect foreign keys for %s: %w", table, err)
		}
		var actual []foreignKeySpec
		for rows.Next() {
			var id, sequence int
			var spec foreignKeySpec
			if err := rows.Scan(&id, &sequence, &spec.table, &spec.from, &spec.to, &spec.onUpdate, &spec.onDelete, &spec.match); err != nil {
				rows.Close()
				return fmt.Errorf("scan foreign keys for %s: %w", table, err)
			}
			actual = append(actual, spec)
		}
		rows.Close()
		expected := requiredForeignKeys[table]
		if len(actual) != len(expected) {
			return fmt.Errorf("required schema table %s has incompatible foreign keys", table)
		}
		for index := range expected {
			if actual[index] != expected[index] {
				return fmt.Errorf("required schema table %s has incompatible foreign keys", table)
			}
		}
	}
	return nil
}

var requiredIndexFingerprints = map[string][]string{
	"schema_migrations":  {},
	"scans":              {"c:0:finished_at,id", "pk:1:id"},
	"assets":             {"pk:1:scan_id,asset_id"},
	"relationships":      {"pk:1:scan_id,from_id,kind,to_id"},
	"coverage":           {"pk:1:scan_id,collector"},
	"inventory_state":    {"pk:1:scan_id"},
	"asset_state":        {"pk:1:scan_id,asset_id", "u:1:scan_id,asset_index"},
	"relationship_state": {"pk:1:scan_id,from_id,kind,to_id", "u:1:scan_id,relationship_index"},
	"inventory_errors":   {"pk:1:scan_id,error_index"},
}

func verifyIndices(db *sql.DB) error {
	for table, expected := range requiredIndexFingerprints {
		rows, err := db.Query(`PRAGMA index_list("` + table + `")`)
		if err != nil {
			return fmt.Errorf("inspect indices for %s: %w", table, err)
		}
		type indexEntry struct {
			name, origin string
			unique       int
		}
		var entries []indexEntry
		for rows.Next() {
			var sequence, unique, partial int
			var name, origin string
			if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
				rows.Close()
				return fmt.Errorf("scan indices for %s: %w", table, err)
			}
			entries = append(entries, indexEntry{name: name, origin: origin, unique: unique})
		}
		rows.Close()
		var actual []string
		for _, entry := range entries {
			columns, err := indexColumns(db, entry.name)
			if err != nil {
				return err
			}
			actual = append(actual, fmt.Sprintf("%s:%d:%s", entry.origin, entry.unique, strings.Join(columns, ",")))
		}
		sort.Strings(actual)
		want := append([]string(nil), expected...)
		sort.Strings(want)
		if strings.Join(actual, "|") != strings.Join(want, "|") {
			return fmt.Errorf("required schema table %s has incompatible indices", table)
		}
	}
	var indexSQL string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'scans_latest_idx'`).Scan(&indexSQL); err != nil {
		return errors.New("required schema index scans_latest_idx is missing")
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(indexSQL), " "))
	if normalized != "create index scans_latest_idx on scans(finished_at desc, id desc)" {
		return errors.New("required schema index scans_latest_idx is incompatible")
	}
	return nil
}

func indexColumns(db *sql.DB, index string) ([]string, error) {
	rows, err := db.Query(`PRAGMA index_info("` + strings.ReplaceAll(index, `"`, `""`) + `")`)
	if err != nil {
		return nil, fmt.Errorf("inspect index columns: %w", err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var sequence, cid int
		var name string
		if err := rows.Scan(&sequence, &cid, &name); err != nil {
			return nil, fmt.Errorf("scan index columns: %w", err)
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}
