package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Usage is the store's on-disk footprint and the retention windows that bound
// it. Design §12 budgets 500 MB for the binary, bundles, state, and retained
// reports combined; nothing else measures the state half of that budget.
type Usage struct {
	// SizeBytes covers the database and its write-ahead log and shared-memory
	// files. The log can briefly exceed the database itself, so reporting the
	// database alone would understate the footprint.
	SizeBytes int64
	// ReclaimableBytes is the freelist: pages that pruning released but that
	// still occupy disk until a full rewrite hands them back. Reclamation is
	// gated on the freelist being both large and a large fraction of the file,
	// so a store that can never clear the gate creeps upward; this figure is
	// the only signal that it is happening.
	ReclaimableBytes int64
	// SnapshotCount is the number of retained snapshots.
	SnapshotCount int
	// SnapshotRetention and AssetHistoryRetention are the active windows,
	// including the defaults an unset Options selects.
	SnapshotRetention     time.Duration
	AssetHistoryRetention time.Duration
}

// UsageAt reports usage for the store at path. It neither creates nor migrates
// a database: a store that has never been created reports zero sizes and counts
// rather than an error, and an existing one is opened read-only.
func UsageAt(ctx context.Context, path string, options Options) (Usage, error) {
	usage := Usage{
		SnapshotRetention:     options.snapshotWindow(),
		AssetHistoryRetention: options.assetHistoryWindow(),
	}
	if err := ctx.Err(); err != nil {
		return usage, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return usage, fmt.Errorf("resolve database path: %w", err)
	}
	abs = filepath.Clean(abs)
	database, err := os.Lstat(abs)
	if errors.Is(err, os.ErrNotExist) {
		return usage, nil
	}
	if err != nil {
		return usage, fmt.Errorf("inspect database file: %w", err)
	}
	if !database.Mode().IsRegular() {
		return usage, errors.New("database path is not a regular file")
	}
	usage.SizeBytes = database.Size()
	logged := false
	measured := map[string]os.FileInfo{}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, statErr := os.Lstat(abs + suffix)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return usage, fmt.Errorf("inspect sqlite file: %w", statErr)
		}
		if !info.Mode().IsRegular() {
			return usage, errors.New("sqlite file is not a regular file")
		}
		// Only a log with frames holds rows the database file does not. A
		// shared-memory file is an index into the log, so a leftover one on its
		// own — a crashed writer's residue — is no reason to read through
		// anything, and reading through nothing is what keeps this measurement
		// from creating the log it claimed to find.
		if suffix == "-wal" && info.Size() > 0 {
			logged = true
		}
		measured[suffix] = info
		usage.SizeBytes += info.Size()
	}
	if usage.SizeBytes == 0 {
		return usage, nil
	}
	err = readUsageCounts(ctx, abs, logged, &usage)
	if logged {
		if discardErr := discardMeasurementSQLiteFiles(abs, measured); err == nil {
			err = discardErr
		}
	}
	if err != nil {
		return usage, err
	}
	// Measurement is the only pass that touches these files between store opens,
	// so it is where a mode loosened out of band is pulled back, and where a
	// shared-memory file that reading through a log had to create gets the
	// store's mode instead of the process umask.
	return usage, secureSQLiteFiles(abs, nil)
}

// discardMeasurementSQLiteFiles removes log and shared-memory files that
// measurement itself created. A writer that checkpoints its log away between the
// stats above and the read below leaves this connection creating both files
// again, and files measurement adds are files the next measurement counts.
//
// Only files whose identity changed since they were stat'd are removed, and only
// while the log holds no frames: a log unchanged since it was measured, or one
// carrying frames, belongs to a writer and is left alone. A writer that appears
// inside that window and has not yet committed can still lose the empty log it
// just made, which costs it nothing durable — its frames go to the descriptor it
// already holds and its own close checkpoints them into the database.
func discardMeasurementSQLiteFiles(path string, measured map[string]os.FileInfo) error {
	log, err := os.Lstat(path + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect sqlite file: %w", err)
	}
	if !log.Mode().IsRegular() || log.Size() > 0 || os.SameFile(measured["-wal"], log) {
		return nil
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect sqlite file: %w", err)
		}
		if !info.Mode().IsRegular() || os.SameFile(measured[suffix], info) {
			continue
		}
		if err := os.Remove(path + suffix); err != nil {
			return fmt.Errorf("discard measurement sqlite file: %w", err)
		}
	}
	return nil
}

func readUsageCounts(ctx context.Context, path string, logged bool, usage *Usage) error {
	db, err := sql.Open("sqlite", readOnlySQLiteDSN(path, logged))
	if err != nil {
		return fmt.Errorf("open sqlite database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scans`).Scan(&usage.SnapshotCount); err != nil {
		return fmt.Errorf("count snapshots: %w", err)
	}
	var pageSize, freePages int64
	if err := db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return fmt.Errorf("read sqlite page size: %w", err)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freePages); err != nil {
		return fmt.Errorf("read sqlite freelist: %w", err)
	}
	usage.ReclaimableBytes = pageSize * freePages
	return nil
}

// readOnlySQLiteDSN opens the database for measurement only.
//
// With no log frames to read the database stands on its own, and an immutable
// connection reads it without creating anything: a plain read-only connection
// would create the log and shared-memory files, leaving umask-moded files in the
// state directory and inflating the footprint being measured. With frames in the
// log it holds rows the database file does not — a store open elsewhere keeps
// its whole uncheckpointed schema there — so measurement must read through it,
// and the shared-memory file it needs is the one that writer already made.
func readOnlySQLiteDSN(path string, logged bool) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := url.Values{}
	query.Add("mode", "ro")
	if !logged {
		query.Add("immutable", "1")
	}
	query.Add("_pragma", "query_only(1)")
	query.Add("_pragma", "busy_timeout("+strconv.Itoa(busyTimeoutMilliseconds)+")")
	u.RawQuery = query.Encode()
	return u.String()
}
