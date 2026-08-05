// Package store persists immutable inventory snapshots.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"
)

const busyTimeoutMilliseconds = 5000

// Store is a SQLite-backed immutable snapshot store.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates a snapshot store at path.
func Open(path string) (_ *Store, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	abs = filepath.Clean(abs)
	if err := prepareParent(filepath.Dir(abs)); err != nil {
		return nil, err
	}

	created, err := prepareDatabaseFile(abs)
	if err != nil {
		return nil, err
	}
	if created {
		defer func() {
			if err != nil {
				_ = os.Remove(abs)
			}
		}()
	}

	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("canonicalize database parent: %w", err)
	}
	canonical := filepath.Join(canonicalParent, filepath.Base(abs))
	dsn := sqliteDSN(canonical)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("connect sqlite database: %w", err)
	}
	if err = verifyPragmas(db); err != nil {
		return nil, err
	}
	if err = applyMigrations(db); err != nil {
		return nil, err
	}
	return &Store{db: db, path: canonical}, nil
}

// Path returns the canonical path to the database file.
func (s *Store) Path() string { return s.path }

// Close releases database resources.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func sqliteDSN(path string) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := url.Values{}
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "busy_timeout("+strconv.Itoa(busyTimeoutMilliseconds)+")")
	u.RawQuery = query.Encode()
	return u.String()
}

func prepareParent(parent string) error {
	info, err := os.Lstat(parent)
	if err == nil {
		return validateParent(parent, info)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect database parent %q: %w", parent, err)
	}

	var missing []string
	current := parent
	for {
		info, err = os.Lstat(current)
		if err == nil {
			if err := validateParent(current, info); err != nil {
				return err
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect database parent %q: %w", current, err)
		}
		missing = append(missing, current)
		next := filepath.Dir(current)
		if next == current {
			return fmt.Errorf("find existing database parent for %q", parent)
		}
		current = next
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil {
			return fmt.Errorf("create database parent %q: %w", missing[i], err)
		}
		if err := os.Chmod(missing[i], 0o700); err != nil {
			return fmt.Errorf("secure database parent %q: %w", missing[i], err)
		}
	}
	return nil
}

func validateParent(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database parent %q must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("database parent %q is not a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("database parent %q has insecure permissions %04o; group and other access must be disabled", path, info.Mode().Perm())
	}
	return nil
}

func prepareDatabaseFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("database path %q must not be a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("database path %q is not a regular file", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return false, fmt.Errorf("secure database file %q: %w", path, err)
		}
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return false, fmt.Errorf("create database file %q: %w", path, err)
		}
		if err := file.Close(); err != nil {
			return false, fmt.Errorf("close new database file %q: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return false, fmt.Errorf("secure database file %q: %w", path, err)
		}
		return true, nil
	default:
		return false, fmt.Errorf("inspect database path %q: %w", path, err)
	}
}

func verifyPragmas(db *sql.DB) error {
	checks := []struct {
		name string
		want int
	}{
		{name: "foreign_keys", want: 1},
		{name: "busy_timeout", want: busyTimeoutMilliseconds},
	}
	for _, check := range checks {
		var got int
		if err := db.QueryRow("PRAGMA " + check.name).Scan(&got); err != nil {
			return fmt.Errorf("verify sqlite %s pragma: %w", check.name, err)
		}
		if got != check.want {
			return fmt.Errorf("verify sqlite %s pragma: got %d, want %d", check.name, got, check.want)
		}
	}
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("verify sqlite journal_mode pragma: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("verify sqlite journal_mode pragma: got %q, want %q", journalMode, "wal")
	}
	return nil
}
