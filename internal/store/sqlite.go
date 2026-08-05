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
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const busyTimeoutMilliseconds = 5000

// testHookAfterDatabaseGuard is a deterministic test seam for pathname replacement.
var testHookAfterDatabaseGuard func(string) error

// ErrStoreClosed is returned by operations started after Close takes ownership.
var ErrStoreClosed = errors.New("snapshot store is closed")

// Store is a SQLite-backed immutable snapshot store.
//
// The retained guard detects replacement between the verified open and SQLite's
// first pathname open. Defending against later malicious same-UID replacement or
// a hostile custom SQLite VFS is outside the foundation store's threat boundary.
type Store struct {
	mu    sync.RWMutex
	db    *sql.DB
	guard *os.File
	path  string
}

// Open opens or creates a snapshot store at path.
func Open(path string) (_ *Store, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	abs = filepath.Clean(abs)
	parent, err := openVerifiedParent(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	guard, created, err := openDatabaseGuard(parent, filepath.Base(abs), abs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if created {
				removeCreatedIfSame(abs, guard)
			}
			_ = guard.Close()
		}
	}()
	if hook := testHookAfterDatabaseGuard; hook != nil {
		if err = hook(abs); err != nil {
			return nil, fmt.Errorf("database open test hook: %w", err)
		}
	}

	db, err := sql.Open("sqlite", sqliteDSN(abs))
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
	if err = verifyPathIdentity(abs, guard); err != nil {
		return nil, err
	}
	if err = verifyPragmas(db); err != nil {
		return nil, err
	}
	if err = applyMigrations(db); err != nil {
		return nil, err
	}
	if err = secureSQLiteFiles(abs, guard); err != nil {
		return nil, err
	}
	return &Store{db: db, guard: guard, path: abs}, nil
}

// Path returns the verified absolute path to the database file.
func (s *Store) Path() string { return s.path }

// Close releases database resources.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var closeErrors []error
	if s.db != nil {
		if err := secureSQLiteFiles(s.path, s.guard); err != nil {
			closeErrors = append(closeErrors, err)
		}
		if err := s.db.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		s.db = nil
	}
	if s.guard != nil {
		if err := s.guard.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
		s.guard = nil
	}
	return errors.Join(closeErrors...)
}

func (s *Store) beginOperation() (*sql.DB, *os.File, func(), error) {
	if s == nil {
		return nil, nil, nil, ErrStoreClosed
	}
	s.mu.RLock()
	if s.db == nil || s.guard == nil {
		s.mu.RUnlock()
		return nil, nil, nil, ErrStoreClosed
	}
	return s.db, s.guard, s.mu.RUnlock, nil
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

func openVerifiedParent(parentPath string) (*os.File, error) {
	root, err := os.Open(string(os.PathSeparator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := root
	components := strings.Split(strings.TrimPrefix(parentPath, string(os.PathSeparator)), string(os.PathSeparator))
	for _, component := range components {
		if component == "" {
			continue
		}
		var entry unix.Stat_t
		entryErr := unix.Fstatat(int(current.Fd()), component, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if entryErr == nil && entry.Mode&unix.S_IFMT == unix.S_IFLNK {
			current.Close()
			return nil, errors.New("database parent must not be a symlink or contain symlinks")
		}
		if entryErr == nil && entry.Mode&unix.S_IFMT != unix.S_IFDIR {
			current.Close()
			return nil, errors.New("database parent component is not a directory")
		}
		if entryErr != nil && !errors.Is(entryErr, unix.ENOENT) {
			current.Close()
			return nil, fmt.Errorf("inspect database parent component: %w", entryErr)
		}
		createdComponent := false
		if errors.Is(entryErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), component, 0o700); mkdirErr != nil {
				current.Close()
				return nil, fmt.Errorf("create database parent component: %w", mkdirErr)
			}
			createdComponent = true
		}
		childFD, openErr := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			current.Close()
			if errors.Is(openErr, unix.ELOOP) {
				return nil, errors.New("database parent must not be a symlink or contain symlinks")
			}
			return nil, fmt.Errorf("open database parent component: %w", openErr)
		}
		child := os.NewFile(uintptr(childFD), component)
		if createdComponent {
			if err := child.Chmod(0o700); err != nil {
				child.Close()
				current.Close()
				return nil, fmt.Errorf("secure database parent component: %w", err)
			}
		}
		if err := verifyDirectoryEntry(int(current.Fd()), component, child); err != nil {
			child.Close()
			current.Close()
			return nil, err
		}
		current.Close()
		current = child
	}
	info, err := current.Stat()
	if err != nil {
		current.Close()
		return nil, fmt.Errorf("inspect final database parent: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		current.Close()
		return nil, fmt.Errorf("database parent has insecure permissions %04o; group and other access must be disabled", info.Mode().Perm())
	}
	return current, nil
}

func verifyDirectoryEntry(parentFD int, name string, child *os.File) error {
	var entry, opened unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("verify database parent entry: %w", err)
	}
	if entry.Mode&unix.S_IFMT == unix.S_IFLNK {
		return errors.New("database parent must not be a symlink or contain symlinks")
	}
	if err := unix.Fstat(int(child.Fd()), &opened); err != nil {
		return fmt.Errorf("verify opened database parent: %w", err)
	}
	if entry.Dev != opened.Dev || entry.Ino != opened.Ino {
		return errors.New("database parent changed during verification")
	}
	return nil
}

func openDatabaseGuard(parent *os.File, name, fullPath string) (*os.File, bool, error) {
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	var entry unix.Stat_t
	entryErr := unix.Fstatat(int(parent.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr == nil {
		switch entry.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return nil, false, fmt.Errorf("database path %q must not be a symlink", fullPath)
		case unix.S_IFREG:
			if os.FileMode(entry.Mode).Perm()&0o077 != 0 {
				return nil, false, fmt.Errorf("database file %q has insecure permissions %04o", fullPath, os.FileMode(entry.Mode).Perm())
			}
		default:
			return nil, false, fmt.Errorf("database path %q is not a regular file", fullPath)
		}
	} else if !errors.Is(entryErr, unix.ENOENT) {
		return nil, false, fmt.Errorf("inspect database path %q: %w", fullPath, entryErr)
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0)
	created := false
	if errors.Is(err, unix.ENOENT) {
		fd, err = unix.Openat(int(parent.Fd()), name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		created = err == nil
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, false, fmt.Errorf("database path %q must not be a symlink", fullPath)
		}
		return nil, false, fmt.Errorf("open database file %q: %w", fullPath, err)
	}
	guard := os.NewFile(uintptr(fd), fullPath)
	info, err := guard.Stat()
	if err != nil {
		guard.Close()
		return nil, created, fmt.Errorf("inspect database file %q: %w", fullPath, err)
	}
	if !info.Mode().IsRegular() {
		guard.Close()
		return nil, created, fmt.Errorf("database path %q is not a regular file", fullPath)
	}
	if !created && info.Mode().Perm()&0o077 != 0 {
		guard.Close()
		return nil, false, fmt.Errorf("database file %q has insecure permissions %04o", fullPath, info.Mode().Perm())
	}
	if err := guard.Chmod(0o600); err != nil {
		guard.Close()
		return nil, created, fmt.Errorf("secure database file %q: %w", fullPath, err)
	}
	if info, err = guard.Stat(); err != nil || info.Mode().Perm() != 0o600 {
		guard.Close()
		return nil, created, fmt.Errorf("verify database file permissions %q", fullPath)
	}
	return guard, created, nil
}

func verifyPathIdentity(path string, guard *os.File) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("verify sqlite database pathname: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return errors.New("sqlite database pathname changed during open")
	}
	guardInfo, err := guard.Stat()
	if err != nil {
		return fmt.Errorf("verify sqlite database guard: %w", err)
	}
	if !os.SameFile(pathInfo, guardInfo) {
		return errors.New("sqlite database pathname changed during open")
	}
	return nil
}

func removeCreatedIfSame(path string, guard *os.File) {
	guardInfo, guardErr := guard.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if guardErr == nil && pathErr == nil && pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(pathInfo, guardInfo) {
		_ = os.Remove(path)
	}
}

func secureSQLiteFiles(path string, guard *os.File) error {
	if guard != nil {
		if err := verifyPathIdentity(path, guard); err != nil {
			return err
		}
		if err := guard.Chmod(0o600); err != nil {
			return fmt.Errorf("secure sqlite database: %w", err)
		}
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect sqlite file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("sqlite file is not a regular file")
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return fmt.Errorf("secure sqlite file: %w", err)
		}
		verified, err := os.Stat(candidate)
		if err != nil || verified.Mode().Perm() != 0o600 {
			return errors.New("verify sqlite file permissions")
		}
	}
	return nil
}

func verifyPragmas(db *sql.DB) error {
	checks := []struct {
		name string
		want int
	}{{"foreign_keys", 1}, {"busy_timeout", busyTimeoutMilliseconds}}
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
