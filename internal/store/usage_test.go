package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func statSizeSum(t *testing.T, path string) int64 {
	t.Helper()
	var total int64
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(candidate)
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

func TestUsageAtReportsSizeSnapshotCountAndDefaultRetention(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "usage-one", now.Add(-2*time.Hour), now)
	saveSnapshotAt(t, s, "usage-two", now.Add(-time.Hour), now)

	usage, err := UsageAt(context.Background(), s.Path(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.SnapshotCount != 2 {
		t.Fatalf("snapshot count=%d want=2", usage.SnapshotCount)
	}
	total := statSizeSum(t, s.Path())
	if difference := usage.SizeBytes - total; difference > 4096 || difference < -4096 {
		t.Fatalf("size=%d stat total=%d", usage.SizeBytes, total)
	}
	databaseOnly, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if usage.SizeBytes <= databaseOnly.Size() {
		t.Fatalf("size=%d excludes the write-ahead log (database alone=%d)", usage.SizeBytes, databaseOnly.Size())
	}
	if usage.SnapshotRetention != 30*24*time.Hour || usage.AssetHistoryRetention != 90*24*time.Hour {
		t.Fatalf("retention=%v/%v want 30d/90d", usage.SnapshotRetention, usage.AssetHistoryRetention)
	}
}

func TestUsageAtEchoesConfiguredRetentionWindows(t *testing.T) {
	s := openTestStore(t)

	usage, err := UsageAt(context.Background(), s.Path(), Options{SnapshotRetention: 3 * time.Hour, AssetHistoryRetention: 5 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if usage.SnapshotRetention != 3*time.Hour || usage.AssetHistoryRetention != 5*time.Hour {
		t.Fatalf("retention=%v/%v want 3h/5h", usage.SnapshotRetention, usage.AssetHistoryRetention)
	}
}

// TestUsageAtReportsReclaimableSpaceFromTheFreelist covers the state the
// reclamation gate can never clear on its own: pruning leaves free pages that
// stay below the gate's thresholds, so the file never shrinks. Reclaimable
// bytes is the only user-visible signal that this is happening.
func TestUsageAtReportsReclaimableSpaceFromTheFreelist(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for index := 0; index < 24; index++ {
		saveSnapshotAt(t, s, "reclaim-"+string(rune('a'+index)), now.Add(time.Duration(index)*time.Minute), now)
	}
	// One later save prunes every accumulated snapshot at once, which is the
	// state the reclamation gate is meant to notice and, below its thresholds,
	// silently does not.
	saveSnapshotAt(t, s, "reclaim-final", now.Add(90*24*time.Hour), now.Add(90*24*time.Hour))

	usage, err := UsageAt(context.Background(), s.Path(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.ReclaimableBytes <= 0 {
		t.Fatalf("reclaimable=%d want >0 after pruning", usage.ReclaimableBytes)
	}
	if usage.ReclaimableBytes%4096 != 0 {
		t.Fatalf("reclaimable=%d is not a whole number of 4096-byte pages", usage.ReclaimableBytes)
	}
	if usage.ReclaimableBytes > usage.SizeBytes {
		t.Fatalf("reclaimable=%d exceeds size=%d", usage.ReclaimableBytes, usage.SizeBytes)
	}
}

// TestUsageAtCreatesNoSQLiteSidecarFiles keeps measurement free of side effects:
// a read-only connection to a write-ahead-logged database would otherwise create
// the log and shared-memory files, leaving umask-moded files in the state
// directory and inflating the footprint the caller asked about.
func TestUsageAtCreatesNoSQLiteSidecarFiles(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "sidecar-one", now, now)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	usage, err := UsageAt(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.SnapshotCount != 1 {
		t.Fatalf("snapshot count=%d want=1", usage.SnapshotCount)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("usage created %s: %v", suffix, err)
		}
	}
}

func TestUsageAtMissingStoreReportsZeroRatherThanFailing(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.db")

	usage, err := UsageAt(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.SizeBytes != 0 || usage.ReclaimableBytes != 0 || usage.SnapshotCount != 0 {
		t.Fatalf("usage=%+v want zero sizes and counts", usage)
	}
	if usage.SnapshotRetention != 30*24*time.Hour || usage.AssetHistoryRetention != 90*24*time.Hour {
		t.Fatalf("retention=%v/%v want 30d/90d", usage.SnapshotRetention, usage.AssetHistoryRetention)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("usage created the database: %v", err)
	}
}

// TestUsageAtCreatesNoWalWhenOnlyShmExists pins the invariant that measurement
// never leaves a file behind: a leftover shared-memory file with no log selects
// the read-through branch, whose connection would otherwise create the log.
func TestUsageAtCreatesNoWalWhenOnlyShmExists(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "shm-only", now, now)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture already has %s: %v", suffix, err)
		}
	}
	if err := os.WriteFile(path+"-shm", nil, 0o600); err != nil {
		t.Fatal(err)
	}

	usage, err := UsageAt(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if usage.SnapshotCount != 1 {
		t.Fatalf("snapshot count=%d want=1", usage.SnapshotCount)
	}
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("UsageAt created state.db-wal that did not exist before the call: %v", err)
	}
}

// TestUsageAtRestoresLoosenedSQLiteFileModes covers a mode loosened out of band:
// measurement is the only pass that touches these files between store opens, so
// it is where a 0644 database or shared-memory file gets pulled back to 0600.
func TestUsageAtRestoresLoosenedSQLiteFileModes(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	saveSnapshotAt(t, s, "modes", now, now)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+"-shm", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-shm"} {
		if err := os.Chmod(candidate, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := UsageAt(context.Background(), path, Options{}); err != nil {
		t.Fatal(err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%q mode=%v want 0600", suffix, info.Mode().Perm())
		}
	}
}

// TestUsageAtReclaimableMatchesTheFreelistProduct pins the figure to the
// freelist itself rather than to any positive multiple of it: a doubled or
// halved reclaimable figure misreports how much of the footprint pruning
// already released.
func TestUsageAtReclaimableMatchesTheFreelistProduct(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for index := 0; index < 24; index++ {
		saveSnapshotAt(t, s, "freelist-"+string(rune('a'+index)), now.Add(time.Duration(index)*time.Minute), now)
	}
	saveSnapshotAt(t, s, "freelist-final", now.Add(90*24*time.Hour), now.Add(90*24*time.Hour))

	usage, err := UsageAt(context.Background(), s.Path(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	var pageSize, freePages int64
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&freePages); err != nil {
		t.Fatal(err)
	}
	if freePages == 0 {
		t.Fatal("fixture has an empty freelist")
	}
	if want := pageSize * freePages; usage.ReclaimableBytes != want {
		t.Fatalf("reclaimable=%d want %d (page_size=%d freelist_count=%d)", usage.ReclaimableBytes, want, pageSize, freePages)
	}
}

func writeSidecar(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
}

func measuredSidecars(t *testing.T, path string) map[string]os.FileInfo {
	t.Helper()
	measured := map[string]os.FileInfo{}
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		measured[suffix] = info
	}
	return measured
}

func sidecarExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// TestDiscardMeasurementSQLiteFilesRemovesOnlyWhatMeasurementCreated covers the
// race the read-through branch cannot dodge: the log is measured, the writer
// checkpoints it away, and the measuring connection creates it again. What
// measurement made goes; what a writer holds stays.
func TestDiscardMeasurementSQLiteFilesRemovesOnlyWhatMeasurementCreated(t *testing.T) {
	t.Run("recreated empty log and shared memory", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.db")
		writeSidecar(t, path+"-wal", 32)
		writeSidecar(t, path+"-shm", 32768)
		measured := measuredSidecars(t, path)
		for _, suffix := range []string{"-wal", "-shm"} {
			if err := os.Remove(path + suffix); err != nil {
				t.Fatal(err)
			}
			writeSidecar(t, path+suffix, 0)
		}

		if err := discardMeasurementSQLiteFiles(path, measured); err != nil {
			t.Fatal(err)
		}

		for _, suffix := range []string{"-wal", "-shm"} {
			if sidecarExists(t, path+suffix) {
				t.Fatalf("measurement left %s behind", suffix)
			}
		}
	})

	t.Run("shared memory that measurement did not create", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.db")
		writeSidecar(t, path+"-wal", 32)
		writeSidecar(t, path+"-shm", 32768)
		measured := measuredSidecars(t, path)
		if err := os.Remove(path + "-wal"); err != nil {
			t.Fatal(err)
		}
		writeSidecar(t, path+"-wal", 0)

		if err := discardMeasurementSQLiteFiles(path, measured); err != nil {
			t.Fatal(err)
		}

		if sidecarExists(t, path+"-wal") {
			t.Fatal("measurement left -wal behind")
		}
		if !sidecarExists(t, path+"-shm") {
			t.Fatal("removed -shm that measurement did not create")
		}
	})

	t.Run("recreated log carrying frames", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.db")
		writeSidecar(t, path+"-wal", 32)
		measured := measuredSidecars(t, path)
		if err := os.Remove(path + "-wal"); err != nil {
			t.Fatal(err)
		}
		writeSidecar(t, path+"-wal", 4096)
		writeSidecar(t, path+"-shm", 32768)

		if err := discardMeasurementSQLiteFiles(path, measured); err != nil {
			t.Fatal(err)
		}

		for _, suffix := range []string{"-wal", "-shm"} {
			if !sidecarExists(t, path+suffix) {
				t.Fatalf("removed %s while a writer was using it", suffix)
			}
		}
	})

	t.Run("log unchanged since it was measured", func(t *testing.T) {
		path := filepath.Join(privateTempDir(t), "state.db")
		writeSidecar(t, path+"-wal", 0)
		writeSidecar(t, path+"-shm", 32768)
		measured := measuredSidecars(t, path)

		if err := discardMeasurementSQLiteFiles(path, measured); err != nil {
			t.Fatal(err)
		}

		for _, suffix := range []string{"-wal", "-shm"} {
			if !sidecarExists(t, path+suffix) {
				t.Fatalf("removed %s that measurement did not create", suffix)
			}
		}
	})
}
