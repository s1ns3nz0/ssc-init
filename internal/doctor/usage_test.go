package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

const (
	defaultSnapshotRetentionSeconds     = 30 * 24 * 60 * 60
	defaultAssetHistoryRetentionSeconds = 90 * 24 * 60 * 60
)

// canonicalTempDir resolves macOS's /var alias so the store's no-symlink path
// traversal accepts the fixture directory.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func openFixtureStore(t *testing.T, databasePath string) {
	t.Helper()
	opened, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func checkerForHome(t *testing.T, home string) *Checker {
	t.Helper()
	paths := platform.PathsForHome(home)
	return New(Config{
		Paths:             paths,
		DatabasePath:      filepath.Join(paths.DataDir, "state.db"),
		LookPath:          func(string) (string, error) { return "", errors.New("missing") },
		DirectoryWritable: func(string) bool { return true },
	})
}

func TestCheckReportsStoreFootprintAndRetentionWindows(t *testing.T) {
	home := canonicalTempDir(t)
	paths := platform.PathsForHome(home)
	databasePath := filepath.Join(paths.DataDir, "state.db")
	openFixtureStore(t, databasePath)

	result := checkerForHome(t, home).Check(context.Background())

	var total int64
	for _, candidate := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		info, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total == 0 {
		t.Fatal("fixture store has no on-disk size")
	}
	if difference := result.Store.SizeBytes - total; difference > 4096 || difference < -4096 {
		t.Fatalf("size=%d stat total=%d", result.Store.SizeBytes, total)
	}
	if result.Store.SnapshotCount != 0 || result.Store.ReclaimableBytes != 0 {
		t.Fatalf("store=%+v want an empty store", result.Store)
	}
	if result.Store.SnapshotRetentionSeconds != defaultSnapshotRetentionSeconds ||
		result.Store.AssetHistoryRetentionSeconds != defaultAssetHistoryRetentionSeconds {
		t.Fatalf("retention=%+v want %d/%d", result.Store, defaultSnapshotRetentionSeconds, defaultAssetHistoryRetentionSeconds)
	}
	if result.Status != "ready" {
		t.Fatalf("status=%q", result.Status)
	}
}

func TestCheckReportsZeroFootprintForAStoreThatWasNeverCreated(t *testing.T) {
	home := canonicalTempDir(t)

	result := checkerForHome(t, home).Check(context.Background())

	if result.Store.SizeBytes != 0 || result.Store.SnapshotCount != 0 || result.Store.ReclaimableBytes != 0 {
		t.Fatalf("store=%+v want zero", result.Store)
	}
	if result.Store.SnapshotRetentionSeconds != defaultSnapshotRetentionSeconds ||
		result.Store.AssetHistoryRetentionSeconds != defaultAssetHistoryRetentionSeconds {
		t.Fatalf("retention=%+v", result.Store)
	}
	if result.Status != "ready" {
		t.Fatalf("status=%q", result.Status)
	}
	if _, err := os.Stat(filepath.Join(platform.PathsForHome(home).DataDir, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("doctor created the database: %v", err)
	}
}

// TestCheckPayloadCarriesNoAbsolutePath pins the privacy invariant across every
// field, including the ones this task added: doctor reports sizes and counts,
// never locations.
func TestCheckPayloadCarriesNoAbsolutePath(t *testing.T) {
	home := canonicalTempDir(t)
	databasePath := filepath.Join(platform.PathsForHome(home).DataDir, "state.db")
	openFixtureStore(t, databasePath)

	result := checkerForHome(t, home).Check(context.Background())

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), home) {
		t.Fatalf("home leaked: %s", raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	forEachString(payload, func(value string) {
		if strings.HasPrefix(value, "/") {
			t.Fatalf("absolute path %q in payload: %s", value, raw)
		}
	})
}

func forEachString(value any, visit func(string)) {
	switch typed := value.(type) {
	case string:
		visit(typed)
	case []any:
		for _, element := range typed {
			forEachString(element, visit)
		}
	case map[string]any:
		for _, element := range typed {
			forEachString(element, visit)
		}
	}
}
