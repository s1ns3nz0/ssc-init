package audit

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerSavePublishesOnlyVerifiedPrivateZIP(t *testing.T) {
	manager := newTestManager(t)
	stored, err := manager.Save(context.Background(), validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if stored.RunID != validRecord().Run.ID || stored.SafePath == "" || filepath.IsAbs(stored.SafePath) || !strings.HasPrefix(stored.SafePath, "$SSC_INIT_DATA/audit/") || !stored.Valid {
		t.Fatalf("unsafe stored result: %#v", stored)
	}
	name := strings.TrimPrefix(stored.SafePath, "$SSC_INIT_DATA/audit/")
	path := filepath.Join(manager.Root, name)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %v", info.Mode())
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	verified, err := Verify(file, info.Size())
	if err != nil || verified.ZIPSHA256 != stored.SHA256 {
		t.Fatalf("saved archive verification = %#v, %v", verified, err)
	}
	entries, err := os.ReadDir(manager.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary archive remains: %q", entry.Name())
		}
	}
}

func TestManagerListMarksCorruptArchiveInvalidWithoutDeletingIt(t *testing.T) {
	manager := newTestManager(t)
	if err := os.MkdirAll(manager.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "20260813T010203.000000000Z_0123456789abcdef0123456789abcdef.zip"
	path := filepath.Join(manager.Root, name)
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	listed, err := manager.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Valid || listed[0].SafePath != "$SSC_INIT_DATA/audit/"+name {
		t.Fatalf("List = %#v", listed)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("corrupt archive was removed: %v", err)
	}
}

func TestManagerRejectsSymlinkedRootAndArchive(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		manager := newTestManager(t)
		external := t.TempDir()
		if err := os.MkdirAll(filepath.Dir(manager.Root), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(external, manager.Root); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Save(context.Background(), validRecord()); err == nil {
			t.Fatal("Save accepted symlinked root")
		}
	})
	t.Run("archive", func(t *testing.T) {
		manager := newTestManager(t)
		if err := os.MkdirAll(manager.Root, 0o700); err != nil {
			t.Fatal(err)
		}
		name := "20260813T010203.000000000Z_0123456789abcdef0123456789abcdef.zip"
		if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(manager.Root, name)); err != nil {
			t.Fatal(err)
		}
		listed, err := manager.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(listed) != 1 || listed[0].Valid {
			t.Fatalf("List accepted symlinked archive: %#v", listed)
		}
		if _, err := manager.Open(context.Background(), "run:hex:0123456789abcdef0123456789abcdef"); err == nil {
			t.Fatal("Open accepted symlinked archive")
		}
	})
}

func TestManagerExportIsAtomicNoClobberAndRejectsUnsafeParents(t *testing.T) {
	manager := newTestManager(t)
	stored, err := manager.Save(context.Background(), validRecord())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(manager.Root, strings.TrimPrefix(stored.SafePath, safeAuditPrefix))
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(realTempDir(t), "export.zip")
	exported, err := manager.Export(context.Background(), stored.RunID, output, false)
	if err != nil {
		t.Fatal(err)
	}
	outputBytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceBytes, outputBytes) || exported.SHA256 != stored.SHA256 || exported.Profile != ProfileInternal {
		t.Fatalf("internal export changed bytes: %#v", exported)
	}
	if _, err := manager.Export(context.Background(), stored.RunID, output, false); err == nil {
		t.Fatal("Export overwrote an existing file")
	}
	external := t.TempDir()
	symlinkParent := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(external, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Export(context.Background(), stored.RunID, filepath.Join(symlinkParent, "unsafe.zip"), false); err == nil {
		t.Fatal("Export traversed a symlinked parent")
	}
}

func TestManagerRedactedExportsUseFreshUnlinkableTokens(t *testing.T) {
	manager := newTestManager(t)
	stored, err := manager.Save(context.Background(), namedRecord())
	if err != nil {
		t.Fatal(err)
	}
	firstPath := filepath.Join(realTempDir(t), "first.zip")
	secondPath := filepath.Join(realTempDir(t), "second.zip")
	first, err := manager.Export(context.Background(), stored.RunID, firstPath, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Export(context.Background(), stored.RunID, secondPath, true)
	if err != nil {
		t.Fatal(err)
	}
	firstVerified := verifyPath(t, firstPath)
	secondVerified := verifyPath(t, secondPath)
	if first.Profile != ProfileRedacted || second.Profile != ProfileRedacted || first.SHA256 == second.SHA256 || firstVerified.Record.Run.ID == secondVerified.Record.Run.ID || reflect.DeepEqual(firstVerified.Record.Inventory.Assets, secondVerified.Record.Inventory.Assets) {
		t.Fatalf("redacted exports are linkable: %#v / %#v", first, second)
	}
}

func TestManagerPruneEnforcesThirtyDaysAndOneGiBButKeepsNewest(t *testing.T) {
	t.Run("age", func(t *testing.T) {
		manager := newTestManager(t)
		now := time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
		manager.Now = func() time.Time { return now }
		manager.retentionAge = 30 * 24 * time.Hour
		manager.retentionBytes = 1 << 30
		now = now.Add(-31 * 24 * time.Hour)
		if _, err := manager.Save(context.Background(), recordWithRunID(validRecord(), 1)); err != nil {
			t.Fatal(err)
		}
		now = time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC)
		latest, err := manager.Save(context.Background(), recordWithRunID(validRecord(), 2))
		if err != nil {
			t.Fatal(err)
		}
		listed, err := manager.List(context.Background())
		if err != nil || len(listed) != 1 || listed[0].RunID != latest.RunID {
			t.Fatalf("age prune = %#v, %v", listed, err)
		}
	})
	t.Run("size and newest", func(t *testing.T) {
		manager := newTestManager(t)
		now := time.Date(2026, 8, 13, 1, 2, 1, 0, time.UTC)
		manager.Now = func() time.Time { return now }
		var stored []Stored
		for index := 0; index < 3; index++ {
			item, err := manager.Save(context.Background(), recordWithRunID(validRecord(), index+10))
			if err != nil {
				t.Fatal(err)
			}
			stored = append(stored, item)
			now = now.Add(time.Second)
		}
		manager.retentionBytes = stored[2].Size + stored[1].Size - 1
		if err := manager.Prune(context.Background()); err != nil {
			t.Fatal(err)
		}
		listed, err := manager.List(context.Background())
		if err != nil || len(listed) != 1 || listed[0].RunID != stored[2].RunID {
			t.Fatalf("size prune = %#v, %v", listed, err)
		}
		manager.retentionBytes = stored[2].Size - 1
		if err := manager.Prune(context.Background()); err != nil {
			t.Fatal(err)
		}
		listed, err = manager.List(context.Background())
		if err != nil || len(listed) != 1 || listed[0].RunID != stored[2].RunID {
			t.Fatalf("newest was not preserved: %#v, %v", listed, err)
		}
	})
}

func TestManagerConcurrentSaveOpenExportAndPrune(t *testing.T) {
	manager := newTestManager(t)
	const operations = 16
	var wait sync.WaitGroup
	errorsSeen := make(chan error, operations)
	for index := 0; index < operations; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			record := recordWithRunID(validRecord(), index+100)
			stored, err := manager.Save(context.Background(), record)
			if err != nil {
				errorsSeen <- err
				return
			}
			if _, err := manager.Open(context.Background(), stored.RunID); err != nil {
				errorsSeen <- err
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if err := manager.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	listed, err := manager.List(context.Background())
	if err != nil || len(listed) != operations {
		t.Fatalf("concurrent list = %d, %v", len(listed), err)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	home := t.TempDir()
	random := make([]byte, 8192)
	for index := range random {
		random[index] = byte(index)
	}
	return &Manager{
		Root:   filepath.Join(home, "Library", "Application Support", "SSC Init", "audit"),
		Home:   home,
		Now:    func() time.Time { return time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC) },
		Random: bytes.NewReader(random),
		Render: func(Record) ([]byte, error) { return []byte("report\n"), nil },
	}
}

func verifyPath(t *testing.T, path string) Verified {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func recordWithRunID(record Record, value int) Record {
	record.Run.ID = fmt.Sprintf("run:hex:%032x", value)
	return record
}

func realTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
