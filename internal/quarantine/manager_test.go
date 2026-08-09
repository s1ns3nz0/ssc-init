package quarantine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type memoryRecorder struct{ records []Record }

func (m *memoryRecorder) SaveQuarantineRecord(_ context.Context, record Record) error {
	m.records = append(m.records, record)
	return nil
}

func TestManagerQuarantinesExactRegularFileAndRemovesExecution(t *testing.T) {
	home := physicalTempDir(t)
	source := filepath.Join(home, ".tools", "fixture")
	writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
	recorder := &memoryRecorder{}
	manager := Manager{Home: home, Recorder: recorder, Now: sequenceClock(time.Unix(10, 0).UTC())}
	record := fixtureRecord("$HOME/.tools/fixture", []byte("fixture bytes"))

	got, err := manager.Quarantine(context.Background(), record)
	if err != nil || got.State != StateQuarantined || len(recorder.records) != 2 || recorder.records[0].State != StateRequested {
		t.Fatalf("record=%+v saved=%+v err=%v", got, recorder.records, err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	stored := manager.quarantineFile(record.ID)
	info, err := os.Lstat(stored)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("quarantine mode=%v err=%v", info, err)
	}
	content, err := os.ReadFile(stored)
	if err != nil || string(content) != "fixture bytes" {
		t.Fatalf("content=%q err=%v", content, err)
	}
}

func TestManagerRejectsSymlinkDigestMismatchCollisionAndReplacement(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(t *testing.T, home, source string, manager *Manager, record *Record)
	}{
		{name: "symlink", setup: func(t *testing.T, home, source string, _ *Manager, _ *Record) {
			writeQuarantineFixture(t, filepath.Join(home, "target"), []byte("fixture bytes"), 0o755)
			if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "target"), source); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "parent-symlink", setup: func(t *testing.T, home, _ string, _ *Manager, _ *Record) {
			target := filepath.Join(home, "elsewhere")
			writeQuarantineFixture(t, filepath.Join(target, "fixture"), []byte("fixture bytes"), 0o755)
			if err := os.Symlink(target, filepath.Join(home, ".tools")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "digest", setup: func(t *testing.T, _, source string, _ *Manager, record *Record) {
			writeQuarantineFixture(t, source, []byte("changed"), 0o755)
		}},
		{name: "collision", setup: func(t *testing.T, _, source string, manager *Manager, record *Record) {
			writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
			writeQuarantineFixture(t, manager.quarantineFile(record.ID), []byte("occupied"), 0o600)
		}},
		{name: "replacement", setup: func(t *testing.T, _, source string, manager *Manager, _ *Record) {
			writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
			manager.beforeSourceRemoval = func() {
				replacement := source + ".replacement"
				writeQuarantineFixture(t, replacement, []byte("replacement"), 0o755)
				if err := os.Rename(replacement, source); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := physicalTempDir(t)
			source := filepath.Join(home, ".tools", "fixture")
			recorder := &memoryRecorder{}
			manager := Manager{Home: home, Recorder: recorder, Now: sequenceClock(time.Unix(10, 0).UTC())}
			record := fixtureRecord("$HOME/.tools/fixture", []byte("fixture bytes"))
			testCase.setup(t, home, source, &manager, &record)
			if _, err := manager.Quarantine(context.Background(), record); err == nil {
				t.Fatal("unsafe quarantine succeeded")
			}
			if testCase.name == "replacement" {
				if len(recorder.records) != 2 || recorder.records[1].State != StateQuarantined {
					t.Fatalf("records=%+v", recorder.records)
				}
			} else if len(recorder.records) != 2 || recorder.records[1].State != StateFailed {
				t.Fatalf("records=%+v", recorder.records)
			}
			if testCase.name == "replacement" {
				content, err := os.ReadFile(source)
				if err != nil || string(content) != "replacement" {
					t.Fatalf("replacement removed: %q %v", content, err)
				}
			}
		})
	}
}

func TestManagerCancellationPersistsFailureWithoutTouchingSource(t *testing.T) {
	home := physicalTempDir(t)
	source := filepath.Join(home, ".tools", "fixture")
	writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
	recorder := &memoryRecorder{}
	manager := Manager{Home: home, Recorder: recorder, Now: sequenceClock(time.Unix(10, 0).UTC())}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Quarantine(ctx, fixtureRecord("$HOME/.tools/fixture", []byte("fixture bytes"))); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if len(recorder.records) != 2 || recorder.records[1].State != StateFailed || recorder.records[1].FailureCode != FailureCancelled {
		t.Fatalf("records=%+v", recorder.records)
	}
	if content, err := os.ReadFile(source); err != nil || string(content) != "fixture bytes" {
		t.Fatalf("source changed: %q %v", content, err)
	}
}

func TestManagerRestoresExactBytesAndOriginalModeWithoutOverwrite(t *testing.T) {
	home := physicalTempDir(t)
	source := filepath.Join(home, ".tools", "fixture")
	writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
	recorder := &memoryRecorder{}
	manager := Manager{Home: home, Recorder: recorder, Now: sequenceClock(time.Unix(10, 0).UTC())}
	quarantined, err := manager.Quarantine(context.Background(), fixtureRecord("$HOME/.tools/fixture", []byte("fixture bytes")))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := manager.Restore(context.Background(), quarantined)
	if err != nil || restored.State != StateRestored || len(recorder.records) != 3 {
		t.Fatalf("record=%+v records=%+v err=%v", restored, recorder.records, err)
	}
	content, err := os.ReadFile(source)
	info, statErr := os.Lstat(source)
	if err != nil || statErr != nil || string(content) != "fixture bytes" || info.Mode().Perm() != 0o755 {
		t.Fatalf("content=%q mode=%v err=%v statErr=%v", content, info, err, statErr)
	}
	if _, err := os.Lstat(manager.quarantineFile(quarantined.ID)); !os.IsNotExist(err) {
		t.Fatalf("quarantine copy remains: %v", err)
	}
}

func TestManagerRestoreRefusesExistingDestinationAndKeepsQuarantine(t *testing.T) {
	home := physicalTempDir(t)
	source := filepath.Join(home, ".tools", "fixture")
	writeQuarantineFixture(t, source, []byte("fixture bytes"), 0o755)
	recorder := &memoryRecorder{}
	manager := Manager{Home: home, Recorder: recorder, Now: sequenceClock(time.Unix(10, 0).UTC())}
	quarantined, err := manager.Quarantine(context.Background(), fixtureRecord("$HOME/.tools/fixture", []byte("fixture bytes")))
	if err != nil {
		t.Fatal(err)
	}
	writeQuarantineFixture(t, source, []byte("new owner"), 0o644)
	if _, err := manager.Restore(context.Background(), quarantined); !errors.Is(err, ErrQuarantineCollision) {
		t.Fatalf("restore err=%v", err)
	}
	content, err := os.ReadFile(source)
	if err != nil || string(content) != "new owner" {
		t.Fatalf("destination changed: %q %v", content, err)
	}
	if _, err := os.Lstat(manager.quarantineFile(quarantined.ID)); err != nil {
		t.Fatalf("quarantine removed: %v", err)
	}
}

func fixtureRecord(ref string, content []byte) Record {
	digest := sha256.Sum256(content)
	return Record{ID: "quarantine:fixture", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: ref, SHA256: fmt.Sprintf("%x", digest), OriginalMode: 0o755}
}

func writeQuarantineFixture(t *testing.T, name string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, mode); err != nil {
		t.Fatal(err)
	}
}

func physicalTempDir(t *testing.T) string {
	t.Helper()
	value, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func sequenceClock(start time.Time) func() time.Time {
	next := start
	return func() time.Time { value := next; next = next.Add(time.Second); return value }
}
