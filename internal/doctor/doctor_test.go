package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"golang.org/x/sys/unix"
)

func TestCheckReportsRedactedReadOnlyDiagnostics(t *testing.T) {
	home := t.TempDir()
	paths := platform.PathsForHome(home)
	var writablePath string
	checker := New(Config{
		Product:          "SSC Init",
		Version:          "test",
		Paths:            paths,
		DatabasePath:     filepath.Join(paths.DataDir, "state.db"),
		Ecosystems:       []string{"npm", "agents", "npm"},
		OptionalCommands: []string{"docker", "npm"},
		LookPath: func(command string) (string, error) {
			if command == "npm" {
				return "/usr/bin/npm", nil
			}
			return "", errors.New("missing")
		},
		DirectoryWritable: func(path string) bool {
			writablePath = path
			return true
		},
	})

	result := checker.Check(context.Background())
	if result.Product != "SSC Init" || result.Version != "test" || result.GOOS != runtime.GOOS || result.GOARCH != runtime.GOARCH {
		t.Fatalf("result=%+v", result)
	}
	if writablePath != paths.DataDir || !result.DatabaseDirectoryWritable {
		t.Fatalf("writablePath=%q result=%+v", writablePath, result)
	}
	if len(result.CorePaths) != 2 || result.CorePaths[0].Path == home || !strings.HasPrefix(result.CorePaths[0].Path, "$HOME") {
		t.Fatalf("paths=%+v", result.CorePaths)
	}
	if got := append([]string(nil), result.Ecosystems...); !sort.StringsAreSorted(got) || len(got) != 2 {
		t.Fatalf("ecosystems=%v", result.Ecosystems)
	}
	if len(result.MissingOptionalCommands) != 1 || result.MissingOptionalCommands[0] != "docker" {
		t.Fatalf("missing=%v", result.MissingOptionalCommands)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), home) {
		t.Fatalf("home leaked: %s", raw)
	}
}

// TestResultJSONContractIsPinned is the contract test for the doctor payload:
// it fails on any added, removed, renamed, or reordered field, so a schema
// change is a deliberate edit here rather than an accident somewhere else.
func TestResultJSONContractIsPinned(t *testing.T) {
	raw, err := json.Marshal(Result{
		SchemaVersion:             schemaVersion,
		Product:                   "SSC Init",
		Version:                   "v0.2.0",
		Status:                    "ready",
		GOOS:                      "darwin",
		GOARCH:                    "arm64",
		DatabaseDirectoryWritable: true,
		Store: StoreUsage{
			SizeBytes:                    1,
			ReclaimableBytes:             2,
			SnapshotCount:                3,
			SnapshotRetentionSeconds:     4,
			AssetHistoryRetentionSeconds: 5,
		},
		Install: Install{
			Managed:           true,
			CurrentVersion:    "v0.2.0",
			PreviousVersion:   "v0.1.0",
			RollbackAvailable: true,
			VersionsInstalled: 2,
			CoreAvailable:     true,
		},
		CorePaths:               []Path{{Name: "data", Path: "$HOME/data"}},
		Ecosystems:              []string{"npm"},
		MissingOptionalCommands: []string{"docker"},
		Fatal:                   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"schemaVersion":"ssc-init.doctor.v2","product":"SSC Init","version":"v0.2.0",` +
		`"status":"ready","goos":"darwin","goarch":"arm64","databaseDirectoryWritable":true,` +
		`"store":{"sizeBytes":1,"reclaimableBytes":2,"snapshotCount":3,` +
		`"snapshotRetentionSeconds":4,"assetHistoryRetentionSeconds":5},` +
		`"install":{"managed":true,"currentVersion":"v0.2.0","previousVersion":"v0.1.0",` +
		`"rollbackAvailable":true,"versionsInstalled":2,"coreAvailable":true},` +
		`"corePaths":[{"name":"data","path":"$HOME/data"}],"ecosystems":["npm"],` +
		`"missingOptionalCommands":["docker"]}`
	if string(raw) != want {
		t.Fatalf("doctor payload changed:\n got=%s\nwant=%s", raw, want)
	}
}

func TestCheckReportsInstallHealth(t *testing.T) {
	want := Install{
		Managed:           true,
		CurrentVersion:    "v0.2.0",
		PreviousVersion:   "v0.1.0",
		RollbackAvailable: true,
		VersionsInstalled: 2,
		CoreAvailable:     true,
	}
	checker := New(Config{
		Paths:             platform.PathsForHome(t.TempDir()),
		DirectoryWritable: func(string) bool { return true },
		InstallReporter:   func() (Install, error) { return want, nil },
	})

	result := checker.Check(context.Background())
	if result.Install != want || result.Status != "ready" {
		t.Fatalf("result=%+v", result)
	}
	if result.SchemaVersion != "ssc-init.doctor.v2" {
		t.Fatalf("schemaVersion=%q", result.SchemaVersion)
	}
}

// A developer running a source build has no managed install and is not broken.
func TestCheckReportsNoInstallWithoutDegrading(t *testing.T) {
	checker := New(Config{
		Paths:             platform.PathsForHome(t.TempDir()),
		DirectoryWritable: func(string) bool { return true },
		InstallReporter:   func() (Install, error) { return Install{}, nil },
	})

	result := checker.Check(context.Background())
	if result.Status != "ready" || result.Install.Managed {
		t.Fatalf("result=%+v", result)
	}
}

func TestCheckDegradesWhenTheActiveCoreIsUnavailable(t *testing.T) {
	checker := New(Config{
		Paths:             platform.PathsForHome(t.TempDir()),
		DirectoryWritable: func(string) bool { return true },
		InstallReporter: func() (Install, error) {
			return Install{Managed: true, CurrentVersion: "v0.2.0", VersionsInstalled: 1}, nil
		},
	})

	result := checker.Check(context.Background())
	if result.Status != "degraded" {
		t.Fatalf("result=%+v", result)
	}
}

// A measurement failure degrades the report rather than failing the command.
func TestCheckDegradesWhenTheInstallCannotBeMeasured(t *testing.T) {
	checker := New(Config{
		Paths:             platform.PathsForHome(t.TempDir()),
		DirectoryWritable: func(string) bool { return true },
		InstallReporter:   func() (Install, error) { return Install{}, errors.New("install root is unavailable") },
	})

	result := checker.Check(context.Background())
	if result.Status != "degraded" || result.Fatal || result.Install != (Install{}) {
		t.Fatalf("result=%+v", result)
	}
}

func TestCheckMarksUnwritableDatabaseDirectoryDegraded(t *testing.T) {
	paths := platform.PathsForHome(t.TempDir())
	checker := New(Config{Paths: paths, DirectoryWritable: func(string) bool { return false }})

	result := checker.Check(context.Background())
	if result.Status != "degraded" || result.DatabaseDirectoryWritable {
		t.Fatalf("result=%+v", result)
	}
}

func TestDirectoryWritableRequiresWriteAndSearchOnNearestExistingDirectory(t *testing.T) {
	existing := t.TempDir()
	target := filepath.Join(existing, "not-created", "state")
	var gotPath string
	var gotMode uint32

	got := directoryWritableWith(target, os.Stat, func(path string, mode uint32) error {
		gotPath = path
		gotMode = mode
		return errors.New("search denied")
	})

	if got {
		t.Fatal("directoryWritableWith=true")
	}
	if gotPath != existing {
		t.Fatalf("access path=%q want=%q", gotPath, existing)
	}
	if gotMode != unix.W_OK|unix.X_OK {
		t.Fatalf("access mode=%d want=%d", gotMode, unix.W_OK|unix.X_OK)
	}
}

func TestCheckOnlyLooksUpOptionalExecutableAndNeverRunsPackageProbe(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "executed")
	executable := filepath.Join(bin, "package-probe")
	script := "#!/bin/sh\nprintf invoked > \"" + marker + "\"\n"
	if err := os.WriteFile(executable, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	lookups := 0
	checker := New(Config{
		Paths:            platform.PathsForHome(t.TempDir()),
		OptionalCommands: []string{"package-probe"},
		LookPath: func(command string) (string, error) {
			lookups++
			return executable, nil
		},
		DirectoryWritable: func(string) bool { return true },
	})

	result := checker.Check(context.Background())
	if result.Status != "ready" || lookups != 1 {
		t.Fatalf("result=%+v lookups=%d", result, lookups)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("optional package probe executed: %v", err)
	}
}
