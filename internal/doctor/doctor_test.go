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

	"github.com/ssc-init/ssc-init/internal/platform"
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
