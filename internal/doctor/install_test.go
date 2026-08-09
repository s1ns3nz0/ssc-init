package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

// installFixture lays down a managed installation the way install.Manager
// leaves one: version directories holding an executable core, plus pointer
// files naming versions.
func installFixture(t *testing.T, versions []string, current, previous string) (string, platform.InstallLayout) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	layout := platform.PathsForHome(home).Install()
	for _, version := range versions {
		directory := filepath.Join(layout.VersionsDir, version)
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		core := filepath.Join(directory, platform.CoreExecutableName)
		content := []byte("core-" + version)
		if err := os.WriteFile(core, content, 0o755); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		manifest := map[string]string{
			"schemaVersion": "ssc-init.install.manifest.v1",
			"version":       version,
			"sha256":        hex.EncodeToString(digest[:]),
		}
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "manifest.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(layout.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{layout.CurrentFile: current, layout.PreviousFile: previous} {
		if value == "" {
			continue
		}
		if err := os.WriteFile(name, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home, layout
}

func TestInstallReportOnAFreshMachineIsUnmanagedAndCreatesNothing(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatalf("fresh machine reported an error: %v", err)
	}
	if report != (Install{}) {
		t.Fatalf("report=%+v", report)
	}
	if _, err := os.Lstat(platform.PathsForHome(home).DataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reporting created host state: %v", err)
	}
}

func TestInstallReportCountsVersionsAndTheRollbackTarget(t *testing.T) {
	home, _ := installFixture(t, []string{"v0.1.0", "v0.2.0"}, "v0.2.0", "v0.1.0")

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	want := Install{
		Managed:           true,
		CurrentVersion:    "v0.2.0",
		PreviousVersion:   "v0.1.0",
		RollbackAvailable: true,
		VersionsInstalled: 2,
		IntegrityVerified: true,
	}
	if report != want {
		t.Fatalf("report=%+v want=%+v", report, want)
	}
}

func TestInstallReportWithoutARollbackTarget(t *testing.T) {
	home, _ := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	want := Install{
		Managed:           true,
		CurrentVersion:    "v0.1.0",
		VersionsInstalled: 1,
		IntegrityVerified: true,
	}
	if report != want {
		t.Fatalf("report=%+v want=%+v", report, want)
	}
}

// A previous pointer naming the active version is the residue of an interrupted
// rollback, not a rollback target.
func TestInstallReportIgnoresASelfNamingRollbackTarget(t *testing.T) {
	home, _ := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "v0.1.0")

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.RollbackAvailable || report.PreviousVersion != "" {
		t.Fatalf("report=%+v", report)
	}
}

func TestInstallReportRejectsAnUnusableCurrentPointer(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	if err := os.WriteFile(layout.CurrentFile, []byte("../../../etc/passwd\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err == nil {
		t.Fatalf("an unusable pointer reported success: %+v", report)
	}
	if report.Managed || report.CurrentVersion != "" {
		t.Fatalf("report=%+v", report)
	}
}

func TestInstallReportMarksAMissingActiveCoreUnavailable(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	if err := os.Remove(filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatalf("a missing core became an error rather than a report: %v", err)
	}
	if !report.Managed || report.IntegrityVerified || report.CurrentVersion != "v0.1.0" {
		t.Fatalf("report=%+v", report)
	}
}

func TestInstallReportMarksADigestMismatchUnverified(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	core := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	if err := os.WriteFile(core, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatalf("a digest mismatch became an unreadable report: %v", err)
	}
	if !report.Managed || report.IntegrityVerified || report.CurrentVersion != "v0.1.0" {
		t.Fatalf("report=%+v", report)
	}
}

func TestInstallReportDoesNotFollowASymlinkedCore(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	core := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	if err := os.Remove(core); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", core); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.IntegrityVerified {
		t.Fatalf("a symlinked core was reported available: %+v", report)
	}
}

// A version directory whose name the release build cannot produce is not an
// installed version, so it is never counted and never becomes a path.
func TestInstallReportCountsOnlyValidVersionDirectories(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	for _, name := range []string{"not-a-version", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(layout.VersionsDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(layout.VersionsDir, "v9.9.9"), []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.VersionsInstalled != 1 {
		t.Fatalf("versionsInstalled=%d want=1", report.VersionsInstalled)
	}
}

func TestInstallReportCarriesNoAbsolutePath(t *testing.T) {
	home, _ := installFixture(t, []string{"v0.1.0", "v0.2.0"}, "v0.2.0", "v0.1.0")

	report, err := InstallReport(home)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), home) || strings.Contains(string(raw), "/") {
		t.Fatalf("install report carries a path: %s", raw)
	}
}

// Reporting must never start a process: the health check that runs a core is
// the explicit install and rollback path, not a side effect of diagnostics.
func TestInstallReportExecutesNothing(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	marker := filepath.Join(t.TempDir(), "executed")
	core := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	script := "#!/bin/sh\nprintf invoked > \"" + marker + "\"\n"
	if err := os.WriteFile(core, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := InstallReport(home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the installed core was executed: %v", err)
	}
}

// Reporting takes no install lock: the lock is non-blocking, so acquiring it
// would turn a concurrent install into a failed report — and doctor is itself
// what the install health check runs while that lock is held.
func TestInstallReportReadsThroughAHeldInstallLock(t *testing.T) {
	home, layout := installFixture(t, []string{"v0.1.0"}, "v0.1.0", "")
	guard, err := os.OpenFile(filepath.Join(layout.Root, ".lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	report, err := InstallReport(home)
	if err != nil {
		t.Fatalf("a held install lock blocked reporting: %v", err)
	}
	if !report.Managed || report.CurrentVersion != "v0.1.0" {
		t.Fatalf("report=%+v", report)
	}
}
