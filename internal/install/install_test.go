package install_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/install"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const (
	cpuTypeX8664 = 0x01000007
	cpuTypeARM64 = 0x0100000c
)

// isolatedHome returns a resolved temporary home; macOS temp directories live
// under the /var -> /private/var symlink.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func newManager(t *testing.T, home string) install.Manager {
	t.Helper()
	return install.New(home)
}

// universalCore builds a minimal fat Mach-O image carrying one slice per cpu type.
func universalCore(cpuTypes ...uint32) []byte {
	const sliceSize = 4096
	image := make([]byte, sliceSize*(len(cpuTypes)+1))
	binary.BigEndian.PutUint32(image[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(image[4:], uint32(len(cpuTypes)))
	for index, cpuType := range cpuTypes {
		entry := image[8+20*index:]
		offset := sliceSize * (index + 1)
		binary.BigEndian.PutUint32(entry[0:], cpuType)
		binary.BigEndian.PutUint32(entry[4:], 0)
		binary.BigEndian.PutUint32(entry[8:], uint32(offset))
		binary.BigEndian.PutUint32(entry[12:], sliceSize)
		binary.BigEndian.PutUint32(entry[16:], 12)
		binary.LittleEndian.PutUint32(image[offset:], 0xfeedfacf)
		image[offset+sliceSize-1] = byte(index + 1)
	}
	return image
}

func writeFakeCore(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssc-init-darwin-universal")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestOf(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

// assertNothingStaged proves the fail-closed contract: no promoted version and
// no staging remnant.
func assertNothingStaged(t *testing.T, home, version string) {
	t.Helper()
	layout := platform.PathsForHome(home).Install()
	if _, err := os.Lstat(filepath.Join(layout.VersionsDir, version)); !os.IsNotExist(err) {
		t.Fatalf("failed stage left a version directory behind: %v", err)
	}
	entries, err := os.ReadDir(layout.StagingDir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("failed stage left %d staging entries behind", len(entries))
	}
}

func assertValueFree(t *testing.T, err error, values ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, value := range values {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("error leaks %q: %v", value, err)
		}
	}
}

func TestStageInstallsAVerifiedVersionWithoutActivatingIt(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)

	if err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content)); err != nil {
		t.Fatal(err)
	}

	layout := platform.PathsForHome(home).Install()
	corePath := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	info, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("staged core is not a regular file: %v", info.Mode())
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("staged core is not executable: %v", info.Mode().Perm())
	}
	staged, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(content) {
		t.Fatal("staged core does not match the verified source bytes")
	}
	if _, err := os.Stat(layout.CurrentFile); !os.IsNotExist(err) {
		t.Fatal("Stage activated the version instead of only staging it")
	}

	raw, err := os.ReadFile(filepath.Join(layout.VersionsDir, "v0.1.0", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]string
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, raw)
	}
	want := map[string]string{
		"schemaVersion": "ssc-init.install.manifest.v1",
		"version":       "v0.1.0",
		"sha256":        digestOf(content),
	}
	if len(manifest) != len(want) {
		t.Fatalf("manifest records more than version and digest: %v", manifest)
	}
	for key, value := range want {
		if manifest[key] != value {
			t.Fatalf("manifest %s = %q, want %q", key, manifest[key], value)
		}
	}
	if strings.Contains(string(raw), home) || strings.Contains(string(raw), source) {
		t.Fatal("manifest records a host path")
	}
}

func TestStageRejectsADigestMismatchAndLeavesNothingBehind(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := writeFakeCore(t, universalCore(cpuTypeX8664, cpuTypeARM64))

	err := manager.Stage(context.Background(), source, "v0.1.0", strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("Stage accepted a binary whose digest does not match")
	}
	assertValueFree(t, err, source, home)
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageRejectsAnUnusableExpectedDigest(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)

	for _, digest := range []string{
		"",
		strings.Repeat("0", 63),
		strings.Repeat("0", 65),
		strings.ToUpper(digestOf(content)),
		strings.Repeat("z", 64),
	} {
		if err := manager.Stage(context.Background(), source, "v0.1.0", digest); err == nil {
			t.Fatalf("Stage accepted digest %q", digest)
		}
		assertNothingStaged(t, home, "v0.1.0")
	}
}

func TestStageRejectsATruncatedCore(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)[:2048]
	source := writeFakeCore(t, content)

	err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content))
	if err == nil {
		t.Fatal("Stage accepted a truncated core")
	}
	assertValueFree(t, err, source, home)
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageRejectsSomethingThatIsNotMachO(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := []byte("core-bytes")
	source := writeFakeCore(t, content)

	err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content))
	if err == nil {
		t.Fatal("Stage accepted a core that is not a mach-o binary")
	}
	assertValueFree(t, err, source, home)
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageRejectsASingleArchitectureCore(t *testing.T) {
	home := isolatedHome(t)
	for _, cpuType := range []uint32{cpuTypeARM64, cpuTypeX8664} {
		manager := newManager(t, home)
		content := universalCore(cpuType)
		source := writeFakeCore(t, content)

		err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content))
		if err == nil {
			t.Fatalf("Stage accepted a single-architecture core (cpu %#x)", cpuType)
		}
		assertValueFree(t, err, source, home)
		assertNothingStaged(t, home, "v0.1.0")
	}
}

func TestStageRejectsAVersionItCannotName(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)

	for _, version := range []string{"../escape", "", "latest", "v1.0.0/nested", "v1.0.0\n"} {
		err := manager.Stage(context.Background(), source, version, digestOf(content))
		if err == nil {
			t.Fatalf("Stage accepted version %q", version)
		}
		assertValueFree(t, err, source, home)
	}
	layout := platform.PathsForHome(home).Install()
	if _, err := os.Lstat(layout.VersionsDir); !os.IsNotExist(err) {
		t.Fatalf("a rejected version created the versions directory: %v", err)
	}
}

func TestStageRejectsASymlinkedSource(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	target := writeFakeCore(t, content)
	source := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, source); err != nil {
		t.Fatal(err)
	}

	err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content))
	if err == nil {
		t.Fatal("Stage followed a symlinked source")
	}
	assertValueFree(t, err, source, target, home)
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageRejectsADirectorySource(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := t.TempDir()

	err := manager.Stage(context.Background(), source, "v0.1.0", strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("Stage accepted a directory as a core binary")
	}
	assertValueFree(t, err, source, home)
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageRejectsAFIFOSourceWithoutBlocking(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(source, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- manager.Stage(context.Background(), source, "v0.1.0", strings.Repeat("a", 64))
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Stage accepted a FIFO as a core binary")
		}
		assertValueFree(t, err, source, home)
	case <-time.After(10 * time.Second):
		t.Fatal("Stage blocked on a FIFO source")
	}
	assertNothingStaged(t, home, "v0.1.0")
}

func TestStageReplacesAPartialStagingArtifact(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	layout := platform.PathsForHome(home).Install()
	partial := filepath.Join(layout.StagingDir, "v0.1.0")
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, platform.CoreExecutableName), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)

	if err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content)); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(content) {
		t.Fatal("a partial staging artifact survived into the promoted version")
	}
	entries, err := os.ReadDir(layout.StagingDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("staging still holds %d entries after a successful stage", len(entries))
	}
}

func TestStageIsIdempotentAcrossRuns(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)
	layout := platform.PathsForHome(home).Install()
	corePath := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)

	for run := range 3 {
		if err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content)); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		staged, err := os.ReadFile(corePath)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if string(staged) != string(content) {
			t.Fatalf("run %d: staged core changed", run)
		}
	}
	versions, err := os.ReadDir(layout.VersionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("repeated staging produced %d version directories", len(versions))
	}
}

func TestStageFailureAfterASuccessKeepsTheInstalledVersion(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)
	if err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content)); err != nil {
		t.Fatal(err)
	}

	bad := writeFakeCore(t, []byte("core-bytes"))
	if err := manager.Stage(context.Background(), bad, "v0.1.0", digestOf([]byte("core-bytes"))); err == nil {
		t.Fatal("Stage accepted a core that is not a mach-o binary")
	}

	layout := platform.PathsForHome(home).Install()
	staged, err := os.ReadFile(filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName))
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(content) {
		t.Fatal("a failed re-stage damaged the installed version")
	}
	entries, err := os.ReadDir(layout.StagingDir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("failed re-stage left %d staging entries behind", len(entries))
	}
}

func TestStageCannotEscapeTheInstallRoot(t *testing.T) {
	home := isolatedHome(t)
	layout := platform.PathsForHome(home).Install()
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(layout.VersionsDir, "v0.1.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.StagingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(layout.StagingDir, "v0.2.0")); err != nil {
		t.Fatal(err)
	}

	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)
	for _, version := range []string{"v0.1.0", "v0.2.0"} {
		_ = manager.Stage(context.Background(), source, version, digestOf(content))
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Stage wrote %d entries outside the install root", len(entries))
	}
}

func TestStageNeverTouchesSharedState(t *testing.T) {
	home := isolatedHome(t)
	statePath := filepath.Join(platform.PathsForHome(home).DataDir, "state.db")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)

	if err := manager.Stage(context.Background(), source, "v0.1.0", digestOf(content)); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(statePath)
	if err != nil || string(stored) != "state" {
		t.Fatalf("Stage disturbed the shared state database: %q %v", stored, err)
	}
}

func TestStagePropagatesCancellation(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	content := universalCore(cpuTypeX8664, cpuTypeARM64)
	source := writeFakeCore(t, content)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := manager.Stage(ctx, source, "v0.1.0", digestOf(content))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stage did not propagate cancellation: %v", err)
	}
	assertNothingStaged(t, home, "v0.1.0")
}

// --- Task 7: health check, atomic switch, previous known-good, rollback, prune

// coreFor makes each version's bytes distinct so a digest identifies a version.
func coreFor(version string) []byte {
	image := universalCore(cpuTypeX8664, cpuTypeARM64)
	copy(image[len(image)-len(version)-1:], version)
	return image
}

func stagedManager(t *testing.T, home string, versions ...string) install.Manager {
	t.Helper()
	manager := install.New(home)
	manager.Health = func(context.Context, string) error { return nil }
	for _, version := range versions {
		stage(t, manager, version)
	}
	return manager
}

func stage(t *testing.T, manager install.Manager, version string) {
	t.Helper()
	content := coreFor(version)
	if err := manager.Stage(context.Background(), writeFakeCore(t, content), version, digestOf(content)); err != nil {
		t.Fatalf("stage %s: %v", version, err)
	}
}

// activate performs the real install sequence — stage the version, then switch
// to it. Staging several versions ahead of any activation is not that sequence:
// prune retains only the active version and its rollback target, so a version
// staged before an unrelated switch is superseded by definition.
func activate(t *testing.T, manager install.Manager, versions ...string) {
	t.Helper()
	for _, version := range versions {
		stage(t, manager, version)
		if err := manager.Activate(context.Background(), version); err != nil {
			t.Fatalf("activate %s: %v", version, err)
		}
	}
}

func readPointerFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pointer: %v", err)
	}
	return strings.TrimSpace(string(content))
}

func assertPointers(t *testing.T, home, current, previous string) {
	t.Helper()
	layout := platform.PathsForHome(home).Install()
	if got := readPointerFile(t, layout.CurrentFile); got != current {
		t.Fatalf("current = %q, want %q", got, current)
	}
	if previous == "" {
		if _, err := os.Lstat(layout.PreviousFile); !os.IsNotExist(err) {
			t.Fatalf("previous exists when none was expected: %v", err)
		}
		return
	}
	if got := readPointerFile(t, layout.PreviousFile); got != previous {
		t.Fatalf("previous = %q, want %q", got, previous)
	}
}

func assertVersionsPresent(t *testing.T, home string, versions ...string) {
	t.Helper()
	layout := platform.PathsForHome(home).Install()
	entries, err := os.ReadDir(layout.VersionsDir)
	if err != nil {
		t.Fatal(err)
	}
	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		present[entry.Name()] = true
	}
	if len(present) != len(versions) {
		t.Fatalf("installed versions = %v, want %v", present, versions)
	}
	for _, version := range versions {
		if !present[version] {
			t.Fatalf("installed versions = %v, want %v", present, versions)
		}
	}
}

// sharedData is everything an install, an update, a rollback, or a prune must
// never read, write, or remove (design §5.3).
func sharedData(home string) map[string]string {
	layout := platform.PathsForHome(home).Install()
	return map[string]string{
		layout.StateDatabase:                        "state",
		filepath.Join(layout.BundlesDir, "ti.json"): "bundle",
		filepath.Join(layout.ReportsDir, "r.json"):  "report",
		filepath.Join(layout.QuarantineDir, "q"):    "quarantined",
	}
}

func seedSharedData(t *testing.T, home string) {
	t.Helper()
	for path, content := range sharedData(home) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertSharedDataIntact(t *testing.T, home string) {
	t.Helper()
	for path, want := range sharedData(home) {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("shared data at %s = %q (%v), want %q", filepath.Base(path), got, err, want)
		}
	}
}

// assertUsableInstall is the crash-safety predicate: either nothing is active,
// or the active pointer names an installed version with a runnable core.
func assertUsableInstall(t *testing.T, home string) {
	t.Helper()
	layout := platform.PathsForHome(home).Install()
	manager := install.New(home)
	version, ok, err := manager.Current()
	if err != nil {
		t.Fatalf("current pointer is unreadable after a crash: %v", err)
	}
	if !ok {
		return
	}
	if !platform.ValidInstallVersion(version) {
		t.Fatalf("current pointer holds an unusable version %q", version)
	}
	info, err := os.Lstat(filepath.Join(layout.VersionsDir, version, platform.CoreExecutableName))
	if err != nil {
		t.Fatalf("active version %q has no core: %v", version, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("active core is not a runnable regular file: %v", info.Mode())
	}
}

func TestActivateSwitchesOnlyAfterAPassingHealthCheck(t *testing.T) {
	home := isolatedHome(t)
	seedSharedData(t, home)
	manager := stagedManager(t, home, "v0.1.0")
	layout := platform.PathsForHome(home).Install()

	var checked string
	var checkedBeforeSwitch bool
	manager.Health = func(_ context.Context, executablePath string) error {
		checked = executablePath
		_, err := os.Stat(layout.CurrentFile)
		checkedBeforeSwitch = os.IsNotExist(err)
		return nil
	}

	if err := manager.Activate(context.Background(), "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	if !checkedBeforeSwitch {
		t.Fatal("Activate switched the pointer before the health check ran")
	}
	want := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	if checked != want {
		t.Fatalf("health check ran against %q, want %q", checked, want)
	}
	assertPointers(t, home, "v0.1.0", "")
	version, ok, err := manager.Current()
	if err != nil || !ok || version != "v0.1.0" {
		t.Fatalf("Current() = %q %v %v", version, ok, err)
	}
	assertSharedDataIntact(t, home)
}

func TestActivateRefusesWithoutAHealthCheck(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home, "v0.1.0")
	manager.Health = nil

	if err := manager.Activate(context.Background(), "v0.1.0"); err == nil {
		t.Fatal("Activate switched without a health check")
	}
	if _, err := os.Stat(platform.PathsForHome(home).Install().CurrentFile); !os.IsNotExist(err) {
		t.Fatal("Activate wrote a pointer without a health check")
	}
}

func TestActivateKeepsTheLastKnownGoodWhenHealthFails(t *testing.T) {
	home := isolatedHome(t)
	seedSharedData(t, home)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	manager.Health = func(context.Context, string) error { return errors.New("doctor: degraded") }
	err := manager.Activate(context.Background(), "v0.2.0")
	if err == nil {
		t.Fatal("Activate switched to a version that failed its health check")
	}
	assertValueFree(t, err, home)

	assertPointers(t, home, "v0.1.0", "")
	// The failed version stays staged so the operator can retry without
	// re-downloading it.
	assertVersionsPresent(t, home, "v0.1.0", "v0.2.0")
	assertSharedDataIntact(t, home)
}

func TestActivateRecordsThePreviousVersionForRollback(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)

	activate(t, manager, "v0.1.0")
	assertPointers(t, home, "v0.1.0", "")
	activate(t, manager, "v0.2.0")
	assertPointers(t, home, "v0.2.0", "v0.1.0")
	activate(t, manager, "v0.3.0")
	assertPointers(t, home, "v0.3.0", "v0.2.0")

	previous, ok, err := manager.Previous()
	if err != nil || !ok || previous != "v0.2.0" {
		t.Fatalf("Previous() = %q %v %v", previous, ok, err)
	}
}

func TestActivatingTheCurrentVersionDoesNotDestroyTheRollbackTarget(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0", "v0.2.0", "v0.2.0")

	assertPointers(t, home, "v0.2.0", "v0.1.0")
}

func TestActivateRejectsAVersionTamperedWithAfterStaging(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	layout := platform.PathsForHome(home).Install()
	tampered := filepath.Join(layout.VersionsDir, "v0.2.0", platform.CoreExecutableName)
	if err := os.WriteFile(tampered, coreFor("v0.9.9"), 0o755); err != nil {
		t.Fatal(err)
	}
	ran := false
	manager.Health = func(context.Context, string) error { ran = true; return nil }

	err := manager.Activate(context.Background(), "v0.2.0")
	if err == nil {
		t.Fatal("Activate accepted a version tampered with after staging")
	}
	if ran {
		t.Fatal("Activate executed a version whose digest no longer matches its manifest")
	}
	assertValueFree(t, err, home, tampered)
	assertPointers(t, home, "v0.1.0", "")
}

func TestActivateRejectsAVersionSwappedDuringItsHealthCheck(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	layout := platform.PathsForHome(home).Install()
	manager.Health = func(context.Context, string) error {
		return os.WriteFile(
			filepath.Join(layout.VersionsDir, "v0.2.0", platform.CoreExecutableName),
			coreFor("v0.9.9"), 0o755,
		)
	}
	if err := manager.Activate(context.Background(), "v0.2.0"); err == nil {
		t.Fatal("Activate switched to a core replaced during its health check")
	}
	assertPointers(t, home, "v0.1.0", "")
}

func TestActivateRejectsAVersionThatIsNotInstalled(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")

	for _, version := range []string{"v9.9.9", "../escape", "", "latest", "v1.0.0/nested", "v1.0.0\n"} {
		err := manager.Activate(context.Background(), version)
		if err == nil {
			t.Fatalf("Activate accepted version %q", version)
		}
		assertValueFree(t, err, home)
	}
	assertPointers(t, home, "v0.1.0", "")
}

func TestActivateRejectsASymlinkedVersionDirectory(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")

	layout := platform.PathsForHome(home).Install()
	if err := os.Symlink(filepath.Join(layout.VersionsDir, "v0.1.0"), filepath.Join(layout.VersionsDir, "v0.2.0")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(context.Background(), "v0.2.0"); err == nil {
		t.Fatal("Activate followed a symlinked version directory")
	}
	assertPointers(t, home, "v0.1.0", "")
}

func TestActivatePropagatesCancellation(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home, "v0.1.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := manager.Activate(ctx, "v0.1.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Activate did not propagate cancellation: %v", err)
	}
	if _, err := os.Stat(platform.PathsForHome(home).Install().CurrentFile); !os.IsNotExist(err) {
		t.Fatal("a cancelled Activate switched the pointer")
	}
}

func TestActivatePropagatesAHealthCheckDeadline(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home, "v0.1.0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.Health = func(ctx context.Context, _ string) error {
		cancel()
		return ctx.Err()
	}

	if err := manager.Activate(ctx, "v0.1.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Activate swallowed a cancelled health check: %v", err)
	}
	if _, err := os.Stat(platform.PathsForHome(home).Install().CurrentFile); !os.IsNotExist(err) {
		t.Fatal("a cancelled health check still switched the pointer")
	}
}

func TestRollbackRestoresThePreviousKnownGood(t *testing.T) {
	home := isolatedHome(t)
	seedSharedData(t, home)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0", "v0.2.0")

	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertPointers(t, home, "v0.1.0", "v0.2.0")

	// Rollback is an exchange, not a stack pop: a bad rollback is reversible.
	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertPointers(t, home, "v0.2.0", "v0.1.0")
	assertVersionsPresent(t, home, "v0.1.0", "v0.2.0")
	assertSharedDataIntact(t, home)
}

func TestRollbackFailsWhenThereIsNoPreviousVersion(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home, "v0.1.0")

	if err := manager.Rollback(context.Background()); err == nil {
		t.Fatal("Rollback succeeded with nothing installed")
	}
	activate(t, manager, "v0.1.0")
	err := manager.Rollback(context.Background())
	if err == nil {
		t.Fatal("Rollback succeeded with no previous version")
	}
	assertValueFree(t, err, home)
	assertPointers(t, home, "v0.1.0", "")
}

func TestRollbackRefusesWhenThePreviousVersionIsUnusable(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0", "v0.2.0")

	layout := platform.PathsForHome(home).Install()
	if err := os.RemoveAll(filepath.Join(layout.VersionsDir, "v0.1.0")); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(context.Background()); err == nil {
		t.Fatal("Rollback switched to a version that is no longer installed")
	}
	assertPointers(t, home, "v0.2.0", "v0.1.0")
	assertUsableInstall(t, home)
}

func TestPruneKeepsCurrentAndPreviousOnly(t *testing.T) {
	home := isolatedHome(t)
	seedSharedData(t, home)
	manager := stagedManager(t, home)

	activate(t, manager, "v0.1.0", "v0.2.0", "v0.3.0")

	assertPointers(t, home, "v0.3.0", "v0.2.0")
	assertVersionsPresent(t, home, "v0.2.0", "v0.3.0")
	if err := manager.Prune(); err != nil {
		t.Fatal(err)
	}
	assertVersionsPresent(t, home, "v0.2.0", "v0.3.0")
	assertSharedDataIntact(t, home)
	assertUsableInstall(t, home)
}

func TestPruneKeepsEverythingWhenThePointerIsUnusable(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home, "v0.1.0", "v0.2.0", "v0.3.0")
	layout := platform.PathsForHome(home).Install()
	if err := os.MkdirAll(layout.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.CurrentFile, []byte("../escape\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := manager.Prune(); err == nil {
		t.Fatal("Prune removed versions with an unusable current pointer")
	}
	assertVersionsPresent(t, home, "v0.1.0", "v0.2.0", "v0.3.0")
}

func TestPruneNeverTouchesSharedData(t *testing.T) {
	home := isolatedHome(t)
	seedSharedData(t, home)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0", "v0.2.0")

	if err := manager.Prune(); err != nil {
		t.Fatal(err)
	}
	assertSharedDataIntact(t, home)
}

func TestCurrentRejectsAnUnusablePointer(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	layout := platform.PathsForHome(home).Install()

	for _, pointer := range []string{
		"../../../../etc/passwd\n",
		"v0.1.0/../../escape\n",
		"latest\n",
		"",
		strings.Repeat("v0.1.0\n", 64),
	} {
		if err := os.WriteFile(layout.CurrentFile, []byte(pointer), 0o644); err != nil {
			t.Fatal(err)
		}
		version, ok, err := manager.Current()
		if err == nil && ok {
			t.Fatalf("Current() accepted pointer %q as %q", pointer, version)
		}
		if version != "" {
			t.Fatalf("Current() returned %q for pointer %q", version, pointer)
		}
	}
}

func TestCurrentReportsNothingInstalled(t *testing.T) {
	home := isolatedHome(t)
	manager := install.New(home)

	version, ok, err := manager.Current()
	if err != nil || ok || version != "" {
		t.Fatalf("Current() = %q %v %v on an empty home", version, ok, err)
	}
}

// TestPointerWriteNeverFollowsAPlantedTemporary proves the temp-then-rename
// switch cannot be turned into a write primitive by pre-creating the temporary
// name as a symlink inside the install root.
func TestPointerWriteNeverFollowsAPlantedTemporary(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	layout := platform.PathsForHome(home).Install()
	victim := filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName)
	for _, temporary := range []string{layout.CurrentFile + ".tmp", layout.PreviousFile + ".tmp"} {
		if err := os.Symlink(victim, temporary); err != nil {
			t.Fatal(err)
		}
	}

	if err := manager.Activate(context.Background(), "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(coreFor("v0.1.0")) {
		t.Fatal("the pointer write followed a planted symlink and clobbered an installed core")
	}
	assertPointers(t, home, "v0.2.0", "v0.1.0")
}

// TestSwitchSurvivesACrashBetweenAnyTwoSteps enumerates every on-disk state an
// interrupted Activate or Rollback can leave: each mutating step is one file
// operation, so "crashed after step k" is exactly the state produced by
// performing steps 1..k. Each state must leave a usable install and must be
// recoverable by re-running the operation.
func TestSwitchSurvivesACrashBetweenAnyTwoSteps(t *testing.T) {
	layoutOf := func(home string) platform.InstallLayout {
		return platform.PathsForHome(home).Install()
	}
	writeRaw := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, crash := range []struct {
		name  string
		setUp func(t *testing.T, home string)
	}{
		{"before any pointer exists", func(*testing.T, string) {}},
		{"after the first current.tmp is written", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile+".tmp", "v0.2.0\n")
		}},
		{"after the first current rename", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.2.0\n")
		}},
		{"after a switch, before previous.tmp", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.3.0\n")
		}},
		{"after previous.tmp is written", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.3.0\n")
			writeRaw(t, layoutOf(home).PreviousFile+".tmp", "v0.2.0\n")
		}},
		{"after the previous rename", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.3.0\n")
			writeRaw(t, layoutOf(home).PreviousFile, "v0.2.0\n")
		}},
		{"mid-rollback: current moved, previous not yet", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.2.0\n")
			writeRaw(t, layoutOf(home).PreviousFile, "v0.2.0\n")
		}},
		{"a truncated pointer from a non-atomic writer", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.3.0\n")
			writeRaw(t, layoutOf(home).PreviousFile, "v0.")
		}},
		{"an orphaned temporary from a dead process", func(t *testing.T, home string) {
			writeRaw(t, layoutOf(home).CurrentFile, "v0.3.0\n")
			writeRaw(t, layoutOf(home).PreviousFile, "v0.2.0\n")
			writeRaw(t, layoutOf(home).CurrentFile+".tmp", "v9.9.9\n")
			writeRaw(t, layoutOf(home).PreviousFile+".tmp", "v9.9.9\n")
		}},
	} {
		t.Run(crash.name, func(t *testing.T) {
			home := isolatedHome(t)
			seedSharedData(t, home)
			manager := stagedManager(t, home, "v0.1.0", "v0.2.0", "v0.3.0")
			crash.setUp(t, home)

			assertUsableInstall(t, home)

			// Recovery: re-running the interrupted operation completes it.
			if err := manager.Activate(context.Background(), "v0.3.0"); err != nil {
				t.Fatalf("recovery activate: %v", err)
			}
			assertUsableInstall(t, home)
			if got := readPointerFile(t, layoutOf(home).CurrentFile); got != "v0.3.0" {
				t.Fatalf("after recovery current = %q", got)
			}
			assertSharedDataIntact(t, home)
		})
	}
}

// TestConcurrentActivationsLeaveAUsableInstall covers the cross-process case:
// two adapters bootstrapping at once must not leave the pointer naming a
// version that the other run's prune removed.
func TestConcurrentActivationsLeaveAUsableInstall(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")
	stage(t, manager, "v0.3.0")

	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			assertUsableInstall(t, home)
		}
	}()

	var group sync.WaitGroup
	for _, version := range []string{"v0.2.0", "v0.3.0", "v0.2.0", "v0.3.0"} {
		group.Add(1)
		go func() {
			defer group.Done()
			_ = manager.Activate(context.Background(), version)
		}()
	}
	group.Wait()
	close(stop)
	<-done

	assertUsableInstall(t, home)
	version, ok, err := manager.Current()
	if err != nil || !ok {
		t.Fatalf("Current() = %q %v %v", version, ok, err)
	}
	if version != "v0.2.0" && version != "v0.3.0" {
		t.Fatalf("Current() = %q after concurrent activations", version)
	}
}

// TestActivateRefusesWhileAnotherProcessHoldsTheInstallLock catches removal
// or weakening of the advisory flock. The broader concurrency test exercises
// resulting state, but scheduling can serialize its goroutines by chance; this
// test deterministically establishes the competing writer first.
func TestActivateRefusesWhileAnotherProcessHoldsTheInstallLock(t *testing.T) {
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	layout := platform.PathsForHome(home).Install()
	lockPath := filepath.Join(layout.Root, ".lock")
	guard, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := syscall.Flock(int(guard.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(guard.Fd()), syscall.LOCK_UN) //nolint:errcheck

	if err := manager.Activate(context.Background(), "v0.2.0"); err == nil {
		t.Fatal("Activate ignored a competing installer holding the install lock")
	}
	if got := readPointerFile(t, layout.CurrentFile); got != "v0.1.0" {
		t.Fatalf("current = %q after refused competing activation, want v0.1.0", got)
	}
}

const crashHomeEnv = "SSC_INSTALL_CRASH_HOME"

// TestActivateCrashChild is the child half of TestActivateSurvivesRealProcessDeath.
func TestActivateCrashChild(t *testing.T) {
	home := os.Getenv(crashHomeEnv)
	if home == "" {
		t.Skip("child process helper")
	}
	manager := install.New(home)
	manager.Health = func(context.Context, string) error {
		time.Sleep(time.Millisecond)
		return nil
	}
	if err := manager.Activate(context.Background(), "v0.2.0"); err != nil {
		t.Fatal(err)
	}
}

// TestActivateSurvivesRealProcessDeath kills a real process mid-Activate across
// a sweep of delays wide enough to land both before and after the switch, and
// requires that every resulting on-disk state is a usable install that a re-run
// can finish. It also proves the install lock is released by process death
// rather than stranding the installation. The sweep is required to straddle the
// switch, so the test cannot pass by never reaching the interesting window.
var crashSweepOnce sync.Once

func TestActivateSurvivesRealProcessDeath(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns one process per sampled crash point")
	}
	// The sweep is deterministic and costs one process per sample, so repeating
	// it under -count=50 buys nothing; the race-prone in-process paths are
	// covered by TestConcurrentActivationsLeaveAUsableInstall.
	first := false
	crashSweepOnce.Do(func() { first = true })
	if !first {
		t.Skip("one crash sweep per test binary is enough")
	}
	// The sweep is calibrated against an uninterrupted run rather than fixed in
	// milliseconds, so it still straddles the switch on a slower machine.
	const samples = 24
	baseline := timeAnActivation(t)
	var beforeSwitch, afterSwitch int
	for step := range samples {
		delay := baseline * 2 * time.Duration(step) / samples
		t.Run(delay.String(), func(t *testing.T) {
			home := isolatedHome(t)
			seedSharedData(t, home)
			manager := stagedManager(t, home)
			activate(t, manager, "v0.1.0")
			stage(t, manager, "v0.2.0")

			child := exec.Command(os.Args[0], "-test.run=TestActivateCrashChild")
			child.Env = append(os.Environ(), crashHomeEnv+"="+home)
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(delay)
			_ = child.Process.Kill()
			_ = child.Wait()

			assertUsableInstall(t, home)
			version, ok, err := manager.Current()
			if err != nil || !ok {
				t.Fatalf("Current() = %q %v %v after a killed activation", version, ok, err)
			}
			rollback, _, err := manager.Previous()
			if err != nil {
				t.Fatalf("previous pointer is unreadable after a killed activation: %v", err)
			}
			switch version {
			case "v0.1.0":
				beforeSwitch++
			case "v0.2.0":
				afterSwitch++
			default:
				t.Fatalf("Current() = %q after a killed activation", version)
			}
			t.Logf("killed after %s: current=%s previous=%q", delay, version, rollback)

			// The lock died with the process and the operation is repeatable.
			if err := manager.Activate(context.Background(), "v0.2.0"); err != nil {
				t.Fatalf("recovery activate after a killed activation: %v", err)
			}
			assertUsableInstall(t, home)
			assertSharedDataIntact(t, home)
		})
	}
	if beforeSwitch == 0 || afterSwitch == 0 {
		t.Fatalf("the crash sweep never straddled the switch: %d before, %d after", beforeSwitch, afterSwitch)
	}
}

// timeAnActivation measures one uninterrupted child activation, start to exit.
func timeAnActivation(t *testing.T) time.Duration {
	t.Helper()
	home := isolatedHome(t)
	manager := stagedManager(t, home)
	activate(t, manager, "v0.1.0")
	stage(t, manager, "v0.2.0")

	child := exec.Command(os.Args[0], "-test.run=TestActivateCrashChild")
	child.Env = append(os.Environ(), crashHomeEnv+"="+home)
	started := time.Now()
	if err := child.Run(); err != nil {
		t.Fatalf("uninterrupted child activation: %v", err)
	}
	return time.Since(started)
}
