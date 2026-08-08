package install_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
