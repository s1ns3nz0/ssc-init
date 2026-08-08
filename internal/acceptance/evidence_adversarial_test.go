package acceptance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/report"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

// adversarialOptions configures a bespoke baseline run that, unlike
// runIsolatedBaseline, tolerates scan errors and accepts an injected
// filesystem and context.
type adversarialOptions struct {
	home         string
	databasePath string
	scanID       string
	fileSystem   platform.FileSystem
	ctx          context.Context
	projectRoots []string
	snapshots    scan.SnapshotStore
}

type adversarialBaseline struct {
	Scan      model.ScanResult
	Inventory model.Inventory
	Delta     model.Delta
	Report    []byte
	Err       error
}

func runAdversarialBaseline(t *testing.T, options adversarialOptions) adversarialBaseline {
	t.Helper()
	home, err := filepath.Abs(options.home)
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Clean(home)
	rootValues := options.projectRoots
	if len(rootValues) == 0 {
		rootValues = []string{"$HOME/Projects"}
	}
	roots, err := projects.ResolveRoots(home, rootValues)
	if err != nil {
		t.Fatal(err)
	}
	fileSystem := options.fileSystem
	if fileSystem == nil {
		fileSystem = &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
	}
	environment := collector.Environment{
		Home: home, Platform: "darwin",
		Scope: model.ScanScope{Platform: "darwin", ProjectRoots: projects.RootRefs(roots)},
		FS:    fileSystem, Runner: &matrixRunner{failOnCall: true}, Inspector: &matrixInspector{failOnCall: true},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	snapshots := options.snapshots
	var persistent *store.Store
	if snapshots == nil {
		if options.databasePath == "" {
			options.databasePath = filepath.Join(privateMatrixTempDir(t), "state.db")
		}
		opened, err := store.Open(options.databasePath)
		if err != nil {
			t.Fatal(err)
		}
		persistent = opened
		snapshots = opened
	}
	scanID := options.scanID
	if scanID == "" {
		scanID = "00000000-0000-4000-8000-0000000000c1"
	}
	service := scan.NewService(
		collector.Orchestrator{
			Timeout: time.Second, MaxConcurrent: 4,
			Collectors: []collector.Collector{agents.New(), ide.New(), projects.New(roots), packages.New()},
		},
		snapshots,
		environment.Now,
		func() string { return scanID },
		environment,
	)
	ctx := options.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	scanResult, inventory, delta, scanErr := service.Baseline(ctx)
	result := adversarialBaseline{Scan: scanResult, Inventory: inventory, Delta: delta, Err: scanErr}
	if scanErr == nil {
		var output bytes.Buffer
		if err := report.WriteJSON(&output, scanResult, inventory, delta); err != nil {
			t.Fatal(err)
		}
		result.Report = output.Bytes()
	}
	if persistent != nil {
		if err := persistent.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

// triggerFileSystem runs one mutation the first time the evidence stage
// reopens a specific catalog root. Discovery descends from the opened home
// root, so an OpenRoot call for the exact catalog root marks the boundary
// between discovery and evidence collection.
type triggerFileSystem struct {
	*matrixFileSystem
	once    sync.Once
	match   string
	trigger func()
}

func (f *triggerFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	if filepath.Clean(name) == f.match {
		f.once.Do(f.trigger)
	}
	return f.matrixFileSystem.OpenRoot(name)
}

func adversarialEvidenceBySubject(t *testing.T, inventory model.Inventory, subject string) model.ContentEvidence {
	t.Helper()
	var matches []model.ContentEvidence
	for _, record := range inventory.Evidence {
		if record.Subject == subject {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("evidence for subject %q: matches=%d in %+v", subject, len(matches), inventory.Evidence)
	}
	return matches[0]
}

func requireEvidenceError(t *testing.T, record model.ContentEvidence, code string) {
	t.Helper()
	for _, evidenceError := range record.Errors {
		if evidenceError.Code == code {
			return
		}
	}
	t.Fatalf("evidence record %+v does not carry error code %q", record, code)
}

func assertNoAdversarialLeak(t *testing.T, result adversarialBaseline, databasePath string, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Scan      model.ScanResult `json:"scan"`
		Inventory model.Inventory  `json:"inventory"`
		Delta     model.Delta      `json:"delta"`
	}{result.Scan, result.Inventory, result.Delta})
	if err != nil {
		t.Fatal(err)
	}
	surfaces := [][]byte{encoded, result.Report}
	if databasePath != "" {
		for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
			content, err := os.ReadFile(path)
			if err == nil {
				surfaces = append(surfaces, content)
			}
		}
	}
	for _, surface := range surfaces {
		for _, value := range forbidden {
			if value != "" && bytes.Contains(surface, []byte(value)) {
				t.Fatalf("forbidden value %q leaked into scan output or SQLite", value)
			}
		}
	}
}

func TestEvidenceAdversarialSymlinkCatalogRootIsRejected(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	const outsideSecret = "outside-root-secret-marker"
	writeMatrixFile(t, filepath.Join(outside, "demo", ".codex-plugin", "plugin.json"), `{"name":"`+outsideSecret+`","version":"1.0.0"}`)
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".codex", "plugins")); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	// The symlinked catalog root escapes the isolated home, so the recording
	// filesystem must not report a denied out-of-home path: the collector has
	// to reject the link before any traversal.
	fileSystem := &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
	result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, fileSystem: fileSystem})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(result.Inventory.Evidence) != 0 {
		t.Fatalf("symlinked catalog root produced evidence: %+v", result.Inventory.Evidence)
	}
	for _, asset := range result.Inventory.Assets {
		if asset.Type == model.AssetAgentPlugin {
			t.Fatalf("symlinked catalog root produced a plugin asset: %+v", asset)
		}
	}
	target := requireMatrixTarget(t, result.Scan.Coverage, "agents", "agents.codex.plugins", "")
	if target.Status == model.TargetComplete || target.Assets != 0 {
		t.Fatalf("symlinked catalog root target=%+v", target)
	}
	if denied := fileSystem.deniedPaths(); len(denied) != 0 {
		t.Fatalf("scan attempted paths outside the isolated home: %v", denied)
	}
	assertNoAdversarialLeak(t, result, databasePath, outsideSecret, outside)
}

func TestEvidenceAdversarialSymlinkEntriesAreRepresentedNeverFollowed(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	const outsideSecret = "outside-final-secret-marker"
	secretFile := filepath.Join(outside, "secret.js")
	writeMatrixFile(t, secretFile, outsideSecret+" v1\n")
	writeMatrixFile(t, filepath.Join(outside, "nested", "inner.js"), outsideSecret+" nested\n")
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	if err := os.Symlink(secretFile, filepath.Join(pluginDir, "final-link.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "nested"), filepath.Join(pluginDir, "intermediate-link")); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000d1"})
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	tree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
	if tree.Status != model.EvidencePartial || tree.Symlinks != 2 || tree.Digest == "" {
		t.Fatalf("symlink payload tree=%+v", tree)
	}
	assertNoAdversarialLeak(t, first, databasePath, outsideSecret, outside)

	// Changing the linked file's content must not change the tree digest:
	// only the link-target bytes are represented, never the referent.
	writeMatrixFile(t, secretFile, outsideSecret+" v2 with completely different bytes\n")
	second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000d2"})
	if second.Err != nil {
		t.Fatal(second.Err)
	}
	if got := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree); got.Digest != tree.Digest {
		t.Fatalf("referent content change altered the tree digest: %q != %q", got.Digest, tree.Digest)
	}

	// Repointing the link is a content change of the tree itself.
	if err := os.Remove(filepath.Join(pluginDir, "final-link.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "other.js"), filepath.Join(pluginDir, "final-link.js")); err != nil {
		t.Fatal(err)
	}
	third := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000d3"})
	if third.Err != nil {
		t.Fatal(third.Err)
	}
	if got := adversarialEvidenceBySubject(t, third.Inventory, model.EvidenceSubjectPayloadTree); got.Digest == tree.Digest {
		t.Fatal("link target swap did not change the tree digest")
	}
}

func TestEvidenceAdversarialLinkSwapAfterDiscoveryIsNeverFollowed(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	const outsideSecret = "post-discovery-swap-secret"
	secretFile := filepath.Join(outside, "swapped.js")
	writeMatrixFile(t, secretFile, outsideSecret+"\n")
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	payload := filepath.Join(pluginDir, "payload.js")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, payload, "payload before swap\n")
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	fileSystem := &triggerFileSystem{
		matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		match:            filepath.Join(home, ".codex", "plugins"),
		trigger: func() {
			if err := os.Remove(payload); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(secretFile, payload); err != nil {
				t.Error(err)
			}
		},
	}
	result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, fileSystem: fileSystem})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	// Replacing the payload with a symlink after discovery changes the sealed
	// asset-directory identity, so the engine refuses to pair the discovered
	// asset identity with the swapped revision instead of hashing through it.
	tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
	if tree.Status != model.EvidenceUnavailable || tree.Digest != "" {
		t.Fatalf("post-discovery link swap tree=%+v", tree)
	}
	requireEvidenceError(t, tree, "identity_changed")
	manifest := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectManifest)
	if manifest.Status != model.EvidenceUnavailable || manifest.Digest != "" {
		t.Fatalf("anchored manifest evidence after directory swap=%+v", manifest)
	}
	if result.Scan.EvidenceCoverage.Status != model.CoveragePartial || result.Scan.Status != "partial" {
		t.Fatalf("swap coverage=%v scan=%v", result.Scan.EvidenceCoverage.Status, result.Scan.Status)
	}
	assertNoAdversarialLeak(t, result, databasePath, outsideSecret, outside)
}

func TestEvidenceAdversarialManifestAnchorSwapYieldsIdentityChanged(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	manifestPath := filepath.Join(pluginDir, ".codex-plugin", "plugin.json")
	writeMatrixFile(t, manifestPath, `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	const swappedIdentity = "swapped-after-discovery"
	fileSystem := &triggerFileSystem{
		matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		match:            filepath.Join(home, ".codex", "plugins"),
		trigger: func() {
			if err := os.WriteFile(manifestPath, []byte(`{"name":"`+swappedIdentity+`","version":"9.9.9"}`), 0o600); err != nil {
				t.Error(err)
			}
		},
	}
	result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, fileSystem: fileSystem})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	for _, subject := range []string{model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree} {
		record := adversarialEvidenceBySubject(t, result.Inventory, subject)
		if record.Status != model.EvidenceUnavailable || record.Digest != "" {
			t.Fatalf("anchor-swapped %s evidence=%+v", subject, record)
		}
		requireEvidenceError(t, record, "identity_changed")
	}
	if result.Scan.EvidenceCoverage.Status != model.CoveragePartial || result.Scan.Status != "partial" {
		t.Fatalf("anchor swap coverage=%v scan=%v", result.Scan.EvidenceCoverage.Status, result.Scan.Status)
	}
	// The discovery-time identity ("demo") must never be paired with content
	// from the swapped revision, and the swapped identity must not surface.
	assertNoAdversarialLeak(t, result, databasePath, swappedIdentity)
}

func TestEvidenceAdversarialEntryPointEscapes(t *testing.T) {
	for _, testCase := range []struct {
		name, main string
		wantCode   string
	}{
		{name: "parent traversal", main: "../../../outside.js", wantCode: "path_invalid"},
		{name: "absolute path", main: "/private/tmp/outside-absolute.js", wantCode: "path_invalid"},
		{name: "missing file", main: "dist/missing.js", wantCode: "read_unavailable"},
		{name: "symlinked file", main: "dist/link.js", wantCode: "symlink_rejected"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			outside := t.TempDir()
			const outsideSecret = "entrypoint-escape-secret"
			writeMatrixFile(t, filepath.Join(outside, "escape.js"), outsideSecret+"\n")
			extensionDir := filepath.Join(home, ".vscode", "extensions", "acme.demo-1.0.0")
			writeMatrixFile(t, filepath.Join(extensionDir, "package.json"),
				`{"name":"demo","publisher":"acme","version":"1.0.0","main":"`+testCase.main+`"}`)
			if testCase.name == "symlinked file" {
				if err := os.MkdirAll(filepath.Join(extensionDir, "dist"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "escape.js"), filepath.Join(extensionDir, "dist", "link.js")); err != nil {
					t.Fatal(err)
				}
			}
			databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
			fileSystem := &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
			result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, fileSystem: fileSystem})
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			entrypoint := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectEntrypointMain)
			if entrypoint.Status == model.EvidenceComplete || entrypoint.Digest != "" {
				t.Fatalf("escaping entry point produced content evidence: %+v", entrypoint)
			}
			requireEvidenceError(t, entrypoint, testCase.wantCode)
			manifest := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectManifest)
			if manifest.Status != model.EvidenceComplete {
				t.Fatalf("manifest evidence=%+v", manifest)
			}
			if result.Scan.EvidenceCoverage.Status != model.CoveragePartial {
				t.Fatalf("entry point escape coverage=%v", result.Scan.EvidenceCoverage.Status)
			}
			if denied := fileSystem.deniedPaths(); len(denied) != 0 {
				t.Fatalf("entry point escape reached outside the isolated home: %v", denied)
			}
			assertNoAdversarialLeak(t, result, databasePath, outsideSecret, outside)
		})
	}
}

func TestEvidenceAdversarialSpecialFilesAreNeverOpened(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	if err := syscall.Mkfifo(filepath.Join(pluginDir, "pipe.fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(pluginDir, "s.sock")
	listener, err := net.Listen("unix", socketPath)
	if err == nil {
		defer listener.Close()
	} else {
		// Unix socket paths are length-limited; the FIFO already proves the
		// special-file boundary when the bind path is too long.
		t.Logf("unix socket unavailable in this environment: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
		result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath})
		if result.Err != nil {
			t.Error(result.Err)
			return
		}
		tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
		if tree.Status != model.EvidencePartial || tree.Digest == "" {
			t.Errorf("special-file payload tree=%+v", tree)
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("scan blocked opening a FIFO or socket")
	}
}

func TestEvidenceAdversarialProjectFileByteBounds(t *testing.T) {
	const limit = 32 << 20
	for _, testCase := range []struct {
		name       string
		size       int64
		wantStatus model.EvidenceStatus
	}{
		{name: "exact limit", size: limit, wantStatus: model.EvidenceComplete},
		{name: "one over limit", size: limit + 1, wantStatus: model.EvidenceOversize},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "Projects", "app", "Cargo.lock")
			writeMatrixFile(t, path, "")
			if err := os.Truncate(path, testCase.size); err != nil {
				t.Fatal(err)
			}
			result := runAdversarialBaseline(t, adversarialOptions{home: home})
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			record := adversarialEvidenceBySubject(t, result.Inventory, "project-lockfile:Cargo.lock")
			if record.Status != testCase.wantStatus {
				t.Fatalf("byte bound evidence=%+v want status=%q", record, testCase.wantStatus)
			}
			if testCase.wantStatus == model.EvidenceComplete && (record.Digest == "" || record.Size != testCase.size) {
				t.Fatalf("exact-limit evidence=%+v", record)
			}
			if testCase.wantStatus == model.EvidenceOversize {
				requireEvidenceError(t, record, "byte_limit")
				if record.Digest != "" {
					t.Fatalf("oversize evidence carries a digest: %+v", record)
				}
				if result.Scan.EvidenceCoverage.Status != model.CoveragePartial {
					t.Fatalf("oversize coverage=%v", result.Scan.EvidenceCoverage.Status)
				}
			}
		})
	}
}

func TestEvidenceAdversarialTreeLimits(t *testing.T) {
	t.Run("depth limit", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		deep := pluginDir
		for level := 0; level < 33; level++ {
			deep = filepath.Join(deep, "d")
		}
		writeMatrixFile(t, filepath.Join(deep, "leaf.js"), "deep\n")
		result := runAdversarialBaseline(t, adversarialOptions{home: home})
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
		if tree.Status != model.EvidenceOversize {
			t.Fatalf("deep tree=%+v", tree)
		}
		requireEvidenceError(t, tree, "depth_limit")
	})
	t.Run("entry limit", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		bulk := filepath.Join(pluginDir, "bulk")
		if err := os.MkdirAll(bulk, 0o700); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 4100; index++ {
			if err := os.WriteFile(filepath.Join(bulk, fmt.Sprintf("entry-%04d", index)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		result := runAdversarialBaseline(t, adversarialOptions{home: home})
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
		if tree.Status != model.EvidenceOversize {
			t.Fatalf("entry-heavy tree=%+v", tree)
		}
		requireEvidenceError(t, tree, "file_limit")
	})
	t.Run("total byte limit", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		for index := 0; index < 8; index++ {
			path := filepath.Join(pluginDir, fmt.Sprintf("blob-%d", index))
			writeMatrixFile(t, path, "")
			if err := os.Truncate(path, 32<<20); err != nil {
				t.Fatal(err)
			}
		}
		writeMatrixFile(t, filepath.Join(pluginDir, "final-byte"), "x")
		result := runAdversarialBaseline(t, adversarialOptions{home: home})
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
		if tree.Status != model.EvidenceOversize {
			t.Fatalf("byte-heavy tree=%+v", tree)
		}
		requireEvidenceError(t, tree, "byte_limit")
	})
}

func TestEvidenceAdversarialCancellationPreservesPreviousSnapshot(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000e1"})
	if first.Err != nil {
		t.Fatal(first.Err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fileSystem := &triggerFileSystem{
		matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		match:            filepath.Join(home, ".codex", "plugins"),
		trigger:          cancel,
	}
	canceled := runAdversarialBaseline(t, adversarialOptions{
		home: home, databasePath: databasePath, fileSystem: fileSystem, ctx: ctx,
		scanID: "00000000-0000-4000-8000-0000000000e2",
	})
	if canceled.Err == nil {
		t.Fatalf("canceled evidence stage did not propagate: %+v", canceled.Scan)
	}
	snapshot := reopenLatestSnapshot(t, databasePath)
	if snapshot.Scan.ScanID != first.Scan.ScanID || !reflect.DeepEqual(snapshot.Inventory, first.Inventory) {
		t.Fatalf("cancellation altered the persisted snapshot: %+v", snapshot.Scan)
	}

	// A later clean scan must succeed with no partial runtime residue.
	final := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000e3"})
	if final.Err != nil {
		t.Fatal(final.Err)
	}
	if record := adversarialEvidenceBySubject(t, final.Inventory, model.EvidenceSubjectPayloadTree); record.Status != model.EvidenceComplete {
		t.Fatalf("post-cancellation rescan tree=%+v", record)
	}
}

func TestEvidenceAdversarialPermissionDenialIsIsolated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial cannot be simulated as root")
	}
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	unreadable := filepath.Join(pluginDir, "unreadable.js")
	writeMatrixFile(t, unreadable, "cannot read\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	writeMatrixFile(t, filepath.Join(home, "Projects", "app", "go.mod"), "module example.invalid/app\n")
	result := runAdversarialBaseline(t, adversarialOptions{home: home})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
	if tree.Status != model.EvidencePartial || tree.Digest == "" {
		t.Fatalf("permission-denied tree=%+v", tree)
	}
	requireEvidenceError(t, tree, "read_unavailable")
	manifest := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectManifest)
	project := adversarialEvidenceBySubject(t, result.Inventory, "project-manifest:go.mod")
	if manifest.Status != model.EvidenceComplete || project.Status != model.EvidenceComplete {
		t.Fatalf("permission denial leaked into safe targets: %+v %+v", manifest, project)
	}
}

func TestEvidenceAdversarialHostileSiblingIsolation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial cannot be simulated as root")
	}
	home := t.TempDir()
	outside := t.TempDir()
	safeDir := filepath.Join(home, ".codex", "plugins", "aaa-safe")
	writeMatrixFile(t, filepath.Join(safeDir, ".codex-plugin", "plugin.json"), `{"name":"safe","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(safeDir, "payload.js"), "safe payload\n")
	hostileDir := filepath.Join(home, ".codex", "plugins", "zzz-hostile")
	writeMatrixFile(t, filepath.Join(hostileDir, ".codex-plugin", "plugin.json"), `{"name":"hostile","version":"1.0.0"}`)
	unreadable := filepath.Join(hostileDir, "unreadable.js")
	writeMatrixFile(t, unreadable, "unreadable hostile payload\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	if err := os.Symlink(outside, filepath.Join(hostileDir, "escape-link")); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	statuses := map[string]model.EvidenceStatus{}
	for _, record := range result.Inventory.Evidence {
		statuses[record.AssetID+"/"+record.Subject] = record.Status
	}
	if statuses["agent-plugin:codex:safe@1.0.0/manifest"] != model.EvidenceComplete ||
		statuses["agent-plugin:codex:safe@1.0.0/payload-tree"] != model.EvidenceComplete {
		t.Fatalf("hostile sibling degraded safe evidence: %+v", statuses)
	}
	if statuses["agent-plugin:codex:hostile@1.0.0/payload-tree"] != model.EvidencePartial {
		t.Fatalf("hostile payload tree=%+v", statuses)
	}
	if result.Scan.EvidenceCoverage.Status != model.CoveragePartial {
		t.Fatalf("hostile sibling coverage=%v", result.Scan.EvidenceCoverage.Status)
	}
	snapshot := reopenLatestSnapshot(t, databasePath)
	if len(snapshot.Inventory.Evidence) != len(result.Inventory.Evidence) {
		t.Fatal("hostile sibling prevented snapshot persistence")
	}
}

func TestEvidenceAdversarialUnicodeAndHostileNames(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	// Decomposed Unicode (NFD) and shell-hostile names stay exact-byte
	// entries in the tree manifest.
	writeMatrixFile(t, filepath.Join(pluginDir, "café.js"), "decomposed name\n")
	writeMatrixFile(t, filepath.Join(pluginDir, "$(rm -rf ~)'\" .js"), "hostile name\n")
	if err := os.WriteFile(filepath.Join(pluginDir, "invalid-\xff\xfe.js"), []byte("invalid utf-8 name\n"), 0o600); err != nil {
		// Darwin filesystems enforce UTF-8 names; the attempted fixture and
		// its rejection are both recorded behavior on this platform.
		t.Logf("invalid UTF-8 name rejected by the filesystem: %v", err)
	}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f1"})
	if first.Err != nil {
		t.Fatal(first.Err)
	}
	tree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
	if tree.Status != model.EvidenceComplete || tree.Digest == "" {
		t.Fatalf("unicode-name tree=%+v", tree)
	}
	second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f2"})
	if second.Err != nil {
		t.Fatal(second.Err)
	}
	if got := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree); got.Digest != tree.Digest {
		t.Fatalf("unicode-name tree digest is unstable: %q != %q", got.Digest, tree.Digest)
	}
}

func TestEvidenceAdversarialCacheLifecycle(t *testing.T) {
	t.Run("miss then hit keeps digests identical", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
		databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
		first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f3"})
		if first.Err != nil {
			t.Fatal(first.Err)
		}
		firstTree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
		if firstTree.Metadata["cache"] != "miss" {
			t.Fatalf("first-scan tree cache=%+v", firstTree.Metadata)
		}
		second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f4"})
		if second.Err != nil {
			t.Fatal(second.Err)
		}
		secondTree := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree)
		if secondTree.Metadata["cache"] != "hit" || secondTree.Digest != firstTree.Digest || secondTree.Status != model.EvidenceComplete {
			t.Fatalf("cache-warm tree=%+v want digest %q", secondTree, firstTree.Digest)
		}
	})
	t.Run("size-mismatched cache row is rejected and rehashed", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
		databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
		first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000fa"})
		if first.Err != nil {
			t.Fatal(first.Err)
		}
		firstTree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
		database, err := sql.Open("sqlite", databasePath)
		if err != nil {
			t.Fatal(err)
		}
		mismatched, err := database.Exec(`UPDATE content_cache SET size = size + 1`)
		if err != nil {
			t.Fatal(err)
		}
		if rows, err := mismatched.RowsAffected(); err != nil || rows == 0 {
			t.Fatalf("no cache rows were mismatched: rows=%d err=%v", rows, err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000fb"})
		if second.Err != nil {
			t.Fatal(second.Err)
		}
		secondTree := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree)
		if secondTree.Metadata["cache"] != "rejected" || secondTree.Digest != firstTree.Digest || secondTree.Status != model.EvidenceComplete {
			t.Fatalf("size-mismatched cache rescan tree=%+v want digest %q", secondTree, firstTree.Digest)
		}
	})
	t.Run("corrupt cache row falls back to a rehash", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
		databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
		first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f5"})
		if first.Err != nil {
			t.Fatal(first.Err)
		}
		firstTree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
		database, err := sql.Open("sqlite", databasePath)
		if err != nil {
			t.Fatal(err)
		}
		corrupted, err := database.Exec(`UPDATE content_cache SET digest = ?`, strings.Repeat("f", 63)+"Z")
		if err != nil {
			t.Fatal(err)
		}
		if rows, err := corrupted.RowsAffected(); err != nil || rows == 0 {
			t.Fatalf("no cache rows were corrupted: rows=%d err=%v", rows, err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f6"})
		if second.Err != nil {
			t.Fatal(second.Err)
		}
		// The store validates its own rows: a malformed digest never reaches
		// the engine and surfaces as a safe miss with a correct rehash.
		secondTree := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree)
		if secondTree.Metadata["cache"] != "miss" || secondTree.Digest != firstTree.Digest || secondTree.Status != model.EvidenceComplete {
			t.Fatalf("corrupt-cache rescan tree=%+v want digest %q", secondTree, firstTree.Digest)
		}
	})
	t.Run("size and mtime preserving replacement is detected", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		payload := filepath.Join(pluginDir, "payload.js")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		writeMatrixFile(t, payload, "payload AAAA\n")
		databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
		first := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f7"})
		if first.Err != nil {
			t.Fatal(first.Err)
		}
		firstTree := adversarialEvidenceBySubject(t, first.Inventory, model.EvidenceSubjectPayloadTree)
		info, err := os.Stat(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(payload, []byte("payload BBBB\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(payload, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		second := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, scanID: "00000000-0000-4000-8000-0000000000f8"})
		if second.Err != nil {
			t.Fatal(second.Err)
		}
		secondTree := adversarialEvidenceBySubject(t, second.Inventory, model.EvidenceSubjectPayloadTree)
		if secondTree.Digest == firstTree.Digest {
			t.Fatal("size/mtime-preserving replacement reused a stale cached digest")
		}
		if secondTree.Status != model.EvidenceComplete {
			t.Fatalf("replaced tree=%+v", secondTree)
		}
	})
	t.Run("store without cache support reports disabled", func(t *testing.T) {
		home := t.TempDir()
		pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
		writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
		writeMatrixFile(t, filepath.Join(pluginDir, "payload.js"), "payload v1\n")
		result := runAdversarialBaseline(t, adversarialOptions{home: home, snapshots: newMemorySnapshots()})
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		tree := adversarialEvidenceBySubject(t, result.Inventory, model.EvidenceSubjectPayloadTree)
		if tree.Metadata["cache"] != "disabled" || tree.Status != model.EvidenceComplete {
			t.Fatalf("cache-less store tree=%+v", tree)
		}
	})
}

func TestEvidenceAdversarialExternalProjectRootPrivacy(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	writeMatrixFile(t, filepath.Join(external, "app", "go.mod"), "module example.invalid/external-app\n")
	// The recording filesystem must allow the configured external root while
	// still denying everything else outside the isolated home.
	fileSystem := &allowListFileSystem{
		matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		allowed:          []string{filepath.Clean(external)},
	}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	result := runAdversarialBaseline(t, adversarialOptions{
		home: home, databasePath: databasePath, fileSystem: fileSystem,
		projectRoots: []string{external},
	})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	record := adversarialEvidenceBySubject(t, result.Inventory, "project-manifest:go.mod")
	if record.Status != model.EvidenceComplete || record.Digest == "" {
		t.Fatalf("external project evidence=%+v", record)
	}
	assertNoAdversarialLeak(t, result, databasePath, external)
}

// allowListFileSystem extends the recording matrix filesystem with explicitly
// configured additional roots (for external project roots).
type allowListFileSystem struct {
	*matrixFileSystem
	allowed []string
}

func (f *allowListFileSystem) allowsExtra(name string) bool {
	clean := filepath.Clean(name)
	for _, root := range f.allowed {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (f *allowListFileSystem) ReadFile(name string) ([]byte, error) {
	if f.allowsExtra(name) {
		return platform.OSFileSystem{}.ReadFile(name)
	}
	return f.matrixFileSystem.ReadFile(name)
}

func (f *allowListFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	if f.allowsExtra(name) {
		return platform.OSFileSystem{}.ReadDir(name)
	}
	return f.matrixFileSystem.ReadDir(name)
}

func (f *allowListFileSystem) Stat(name string) (os.FileInfo, error) {
	if f.allowsExtra(name) {
		return platform.OSFileSystem{}.Stat(name)
	}
	return f.matrixFileSystem.Stat(name)
}

func (f *allowListFileSystem) Lstat(name string) (os.FileInfo, error) {
	if f.allowsExtra(name) {
		return platform.OSFileSystem{}.Lstat(name)
	}
	return f.matrixFileSystem.Lstat(name)
}

func (f *allowListFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	if f.allowsExtra(name) {
		return platform.OSFileSystem{}.OpenRoot(name)
	}
	return f.matrixFileSystem.OpenRoot(name)
}

func TestEvidenceAdversarialNoReadsOutsideIsolatedHome(t *testing.T) {
	decoyHome := t.TempDir()
	writeMatrixFile(t, filepath.Join(decoyHome, ".claude.json"), `{"mcpServers":{"`+unconfiguredHomeSentinel+`":{"url":"https://real-home.invalid/mcp"}}}`)
	t.Setenv("HOME", decoyHome)
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".codex", "plugins", "demo")
	writeMatrixFile(t, filepath.Join(pluginDir, ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, "Projects", "app", "go.mod"), "module example.invalid/app\n")
	fileSystem := &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	result := runAdversarialBaseline(t, adversarialOptions{home: home, databasePath: databasePath, fileSystem: fileSystem})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(result.Inventory.Evidence) == 0 {
		t.Fatal("isolated scan produced no evidence")
	}
	if denied := fileSystem.deniedPaths(); len(denied) != 0 {
		t.Fatalf("evidence collection attempted paths outside the isolated home: %v", denied)
	}
	assertNoAdversarialLeak(t, result, databasePath, unconfiguredHomeSentinel, decoyHome)
}
