package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/report"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/scanconfig"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

func TestProjectAutoDiscoveryPrivacyAndExplicitOverrideAcceptance(t *testing.T) {
	home := filepath.Join(privateMatrixTempDir(t), "private-home-marker")
	projectsBySource := map[string]string{
		"code":       filepath.Join(home, "work", "code"),
		"cursor":     filepath.Join(home, "work", "cursor"),
		"windsurf":   filepath.Join(home, "work", "windsurf"),
		"jetbrains":  filepath.Join(home, "work", "jetbrains"),
		"git-main":   filepath.Join(home, "Projects", "git-main"),
		"git-linked": filepath.Join(home, "work", "git-linked"),
	}
	workspaceMarkers := map[string]string{
		"Code":     "private-code-workspace-id",
		"Cursor":   "private-cursor-workspace-id",
		"Windsurf": "private-windsurf-workspace-id",
	}
	for product, marker := range workspaceMarkers {
		project := projectsBySource[strings.ToLower(product)]
		writeMatrixFile(t, filepath.Join(home, "Library", "Application Support", product, "User", "workspaceStorage", marker, "workspace.json"), `{"folder":"file://`+project+`"}`)
		writeMatrixFile(t, filepath.Join(home, "Library", "Application Support", product, "User", "workspaceStorage", "unsupported-remote", "workspace.json"), `{"folder":"vscode-remote://ssh-remote+host/private"}`)
	}
	writeMatrixFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "IntelliJIdea2026.1", "options", "recentProjects.xml"), `<application><component name="RecentProjectsManager"><option name="recentPaths"><list><option value="`+projectsBySource["jetbrains"]+`"/></list></option></component></application>`)
	writeMatrixFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "MalformedProduct", "options", "recentProjects.xml"), `<application>`)

	admin := filepath.Join(projectsBySource["git-main"], ".git", "worktrees", "private-worktree-id")
	writeMatrixFile(t, filepath.Join(admin, "gitdir"), filepath.Join(projectsBySource["git-linked"], ".git")+"\n")
	writeMatrixFile(t, filepath.Join(projectsBySource["git-linked"], ".git"), "gitdir: "+admin+"\n")
	writeMatrixFile(t, filepath.Join(projectsBySource["git-main"], ".git", "worktrees", "stale-private-id", "gitdir"), filepath.Join(home, "missing", ".git")+"\n")
	for source, project := range projectsBySource {
		writeMatrixFile(t, filepath.Join(project, "package.json"), `{"name":"auto-`+source+`","version":"1.0.0"}`)
	}

	automaticFS := &discoveryRecordingFileSystem{matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}}
	automatic := runDiscoveryAcceptanceBaseline(t, home, nil, automaticFS)
	repeatedFS := &discoveryRecordingFileSystem{matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}}
	repeated := runDiscoveryAcceptanceBaseline(t, home, nil, repeatedFS)
	wantScope := []string{"$HOME/Projects", "$HOME/work/code", "$HOME/work/cursor", "$HOME/work/windsurf", "$HOME/work/jetbrains", "$HOME/work/git-linked"}
	if !reflect.DeepEqual(automatic.Scan.Scope.ProjectRoots, wantScope) {
		t.Fatalf("automatic scope=%v want=%v", automatic.Scan.Scope.ProjectRoots, wantScope)
	}
	for _, targetID := range []string{"projects.discovery.vscode", "projects.discovery.cursor", "projects.discovery.windsurf", "projects.discovery.jetbrains", "projects.discovery.git-worktrees"} {
		target := requireMatrixTarget(t, automatic.Scan.Coverage, "projects", targetID, "")
		if target.Status != model.TargetPartial || len(target.Errors) == 0 {
			t.Fatalf("discovery target %q=%+v", targetID, target)
		}
	}
	if got := countAssetsOfType(automatic.Inventory, model.AssetProject); got != len(projectsBySource) {
		t.Fatalf("automatic project assets=%d want=%d: %+v", got, len(projectsBySource), automatic.Inventory.Assets)
	}
	if automatic.Runner.callCount() != 0 {
		t.Fatalf("automatic discovery executed commands: %d", automatic.Runner.callCount())
	}
	if !bytes.Equal(automatic.Report, repeated.Report) || !reflect.DeepEqual(automatic.Scan, repeated.Scan) || !reflect.DeepEqual(automatic.Inventory, repeated.Inventory) || !reflect.DeepEqual(automatic.Snapshot, repeated.Snapshot) {
		t.Fatal("repeated automatic baseline was not byte-identical")
	}
	reopened := reopenLatestSnapshot(t, automatic.DatabasePath)
	if !reflect.DeepEqual(reopened.Scan.Scope, automatic.Scan.Scope) || !reflect.DeepEqual(reopened.Inventory, automatic.Inventory) {
		t.Fatal("real-store reload drifted from automatic baseline")
	}
	snapshotJSON, err := json.Marshal(reopened)
	if err != nil {
		t.Fatal(err)
	}
	privateMarkers := []string{
		home, "private-home-marker", "private-code-workspace-id", "private-cursor-workspace-id", "private-windsurf-workspace-id",
		"unsupported-remote", "vscode-remote://ssh-remote+host/private", "IntelliJIdea2026.1", "MalformedProduct",
		"private-worktree-id", "stale-private-id", admin, filepath.Join(home, "missing", ".git"), "file://" + home,
	}
	for _, marker := range privateMarkers {
		if strings.Contains(string(automatic.Report), marker) || strings.Contains(string(snapshotJSON), marker) {
			t.Fatal("automatic output leaked a private discovery marker")
		}
	}

	explicit := projectsBySource["code"]
	explicitFS := &discoveryRecordingFileSystem{matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}}
	overridden := runDiscoveryAcceptanceBaseline(t, home, []string{explicit}, explicitFS)
	if got := overridden.Scan.Scope.ProjectRoots; !reflect.DeepEqual(got, []string{"$HOME/work/code"}) {
		t.Fatalf("explicit scope=%v", got)
	}
	if explicitFS.openedDiscoveryMetadata() {
		t.Fatal("explicit override opened discovery metadata")
	}
	if got := countAssetsOfType(overridden.Inventory, model.AssetProject); got != 1 {
		t.Fatalf("explicit override project assets=%d want=1: %+v", got, overridden.Inventory.Assets)
	}
}

func countAssetsOfType(inventory model.Inventory, assetType model.AssetType) int {
	count := 0
	for _, asset := range inventory.Assets {
		if asset.Type == assetType {
			count++
		}
	}
	return count
}

type discoveryRecordingFileSystem struct {
	*matrixFileSystem
	mu     sync.Mutex
	opened []string
}

func TestDiscoveryRecordingFileSystemClassifiesGitMetadata(t *testing.T) {
	recorder := &discoveryRecordingFileSystem{matrixFileSystem: &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: t.TempDir()}}
	for _, path := range []string{
		filepath.Join(recorder.root, "Projects", "main", ".git"),
		filepath.Join(recorder.root, "Projects", "main", ".git", "worktrees", "private-id", "gitdir"),
		filepath.Join(recorder.root, "work", "linked", ".git"),
	} {
		recorder.record(path)
	}
	if !recorder.openedDiscoveryMetadata() {
		t.Fatal("Git discovery metadata was not classified")
	}
}

func (f *discoveryRecordingFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	f.record(name)
	root, err := f.matrixFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryRecordingRoot{RootedDirectory: root, owner: f, path: filepath.Clean(name)}, nil
}

func (f *discoveryRecordingFileSystem) record(name string) {
	f.mu.Lock()
	f.opened = append(f.opened, filepath.Clean(name))
	f.mu.Unlock()
}

func (f *discoveryRecordingFileSystem) openedPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.opened...)
}

func (f *discoveryRecordingFileSystem) openedDiscoveryMetadata() bool {
	for _, path := range f.openedPaths() {
		if isDiscoveryMetadataPath(path) {
			return true
		}
	}
	return false
}

func isDiscoveryMetadataPath(path string) bool {
	clean := filepath.Clean(path)
	for _, product := range []string{"Code", "Cursor", "Windsurf"} {
		if strings.Contains(clean, filepath.Join("Library", "Application Support", product, "User", "workspaceStorage")) {
			return true
		}
	}
	if strings.Contains(clean, filepath.Join("Library", "Application Support", "JetBrains")) && (strings.Contains(clean, string(filepath.Separator)+"options") || strings.HasSuffix(clean, "recentProjects.xml")) {
		return true
	}
	separator := string(filepath.Separator)
	return strings.HasSuffix(clean, separator+".git") || strings.Contains(clean, separator+".git"+separator)
}

type discoveryRecordingRoot struct {
	platform.RootedDirectory
	owner *discoveryRecordingFileSystem
	path  string
}

func (r *discoveryRecordingRoot) Lstat(name string) (os.FileInfo, error) {
	r.owner.record(filepath.Join(r.path, name))
	return r.RootedDirectory.Lstat(name)
}

func (r *discoveryRecordingRoot) Readlink(name string) (string, error) {
	r.owner.record(filepath.Join(r.path, name))
	return r.RootedDirectory.Readlink(name)
}

func (r *discoveryRecordingRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	path := filepath.Join(r.path, name)
	r.owner.record(path)
	root, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryRecordingRoot{RootedDirectory: root, owner: r.owner, path: path}, nil
}

func (r *discoveryRecordingRoot) Open(name string) (platform.RootedFile, error) {
	r.owner.record(filepath.Join(r.path, name))
	return r.RootedDirectory.Open(name)
}

func runDiscoveryAcceptanceBaseline(t *testing.T, home string, explicit []string, fileSystem *discoveryRecordingFileSystem) isolatedBaseline {
	t.Helper()
	runner := &matrixRunner{failOnCall: true}
	environment := collector.Environment{Home: home, Platform: "darwin", FS: fileSystem, Runner: runner, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	options := cli.Options{Command: "scan", Baseline: true, JSON: true, ProjectRoots: explicit}
	environment, configured, err := scanconfig.Configure(context.Background(), environment, options, projects.ResolveRoots, projects.DiscoverRoots)
	if err != nil {
		t.Fatal(err)
	}
	configured = []collector.Collector{configured[2]}
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	service := scan.NewService(collector.Orchestrator{Timeout: time.Second, MaxConcurrent: 4, Collectors: configured}, snapshots, environment.Now, func() string { return "00000000-0000-4000-8000-0000000000a7" }, environment)
	scanResult, inventory, delta, _, err := service.Baseline(context.Background())
	if err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil || !initialized {
		_ = snapshots.Close()
		t.Fatalf("latest snapshot initialized=%v err=%v", initialized, err)
	}
	var output bytes.Buffer
	if err := report.WriteJSON(&output, scanResult, inventory, delta); err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	if err := snapshots.Close(); err != nil {
		t.Fatal(err)
	}
	return isolatedBaseline{Scan: scanResult, Inventory: inventory, Delta: delta, Snapshot: snapshot, Report: output.Bytes(), Home: home, DatabasePath: databasePath, FileSystem: fileSystem.matrixFileSystem, Runner: runner}
}

func TestPythonLockfileProvenanceAcceptance(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Projects", "app")
	privacyMarker := "private-python-marker"
	sourceURL := "https://private-user:private-password@packages.example.invalid/simple"
	credential := "private-password"
	filename := "private-wheel-name.whl"
	localPath := "../private-local-source"
	firstHash := strings.Repeat("ab", 32)
	secondHash := strings.Repeat("cd", 32)
	immutableHash := strings.Repeat("ef", 32)

	writeMatrixFile(t, filepath.Join(project, "requirements.txt"), "Requirements__Demo==1.0.0 ; implementation_name == '"+privacyMarker+"' --hash=sha256:"+immutableHash+"\n")
	writeMatrixFile(t, filepath.Join(project, "Pipfile.lock"), `{"default":{"Pipfile__Multi":{"version":"==2.0.0","hashes":["sha256:`+firstHash+`","sha256:`+secondHash+`"],"markers":"`+privacyMarker+`"}}}`)
	writeMatrixFile(t, filepath.Join(project, "poetry.lock"), `[[package]]
name = "Poetry__Source"
version = "3.0.0"
markers = "`+privacyMarker+`"
source = { type = "url", url = "`+sourceURL+`" }
files = [{ file = "`+filename+`", hash = "sha256:`+immutableHash+`" }]
`)
	writeMatrixFile(t, filepath.Join(project, "uv.lock"), `[[package]]
name = "UV__Local"
version = "4.0.0"
source = { directory = "`+localPath+`" }
`)

	result := runIsolatedBaseline(t, baselineOptions{home: home})
	assets := make(map[string]model.Asset, len(result.Inventory.Assets))
	for _, asset := range result.Inventory.Assets {
		assets[asset.ID] = asset
	}
	want := map[string]struct {
		lockfile  string
		status    model.ProvenanceStatus
		integrity string
	}{
		"pkg:pypi/requirements-demo@1.0.0": {"requirements.txt", model.ProvenanceImmutable, "sha256:" + immutableHash},
		"pkg:pypi/pipfile-multi@2.0.0":     {"Pipfile.lock", model.ProvenanceUnknown, ""},
		"pkg:pypi/poetry-source@3.0.0":     {"poetry.lock", model.ProvenanceMutable, ""},
		"pkg:pypi/uv-local@4.0.0":          {"uv.lock", model.ProvenanceMutable, ""},
	}
	for packageID, expected := range want {
		packageAsset, found := assets[packageID]
		if !found || packageAsset.Provenance == nil || packageAsset.Provenance.Status != expected.status || packageAsset.Provenance.Integrity != expected.integrity {
			t.Fatalf("package %q asset=%+v", packageID, packageAsset)
		}
		declaredBy := false
		for _, relationship := range result.Inventory.Relationships {
			if relationship.From == packageID && relationship.Kind == model.RelationshipDeclaredBy && assets[relationship.To].Name == expected.lockfile {
				declaredBy = true
			}
		}
		if !declaredBy {
			t.Fatalf("package %q has no declared-by edge to %q: %+v", packageID, expected.lockfile, result.Inventory.Relationships)
		}
	}

	encodedInventory, err := json.Marshal(result.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{privacyMarker, sourceURL, credential, filename, localPath, firstHash, secondHash, home} {
		if strings.Contains(string(result.Report), private) {
			t.Fatalf("serialized report leaked %q: %s", private, result.Report)
		}
		if strings.Contains(string(encodedInventory), private) {
			t.Fatalf("marshaled inventory leaked %q: %s", private, encodedInventory)
		}
	}
	if result.Runner == nil || result.Runner.callCount() != 0 {
		t.Fatalf("default scan executed commands: %+v", result.Runner)
	}
}

func TestConflictingPythonLockfileFactsPersistConservatively(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Projects", "app")
	digest := strings.Repeat("ab", 32)
	writeMatrixFile(t, filepath.Join(project, "requirements.txt"), "shared-demo==1.0.0\n")
	writeMatrixFile(t, filepath.Join(project, "Pipfile.lock"), `{"default":{"shared-demo":{"version":"==1.0.0","hashes":["sha256:`+digest+`"]}}}`)

	result := runIsolatedBaseline(t, baselineOptions{home: home})
	reopened := reopenLatestSnapshot(t, result.DatabasePath)
	packageID := "pkg:pypi/shared-demo@1.0.0"
	packageAssets := 0
	for _, asset := range reopened.Inventory.Assets {
		if asset.ID != packageID {
			continue
		}
		packageAssets++
		if asset.Provenance == nil || asset.Provenance.Status != model.ProvenanceUnknown || asset.Provenance.Integrity != "" {
			t.Fatalf("persisted package=%+v", asset)
		}
	}
	declaredBy := 0
	for _, relationship := range reopened.Inventory.Relationships {
		if relationship.From == packageID && relationship.Kind == model.RelationshipDeclaredBy {
			declaredBy++
		}
	}
	if packageAssets != 1 || declaredBy != 2 {
		t.Fatalf("package assets=%d declared-by=%d snapshot=%+v", packageAssets, declaredBy, reopened)
	}
	for _, coverage := range reopened.Scan.Coverage {
		if coverage.Collector != "projects" {
			continue
		}
		coveragePackageAssets := 0
		for _, asset := range coverage.Assets {
			if asset.ID == packageID {
				coveragePackageAssets++
			}
		}
		if coveragePackageAssets != 1 {
			t.Fatalf("persisted project coverage has %d package assets: %+v", coveragePackageAssets, coverage.Assets)
		}
	}
}

func TestDockerIdentityRelationshipAndV4PrivacyAcceptance(t *testing.T) {
	home := t.TempDir()
	runner, inspector := dockerProbeFixture(t, home)
	first := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: filepath.Join(privateMatrixTempDir(t), "first.db"),
		externalProbes: true, runner: runner, inspector: inspector,
	})
	if first.Scan.SchemaVersion != "ssc-init.scan.v7" {
		t.Fatalf("schema=%q", first.Scan.SchemaVersion)
	}
	container := requireContentEvidence(t, first.Inventory, "package", model.EvidenceSubjectContainerImage)
	if container.Status != model.EvidenceComplete || container.Algorithm != "sha256" || container.Digest != strings.Repeat("c", 64) {
		t.Fatalf("container=%+v", container)
	}
	probed := false
	for _, relationship := range first.Inventory.Relationships {
		if relationship.Kind == model.RelationshipProbedBy && strings.HasPrefix(relationship.From, "pkg:docker/") && strings.HasPrefix(relationship.To, "tool-executable:sha256:") {
			probed = true
		}
		if !model.ValidRelationshipKind(relationship.Kind) || relationship.From == relationship.To {
			t.Fatalf("invalid relationship=%+v", relationship)
		}
	}
	if !probed {
		t.Fatalf("missing Docker probe relationship: %+v", first.Inventory.Relationships)
	}
	if strings.Contains(string(first.Report), home) || strings.Contains(string(first.Report), "private marker") {
		t.Fatalf("Program D output leaked host data: %s", first.Report)
	}

	dockerPath := filepath.Join(home, "fake-bin", "docker")
	changedRunner, ok := runner.(*matrixRunner)
	if !ok {
		t.Fatalf("runner=%T", runner)
	}
	changedRunner.results[matrixCommandKey(dockerPath, "image", "ls", "--no-trunc", "--format", "{{json .}}")] = platform.CommandResult{
		Stdout: `{"Repository":"demo-image","Tag":"1.0.0","ID":"sha256:` + strings.Repeat("d", 64) + `"}` + "\n",
	}
	second := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: first.DatabasePath, scanID: "00000000-0000-4000-8000-0000000000d2",
		externalProbes: true, runner: runner, inspector: inspector,
	})
	changed := requireContentEvidence(t, second.Inventory, "package", model.EvidenceSubjectContainerImage)
	if changed.ID != container.ID || changed.Digest == container.Digest {
		t.Fatalf("Docker identity mutation was not reflected: before=%+v after=%+v", container, changed)
	}
	deltaFound := false
	for _, change := range second.Delta.Changes {
		if change.Entity == model.ChangeEntityEvidence && change.EntityID == container.ID && change.Kind == model.ChangeChanged {
			deltaFound = true
		}
	}
	if !deltaFound {
		t.Fatalf("Docker identity mutation missing from delta: %+v", second.Delta)
	}
}

func TestProjectProvenanceDeclaredByAcceptance(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, "Projects", "app", "package-lock.json"), `{"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}}`)
	result := runIsolatedBaseline(t, baselineOptions{home: home})

	var packageAsset model.Asset
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "pkg:npm/demo@1.2.3" {
			packageAsset = asset
		}
	}
	if packageAsset.Provenance == nil || packageAsset.Provenance.Status != model.ProvenanceImmutable {
		t.Fatalf("package=%+v", packageAsset)
	}
	found := false
	for _, relationship := range result.Inventory.Relationships {
		if relationship.From == packageAsset.ID && relationship.Kind == model.RelationshipDeclaredBy {
			found = true
		}
	}
	if !found {
		t.Fatalf("relationships=%+v", result.Inventory.Relationships)
	}
	if result.Runner == nil || result.Runner.calls != 0 {
		t.Fatalf("default scan executed commands: %+v", result.Runner)
	}
}
