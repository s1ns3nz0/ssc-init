package projects

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestFinalizeDiscoveredRootsAcceptsCanonicalHomeDirectoryWithoutPersistingHostPaths(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "work", "alpha")
	mkdirDiscoveryCandidate(t, project)

	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{{
		path: project, source: discoveryVSCodeTargetID, priority: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if refs := RootRefs(got.Roots); !reflect.DeepEqual(refs, []string{"$HOME/work/alpha"}) {
		t.Fatalf("refs=%v", refs)
	}
	if len(got.Coverage) != 0 {
		t.Fatalf("coverage=%+v", got.Coverage)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{home, project, filepath.Base(home)} {
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("discovery JSON leaked host marker %q: %s", marker, encoded)
		}
	}
}

func TestDiscoveryCandidateRejectsUnsafeHomeLocationsWithFixedCoverage(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	paths := map[string]string{
		"home itself":       home,
		"outside home":      outside,
		"Library":           filepath.Join(home, "Library", "project"),
		"lowercase Library": filepath.Join(home, "library", "project"),
		"Trash":             filepath.Join(home, ".Trash", "project"),
		"Downloads media":   filepath.Join(home, "Downloads", "recording.mov"),
		"cache":             filepath.Join(home, ".cache", "project"),
		"backup":            filepath.Join(home, "Backups", "project"),
		"relative":          filepath.Join("relative", "project"),
		"nul":               filepath.Join(home, "project") + "\x00private-marker",
		"noncanonical path": home + string(filepath.Separator) + "work" + string(filepath.Separator) + ".." + string(filepath.Separator) + "project",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			if filepath.IsAbs(path) && !strings.ContainsRune(path, '\x00') && path != home && path != outside {
				mkdirDiscoveryCandidate(t, path)
			}
			got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{{
				path: path, source: discoveryCursorTargetID, priority: 2,
			}})
			if err != nil {
				t.Fatal(err)
			}
			assertDiscoveryIssue(t, got, discoveryCursorTargetID, "outside_home")
			assertDiscoveryJSONExcludes(t, got, home, outside, path, "private-marker")
		})
	}
}

func TestDiscoveryCandidateAllowsLegitimateDownloadsProject(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Downloads", "code-project")
	mkdirDiscoveryCandidate(t, project)

	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{{
		path: project, source: discoveryVSCodeTargetID, priority: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if refs := RootRefs(got.Roots); !reflect.DeepEqual(refs, []string{"$HOME/Downloads/code-project"}) {
		t.Fatalf("refs=%v coverage=%+v", refs, got.Coverage)
	}
	assertDiscoveryJSONExcludes(t, got, home, project)
}

func TestDiscoveryCandidateRejectsIntermediateSymlinkEscape(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	mkdirDiscoveryCandidate(t, filepath.Join(outside, "project"))
	link := filepath.Join(home, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(link, "project")

	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{{
		path: candidate, source: discoveryCursorTargetID, priority: 2,
	}})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryIssue(t, got, discoveryCursorTargetID, "symlink_rejected")
	assertDiscoveryJSONExcludes(t, got, home, outside, candidate)
}

func TestDiscoveryCandidateRejectsUnsafeFilesystemObjects(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "target")
	mkdirDiscoveryCandidate(t, target)
	symlink := filepath.Join(home, "linked")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(home, "regular")
	if err := os.WriteFile(regular, []byte("private-file-marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(home, "missing-private-marker")

	for _, testCase := range []struct {
		name string
		path string
		code string
	}{
		{name: "symlink", path: symlink, code: "symlink_rejected"},
		{name: "non-directory", path: regular, code: "metadata_unavailable"},
		{name: "missing", path: missing, code: "metadata_unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{{
				path: testCase.path, source: discoveryWindsurfTargetID, priority: 3,
			}})
			if err != nil {
				t.Fatal(err)
			}
			assertDiscoveryIssue(t, got, discoveryWindsurfTargetID, testCase.code)
			assertDiscoveryJSONExcludes(t, got, home, testCase.path, "private-file-marker", "missing-private-marker")
		})
	}
}

func TestDiscoveryCandidateRejectsDifferentHomeFilesystemDevice(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	mkdirDiscoveryCandidate(t, project)
	fileSystem := &discoveryDeviceFileSystem{
		OSFileSystem: platform.OSFileSystem{}, home: home, candidate: project,
		candidateDevice: ^uint64(0),
	}

	got, err := finalizeDiscoveredRoots(home, fileSystem, []discoveryCandidate{{
		path: project, source: discoveryWindsurfTargetID, priority: 3,
	}})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryIssue(t, got, discoveryWindsurfTargetID, "outside_home")
	if fileSystem.localityChecks == 0 {
		t.Fatal("candidate did not provide local-filesystem evidence")
	}
	assertDiscoveryJSONExcludes(t, got, home, project)
}

func TestDiscoveryCandidateRejectsIdentityReplacementAtFinalAnchoredRecheck(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	replacement := filepath.Join(home, "replacement")
	mkdirDiscoveryCandidate(t, project)
	mkdirDiscoveryCandidate(t, replacement)

	fileSystem := &discoveryFinalSwapFileSystem{
		OSFileSystem: platform.OSFileSystem{}, home: home, target: project, replacement: replacement,
	}
	got, err := finalizeDiscoveredRoots(home, fileSystem, []discoveryCandidate{{
		path: project, source: discoveryJetBrainsTargetID, priority: 4,
	}})
	if err != nil {
		t.Fatal(err)
	}
	assertDiscoveryIssue(t, got, discoveryJetBrainsTargetID, "identity_changed")
	if fileSystem.candidateOpens != 2 || !fileSystem.swapped {
		t.Fatalf("candidate opens=%d swapped=%v", fileSystem.candidateOpens, fileSystem.swapped)
	}
	assertDiscoveryJSONExcludes(t, got, home, project, replacement)
}

func TestFinalizeDiscoveredRootsDeduplicatesIdentityAndMinimizesNestedRoots(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "real")
	mkdirDiscoveryCandidate(t, real)
	aliasA := filepath.Join(home, "alias-a")
	aliasB := filepath.Join(home, "alias-b")
	virtual := &discoveryRedirectFileSystem{
		OSFileSystem: platform.OSFileSystem{},
		redirects:    map[string]string{aliasA: real, aliasB: real},
	}

	got, err := finalizeDiscoveredRoots(home, virtual, []discoveryCandidate{
		{path: aliasB, source: discoveryCursorTargetID, priority: 2},
		{path: aliasA, source: discoveryVSCodeTargetID, priority: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if refs := RootRefs(got.Roots); !reflect.DeepEqual(refs, []string{"$HOME/alias-a"}) {
		t.Fatalf("same-identity refs=%v", refs)
	}

	parent := filepath.Join(home, "workspace")
	child := filepath.Join(parent, "nested", "project")
	mkdirDiscoveryCandidate(t, child)
	got, err = finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{
		{path: child, source: discoveryVSCodeTargetID, priority: 1},
		{path: parent, source: discoveryGitTargetID, priority: 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if refs := RootRefs(got.Roots); !reflect.DeepEqual(refs, []string{"$HOME/workspace"}) {
		t.Fatalf("nested refs=%v", refs)
	}
}

func TestFinalizeDiscoveredRootsOrdersByConventionalRootSourcePriorityAndRef(t *testing.T) {
	home := t.TempDir()
	for _, relative := range []string{"Projects", "z-code", "a-cursor", "b-code"} {
		mkdirDiscoveryCandidate(t, filepath.Join(home, relative))
	}
	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, []discoveryCandidate{
		{path: filepath.Join(home, "a-cursor"), source: discoveryCursorTargetID, priority: 2},
		{path: filepath.Join(home, "z-code"), source: discoveryVSCodeTargetID, priority: 1},
		{path: filepath.Join(home, "Projects"), source: discoveryGitTargetID, priority: 5},
		{path: filepath.Join(home, "b-code"), source: discoveryVSCodeTargetID, priority: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"$HOME/Projects", "$HOME/b-code", "$HOME/z-code", "$HOME/a-cursor"}
	if refs := RootRefs(got.Roots); !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs=%v want=%v", refs, want)
	}
}

func TestFinalizeDiscoveredRootsReservesConventionalRootCapacityWithoutLeakingOmittedRefs(t *testing.T) {
	home := t.TempDir()
	candidates := make([]discoveryCandidate, 0, maxConfiguredRoots+2)
	for index := maxConfiguredRoots + 1; index >= 0; index-- {
		path := filepath.Join(home, "work", fixedDiscoveryIndex(index))
		mkdirDiscoveryCandidate(t, path)
		candidates = append(candidates, discoveryCandidate{
			path: path, source: discoveryGitTargetID, priority: 5,
		})
	}

	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roots) != maxConfiguredRoots-1 {
		t.Fatalf("roots=%d", len(got.Roots))
	}
	if len(got.Coverage) != 1 || got.Coverage[0].TargetID != discoveryGitTargetID || got.Coverage[0].Status != model.TargetPartial || len(got.Coverage[0].Errors) != 1 || got.Coverage[0].Errors[0].Code != "root_limit" || got.Coverage[0].Errors[0].Path != "" {
		t.Fatalf("coverage=%+v", got.Coverage)
	}
	refs := RootRefs(got.Roots)
	if refs[0] != "$HOME/work/00" || refs[len(refs)-1] != "$HOME/work/30" {
		t.Fatalf("refs=%v", refs)
	}
	assertDiscoveryJSONExcludes(t, got, home, "$HOME/work/31", "$HOME/work/32", "$HOME/work/33")
}

func TestFinalizeDiscoveredRootsUsesAllCapacityWhenConventionalRootIsAlreadyDiscovered(t *testing.T) {
	home := t.TempDir()
	candidates := make([]discoveryCandidate, 0, maxConfiguredRoots)
	projects := filepath.Join(home, "Projects")
	mkdirDiscoveryCandidate(t, projects)
	candidates = append(candidates, discoveryCandidate{
		path: projects, source: discoveryGitTargetID, priority: 5,
	})
	for index := 0; index < maxConfiguredRoots-1; index++ {
		path := filepath.Join(home, "work", fixedDiscoveryIndex(index))
		mkdirDiscoveryCandidate(t, path)
		candidates = append(candidates, discoveryCandidate{
			path: path, source: discoveryVSCodeTargetID, priority: 1,
		})
	}

	got, err := finalizeDiscoveredRoots(home, platform.OSFileSystem{}, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roots) != maxConfiguredRoots {
		t.Fatalf("roots=%d refs=%v coverage=%+v", len(got.Roots), RootRefs(got.Roots), got.Coverage)
	}
	if len(got.Coverage) != 0 {
		t.Fatalf("coverage=%+v", got.Coverage)
	}
	refs := RootRefs(got.Roots)
	if refs[0] != "$HOME/Projects" || refs[len(refs)-1] != "$HOME/work/30" {
		t.Fatalf("refs=%v", refs)
	}
	assertDiscoveryJSONExcludes(t, got, home, projects)
}

func TestDiscoveryCandidateRequiresNoFollowAndRootedFilesystemCapabilities(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	mkdirDiscoveryCandidate(t, project)
	osFS := platform.OSFileSystem{}
	for _, fileSystem := range []platform.FileSystem{
		rootedOnlyFileSystem{FileSystem: osFS, rooted: osFS},
		noFollowOnlyFileSystem{FileSystem: osFS, noFollow: osFS},
	} {
		if _, err := finalizeDiscoveredRoots(home, fileSystem, []discoveryCandidate{{
			path: project, source: discoveryVSCodeTargetID, priority: 1,
		}}); err == nil || strings.Contains(err.Error(), home) || strings.Contains(err.Error(), project) {
			t.Fatalf("capability error=%v", err)
		}
	}
}

func TestDiscoveryCoverageIsPrependedDeepCopiedAndMakesCollectionPartial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "empty")
	mkdirDiscoveryCandidate(t, root)
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	coverage := []model.TargetCoverage{{
		TargetID: discoveryCursorTargetID,
		Status:   model.TargetPartial,
		Errors:   []model.CoverageError{{Code: "metadata_malformed", Message: "project discovery metadata is malformed"}},
	}}
	configured := NewWithDiscovery(roots, coverage)
	specs := configured.Targets()
	if len(specs) != 2 || specs[0].ID != projectRootTargetID || specs[1].ID != discoveryCursorTargetID {
		t.Fatalf("target specs=%+v", specs)
	}
	coverage[0].TargetID = "mutated"
	coverage[0].Errors[0].Code = "mutated"

	first, err := configured.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	wantDiscovery := model.TargetCoverage{
		TargetID: discoveryCursorTargetID,
		Status:   model.TargetPartial,
		Errors:   []model.CoverageError{{Code: "metadata_malformed", Message: "project discovery metadata is malformed"}},
	}
	if len(first.Targets) != 2 || !reflect.DeepEqual(first.Targets[0], wantDiscovery) || first.Targets[1].TargetID != projectRootTargetID {
		t.Fatalf("targets=%+v", first.Targets)
	}
	if first.Status != model.CoveragePartial || len(first.Assets) != 0 || len(first.Observations) != 0 {
		t.Fatalf("result=%+v", first)
	}

	first.Targets[0].Errors[0].Code = "mutated-output"
	second, err := configured.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second.Targets[0], wantDiscovery) {
		t.Fatalf("second discovery coverage=%+v", second.Targets[0])
	}
}

func mkdirDiscoveryCandidate(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func fixedDiscoveryIndex(index int) string {
	return string([]byte{'0' + byte(index/10), '0' + byte(index%10)})
}

func assertDiscoveryIssue(t *testing.T, discovery Discovery, targetID, code string) {
	t.Helper()
	if len(discovery.Roots) != 0 {
		t.Fatalf("unsafe candidate produced roots=%v", RootRefs(discovery.Roots))
	}
	if len(discovery.Coverage) != 1 || discovery.Coverage[0].TargetID != targetID || discovery.Coverage[0].Status != model.TargetPartial || len(discovery.Coverage[0].Errors) != 1 || discovery.Coverage[0].Errors[0].Code != code || discovery.Coverage[0].Errors[0].Path != "" {
		t.Fatalf("coverage=%+v want target=%q code=%q", discovery.Coverage, targetID, code)
	}
}

func assertDiscoveryJSONExcludes(t *testing.T, discovery Discovery, markers ...string) {
	t.Helper()
	encoded, err := json.Marshal(discovery)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		if marker != "" && strings.Contains(string(encoded), marker) {
			t.Fatalf("discovery JSON leaked marker %q: %s", marker, encoded)
		}
	}
}

type discoveryFinalSwapFileSystem struct {
	platform.OSFileSystem
	home           string
	target         string
	replacement    string
	candidateOpens int
	swapped        bool
}

func (f *discoveryFinalSwapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil || name != f.home {
		return root, err
	}
	return &discoveryFinalSwapRoot{RootedDirectory: root, owner: f, current: f.home}, nil
}

type discoveryFinalSwapRoot struct {
	platform.RootedDirectory
	owner   *discoveryFinalSwapFileSystem
	current string
}

func (r *discoveryFinalSwapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	path := filepath.Join(r.current, name)
	if path == r.owner.target {
		r.owner.candidateOpens++
		if r.owner.candidateOpens == 2 {
			r.owner.swapped = true
			if err := os.Rename(r.owner.target, r.owner.target+"-original"); err != nil {
				return nil, err
			}
			if err := os.Rename(r.owner.replacement, r.owner.target); err != nil {
				return nil, err
			}
		}
	}
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryFinalSwapRoot{RootedDirectory: child, owner: r.owner, current: path}, nil
}

type discoveryRedirectFileSystem struct {
	platform.OSFileSystem
	redirects map[string]string
}

func (f *discoveryRedirectFileSystem) Lstat(name string) (os.FileInfo, error) {
	if redirected, ok := f.redirects[name]; ok {
		name = redirected
	}
	return f.OSFileSystem.Lstat(name)
}

func (f *discoveryRedirectFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryRedirectRoot{RootedDirectory: root, redirects: f.redirects, current: name}, nil
}

type discoveryRedirectRoot struct {
	platform.RootedDirectory
	redirects map[string]string
	current   string
}

func (r *discoveryRedirectRoot) Lstat(name string) (os.FileInfo, error) {
	path := filepath.Join(r.current, name)
	if redirected, ok := r.redirects[path]; ok {
		return os.Lstat(redirected)
	}
	return r.RootedDirectory.Lstat(name)
}

func (r *discoveryRedirectRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	path := filepath.Join(r.current, name)
	if redirected, ok := r.redirects[path]; ok {
		root, err := platform.OSFileSystem{}.OpenRoot(redirected)
		if err != nil {
			return nil, err
		}
		return &discoveryRedirectRoot{RootedDirectory: root, redirects: r.redirects, current: redirected}, nil
	}
	root, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryRedirectRoot{RootedDirectory: root, redirects: r.redirects, current: path}, nil
}

type discoveryDeviceFileSystem struct {
	platform.OSFileSystem
	home            string
	candidate       string
	candidateDevice uint64
	localityChecks  int
}

func (f *discoveryDeviceFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryDeviceRoot{RootedDirectory: root, owner: f, current: name}, nil
}

type discoveryDeviceRoot struct {
	platform.RootedDirectory
	owner   *discoveryDeviceFileSystem
	current string
}

func (r *discoveryDeviceRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryDeviceRoot{RootedDirectory: child, owner: r.owner, current: filepath.Join(r.current, name)}, nil
}

func (r *discoveryDeviceRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	return &discoveryDeviceFile{RootedFile: file, owner: r.owner}, nil
}

func (r *discoveryDeviceRoot) filesystemDevice() (uint64, bool) {
	if r.current == r.owner.candidate {
		return r.owner.candidateDevice, true
	}
	return 1, true
}

type discoveryDeviceFile struct {
	platform.RootedFile
	owner *discoveryDeviceFileSystem
}

func (f *discoveryDeviceFile) LocalFilesystem() (bool, bool) {
	f.owner.localityChecks++
	return true, true
}
