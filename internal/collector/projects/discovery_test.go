package projects

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestDiscoverVSCodeSourcesAreAbsentWithoutCoverage(t *testing.T) {
	home := t.TempDir()
	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if candidates != nil || coverage != nil {
		t.Fatalf("candidates=%+v coverage=%+v", candidates, coverage)
	}
}

func TestDiscoverVSCodeSortsSourcesAndChildrenConvertsWorkspaceAndIsolatesMalformedSibling(t *testing.T) {
	home := t.TempDir()
	codeProject := filepath.Join(home, "work", "code")
	cursorProject := filepath.Join(home, "work", "cursor")
	windsurfProject := filepath.Join(home, "work", "windsurf")
	workspaceFile := filepath.Join(home, "workspaces", "team.code-workspace")
	for _, project := range []string{codeProject, cursorProject, windsurfProject, filepath.Dir(workspaceFile)} {
		mkdirDiscoveryCandidate(t, project)
	}
	writeVSCodeDiscoveryWorkspace(t, home, "Code", "z-child", "workspace", workspaceFile)
	writeVSCodeDiscoveryWorkspace(t, home, "Code", "a-child", "folder", codeProject)
	writeVSCodeDiscoveryRaw(t, home, "Code", "m-broken", []byte(`{"folder":`))
	writeVSCodeDiscoveryWorkspace(t, home, "Cursor", "only", "folder", cursorProject)
	writeVSCodeDiscoveryWorkspace(t, home, "Windsurf", "only", "folder", windsurfProject)

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryCandidate{
		{path: codeProject, source: discoveryVSCodeTargetID, priority: 1},
		{path: filepath.Dir(workspaceFile), source: discoveryVSCodeTargetID, priority: 1},
		{path: cursorProject, source: discoveryCursorTargetID, priority: 2},
		{path: windsurfProject, source: discoveryWindsurfTargetID, priority: 3},
	}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("candidates=%+v want=%+v", candidates, want)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryVSCodeTargetID, "metadata_malformed")
	assertCoverageExcludes(t, coverage, home, "m-broken", "a-child", "z-child")
}

func TestDiscoverVSCodeCapsChildrenAndRejectsOversizedMetadata(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "work", "project")
	mkdirDiscoveryCandidate(t, project)
	for index := 0; index < 257; index++ {
		writeVSCodeDiscoveryWorkspace(t, home, "Code", fmt.Sprintf("%03d", index), "folder", project)
	}
	writeVSCodeDiscoveryRaw(t, home, "Cursor", "oversized", []byte(`{"folder":"file:///`+strings.Repeat("x", 64*1024)+`"}`))

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 256 {
		t.Fatalf("candidates=%d", len(candidates))
	}
	if candidates[0].source != discoveryVSCodeTargetID || candidates[255].source != discoveryVSCodeTargetID {
		t.Fatalf("unexpected candidates=%+v", candidates)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryVSCodeTargetID, "entry_limit")
	assertDiscoveryCoverageCodes(t, coverage, discoveryCursorTargetID, "metadata_oversized")
	assertCoverageExcludes(t, coverage, home, strings.Repeat("x", 64))
}

func TestDiscoverVSCodeRejectsSourceAndWorkspaceFileSymlinks(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "work", "project")
	mkdirDiscoveryCandidate(t, project)
	realSource := filepath.Join(home, "real-source")
	writeVSCodeWorkspaceAt(t, realSource, "linked", "folder", project)
	codeSource := vscodeDiscoverySourcePath(home, "Code")
	if err := os.MkdirAll(filepath.Dir(codeSource), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realSource, codeSource); err != nil {
		t.Fatal(err)
	}
	cursorChild := filepath.Join(vscodeDiscoverySourcePath(home, "Cursor"), "linked")
	if err := os.MkdirAll(cursorChild, 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(home, "real-workspace.json")
	writeDiscoveryFile(t, realFile, []byte(`{"folder":"file://`+project+`"}`))
	if err := os.Symlink(realFile, filepath.Join(cursorChild, "workspace.json")); err != nil {
		t.Fatal(err)
	}

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates=%+v", candidates)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryVSCodeTargetID, "symlink_rejected")
	assertDiscoveryCoverageCodes(t, coverage, discoveryCursorTargetID, "symlink_rejected")
	assertCoverageExcludes(t, coverage, home, project, realSource, realFile)
}

func TestDiscoverVSCodeRejectsSourceAndFileReplacementAfterRead(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		replaceSrc bool
	}{
		{name: "source", replaceSrc: true},
		{name: "file"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "work", "project")
			other := filepath.Join(home, "work", "other")
			mkdirDiscoveryCandidate(t, project)
			mkdirDiscoveryCandidate(t, other)
			source := vscodeDiscoverySourcePath(home, "Code")
			writeVSCodeWorkspaceAt(t, source, "child", "folder", project)
			workspace := filepath.Join(source, "child", "workspace.json")
			var replace func() error
			if testCase.replaceSrc {
				replacement := filepath.Join(home, "replacement-source")
				writeVSCodeWorkspaceAt(t, replacement, "child", "folder", other)
				replace = func() error { return replaceDiscoveryPath(source, replacement) }
			} else {
				replacement := filepath.Join(home, "replacement-workspace.json")
				writeDiscoveryFile(t, replacement, []byte(`{"folder":"file://`+other+`"}`))
				replace = func() error { return replaceDiscoveryPath(workspace, replacement) }
			}
			fileSystem := &discoveryReadSwapFileSystem{target: workspace, swap: replace}
			env := testutil.Environment(t, home)
			env.FS = fileSystem

			candidates, coverage, err := discoverIDERoots(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if fileSystem.swapErr != nil {
				t.Fatal(fileSystem.swapErr)
			}
			if !fileSystem.swapped || len(candidates) != 0 {
				t.Fatalf("swapped=%v candidates=%+v", fileSystem.swapped, candidates)
			}
			assertDiscoveryCoverageCodes(t, coverage, discoveryVSCodeTargetID, "identity_changed")
			assertCoverageExcludes(t, coverage, home, project, other)
		})
	}
}

func TestDiscoverVSCodeReturnsCancellationWithoutPartialResults(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	candidates, coverage, err := discoverIDERoots(ctx, testutil.Environment(t, home))
	if !errors.Is(err, context.Canceled) || candidates != nil || coverage != nil {
		t.Fatalf("candidates=%+v coverage=%+v err=%v", candidates, coverage, err)
	}
}

func TestDiscoverJetBrainsSortsProductsUsesExactOptionsPathAndResolvesUserHome(t *testing.T) {
	home := t.TempDir()
	alphaProject := filepath.Join(home, "work", "alpha")
	zetaProject := filepath.Join(home, "work", "zeta")
	ignoredProject := filepath.Join(home, "work", "ignored")
	for _, project := range []string{alphaProject, zetaProject, ignoredProject} {
		mkdirDiscoveryCandidate(t, project)
	}
	writeJetBrainsRecent(t, home, "Zeta", []string{"$USER_HOME$/work/zeta"})
	writeJetBrainsRecent(t, home, "Alpha", []string{"~/work/alpha"})
	writeDiscoveryFile(t, filepath.Join(jetbrainsDiscoverySourcePath(home), "Wrong", "recentProjects.xml"), jetBrainsRecentXML([]string{ignoredProject}))

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	want := []discoveryCandidate{
		{path: alphaProject, source: discoveryJetBrainsTargetID, priority: 4},
		{path: zetaProject, source: discoveryJetBrainsTargetID, priority: 4},
	}
	if !reflect.DeepEqual(candidates, want) || coverage != nil {
		t.Fatalf("candidates=%+v want=%+v coverage=%+v", candidates, want, coverage)
	}
}

func TestDiscoverJetBrainsCapsProductsAndIsolatesOversizedAndMalformedProducts(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "work", "project")
	mkdirDiscoveryCandidate(t, project)
	for index := 0; index < 33; index++ {
		writeJetBrainsRecent(t, home, fmt.Sprintf("Product%02d", index), []string{project})
	}
	writeDiscoveryFile(t, filepath.Join(jetbrainsDiscoverySourcePath(home), "Product00", "options", "recentProjects.xml"), []byte(`<application>`))
	oversized := filepath.Join(jetbrainsDiscoverySourcePath(home), "Product01", "options", "recentProjects.xml")
	writeDiscoveryFile(t, oversized, []byte(`<application><!--`+strings.Repeat("x", 256*1024)+`--></application>`))

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 30 {
		t.Fatalf("candidates=%d", len(candidates))
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryJetBrainsTargetID, "entry_limit", "metadata_malformed", "metadata_oversized")
	assertCoverageExcludes(t, coverage, home, "Product00", "Product01", strings.Repeat("x", 64))
}

func TestDiscoverJetBrainsRejectsProductAndRecentFileSymlinks(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "work", "project")
	mkdirDiscoveryCandidate(t, project)
	realProduct := filepath.Join(home, "real-product")
	writeJetBrainsRecentAt(t, realProduct, []string{project})
	source := jetbrainsDiscoverySourcePath(home)
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realProduct, filepath.Join(source, "LinkedProduct")); err != nil {
		t.Fatal(err)
	}
	linkedFileProduct := filepath.Join(source, "LinkedFile", "options")
	if err := os.MkdirAll(linkedFileProduct, 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(home, "real-recent.xml")
	writeDiscoveryFile(t, realFile, jetBrainsRecentXML([]string{project}))
	if err := os.Symlink(realFile, filepath.Join(linkedFileProduct, "recentProjects.xml")); err != nil {
		t.Fatal(err)
	}

	candidates, coverage, err := discoverIDERoots(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates=%+v", candidates)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryJetBrainsTargetID, "symlink_rejected")
	assertCoverageExcludes(t, coverage, home, project, realProduct, realFile)
}

func TestDiscoverJetBrainsRejectsProductAndFileReplacementAfterRead(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		replaceSrc bool
	}{
		{name: "product", replaceSrc: true},
		{name: "file"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "work", "project")
			other := filepath.Join(home, "work", "other")
			mkdirDiscoveryCandidate(t, project)
			mkdirDiscoveryCandidate(t, other)
			product := filepath.Join(jetbrainsDiscoverySourcePath(home), "Idea")
			writeJetBrainsRecentAt(t, product, []string{project})
			recent := filepath.Join(product, "options", "recentProjects.xml")
			var replace func() error
			if testCase.replaceSrc {
				replacement := filepath.Join(home, "replacement-product")
				writeJetBrainsRecentAt(t, replacement, []string{other})
				replace = func() error { return replaceDiscoveryPath(product, replacement) }
			} else {
				replacement := filepath.Join(home, "replacement-recent.xml")
				writeDiscoveryFile(t, replacement, jetBrainsRecentXML([]string{other}))
				replace = func() error { return replaceDiscoveryPath(recent, replacement) }
			}
			fileSystem := &discoveryReadSwapFileSystem{target: recent, swap: replace}
			env := testutil.Environment(t, home)
			env.FS = fileSystem

			candidates, coverage, err := discoverIDERoots(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if fileSystem.swapErr != nil {
				t.Fatal(fileSystem.swapErr)
			}
			if !fileSystem.swapped || len(candidates) != 0 {
				t.Fatalf("swapped=%v candidates=%+v", fileSystem.swapped, candidates)
			}
			assertDiscoveryCoverageCodes(t, coverage, discoveryJetBrainsTargetID, "identity_changed")
			assertCoverageExcludes(t, coverage, home, project, other)
		})
	}
}

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

func vscodeDiscoverySourcePath(home, product string) string {
	return filepath.Join(home, "Library", "Application Support", product, "User", "workspaceStorage")
}

func jetbrainsDiscoverySourcePath(home string) string {
	return filepath.Join(home, "Library", "Application Support", "JetBrains")
}

func writeVSCodeDiscoveryWorkspace(t *testing.T, home, product, child, field, path string) {
	t.Helper()
	writeVSCodeWorkspaceAt(t, vscodeDiscoverySourcePath(home, product), child, field, path)
}

func writeVSCodeWorkspaceAt(t *testing.T, source, child, field, path string) {
	t.Helper()
	writeDiscoveryFile(t, filepath.Join(source, child, "workspace.json"), []byte(fmt.Sprintf(`{"%s":"file://%s"}`, field, path)))
}

func writeVSCodeDiscoveryRaw(t *testing.T, home, product, child string, contents []byte) {
	t.Helper()
	writeDiscoveryFile(t, filepath.Join(vscodeDiscoverySourcePath(home, product), child, "workspace.json"), contents)
}

func writeJetBrainsRecent(t *testing.T, home, product string, paths []string) {
	t.Helper()
	writeJetBrainsRecentAt(t, filepath.Join(jetbrainsDiscoverySourcePath(home), product), paths)
}

func writeJetBrainsRecentAt(t *testing.T, product string, paths []string) {
	t.Helper()
	writeDiscoveryFile(t, filepath.Join(product, "options", "recentProjects.xml"), jetBrainsRecentXML(paths))
}

func jetBrainsRecentXML(paths []string) []byte {
	var contents strings.Builder
	contents.WriteString(`<application><component name="RecentProjectsManager"><option name="recentPaths"><list>`)
	for _, path := range paths {
		contents.WriteString(`<option value="`)
		contents.WriteString(path)
		contents.WriteString(`"/>`)
	}
	contents.WriteString(`</list></option></component></application>`)
	return []byte(contents.String())
}

func writeDiscoveryFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertDiscoveryCoverageCodes(t *testing.T, coverage []model.TargetCoverage, targetID string, wantCodes ...string) {
	t.Helper()
	for _, target := range coverage {
		if target.TargetID != targetID {
			continue
		}
		gotCodes := make([]string, len(target.Errors))
		for index, issue := range target.Errors {
			gotCodes[index] = issue.Code
			if issue.Path != "" {
				t.Fatalf("coverage path=%q target=%q", issue.Path, targetID)
			}
		}
		if !reflect.DeepEqual(gotCodes, wantCodes) {
			t.Fatalf("target=%q codes=%v want=%v", targetID, gotCodes, wantCodes)
		}
		return
	}
	t.Fatalf("missing coverage target=%q in %+v", targetID, coverage)
}

func assertCoverageExcludes(t *testing.T, coverage []model.TargetCoverage, markers ...string) {
	t.Helper()
	encoded, err := json.Marshal(coverage)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		if marker != "" && strings.Contains(string(encoded), marker) {
			t.Fatalf("coverage leaked marker %q: %s", marker, encoded)
		}
	}
}

func replaceDiscoveryPath(target, replacement string) error {
	if err := os.Rename(target, target+"-original"); err != nil {
		return err
	}
	return os.Rename(replacement, target)
}

type discoveryReadSwapFileSystem struct {
	platform.OSFileSystem
	target  string
	swap    func() error
	once    sync.Once
	swapped bool
	swapErr error
}

func (f *discoveryReadSwapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryReadSwapRoot{RootedDirectory: root, owner: f, current: name}, nil
}

type discoveryReadSwapRoot struct {
	platform.RootedDirectory
	owner   *discoveryReadSwapFileSystem
	current string
}

func (r *discoveryReadSwapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &discoveryReadSwapRoot{RootedDirectory: root, owner: r.owner, current: filepath.Join(r.current, name)}, nil
}

func (r *discoveryReadSwapRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(r.current, name)
	if path != r.owner.target {
		return file, nil
	}
	return &discoveryReadSwapFile{RootedFile: file, owner: r.owner}, nil
}

type discoveryReadSwapFile struct {
	platform.RootedFile
	owner *discoveryReadSwapFileSystem
}

func (f *discoveryReadSwapFile) Read(buffer []byte) (int, error) {
	count, err := f.RootedFile.Read(buffer)
	if count > 0 {
		f.owner.once.Do(func() {
			f.owner.swapped = true
			f.owner.swapErr = f.owner.swap()
		})
	}
	return count, err
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
