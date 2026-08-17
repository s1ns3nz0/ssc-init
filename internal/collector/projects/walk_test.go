package projects

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestResolveRootsUsesSafeStableReferences(t *testing.T) {
	home := t.TempDir()
	roots, err := ResolveRoots(home, []string{filepath.Join(home, "Projects"), "/Volumes/team"})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || roots[0].Ref != "$HOME/Projects" || roots[1].Ref != "external-root-1" {
		t.Fatalf("roots=%+v", roots)
	}
	if got := RootRefs(roots); !reflect.DeepEqual(got, []string{"$HOME/Projects", "external-root-1"}) {
		t.Fatalf("refs=%q", got)
	}
	refs := RootRefs(roots)
	refs[0] = "mutated"
	if RootRefs(roots)[0] != "$HOME/Projects" {
		t.Fatalf("roots mutated through refs: %+v", roots)
	}
}

func TestResolveRootsDefaultsSortsAndRejectsUnsafeValues(t *testing.T) {
	home := t.TempDir()
	defaults, err := ResolveRoots(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults) != 1 || defaults[0].Path != filepath.Join(home, "Projects") || defaults[0].Ref != "$HOME/Projects" {
		t.Fatalf("defaults=%+v", defaults)
	}
	externalA := filepath.Join(filepath.Dir(home), "external-a")
	externalZ := filepath.Join(filepath.Dir(home), "external-z")
	roots, err := ResolveRoots(home, []string{externalZ, "$HOME/z", externalA, "$HOME/a"})
	if err != nil {
		t.Fatal(err)
	}
	wantRefs := []string{"$HOME/a", "$HOME/z", "external-root-1", "external-root-2"}
	if got := RootRefs(roots); !reflect.DeepEqual(got, wantRefs) {
		t.Fatalf("refs=%q want=%q", got, wantRefs)
	}
	invalid := [][]string{
		{"relative"},
		{"$HOMEevil/work"},
		{"$HOME/../escape"},
		{filepath.Join(home, "Projects"), filepath.Join(home, "Projects", ".")},
	}
	tooMany := make([]string, maxConfiguredRoots+1)
	for index := range tooMany {
		tooMany[index] = filepath.Join(home, "root", string(rune('a'+index)))
	}
	invalid = append(invalid, tooMany)
	for _, values := range invalid {
		if _, err := ResolveRoots(home, values); err == nil {
			t.Fatalf("accepted roots %q", values)
		}
	}
}

func TestConfiguredRootSymlinkIsRejected(t *testing.T) {
	for _, variant := range []string{"directory", "file", "dangling"} {
		t.Run(variant, func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "target")
			switch variant {
			case "directory":
				if err := os.MkdirAll(target, 0o700); err != nil {
					t.Fatal(err)
				}
			case "file":
				writeWalkFile(t, target, "fixture")
			}
			linkedRoot := filepath.Join(home, "linked")
			if err := os.Symlink(target, linkedRoot); err != nil {
				t.Fatal(err)
			}
			got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: linkedRoot, Ref: "$HOME/linked"}}, limits: defaultWalkLimits()})
			assertExactProjectTarget(t, got, model.TargetCoverage{
				TargetID: projectRootTargetID, InstanceRef: "$HOME/linked", Status: model.TargetPartial,
				Errors: []model.CoverageError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}},
			})
			if len(got.Assets) != 0 || len(got.LocalTargets) != 0 {
				t.Fatalf("result=%+v", got)
			}
		})
	}
}

func TestWalkerNeverFollowsSymlinkedSubtreeOrConfig(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	outside := filepath.Join(home, "outside")
	writeWalkFile(t, filepath.Join(root, "safe", ".mcp.json"), `{}`)
	writeWalkFile(t, filepath.Join(outside, "followed", ".mcp.json"), `{}`)
	if err := os.Symlink(filepath.Join(outside, "followed"), filepath.Join(root, "linked-project")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "followed", ".mcp.json"), filepath.Join(root, "linked-config.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "followed", ".mcp.json"), filepath.Join(root, ".mcp.json")); err != nil {
		t.Fatal(err)
	}
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits()})
	assertTargetIssue(t, got, "$HOME/Projects", model.TargetPartial, "symlink_rejected")
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != filepath.Join(root, "safe", ".mcp.json") {
		t.Fatalf("localTargets=%+v", got.LocalTargets)
	}
}

func TestWalkerSafelySkipsIncidentalSymlinkWithoutPartialCoverage(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "work")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"name":"must-not-follow"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"safe"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "unrelated-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got := collectProjectTest(t, &projectCollector{
		roots: []Root{{Path: root, Ref: "$HOME/work"}}, limits: defaultWalkLimits(),
		beforeOpen: func(relative string) {
			if relative == "unrelated-link" {
				t.Fatal("attempted to open incidental symlink")
			}
		},
	})
	if got.Status != model.CoverageComplete || len(got.Targets) != 1 || got.Targets[0].Status != model.TargetComplete || got.Targets[0].SkippedSymlinks != 1 {
		t.Fatalf("result=%+v", got)
	}
	for _, asset := range got.Assets {
		if asset.Name == "must-not-follow" {
			t.Fatalf("followed incidental symlink: %+v", asset)
		}
	}
}

func TestWalkerRequiredLockfileSymlinkRemainsPartial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "work")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(outside, []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "package-lock.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: root, Ref: "$HOME/work"}}, limits: defaultWalkLimits()})
	assertTargetIssue(t, got, "$HOME/work", model.TargetPartial, "symlink_rejected")
	if got.Targets[0].SkippedSymlinks != 0 {
		t.Fatalf("required target counted as incidental: %+v", got.Targets[0])
	}
}

func TestWalkerExcludesSupplyChainEvidenceFromGeneratedAndDependencyTrees(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "safe", "package.json"), `{"name":"safe"}`)
	for _, directory := range []string{".git", "node_modules", ".venv", "vendor", "build", "dist"} {
		writeWalkFile(t, filepath.Join(root, directory, "package.json"), `{"name":"excluded"}`)
	}
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits()})
	if len(got.LocalEvidenceTargets) != 1 || got.LocalEvidenceTargets[0].RelativePath != filepath.Join("safe", "package.json") {
		t.Fatalf("evidence targets=%+v", got.LocalEvidenceTargets)
	}
}

func TestWalkerRejectsSymlinkedEvidenceAndKeepsSafeSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	outside := filepath.Join(home, "outside-package.json")
	writeWalkFile(t, outside, `{"name":"outside"}`)
	writeWalkFile(t, filepath.Join(root, "safe", "package.json"), `{"name":"safe"}`)
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked", "package.json")); err != nil {
		t.Fatal(err)
	}
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits()})
	assertTargetIssue(t, got, "$HOME/Projects", model.TargetPartial, "symlink_rejected")
	if len(got.LocalEvidenceTargets) != 1 || got.LocalEvidenceTargets[0].RelativePath != filepath.Join("safe", "package.json") {
		t.Fatalf("evidence targets=%+v", got.LocalEvidenceTargets)
	}
}

func TestWalkerIssuesUnavailableTargetForEvidenceIdentitySwap(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	manifest := filepath.Join(root, "swapped", "package.json")
	replacement := filepath.Join(home, "replacement-package.json")
	writeWalkFile(t, manifest, `{"name":"before"}`)
	writeWalkFile(t, replacement, `{"name":"replacement"}`)
	collector := &projectCollector{
		roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits(),
		beforeOpen: func(relative string) {
			if relative != filepath.ToSlash(filepath.Join("swapped", "package.json")) {
				return
			}
			if err := os.Rename(manifest, manifest+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, manifest); err != nil {
				t.Fatal(err)
			}
		},
	}
	got := collectProjectTest(t, collector)
	assertTargetIssue(t, got, "$HOME/Projects", model.TargetPartial, "identity_changed")
	if len(got.LocalEvidenceTargets) != 1 || got.LocalEvidenceTargets[0].PresetStatus != model.EvidenceUnavailable || got.LocalEvidenceTargets[0].RootPath != "" || got.LocalEvidenceTargets[0].RelativePath != "" {
		t.Fatalf("evidence targets=%+v", got.LocalEvidenceTargets)
	}
}

func TestProjectEvidenceKnownOversizeReadsNoContentBytes(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	large := filepath.Join(root, "package-lock.json")
	writeWalkFile(t, large, "x")
	if err := os.Truncate(large, maxProjectEvidenceBytes+1); err != nil {
		t.Fatal(err)
	}
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	fileSystem := &countingProjectFileSystem{readBytesByName: make(map[string]int64)}
	environment := testutil.Environment(t, home)
	environment.FS = fileSystem
	got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	if fileSystem.readCalls != 0 || fileSystem.readBytes != 0 || fileSystem.readBytesByName["package-lock.json"] != 0 {
		t.Fatalf("known oversize file was read: calls=%d bytes=%d byName=%v", fileSystem.readCalls, fileSystem.readBytes, fileSystem.readBytesByName)
	}
	if len(got.LocalEvidenceTargets) != 1 || got.LocalEvidenceTargets[0].PresetStatus != model.EvidenceOversize || got.LocalEvidenceTargets[0].RootPath != "" || got.LocalEvidenceTargets[0].RelativePath != "" {
		t.Fatalf("targets=%+v", got.LocalEvidenceTargets)
	}
}

func TestProjectEvidenceGrowthAfterEnumerationUsesBoundedReadAndKeepsSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	large := filepath.Join(root, "package-lock.json")
	writeWalkFile(t, large, "small-at-enumeration")
	writeWalkFile(t, filepath.Join(root, "requirements.txt"), "safe sibling")
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	fileSystem := &countingProjectFileSystem{readBytesByName: make(map[string]int64)}
	environment := testutil.Environment(t, home)
	environment.FS = fileSystem
	collector := &projectCollector{roots: roots, limits: defaultWalkLimits()}
	collector.beforeEvidenceHash = func(relative string) {
		if relative == "package-lock.json" {
			if err := os.Truncate(large, maxProjectEvidenceBytes+2); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := collector.Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	if fileSystem.readBytesByName["package-lock.json"] != maxProjectEvidenceBytes+1 {
		t.Fatalf("grown file bytes=%d want=%d all=%v", fileSystem.readBytesByName["package-lock.json"], maxProjectEvidenceBytes+1, fileSystem.readBytesByName)
	}
	if len(got.LocalEvidenceTargets) != 2 {
		t.Fatalf("targets=%+v", got.LocalEvidenceTargets)
	}
	statuses := map[string]model.EvidenceStatus{}
	for _, target := range got.LocalEvidenceTargets {
		statuses[target.Subject] = target.PresetStatus
	}
	if statuses["project-lockfile:package-lock.json"] != model.EvidenceOversize || statuses["project-manifest:requirements.txt"] != "" {
		t.Fatalf("statuses=%v targets=%+v", statuses, got.LocalEvidenceTargets)
	}
}

func TestWalkerDetectsDirectoryIdentitySwapAndKeepsSafeSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "safe", ".mcp.json"), `{}`)
	writeWalkFile(t, filepath.Join(root, "swapped", ".mcp.json"), `{}`)
	replacement := filepath.Join(home, "replacement")
	writeWalkFile(t, filepath.Join(replacement, ".mcp.json"), `{}`)
	collector := &projectCollector{
		roots:  []Root{{Path: root, Ref: "$HOME/Projects"}},
		limits: defaultWalkLimits(),
		beforeOpen: func(relative string) {
			if relative != "swapped" {
				return
			}
			if err := os.Rename(filepath.Join(root, "swapped"), filepath.Join(root, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, filepath.Join(root, "swapped")); err != nil {
				t.Fatal(err)
			}
		},
	}
	got := collectProjectTest(t, collector)
	assertTargetIssue(t, got, "$HOME/Projects", model.TargetPartial, "identity_changed")
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != filepath.Join(root, "safe", ".mcp.json") {
		t.Fatalf("localTargets=%+v", got.LocalTargets)
	}
}

func TestWalkerRejectsConfiguredRootSwapBetweenNoFollowObservationAndOpen(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "original", ".mcp.json"), `{}`)
	replacement := filepath.Join(home, "replacement")
	writeWalkFile(t, filepath.Join(replacement, "replacement", ".mcp.json"), `{}`)
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	injected := &rootSwapFileSystem{root: root, replacement: replacement}
	environment := testutil.Environment(t, home)
	environment.FS = injected

	got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	assertTargetIssue(t, got, "$HOME/Projects", model.TargetPartial, "identity_changed")
	if injected.lstatCalls != 1 || injected.openRootCalls != 1 {
		t.Fatalf("injected calls lstat=%d openRoot=%d want=1 each", injected.lstatCalls, injected.openRootCalls)
	}
	if len(got.Assets) != 0 || len(got.LocalTargets) != 0 {
		t.Fatalf("swapped root produced evidence: %+v", got)
	}
}

func TestWalkerFailsClosedWithoutRootedOrNoFollowCapability(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "sample", ".mcp.json"), `{}`)
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	osFileSystem := platform.OSFileSystem{}
	for _, testCase := range []struct {
		name       string
		fileSystem platform.FileSystem
	}{
		{name: "missing no-follow", fileSystem: rootedOnlyFileSystem{FileSystem: osFileSystem, rooted: osFileSystem}},
		{name: "missing rooted", fileSystem: noFollowOnlyFileSystem{FileSystem: osFileSystem, noFollow: osFileSystem}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			environment := testutil.Environment(t, home)
			environment.FS = testCase.fileSystem
			got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(context.Background(), environment)
			if err != nil {
				t.Fatal(err)
			}
			assertExactProjectTarget(t, got, model.TargetCoverage{
				TargetID: projectRootTargetID, InstanceRef: "$HOME/Projects", Status: model.TargetUnavailable,
				Errors: []model.CoverageError{{Code: "root_unavailable", Message: "configured project root is unavailable"}},
			})
			if len(got.Assets) != 0 || len(got.LocalTargets) != 0 {
				t.Fatalf("capability failure produced evidence: %+v", got)
			}
		})
	}
}

func TestWalkerReportsInjectedNoFollowFailureUnavailable(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	environment := testutil.Environment(t, home)
	environment.FS = noFollowErrorFileSystem{OSFileSystem: platform.OSFileSystem{}, err: fs.ErrPermission}
	got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	assertExactProjectTarget(t, got, model.TargetCoverage{
		TargetID: projectRootTargetID, InstanceRef: "$HOME/Projects", Status: model.TargetUnavailable,
		Errors: []model.CoverageError{{Code: "root_unavailable", Message: "configured project root is unavailable"}},
	})
}

type rootedOnlyFileSystem struct {
	platform.FileSystem
	rooted platform.RootedFileSystem
}

func (f rootedOnlyFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	return f.rooted.OpenRoot(name)
}

type noFollowOnlyFileSystem struct {
	platform.FileSystem
	noFollow platform.NoFollowFileSystem
}

func (f noFollowOnlyFileSystem) Lstat(name string) (os.FileInfo, error) {
	return f.noFollow.Lstat(name)
}

type noFollowErrorFileSystem struct {
	platform.OSFileSystem
	err error
}

func (f noFollowErrorFileSystem) Lstat(string) (os.FileInfo, error) {
	return nil, f.err
}

type rootSwapFileSystem struct {
	platform.OSFileSystem
	root          string
	replacement   string
	lstatCalls    int
	openRootCalls int
}

func (f *rootSwapFileSystem) Lstat(name string) (os.FileInfo, error) {
	f.lstatCalls++
	expected, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	moved := f.root + "-moved"
	if err := os.Rename(f.root, moved); err != nil {
		return nil, err
	}
	if err := os.Rename(f.replacement, f.root); err != nil {
		return nil, err
	}
	return expected, nil
}

func (f *rootSwapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	f.openRootCalls++
	return f.OSFileSystem.OpenRoot(name)
}

func TestWalkerReturnsBoundedPartialCoverageAndKeepsSafeRoots(t *testing.T) {
	home := t.TempDir()
	safeRoot := filepath.Join(home, "safe-root")
	writeWalkFile(t, filepath.Join(safeRoot, "project", ".mcp.json"), `{}`)

	t.Run("depth", func(t *testing.T) {
		limitedRoot := filepath.Join(home, "depth-root")
		writeWalkFile(t, filepath.Join(limitedRoot, "a", "b", ".mcp.json"), `{}`)
		limits := defaultWalkLimits()
		limits.maxDepth = 2
		got := collectProjectTest(t, &projectCollector{
			roots: []Root{{Path: safeRoot, Ref: "$HOME/safe-root"}, {Path: limitedRoot, Ref: "$HOME/depth-root"}}, limits: limits,
		})
		assertTargetIssue(t, got, "$HOME/depth-root", model.TargetPartial, "depth_limit")
		assertLocalPath(t, got.LocalTargets, filepath.Join(safeRoot, "project", ".mcp.json"))
	})

	t.Run("entries", func(t *testing.T) {
		limitedRoot := filepath.Join(home, "entry-root")
		for _, name := range []string{"a", "b", "c"} {
			if err := os.MkdirAll(filepath.Join(limitedRoot, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		limits := defaultWalkLimits()
		limits.maxEntries = 2
		got := collectProjectTest(t, &projectCollector{
			roots: []Root{{Path: safeRoot, Ref: "$HOME/safe-root"}, {Path: limitedRoot, Ref: "$HOME/entry-root"}}, limits: limits,
		})
		assertTargetIssue(t, got, "$HOME/entry-root", model.TargetPartial, "entry_limit")
		assertLocalPath(t, got.LocalTargets, filepath.Join(safeRoot, "project", ".mcp.json"))
	})

	t.Run("config count", func(t *testing.T) {
		limitedRoot := filepath.Join(home, "config-root")
		writeWalkFile(t, filepath.Join(limitedRoot, "a", ".mcp.json"), `{}`)
		writeWalkFile(t, filepath.Join(limitedRoot, "b", ".mcp.json"), `{}`)
		limits := defaultWalkLimits()
		limits.maxConfigs = 1
		got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: limitedRoot, Ref: "$HOME/config-root"}}, limits: limits})
		assertTargetIssue(t, got, "$HOME/config-root", model.TargetPartial, "config_limit")
		if len(got.LocalTargets) != 1 || !strings.HasSuffix(got.LocalTargets[0].Path, filepath.Join("a", ".mcp.json")) {
			t.Fatalf("localTargets=%+v", got.LocalTargets)
		}
	})

	t.Run("evidence count", func(t *testing.T) {
		limitedRoot := filepath.Join(home, "evidence-root")
		writeWalkFile(t, filepath.Join(limitedRoot, "a", "package.json"), `{}`)
		writeWalkFile(t, filepath.Join(limitedRoot, "b", "package.json"), `{}`)
		limits := defaultWalkLimits()
		limits.maxConfigs = 1
		got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: limitedRoot, Ref: "$HOME/evidence-root"}}, limits: limits})
		assertTargetIssue(t, got, "$HOME/evidence-root", model.TargetPartial, "config_limit")
		if len(got.LocalEvidenceTargets) != 1 || got.LocalEvidenceTargets[0].RelativePath != filepath.Join("a", "package.json") {
			t.Fatalf("evidence targets=%+v", got.LocalEvidenceTargets)
		}
	})

	t.Run("config bytes", func(t *testing.T) {
		limitedRoot := filepath.Join(home, "bytes-root")
		writeWalkFile(t, filepath.Join(limitedRoot, "large", ".mcp.json"), "123456789")
		writeWalkFile(t, filepath.Join(limitedRoot, "safe", ".mcp.json"), `{}`)
		limits := defaultWalkLimits()
		limits.maxConfigBytes = 8
		got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: limitedRoot, Ref: "$HOME/bytes-root"}}, limits: limits})
		assertTargetIssue(t, got, "$HOME/bytes-root", model.TargetPartial, "config_size_limit")
		if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != filepath.Join(limitedRoot, "safe", ".mcp.json") {
			t.Fatalf("localTargets=%+v", got.LocalTargets)
		}
	})
}

func TestWalkerEmitsDeterministicConfigOrder(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "z-project", ".vscode", "mcp.json"), `{}`)
	writeWalkFile(t, filepath.Join(root, "a-project", ".mcp.json"), `{}`)
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits()})
	paths := make([]string, len(got.LocalTargets))
	for index, target := range got.LocalTargets {
		paths[index] = target.Path
	}
	want := []string{
		filepath.Join(root, "a-project", ".mcp.json"),
		filepath.Join(root, "z-project", ".vscode", "mcp.json"),
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths=%q want=%q", paths, want)
	}
}

func TestWalkerUsesInjectedRootedFilesystemWithoutHostPathFallback(t *testing.T) {
	home := t.TempDir()
	realRoot := filepath.Join(t.TempDir(), "backing-root")
	writeWalkFile(t, filepath.Join(realRoot, "sample", ".mcp.json"), `{}`)
	virtualRoot := filepath.Join(t.TempDir(), "not-present-on-host", "Projects")
	if _, err := os.Lstat(virtualRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("virtual test root unexpectedly exists: %v", err)
	}
	roots, err := ResolveRoots(home, []string{virtualRoot})
	if err != nil {
		t.Fatal(err)
	}
	injected := &redirectedRootedFileSystem{virtualRoot: virtualRoot, realRoot: realRoot}
	environment := testutil.Environment(t, home)
	environment.FS = injected

	got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(context.Background(), environment)
	if err != nil {
		t.Fatal(err)
	}
	if injected.lstatCalls != 1 || injected.openRootCalls != 1 {
		t.Fatalf("injected calls lstat=%d openRoot=%d want=1 each", injected.lstatCalls, injected.openRootCalls)
	}
	if len(got.Targets) != 1 || got.Targets[0].Status != model.TargetComplete {
		t.Fatalf("targets=%+v", got.Targets)
	}
	wantLocalPath := filepath.Join(virtualRoot, "sample", ".mcp.json")
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != wantLocalPath {
		t.Fatalf("localTargets=%+v want path=%q", got.LocalTargets, wantLocalPath)
	}
}

type redirectedRootedFileSystem struct {
	platform.OSFileSystem
	virtualRoot   string
	realRoot      string
	lstatCalls    int
	openRootCalls int
}

func (f *redirectedRootedFileSystem) Lstat(name string) (os.FileInfo, error) {
	f.lstatCalls++
	if name != f.virtualRoot {
		return nil, os.ErrNotExist
	}
	return f.OSFileSystem.Lstat(f.realRoot)
}

func (f *redirectedRootedFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	f.openRootCalls++
	if name != f.virtualRoot {
		return nil, os.ErrNotExist
	}
	return f.OSFileSystem.OpenRoot(f.realRoot)
}

func collectProjectTest(t *testing.T, projectCollector *projectCollector) model.CollectorResult {
	t.Helper()
	home := t.TempDir()
	if len(projectCollector.roots) > 0 {
		for _, root := range projectCollector.roots {
			if strings.HasPrefix(root.Ref, "$HOME") {
				relative := strings.TrimPrefix(root.Ref, "$HOME")
				candidateHome := strings.TrimSuffix(root.Path, filepath.FromSlash(relative))
				if candidateHome != "" {
					home = filepath.Clean(candidateHome)
				}
				break
			}
		}
	}
	values := make([]string, len(projectCollector.roots))
	for index, root := range projectCollector.roots {
		values[index] = root.Path
	}
	resolved, err := ResolveRoots(home, values)
	if err != nil {
		t.Fatal(err)
	}
	projectCollector.roots = resolved
	got, err := projectCollector.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertTargetIssue(t *testing.T, result model.CollectorResult, instanceRef string, status model.TargetStatus, code string) {
	t.Helper()
	for _, target := range result.Targets {
		if target.InstanceRef != instanceRef {
			continue
		}
		if target.Status != status {
			t.Fatalf("target=%+v", target)
		}
		for _, issue := range target.Errors {
			if issue.Code == code {
				return
			}
		}
		t.Fatalf("target=%+v missing issue %q", target, code)
	}
	t.Fatalf("targets=%+v missing instance %q", result.Targets, instanceRef)
}

func assertExactProjectTarget(t *testing.T, result model.CollectorResult, want model.TargetCoverage) {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID == want.TargetID && target.InstanceRef == want.InstanceRef {
			if !reflect.DeepEqual(target, want) {
				t.Fatalf("target=%+v want=%+v", target, want)
			}
			return
		}
	}
	t.Fatalf("targets=%+v missing %q/%q", result.Targets, want.TargetID, want.InstanceRef)
}

func assertLocalPath(t *testing.T, targets []model.LocalTarget, path string) {
	t.Helper()
	for _, target := range targets {
		if target.Path == path {
			return
		}
	}
	t.Fatalf("localTargets=%+v missing %q", targets, path)
}

func writeWalkFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWalkCancellationReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(ctx, testutil.Environment(t, home))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestProjectEvidenceCancellationPropagatesAcrossCollectionPhases(t *testing.T) {
	for _, phase := range []string{"walker callback", "after walk", "project loop", "before hash"} {
		t.Run(phase, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, "Projects")
			writeWalkFile(t, filepath.Join(root, "a", "package.json"), `{}`)
			writeWalkFile(t, filepath.Join(root, "b", "package.json"), `{}`)
			roots, err := ResolveRoots(home, []string{root})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			projectCollector := &projectCollector{roots: roots, limits: defaultWalkLimits()}
			switch phase {
			case "walker callback":
				projectCollector.beforeOpen = func(relative string) {
					if relative == filepath.ToSlash(filepath.Join("a", "package.json")) {
						calls++
						cancel()
					}
				}
			case "after walk":
				projectCollector.afterWalk = func(string) { calls++; cancel() }
			case "project loop":
				projectCollector.beforeProject = func(string) { calls++; cancel() }
			case "before hash":
				projectCollector.beforeEvidenceHash = func(string) { calls++; cancel() }
			}
			got, err := projectCollector.Collect(ctx, testutil.Environment(t, home))
			if !errors.Is(err, context.Canceled) || calls != 1 {
				t.Fatalf("phase=%q calls=%d err=%v result=%+v", phase, calls, err, got)
			}
			if len(got.Targets) != 0 || len(got.Assets) != 0 || len(got.Observations) != 0 || len(got.LocalTargets) != 0 || len(got.LocalEvidenceTargets) != 0 || got.LocalEvidenceIssuer != nil {
				t.Fatalf("canceled collection returned false-success output: %+v", got)
			}
		})
	}
}

func TestProjectEvidenceCancellationDuringHashPropagatesImmediately(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "a", "package.json"), strings.Repeat("x", 1<<20))
	writeWalkFile(t, filepath.Join(root, "b", "package.json"), strings.Repeat("y", 1<<20))
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fileSystem := &countingProjectFileSystem{cancelOnRead: cancel}
	environment := testutil.Environment(t, home)
	environment.FS = fileSystem
	got, err := (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(ctx, environment)
	if !errors.Is(err, context.Canceled) || fileSystem.readCalls != 1 {
		t.Fatalf("calls=%d bytes=%d err=%v result=%+v", fileSystem.readCalls, fileSystem.readBytes, err, got)
	}
	if len(got.Targets) != 0 || len(got.Assets) != 0 || len(got.Observations) != 0 || len(got.LocalTargets) != 0 || len(got.LocalEvidenceTargets) != 0 || got.LocalEvidenceIssuer != nil {
		t.Fatalf("canceled hash returned false-success output: %+v", got)
	}
}

func TestProjectEvidencePropagatesExpiredDeadline(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeWalkFile(t, filepath.Join(root, "package.json"), `{}`)
	roots, err := ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err = (&projectCollector{roots: roots, limits: defaultWalkLimits()}).Collect(ctx, testutil.Environment(t, home))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v", err)
	}
}

type countingProjectFileSystem struct {
	platform.OSFileSystem
	readCalls       int
	readBytes       int64
	readBytesByName map[string]int64
	cancelOnRead    func()
	canceled        bool
}

func (f *countingProjectFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &countingProjectRoot{RootedDirectory: root, owner: f}, nil
}

type countingProjectRoot struct {
	platform.RootedDirectory
	owner *countingProjectFileSystem
}

func (r *countingProjectRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &countingProjectRoot{RootedDirectory: child, owner: r.owner}, nil
}

func (r *countingProjectRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	return &countingProjectFile{RootedFile: file, owner: r.owner, name: name}, nil
}

type countingProjectFile struct {
	platform.RootedFile
	owner *countingProjectFileSystem
	name  string
}

func (f *countingProjectFile) Read(buffer []byte) (int, error) {
	f.owner.readCalls++
	if !f.owner.canceled && f.owner.cancelOnRead != nil {
		f.owner.canceled = true
		f.owner.cancelOnRead()
	}
	count, err := f.RootedFile.Read(buffer)
	f.owner.readBytes += int64(count)
	if f.owner.readBytesByName == nil {
		f.owner.readBytesByName = make(map[string]int64)
	}
	f.owner.readBytesByName[f.name] += int64(count)
	return count, err
}
