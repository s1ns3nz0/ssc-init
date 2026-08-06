package projects

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/testutil"
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
	if !reflect.DeepEqual(defaults, []Root{{Path: filepath.Join(home, "Projects"), Ref: "$HOME/Projects"}}) {
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
	home := t.TempDir()
	realRoot := filepath.Join(home, "real")
	if err := os.MkdirAll(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(home, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	got := collectProjectTest(t, &projectCollector{roots: []Root{{Path: linkedRoot, Ref: "$HOME/linked"}}, limits: defaultWalkLimits()})
	assertTargetIssue(t, got, "$HOME/linked", model.TargetPartial, "symlink_rejected")
	if len(got.Assets) != 0 || len(got.LocalTargets) != 0 {
		t.Fatalf("result=%+v", got)
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
	_, err := (&projectCollector{roots: []Root{{Path: root, Ref: "$HOME/Projects"}}, limits: defaultWalkLimits()}).Collect(ctx, testutil.Environment(t, home))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
