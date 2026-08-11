package projects

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestDiscoverGitWorktreesFindsReciprocalLinkedWorktree(t *testing.T) {
	home := t.TempDir()
	main := filepath.Join(home, "Projects", "main")
	linked := filepath.Join(home, "work", "feature")
	admin := filepath.Join(main, ".git", "worktrees", "feature")
	writeGitFixture(t, filepath.Join(admin, "gitdir"), filepath.Join(linked, ".git")+"\n")
	writeGitFixture(t, filepath.Join(linked, ".git"), "gitdir: "+admin+"\n")

	got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: filepath.Join(home, "Projects")}})
	if err != nil || coverage != nil {
		t.Fatalf("coverage=%+v err=%v", coverage, err)
	}
	want := []discoveryCandidate{{path: linked, source: discoveryGitTargetID, priority: 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}

func TestDiscoverGitWorktreesStopsAtRepositoryAndExcludedDirectories(t *testing.T) {
	home := t.TempDir()
	seed := filepath.Join(home, "Projects")
	makeGitPair(t, filepath.Join(seed, "repo"), filepath.Join(home, "work", "good"), "good")
	makeGitPair(t, filepath.Join(seed, "repo", "nested"), filepath.Join(home, "work", "hidden"), "hidden")
	makeGitPair(t, filepath.Join(seed, "build", "repo"), filepath.Join(home, "work", "build"), "build")
	got, _, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: seed}})
	if err != nil || len(got) != 1 || got[0].path != filepath.Join(home, "work", "good") {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestDiscoverGitWorktreesRejectsForgedAndUnsafeMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, home, main, linked, admin string)
		code   string
	}{
		{"stale target", func(t *testing.T, _, _, linked, _ string) { os.Remove(filepath.Join(linked, ".git")) }, "metadata_unavailable"},
		{"mismatched backlink", func(t *testing.T, home, _, linked, _ string) {
			writeGitFixture(t, filepath.Join(linked, ".git"), "gitdir: "+filepath.Join(home, "other")+"\n")
		}, "metadata_malformed"},
		{"noncanonical backlink", func(t *testing.T, _, _, linked, admin string) {
			writeGitFixture(t, filepath.Join(linked, ".git"), "gitdir: "+admin+string(os.PathSeparator)+".."+string(os.PathSeparator)+filepath.Base(admin)+"\n")
		}, "metadata_malformed"},
		{"missing dotgit suffix", func(t *testing.T, _, main, _, admin string) {
			writeGitFixture(t, filepath.Join(admin, "gitdir"), main+"\n")
		}, "metadata_malformed"},
		{"oversize", func(t *testing.T, _, _, _, admin string) {
			writeGitFixture(t, filepath.Join(admin, "gitdir"), strings.Repeat("x", 4097))
		}, "metadata_oversize"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			main := filepath.Join(home, "Projects", "main")
			linked := filepath.Join(home, "work", "feature")
			admin := makeGitPair(t, main, linked, "feature")
			tt.mutate(t, home, main, linked, admin)
			got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: filepath.Join(home, "Projects")}})
			if err != nil || len(got) != 0 {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			assertDiscoveryCoverageCodes(t, coverage, discoveryGitTargetID, tt.code)
			assertCoverageExcludes(t, coverage, home, main, linked, admin, "feature")
		})
	}
}

func TestDiscoverGitWorktreesRejectsOutsideHomeAndSymlinks(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	main := filepath.Join(home, "Projects", "main")
	makeGitPair(t, main, filepath.Join(outside, "feature"), "outside")
	real := filepath.Join(main, ".git", "worktrees", "real")
	writeGitFixture(t, filepath.Join(real, "gitdir"), filepath.Join(home, "work", "bad", ".git"))
	if err := os.Symlink(real, filepath.Join(main, ".git", "worktrees", "linked")); err != nil {
		t.Fatal(err)
	}
	got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: filepath.Join(home, "Projects")}})
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryGitTargetID, "metadata_unavailable", "outside_home", "symlink_rejected")
}

func TestDiscoverGitWorktreesAcceptsLinkedRepositorySeed(t *testing.T) {
	home := t.TempDir()
	main := filepath.Join(home, "repos", "main")
	linked := filepath.Join(home, "work", "feature")
	makeGitPair(t, main, linked, "feature")
	got, _, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: linked}})
	if err != nil || len(got) != 1 || got[0].path != linked {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestDiscoverGitWorktreesRejectsLinkedSeedWithForgedAdminDirectory(t *testing.T) {
	home := t.TempDir()
	linked := filepath.Join(home, "work", "feature")
	admin := filepath.Join(home, "arbitrary", "admin")
	writeGitFixture(t, filepath.Join(admin, "gitdir"), filepath.Join(linked, ".git")+"\n")
	writeGitFixture(t, filepath.Join(linked, ".git"), "gitdir: "+admin+"\n")
	got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: linked}})
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryGitTargetID, "metadata_malformed")
}

func TestDiscoverGitWorktreesRejectsSymlinkedDotGitAndDepthOverflow(t *testing.T) {
	home := t.TempDir()
	seed := filepath.Join(home, "Projects")
	real := filepath.Join(home, "real-git")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(seed, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(repo, ".git")); err != nil {
		t.Fatal(err)
	}
	deep := seed
	for i := 0; i <= gitDiscoveryMaxDepth; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%02d", i))
	}
	makeGitPair(t, filepath.Join(deep, "main"), filepath.Join(home, "work", "too-deep"), "deep")
	got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: seed}})
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryGitTargetID, "root_limit", "symlink_rejected")
}

func TestDiscoverGitWorktreesHonorsAdminLimitAndCancellation(t *testing.T) {
	home := t.TempDir()
	main := filepath.Join(home, "Projects", "main")
	for i := 0; i < 65; i++ {
		makeGitPair(t, main, filepath.Join(home, "work", fmt.Sprintf("feature-%03d", i)), fmt.Sprintf("id-%03d", i))
	}
	got, coverage, err := discoverGitWorktrees(context.Background(), testutil.Environment(t, home), []discoveryCandidate{{path: filepath.Join(home, "Projects")}})
	if err != nil || len(got) != 64 {
		t.Fatalf("got=%d err=%v", len(got), err)
	}
	assertDiscoveryCoverageCodes(t, coverage, discoveryGitTargetID, "root_limit")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, coverage, err = discoverGitWorktrees(ctx, testutil.Environment(t, home), []discoveryCandidate{{path: filepath.Join(home, "Projects")}})
	if !errors.Is(err, context.Canceled) || got != nil || coverage != nil {
		t.Fatalf("got=%+v coverage=%+v err=%v", got, coverage, err)
	}
}

func makeGitPair(t *testing.T, main, linked, id string) string {
	t.Helper()
	admin := filepath.Join(main, ".git", "worktrees", id)
	writeGitFixture(t, filepath.Join(admin, "gitdir"), filepath.Join(linked, ".git")+"\n")
	writeGitFixture(t, filepath.Join(linked, ".git"), "gitdir: "+admin+"\n")
	return admin
}

func writeGitFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
