package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestBuildScriptDeclaresStaticTargets(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#!/bin/sh",
		"set -eu",
		"CGO_ENABLED=0",
		"GOOS=darwin",
		"GOARCH=arm64",
		"GOARCH=amd64",
		"-trimpath",
		"-buildvcs=false",
		"git -C \"$REPOSITORY_ROOT\" rev-parse",
		"-X main.version=",
		"SOURCE_DATE_EPOCH",
		"shasum -a 256",
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("build script missing %q", want)
		}
	}
}

func TestBuildScriptWorksOutsideRepositoryAndIsReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build smoke test")
	}
	repositoryRoot := repositoryRoot(t)
	script := filepath.Join(repositoryRoot, "scripts", "build-darwin.sh")
	revision := worktreeRevision(t, repositoryRoot)
	wantVersion := "dev+git." + revision
	runBuild := func() map[string][32]byte {
		t.Helper()
		command := exec.Command("sh", script)
		command.Dir = t.TempDir()
		command.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build failed: %v\n%s", err, output)
		}
		digests := make(map[string][32]byte, 3)
		for _, name := range []string{"ssc-init-darwin-amd64", "ssc-init-darwin-arm64", "checksums.txt"} {
			path := filepath.Join(repositoryRoot, "dist", name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if name != "checksums.txt" && bytes.Contains(content, []byte(repositoryRoot)) {
				t.Fatalf("%s contains absolute repository path %q", name, repositoryRoot)
			}
			if name != "checksums.txt" {
				if !bytes.Contains(content, []byte(revision)) {
					t.Fatalf("%s does not contain worktree revision %q", name, revision)
				}
				assertNoAutomaticVCSSettings(t, path)
			}
			digests[name] = sha256.Sum256(content)
		}
		assertNativeVersion(t, repositoryRoot, wantVersion)
		return digests
	}

	first := runBuild()
	second := runBuild()
	for name, firstDigest := range first {
		if second[name] != firstDigest {
			t.Errorf("%s changed between identical builds: %x != %x", name, firstDigest, second[name])
		}
	}

	checksums, err := os.ReadFile(filepath.Join(repositoryRoot, "dist", "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "  dist/ssc-init-darwin-amd64") || !strings.HasSuffix(lines[1], "  dist/ssc-init-darwin-arm64") {
		t.Fatalf("checksums are not deterministically sorted:\n%s", checksums)
	}
}

func TestBuildScriptRejectsInvalidRevision(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	binDirectory := t.TempDir()
	fakeGit := filepath.Join(binDirectory, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nprintf '%s\\n' not-a-commit\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), "PATH="+binDirectory+":/usr/bin:/bin")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("build accepted invalid revision:\n%s", output)
	}
	if !bytes.Contains(output, []byte("revision is not a 40-character lowercase hexadecimal commit")) {
		t.Fatalf("unexpected failure for invalid revision: %v\n%s", err, output)
	}
}

func worktreeRevision(t *testing.T, repositoryRoot string) string {
	t.Helper()
	command := exec.Command("git", "-C", repositoryRoot, "rev-parse", "--verify", "HEAD^{commit}")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(output))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(revision) {
		t.Fatalf("invalid worktree revision %q", revision)
	}
	return revision
}

func assertNoAutomaticVCSSettings(t *testing.T, binary string) {
	t.Helper()
	command := exec.Command("go", "version", "-m", binary)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect build metadata: %v\n%s", err, output)
	}
	for _, forbidden := range []string{"\tbuild\tvcs=", "\tbuild\tvcs.revision=", "\tbuild\tvcs.time=", "\tbuild\tvcs.modified="} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Fatalf("%s contains automatic VCS metadata %q:\n%s", filepath.Base(binary), forbidden, output)
		}
	}
}

func assertNativeVersion(t *testing.T, repositoryRoot, want string) {
	t.Helper()
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("native Darwin provenance smoke test")
	}
	binary := filepath.Join(repositoryRoot, "dist", "ssc-init-darwin-"+runtime.GOARCH)
	command := exec.Command(binary, "version", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native version smoke failed: %v\n%s", err, output)
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode native version output: %v\n%s", err, output)
	}
	if result.Version != want {
		t.Fatalf("native version=%q, want %q", result.Version, want)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(fmt.Errorf("locate repository root: %w", err))
	}
	return root
}
