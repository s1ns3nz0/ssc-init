package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			digests[name] = sha256.Sum256(content)
		}
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
