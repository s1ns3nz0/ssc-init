package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignScriptFailsClosedWithoutAnIdentity(t *testing.T) {
	repository := repositoryRoot(t)
	script := filepath.Join(repository, "scripts", "sign-darwin.sh")
	distribution := t.TempDir()
	artifact := filepath.Join(distribution, "ssc-init-darwin-universal")
	before := []byte("not-really-a-binary")
	if err := os.WriteFile(artifact, before, 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", script)
	command.Dir = t.TempDir()
	command.Env = append(environmentWith("SSC_INIT_DIST_DIR", distribution), "SSC_INIT_SIGNING_IDENTITY=")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("sign script ran without an identity:\n%s", output)
	}
	if got := strings.TrimSpace(string(output)); got != "SSC_INIT_SIGNING_IDENTITY is not set; a Developer ID Application identity is required to sign" {
		t.Fatalf("unexpected error %q", got)
	}
	after, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("artifact changed before identity validation")
	}
	if _, err := os.Stat(filepath.Join(distribution, "checksums-signed.txt")); !os.IsNotExist(err) {
		t.Fatal("signed checksum exists without signing")
	}
}

func TestSignScriptFailsClosedWithoutAnArtifact(t *testing.T) {
	command := exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "sign-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = append(environmentWith("SSC_INIT_DIST_DIR", t.TempDir()), "SSC_INIT_SIGNING_IDENTITY=Developer ID Application: Test (TEAM)")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("sign script ran without an artifact:\n%s", output)
	}
	if got := strings.TrimSpace(string(output)); got != "universal binary not found; run scripts/build-darwin.sh first" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestSignScriptUsesHardenedTimestampedIdentityAndWritesShippingChecksum(t *testing.T) {
	distribution := t.TempDir()
	artifact := filepath.Join(distribution, "ssc-init-darwin-universal")
	if err := os.WriteFile(artifact, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "codesign.log")
	fake := filepath.Join(bin, "codesign")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SIGN_TEST_LOG\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "sign-darwin.sh"))
	command.Env = append(environmentWith("PATH", bin+":/usr/bin:/bin"),
		"SSC_INIT_DIST_DIR="+distribution,
		"SSC_INIT_SIGNING_IDENTITY=Developer ID Application: Test (TEAM)",
		"SIGN_TEST_LOG="+logPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sign script failed: %v\n%s", err, output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--sign Developer ID Application: Test (TEAM)", "--identifier dev.sscinit.core", "--options runtime", "--timestamp", "--force", "--verify --strict --verbose=2"} {
		if !strings.Contains(string(log), required) {
			t.Fatalf("codesign log missing %q: %s", required, log)
		}
	}
	checksum, err := os.ReadFile(filepath.Join(distribution, "checksums-signed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(checksum)), "  dist/ssc-init-darwin-universal") || strings.Contains(string(checksum), distribution) {
		t.Fatalf("unsafe signed checksum: %q", checksum)
	}
}
