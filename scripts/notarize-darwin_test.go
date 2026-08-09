package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNotarizeScriptFailsClosedWithoutAKeychainProfile(t *testing.T) {
	distribution := t.TempDir()
	command := exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "notarize-darwin.sh"))
	command.Env = append(environmentWith("SSC_INIT_DIST_DIR", distribution), "SSC_INIT_NOTARY_PROFILE=")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("notarize script ran without a profile:\n%s", output)
	}
	if got := strings.TrimSpace(string(output)); got != "SSC_INIT_NOTARY_PROFILE is not set; run xcrun notarytool store-credentials first" {
		t.Fatalf("unexpected error %q", got)
	}
	if _, err := os.Stat(filepath.Join(distribution, "ssc-init-darwin.dmg")); !os.IsNotExist(err) {
		t.Fatal("dmg exists without a notary profile")
	}
}

func TestNotarizeScriptFailsClosedOnAnUnsignedArtifact(t *testing.T) {
	distribution := t.TempDir()
	if err := os.WriteFile(filepath.Join(distribution, "ssc-init-darwin-universal"), []byte("unsigned"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "notarize-darwin.sh"))
	command.Env = append(environmentWith("SSC_INIT_DIST_DIR", distribution),
		"SSC_INIT_NOTARY_PROFILE=test-profile", "SSC_INIT_SIGNING_IDENTITY=Developer ID Application: Test (TEAM)")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("notarize script accepted an unsigned artifact:\n%s", output)
	}
	if got := strings.TrimSpace(string(output)); got != "universal binary is not signed; run scripts/sign-darwin.sh first" {
		t.Fatalf("unexpected error %q", got)
	}
	if _, err := os.Stat(filepath.Join(distribution, "ssc-init-darwin.dmg")); !os.IsNotExist(err) {
		t.Fatal("dmg exists for an unsigned artifact")
	}
}

func TestNotarizeScriptShipsAStapledDiskImage(t *testing.T) {
	distribution := t.TempDir()
	if err := os.WriteFile(filepath.Join(distribution, "ssc-init-darwin-universal"), []byte("signed-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "tools.log")
	writeTool := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTool("codesign", `printf 'codesign %s\n' "$*" >> "$NOTARY_TEST_LOG"`+"\n")
	writeTool("hdiutil", `printf 'hdiutil %s\n' "$*" >> "$NOTARY_TEST_LOG"
for value do output=$value; done
printf dmg > "$output"
`)
	writeTool("xcrun", `printf 'xcrun %s\n' "$*" >> "$NOTARY_TEST_LOG"`+"\n")
	writeTool("spctl", `printf 'spctl %s\n' "$*" >> "$NOTARY_TEST_LOG"`+"\n")

	command := exec.Command("sh", filepath.Join(repositoryRoot(t), "scripts", "notarize-darwin.sh"))
	command.Env = append(environmentWith("PATH", bin+":/usr/bin:/bin"),
		"SSC_INIT_DIST_DIR="+distribution,
		"SSC_INIT_NOTARY_PROFILE=test-profile",
		"SSC_INIT_SIGNING_IDENTITY=Developer ID Application: Test (TEAM)",
		"NOTARY_TEST_LOG="+logPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("notarize script failed: %v\n%s", err, output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"hdiutil create -quiet -ov -format UDZO -volname SSC Init -srcfolder",
		"codesign --sign Developer ID Application: Test (TEAM) --timestamp --force",
		"xcrun notarytool submit " + filepath.Join(distribution, "ssc-init-darwin.dmg") + " --keychain-profile test-profile --wait",
		"xcrun stapler staple " + filepath.Join(distribution, "ssc-init-darwin.dmg"),
		"xcrun stapler validate " + filepath.Join(distribution, "ssc-init-darwin.dmg"),
		"spctl --assess -vvv --type open --context context:primary-signature",
	} {
		if !strings.Contains(string(log), required) {
			t.Fatalf("tool log missing %q: %s", required, log)
		}
	}
	checksum, err := os.ReadFile(filepath.Join(distribution, "checksums-notarized.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(checksum)), "  dist/ssc-init-darwin.dmg") || strings.Contains(string(checksum), distribution) {
		t.Fatalf("unsafe notarized checksum: %q", checksum)
	}
}
