package scripts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryHasNoAppleReleasePipeline(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		"scripts/sign-darwin.sh",
		"scripts/sign-darwin_test.go",
		"scripts/notarize-darwin.sh",
		"scripts/notarize-darwin_test.go",
	} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("obsolete Apple release surface exists: %s", name)
		}
	}

	active := []string{
		".github/workflows/ci.yml",
		"CLAUDE.md",
		"README.md",
		"docs/release-runbook.md",
		"docs/testing/2026-08-09-foundation-completion-audit.md",
	}
	forbidden := []string{
		"Developer ID", "notarytool", "notarization", "stapler",
		"checksums-signed.txt", "checksums-notarized.txt",
		"ssc-init-darwin.dmg", "sign-darwin.sh", "notarize-darwin.sh",
	}
	for _, name := range active {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if strings.Contains(string(raw), value) {
				t.Errorf("active release file %s contains obsolete surface %q", name, value)
			}
		}
	}
}
