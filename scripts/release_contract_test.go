package scripts_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryHasNoAppleReleasePipeline(t *testing.T) {
	root := repositoryRoot(t)
	for _, violation := range appleReleaseSurfaceViolations(root) {
		t.Error(violation)
	}
}

func TestAppleReleaseContractRejectsReintroductionMutations(t *testing.T) {
	mutations := []struct {
		name     string
		path     string
		mode     os.FileMode
		content  string
		workflow string
	}{
		{
			name:    "active Darwin build signs output",
			path:    "scripts/build-darwin.sh",
			mode:    0o755,
			content: "#!/bin/sh\n/usr/bin/codesign --sign release dist/ssc-init-darwin-universal\n",
		},
		{
			name:    "newly named executable submits output",
			path:    "scripts/publish-darwin.sh",
			mode:    0o755,
			content: "#!/bin/sh\nxcrun notarytool submit dist/release.zip\n",
		},
		{
			name:     "workflow invokes non-executable shell release helper",
			path:     "scripts/publish-release.sh",
			mode:     0o644,
			content:  "#!/bin/sh\n/usr/bin/codesign --sign release dist/ssc-init-darwin-universal\n",
			workflow: "jobs:\n  release:\n    steps:\n      - run: sh scripts/publish-release.sh\n",
		},
		{
			name:     "workflow invokes non-executable Go release helper",
			path:     "scripts/publish-release.go",
			mode:     0o644,
			content:  "package main\n\nconst releaseTool = \"notarytool\"\n",
			workflow: "jobs:\n  release:\n    steps:\n      - run: go run ./scripts/publish-release.go\n",
		},
		{
			name:    "workflow staples output",
			path:    ".github/workflows/ci.yml",
			mode:    0o644,
			content: "jobs:\n  release:\n    steps:\n      - run: xcrun stapler staple dist/release\n",
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			root := newAppleReleaseContractFixture(t)
			writeContractFixtureFile(t, root, mutation.path, mutation.content, mutation.mode)
			if mutation.workflow != "" {
				writeContractFixtureFile(t, root, ".github/workflows/ci.yml", mutation.workflow, 0o644)
			}
			if violations := appleReleaseSurfaceViolations(root); len(violations) == 0 {
				t.Fatalf("release contract accepted mutation in %s", mutation.path)
			}
		})
	}
}

func TestAppleReleaseContractAllowsPassivePlatformSignatureInspection(t *testing.T) {
	root := newAppleReleaseContractFixture(t)
	writeContractFixtureFile(t, root, "internal/platform/signature.go", "package platform\n\nconst codesign = \"/usr/bin/codesign\"\n", 0o644)
	if violations := appleReleaseSurfaceViolations(root); len(violations) != 0 {
		t.Fatalf("passive platform inspection was rejected: %s", strings.Join(violations, "; "))
	}
}

func TestAppleReleaseContractAllowsNegativeTestFixtureLiterals(t *testing.T) {
	root := newAppleReleaseContractFixture(t)
	writeContractFixtureFile(t, root, "scripts/release_contract_test.go", "package scripts_test\n\nconst forbiddenFixture = \"codesign --sign\"\n", 0o644)
	if violations := appleReleaseSurfaceViolations(root); len(violations) != 0 {
		t.Fatalf("negative test fixture was rejected: %s", strings.Join(violations, "; "))
	}
}

func appleReleaseSurfaceViolations(root string) []string {
	var violations []string
	for _, name := range []string{
		"scripts/sign-darwin.sh",
		"scripts/sign-darwin_test.go",
		"scripts/notarize-darwin.sh",
		"scripts/notarize-darwin_test.go",
	} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			violations = append(violations, "obsolete Apple release surface exists: "+name)
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
			violations = append(violations, "read active release file "+name+": "+err.Error())
			continue
		}
		for _, value := range forbidden {
			if strings.Contains(string(raw), value) {
				violations = append(violations, "active release file "+name+" contains obsolete surface "+value)
			}
		}
	}

	forbiddenExecution := []string{
		"codesign", "notarytool", "stapler", "developer id",
		"apple_id", "developer_id", "signing_identity",
		"checksums-signed.txt", "checksums-notarized.txt",
		"ssc-init-darwin.dmg", "sign-darwin", "notarize-darwin",
	}
	scanExecutionTree := func(directory string, include func(string, fs.FileInfo) bool) {
		walkRoot := filepath.Join(root, directory)
		err := filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || !include(filepath.ToSlash(relative), info) {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			lower := strings.ToLower(string(raw))
			for _, value := range forbiddenExecution {
				if strings.Contains(lower, value) {
					violations = append(violations, "active release execution file "+filepath.ToSlash(relative)+" contains obsolete surface "+value)
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			violations = append(violations, "scan active release execution path "+directory+": "+err.Error())
		}
	}
	scanExecutionTree(".github/workflows", func(string, fs.FileInfo) bool { return true })
	scanExecutionTree("scripts", func(name string, _ fs.FileInfo) bool {
		// Go test sources contain the forbidden literals used by mutation
		// fixtures, but are never release helpers. Every other regular file is
		// scanned regardless of mode because workflows can invoke 0644 shell
		// and Go sources through `sh` and `go run`.
		return !strings.HasSuffix(name, "_test.go")
	})
	return violations
}

func newAppleReleaseContractFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{
		".github/workflows/ci.yml",
		"CLAUDE.md",
		"README.md",
		"docs/release-runbook.md",
		"docs/testing/2026-08-09-foundation-completion-audit.md",
	} {
		writeContractFixtureFile(t, root, name, "current unsigned release contract\n", 0o644)
	}
	return root
}

func writeContractFixtureFile(t *testing.T, root, name, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
