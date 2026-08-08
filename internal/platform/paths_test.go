package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactHomeOnlyOnPathBoundary(t *testing.T) {
	home := "/Users/alice"

	if got := RedactHome(home, "/Users/alice/.claude/settings.json"); got != "$HOME/.claude/settings.json" {
		t.Fatal(got)
	}
	if got := RedactHome(home, "/Users/alice2/file"); got != "/Users/alice2/file" {
		t.Fatal(got)
	}
}

func TestRedactHomeRedactsRootHome(t *testing.T) {
	if got := RedactHome("/", "/private/tmp/file"); got != "$HOME/private/tmp/file" {
		t.Fatal(got)
	}
}

// hostileInstallVersions are the values that must never name a directory.
var hostileInstallVersions = []string{
	"",
	" ",
	".",
	"..",
	"../..",
	"../../../../etc",
	"a/b",
	`a\b`,
	"/abs",
	"~",
	"-x",
	"v1/../../escape",
	"v1.0.0/nested",
	"v1.0.0\x00",
	"v1.0.0\n",
	"v1.0.0\t",
	"v1.0.0\x7f",
	"v1.0.0 ",
	"dev+git.NOTHEX0000000000000000000000000000000000",
	"dev+git.0123456789ABCDEF0123456789abcdef01234567",
	"latest",
	"V1.0.0",
	strings.Repeat("v1.0.0", 32),
}

func TestInstallLayoutIsRootedInTheDataDirectory(t *testing.T) {
	paths := PathsForHome("/Users/example")
	layout := paths.Install()

	members := map[string]string{
		"root":       layout.Root,
		"versions":   layout.VersionsDir,
		"current":    layout.CurrentFile,
		"previous":   layout.PreviousFile,
		"staging":    layout.StagingDir,
		"state":      layout.StateDatabase,
		"bundles":    layout.BundlesDir,
		"reports":    layout.ReportsDir,
		"quarantine": layout.QuarantineDir,
	}
	seen := map[string]string{}
	for name, got := range members {
		if !strings.HasPrefix(got, paths.DataDir+string(filepath.Separator)) {
			t.Fatalf("%s escapes the data directory: %q", name, got)
		}
		if other, duplicate := seen[got]; duplicate {
			t.Fatalf("%s and %s share a path: %q", name, other, got)
		}
		seen[got] = name
	}
	for _, core := range []string{layout.VersionsDir, layout.CurrentFile, layout.PreviousFile, layout.StagingDir} {
		if filepath.Dir(core) != layout.Root {
			t.Fatalf("core member %q is not a direct child of the core root %q", core, layout.Root)
		}
	}
}

func TestInstallVersionRejectsAnythingTheBuildCannotProduce(t *testing.T) {
	for _, valid := range []string{
		"v0.1.0",
		"v0.2.0",
		"v1.2.3-rc.1",
		"v1.2.3+build.4",
		"dev+git.0123456789abcdef0123456789abcdef01234567",
	} {
		if !ValidInstallVersion(valid) {
			t.Fatalf("release version %q rejected", valid)
		}
	}
	for _, invalid := range hostileInstallVersions {
		if ValidInstallVersion(invalid) {
			t.Fatalf("unsafe version %q accepted", invalid)
		}
	}
}

func TestVersionDirRejectsUnsafeVersions(t *testing.T) {
	layout := PathsForHome("/Users/example").Install()

	if _, err := layout.VersionDir("../escape"); err == nil {
		t.Fatal("VersionDir accepted a traversing version")
	}
	directory, err := layout.VersionDir("v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(directory) != layout.VersionsDir {
		t.Fatalf("version directory is not a direct child of versions: %q", directory)
	}
}

func TestVersionDirNeverEscapesTheVersionsRoot(t *testing.T) {
	home := t.TempDir()
	layout := PathsForHome(home).Install()
	if err := os.MkdirAll(layout.VersionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(layout.VersionsDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	versionsRoot, err := os.Stat(layout.VersionsDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range hostileInstallVersions {
		directory, err := layout.VersionDir(version)
		if err == nil {
			t.Fatalf("VersionDir accepted %q and produced %q", version, directory)
		}
		if directory != "" {
			t.Fatalf("VersionDir returned a path %q for rejected version %q", directory, version)
		}
		// Nothing rejected may name a location other than the versions root
		// itself; a traversing version must not reach a parent directory.
		if resolved, err := root.Stat(version); err == nil && !os.SameFile(resolved, versionsRoot) {
			t.Fatalf("rejected version %q resolves to a location inside the versions root", version)
		}
	}

	directory, err := layout.VersionDir("v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if directory != filepath.Clean(directory) || !strings.HasPrefix(directory, layout.VersionsDir+string(filepath.Separator)) {
		t.Fatalf("accepted version produced an unclean or escaping path: %q", directory)
	}
	if err := root.Mkdir("v0.1.0", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); err != nil {
		t.Fatalf("root-resolved directory does not match the layout path: %v", err)
	}
}
