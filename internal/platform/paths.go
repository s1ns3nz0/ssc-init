package platform

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Paths identifies the macOS locations owned by SSC Init for one home directory.
type Paths struct {
	Home    string
	DataDir string
}

// SafeLocationRef returns a home-redacted path or a stable, non-revealing
// reference for a path outside home.
func SafeLocationRef(home, path, externalLabel string) string {
	cleanHome, cleanPath := filepath.Clean(home), filepath.Clean(path)
	if redacted := RedactHome(cleanHome, cleanPath); strings.HasPrefix(redacted, "$HOME") {
		return filepath.ToSlash(redacted)
	}
	digest := sha256.Sum256([]byte(filepath.ToSlash(cleanPath)))
	return fmt.Sprintf("%s/path-sha256:%x", externalLabel, digest)
}

// PathsForHome derives the SSC Init data location without reading the host environment.
func PathsForHome(home string) Paths {
	return Paths{
		Home:    home,
		DataDir: filepath.Join(home, "Library", "Application Support", "SSC Init"),
	}
}

// CoreExecutableName is the file name of an installed core binary inside a
// version directory.
const CoreExecutableName = "ssc-init"

// InstallLayout is the design §5.3 shared installation beneath DataDir: a
// versioned core with a current-version pointer, one state database, the TI and
// policy bundles, local reports, and reversible quarantine. All members are
// absolute host paths, so nothing here is ever persisted or reported; report
// them through RedactHome or SafeLocationRef.
//
// The current-version pointer is a file holding a version string, not a
// symlink: the rest of this product refuses to follow symlinks, and the install
// is the last place to make an exception.
type InstallLayout struct {
	Root         string // <DataDir>/core — install-owned, everything below it is replaceable
	VersionsDir  string // <DataDir>/core/versions
	CurrentFile  string // <DataDir>/core/current
	PreviousFile string // <DataDir>/core/previous
	StagingDir   string // <DataDir>/core/staging

	// Shared data. Siblings of Root, never touched by an install, an update,
	// a rollback, or the removal of an adapter.
	StateDatabase string // <DataDir>/state.db
	BundlesDir    string // <DataDir>/bundles — TI and policy bundles
	ReportsDir    string // <DataDir>/reports
	QuarantineDir string // <DataDir>/quarantine
	PolicyFile    string // <DataDir>/policy.json — local levels 4 and 5
}

// Install returns the shared installation layout for these paths.
func (p Paths) Install() InstallLayout {
	root := filepath.Join(p.DataDir, "core")
	return InstallLayout{
		Root:         root,
		VersionsDir:  filepath.Join(root, "versions"),
		CurrentFile:  filepath.Join(root, "current"),
		PreviousFile: filepath.Join(root, "previous"),
		StagingDir:   filepath.Join(root, "staging"),

		StateDatabase: filepath.Join(p.DataDir, "state.db"),
		BundlesDir:    filepath.Join(p.DataDir, "bundles"),
		ReportsDir:    filepath.Join(p.DataDir, "reports"),
		QuarantineDir: filepath.Join(p.DataDir, "quarantine"),
		PolicyFile:    filepath.Join(p.DataDir, "policy.json"),
	}
}

// installVersionPattern mirrors scripts/build-darwin.sh exactly: an exact
// v-prefixed release tag over a safe character set, or the committed-revision
// fallback. \A…\z rather than ^…$ so a trailing newline cannot slip through.
// Nothing else can name a version directory, so no supplied version can
// traverse, hide, or collide.
var installVersionPattern = regexp.MustCompile(`\A(v[0-9][0-9A-Za-z.+-]*|dev\+git\.[0-9a-f]{40})\z`)

// ValidInstallVersion reports whether version is a version string the release
// build can produce and is therefore safe to use as a single path element.
func ValidInstallVersion(version string) bool {
	return len(version) <= 64 && installVersionPattern.MatchString(version)
}

// VersionDir returns the directory holding one installed core version. A
// version that the release build cannot produce never becomes a path.
func (l InstallLayout) VersionDir(version string) (string, error) {
	if !ValidInstallVersion(version) {
		return "", errors.New("unsupported core version")
	}
	return filepath.Join(l.VersionsDir, version), nil
}

// RedactHome replaces a leading home path only when it ends at a path boundary.
func RedactHome(home, value string) string {
	if home == "" {
		return value
	}

	home = strings.TrimRight(home, string(filepath.Separator))
	if home == "" {
		home = string(filepath.Separator)
	}
	if value == home {
		return "$HOME"
	}
	if home == string(filepath.Separator) && strings.HasPrefix(value, home) {
		return "$HOME" + value
	}
	if strings.HasPrefix(value, home) && len(value) > len(home) && value[len(home)] == filepath.Separator {
		return "$HOME" + value[len(home):]
	}
	return value
}
