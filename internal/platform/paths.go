package platform

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
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
