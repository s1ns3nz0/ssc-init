package platform

import (
	"path/filepath"
	"strings"
)

// Paths identifies the macOS locations owned by SSC Init for one home directory.
type Paths struct {
	Home    string
	DataDir string
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
