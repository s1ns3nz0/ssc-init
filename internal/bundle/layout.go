package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrLayout = errors.New("bundle layout is unavailable")

type Layout struct {
	Home          string
	Root          string
	VersionsDir   string
	StagingDir    string
	CurrentFile   string
	PreviousFile  string
	HighWaterFile string
}

func LayoutFor(home string, family Family) (Layout, error) {
	if !validFamily(family) || home == "" || !filepath.IsAbs(home) {
		return Layout{}, ErrLayout
	}
	root := filepath.Join(home, "Library", "Application Support", "SSC Init", "bundles", string(family))
	return Layout{
		Home: home, Root: root, VersionsDir: filepath.Join(root, "versions"), StagingDir: filepath.Join(root, "staging"),
		CurrentFile: filepath.Join(root, "current"), PreviousFile: filepath.Join(root, "previous"), HighWaterFile: filepath.Join(root, "highest-sequence"),
	}, nil
}

func (l Layout) VersionDir(sequence uint64) string {
	return filepath.Join(l.VersionsDir, fmt.Sprintf("%d", sequence))
}

func (l Layout) Initialize() error {
	if l.Home == "" || !filepath.IsAbs(l.Home) {
		return ErrLayout
	}
	info, err := os.Lstat(l.Home)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrLayout
	}
	relative, err := filepath.Rel(l.Home, l.Root)
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) {
		return ErrLayout
	}
	current := l.Home
	for _, component := range splitPath(relative) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return ErrLayout
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrLayout
		}
	}
	for _, directory := range []string{l.VersionsDir, l.StagingDir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
			return ErrLayout
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrLayout
		}
	}
	return nil
}

func splitPath(value string) []string {
	var components []string
	for value != "." && value != "" {
		directory, base := filepath.Split(value)
		if base != "" {
			components = append([]string{base}, components...)
		}
		value = filepath.Clean(directory)
		if value == string(filepath.Separator) {
			break
		}
	}
	return components
}
