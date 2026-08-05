package platform

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsafeRootedPath indicates that a rooted path was symlinked, swapped, or
// otherwise failed identity validation.
var ErrUnsafeRootedPath = errors.New("unsafe rooted path")

// OpenVerifiedRoot opens directory components relative to root without
// following symlinks and verifies each opened directory's identity.
func OpenVerifiedRoot(ctx context.Context, root RootedDirectory, components ...string) (RootedDirectory, error) {
	if len(components) == 0 {
		return nil, ErrUnsafeRootedPath
	}
	current := root
	owned := false
	closeOwned := func() {
		if owned {
			_ = current.Close()
		}
	}

	for _, component := range components {
		if err := ctx.Err(); err != nil {
			closeOwned()
			return nil, err
		}
		if !validRootComponent(component) {
			closeOwned()
			return nil, ErrUnsafeRootedPath
		}
		expected, err := current.Lstat(component)
		if err != nil {
			closeOwned()
			return nil, err
		}
		if expected == nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
			closeOwned()
			return nil, ErrUnsafeRootedPath
		}
		child, err := current.OpenRoot(component)
		if err != nil {
			closeOwned()
			return nil, err
		}
		opened, err := child.Lstat(".")
		if err != nil || opened == nil || !os.SameFile(expected, opened) {
			_ = child.Close()
			closeOwned()
			return nil, ErrUnsafeRootedPath
		}
		if owned {
			_ = current.Close()
		}
		current = child
		owned = true
	}
	return current, nil
}

// OpenVerifiedFile opens a regular file relative to root and verifies that the
// opened descriptor has the identity established by Lstat.
func OpenVerifiedFile(root RootedDirectory, name string) (RootedFile, os.FileInfo, os.FileInfo, error) {
	if !validRootComponent(name) {
		return nil, nil, nil, ErrUnsafeRootedPath
	}
	expected, err := root.Lstat(name)
	if err != nil {
		return nil, nil, nil, err
	}
	if expected == nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return nil, nil, nil, ErrUnsafeRootedPath
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || opened == nil || !os.SameFile(expected, opened) {
		_ = file.Close()
		return nil, nil, nil, ErrUnsafeRootedPath
	}
	return file, expected, opened, nil
}

// OpenVerifiedDirectory opens the current rooted directory for enumeration and
// verifies that the returned descriptor has the same identity.
func OpenVerifiedDirectory(root RootedDirectory) (RootedFile, error) {
	expected, err := root.Lstat(".")
	if err != nil {
		return nil, err
	}
	if expected == nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
		return nil, ErrUnsafeRootedPath
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	opened, err := directory.Stat()
	if err != nil || opened == nil || !os.SameFile(expected, opened) {
		_ = directory.Close()
		return nil, ErrUnsafeRootedPath
	}
	return directory, nil
}

func validRootComponent(component string) bool {
	return component != "" && component != "." && component != ".." &&
		filepath.Base(component) == component && !strings.ContainsRune(component, filepath.Separator)
}
