// Package platform contains adapters for operating-system access.
package platform

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// FileSystem is the read-only filesystem boundary used by collectors.
type FileSystem interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]os.DirEntry, error)
	Stat(name string) (os.FileInfo, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
}

// RootedFileSystem is an optional read boundary for collectors that must keep
// traversal anchored to an already-open directory.
type RootedFileSystem interface {
	OpenRoot(name string) (RootedDirectory, error)
}

// RootedDirectory exposes only fd-anchored operations needed by collectors.
type RootedDirectory interface {
	Lstat(name string) (os.FileInfo, error)
	OpenRoot(name string) (RootedDirectory, error)
	Open(name string) (RootedFile, error)
	Close() error
}

// RootedFile is an already-open file or directory descriptor.
type RootedFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	ReadDir(n int) ([]os.DirEntry, error)
	Close() error
}

// OSFileSystem implements FileSystem using the host operating system.
type OSFileSystem struct{}

type osRootedDirectory struct {
	root *os.Root
}

func (OSFileSystem) OpenRoot(name string) (RootedDirectory, error) {
	expected, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if expected == nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
		return nil, ErrUnsafeRootedPath
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := root.Lstat(".")
	if err != nil || opened == nil || !os.SameFile(expected, opened) {
		_ = root.Close()
		return nil, ErrUnsafeRootedPath
	}
	return &osRootedDirectory{root: root}, nil
}

func (r *osRootedDirectory) Lstat(name string) (os.FileInfo, error) {
	return r.root.Lstat(name)
}

func (r *osRootedDirectory) OpenRoot(name string) (RootedDirectory, error) {
	root, err := r.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &osRootedDirectory{root: root}, nil
}

func (r *osRootedDirectory) Open(name string) (RootedFile, error) {
	return r.root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}

func (r *osRootedDirectory) Close() error {
	return r.root.Close()
}

func (OSFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (OSFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	return os.ReadDir(name)
}

func (OSFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (OSFileSystem) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}
