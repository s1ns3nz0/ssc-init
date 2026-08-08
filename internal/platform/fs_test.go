package platform

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOSFileSystemProvidesRootedReadBoundary(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "configs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "configs", "mcp.json"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "configs"), filepath.Join(home, "linked")); err != nil {
		t.Fatal(err)
	}

	filesystem, ok := any(OSFileSystem{}).(RootedFileSystem)
	if !ok {
		t.Fatal("OSFileSystem does not provide rooted reads")
	}
	noFollow, ok := any(OSFileSystem{}).(NoFollowFileSystem)
	if !ok {
		t.Fatal("OSFileSystem does not provide no-follow observations")
	}
	linkedFromHost, err := noFollow.Lstat(filepath.Join(home, "linked"))
	if err != nil {
		t.Fatal(err)
	}
	if linkedFromHost.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("host no-follow mode=%v", linkedFromHost.Mode())
	}
	root, err := filesystem.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	linked, err := root.Lstat("linked")
	if err != nil {
		t.Fatal(err)
	}
	if linked.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("mode=%v", linked.Mode())
	}
	if _, err := OpenVerifiedRoot(context.Background(), root, "linked"); !errors.Is(err, ErrUnsafeRootedPath) {
		t.Fatalf("symlink error=%v", err)
	}
	configs, err := OpenVerifiedRoot(context.Background(), root, "configs")
	if err != nil {
		t.Fatal(err)
	}
	defer configs.Close()
	file, _, _, err := OpenVerifiedFile(configs, "mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "safe" {
		t.Fatalf("contents=%q", contents)
	}
}

func TestOSRootedDirectoryReadlinkDoesNotResolveTarget(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "secret"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := (OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	got, err := root.Readlink("link")
	if err != nil {
		t.Fatal(err)
	}
	if got != "secret" {
		t.Fatalf("target=%q", got)
	}
}

func TestOSRootedDirectoryReadlinkRejectsInvalidComponent(t *testing.T) {
	root, err := (OSFileSystem{}).OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, name := range []string{"nested/link", "link\x00"} {
		if _, err := root.Readlink(name); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("name=%q error=%v", name, err)
		}
	}
}

func TestOSRootedFileReportsLocalFilesystem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("local filesystem classification is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "file"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := (OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	file, err := root.Open("file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	localFile, ok := file.(LocalRootedFile)
	if !ok {
		t.Fatal("opened file does not report filesystem locality")
	}
	local, known := localFile.LocalFilesystem()
	if !known || !local {
		t.Fatalf("local=%t known=%t", local, known)
	}
}
