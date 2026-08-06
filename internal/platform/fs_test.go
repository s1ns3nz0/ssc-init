package platform

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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
