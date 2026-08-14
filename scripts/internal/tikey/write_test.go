package tikey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePrivateExclusiveRejectsSynchronizedAncestorSwap(t *testing.T) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(userHome, ".ssc-ti-ancestor-swap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	original := filepath.Join(root, "writable", "a")
	if err := os.MkdirAll(filepath.Join(original, "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	attacker := filepath.Join(root, "attacker", "tree")
	if err := os.MkdirAll(filepath.Join(attacker, "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(original, "b", "private.key")
	moved := filepath.Join(root, "writable", "a-original")
	err = WritePrivateExclusive(target, bytes.Repeat([]byte{7}, 64), func() {
		if renameErr := os.Rename(original, moved); renameErr != nil {
			t.Fatal(renameErr)
		}
		if linkErr := os.Symlink(attacker, original); linkErr != nil {
			t.Fatal(linkErr)
		}
	})
	if err == nil {
		t.Fatal("ancestor swap was accepted")
	}
	for _, path := range []string{filepath.Join(attacker, "b", "private.key"), filepath.Join(moved, "b", "private.key")} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("private key written during ancestor swap: %s err=%v", path, statErr)
		}
	}
}

func TestWritePrivateExclusiveRejectsFinalLinksAndCleansFailedCreate(t *testing.T) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(userHome, ".ssc-ti-final-link-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	victim := filepath.Join(root, "victim")
	link := filepath.Join(root, "private.key")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateExclusive(link, bytes.Repeat([]byte{3}, 64), nil); err == nil {
		t.Fatal("dangling final symlink accepted")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("victim modified: %v", err)
	}
}
