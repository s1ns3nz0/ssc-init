package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestHashVerifiedFileHonorsExactLimit(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "payload"), []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	got, status, errs := HashVerifiedFile(context.Background(), root, "payload", 4)
	want := sha256.Sum256([]byte("abcd"))
	if status != model.EvidenceComplete || len(errs) != 0 || got.SHA256 != hex.EncodeToString(want[:]) || got.Size != 4 {
		t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
	}
}

func TestHashVerifiedFileRejectsFinalSymlink(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "target"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	got, status, errs := HashVerifiedFile(context.Background(), root, "link", 4)
	if got.SHA256 != "" || status != model.EvidenceUnavailable || len(errs) != 1 || errs[0].Code != "symlink_rejected" {
		t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
	}
}

func TestHashVerifiedFileRejectsAfterOpenChanges(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{
			name: "replacement",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				replacement := path + ".replacement"
				if err := os.WriteFile(replacement, []byte("replaced"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncation",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Truncate(path, 1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "append",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if _, err := file.WriteString("+"); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rootPath := t.TempDir()
			path := filepath.Join(rootPath, "payload")
			if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			afterOpenFile = func() { testCase.mutate(t, path) }
			t.Cleanup(func() { afterOpenFile = nil })

			got, status, errs := HashVerifiedFile(context.Background(), root, "payload", 64)
			if got != (FileDigest{}) || status != model.EvidenceUnavailable || len(errs) != 1 || errs[0].Code != "identity_changed" {
				t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
			}
		})
	}
}
