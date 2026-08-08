package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
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

			ctx := context.WithValue(context.Background(), afterOpenFileContextKey{}, func() { testCase.mutate(t, path) })

			got, status, errs := HashVerifiedFile(ctx, root, "payload", 64)
			if got != (FileDigest{}) || status != model.EvidenceUnavailable || len(errs) != 1 || errs[0].Code != "identity_changed" {
				t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
			}
		})
	}
}

func TestHashVerifiedFileScopesAfterOpenMutationToContext(t *testing.T) {
	type hashResult struct {
		digest FileDigest
		status model.EvidenceStatus
		errs   []model.EvidenceError
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan hashResult, 2)
	mutationErrors := make(chan error, 2)

	for _, name := range []string{"first", "second"} {
		rootPath := t.TempDir()
		path := filepath.Join(rootPath, "payload")
		if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })

		ctx := context.WithValue(context.Background(), afterOpenFileContextKey{}, func() {
			ready <- struct{}{}
			<-release
			mutationErrors <- os.Truncate(path, int64(len(name)))
		})
		go func() {
			digest, status, errs := HashVerifiedFile(ctx, root, "payload", 64)
			results <- hashResult{digest: digest, status: status, errs: errs}
		}()
	}

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range 2 {
		select {
		case <-ready:
		case <-timer.C:
			close(release)
			t.Fatal("concurrent hash did not reach its context-scoped after-open hook")
		}
	}
	close(release)
	for range 2 {
		if err := <-mutationErrors; err != nil {
			t.Fatal(err)
		}
		result := <-results
		if result.digest != (FileDigest{}) || result.status != model.EvidenceUnavailable || len(result.errs) != 1 || result.errs[0].Code != "identity_changed" {
			t.Fatalf("got=%+v status=%s errors=%+v", result.digest, result.status, result.errs)
		}
	}
}
