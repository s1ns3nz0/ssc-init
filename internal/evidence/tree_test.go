package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestHashTreeChangesForContentAndStructure(t *testing.T) {
	rootPath := t.TempDir()
	writeTreeFile(t, rootPath, "a/main.js", "one", 0o600)
	first := hashTreeFixture(t, rootPath, DefaultTreeLimits)
	writeTreeFile(t, rootPath, "a/main.js", "two", 0o600)
	if second := hashTreeFixture(t, rootPath, DefaultTreeLimits); first.Digest == second.Digest {
		t.Fatal("byte mutation did not change tree")
	}

	writeTreeFile(t, rootPath, "added", "x", 0o600)
	if second := hashTreeFixture(t, rootPath, DefaultTreeLimits); first.Digest == second.Digest {
		t.Fatal("add did not change tree")
	}
	if err := os.Remove(filepath.Join(rootPath, "added")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rootPath, "a/main.js"), filepath.Join(rootPath, "a/renamed.js")); err != nil {
		t.Fatal(err)
	}
	if second := hashTreeFixture(t, rootPath, DefaultTreeLimits); first.Digest == second.Digest {
		t.Fatal("rename did not change tree")
	}
	if err := os.Chmod(filepath.Join(rootPath, "a/renamed.js"), 0o700); err != nil {
		t.Fatal(err)
	}
	if third := hashTreeFixture(t, rootPath, DefaultTreeLimits); third.Digest == first.Digest {
		t.Fatal("permission change did not change tree")
	}
}

func TestHashTreeChangesForEntryType(t *testing.T) {
	fileRoot := t.TempDir()
	writeTreeFile(t, fileRoot, "entry", "x", 0o600)
	directoryRoot := t.TempDir()
	writeTreeFile(t, directoryRoot, "entry/child", "x", 0o600)
	if fileTree, directoryTree := hashTreeFixture(t, fileRoot, DefaultTreeLimits), hashTreeFixture(t, directoryRoot, DefaultTreeLimits); fileTree.Digest == directoryTree.Digest {
		t.Fatal("file and directory entries produced the same tree")
	}
}

func TestHashTreeDoesNotFollowSymlinkAndHashesTarget(t *testing.T) {
	rootPath := t.TempDir()
	outside := filepath.Join(t.TempDir(), "real-home-marker")
	writeTreeFile(t, filepath.Dir(outside), filepath.Base(outside), "must-not-read", 0o600)
	if err := os.Symlink(outside, filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	got, status, errs := hashTreeRaw(t, rootPath, DefaultTreeLimits)
	if status != model.EvidencePartial || got.Symlinks != 1 || !hasTreeError(errs, "symlink_rejected") {
		t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
	}
	if err := os.Remove(filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("another-target", filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	changed, changedStatus, changedErrors := hashTreeRaw(t, rootPath, DefaultTreeLimits)
	if changedStatus != model.EvidencePartial || !hasTreeError(changedErrors, "symlink_rejected") || got.Digest == changed.Digest {
		t.Fatal("link target did not change tree")
	}
}

func TestHashTreeMarksSpecialFilesPartial(t *testing.T) {
	rootPath := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(rootPath, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	got, status, errs := hashTreeRaw(t, rootPath, DefaultTreeLimits)
	if status != model.EvidencePartial || !hasTreeError(errs, "special_file_rejected") || got.Files != 0 {
		t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
	}
}

func TestTreeLimitBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*testing.T, string)
		limits TreeLimits
		code   string
	}{
		{"depth", func(t *testing.T, root string) { writeTreeFile(t, root, "a/b/file", "x", 0o600) }, TreeLimits{MaxDepth: 1, MaxEntries: 10, MaxFileBytes: 10, MaxTotalBytes: 10, MaxErrors: 10, Timeout: time.Second}, "depth_limit"},
		{"entries", func(t *testing.T, root string) {
			writeTreeFile(t, root, "a", "x", 0o600)
			writeTreeFile(t, root, "b", "x", 0o600)
		}, TreeLimits{MaxDepth: 10, MaxEntries: 1, MaxFileBytes: 10, MaxTotalBytes: 10, MaxErrors: 10, Timeout: time.Second}, "file_limit"},
		{"file-bytes", func(t *testing.T, root string) { writeTreeFile(t, root, "a", "12", 0o600) }, TreeLimits{MaxDepth: 10, MaxEntries: 10, MaxFileBytes: 1, MaxTotalBytes: 10, MaxErrors: 10, Timeout: time.Second}, "byte_limit"},
		{"total-bytes", func(t *testing.T, root string) { writeTreeFile(t, root, "a", "12", 0o600) }, TreeLimits{MaxDepth: 10, MaxEntries: 10, MaxFileBytes: 2, MaxTotalBytes: 1, MaxErrors: 10, Timeout: time.Second}, "byte_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootPath := t.TempDir()
			tc.setup(t, rootPath)
			_, status, errs := hashTreeRaw(t, rootPath, tc.limits)
			if status != model.EvidenceOversize || !hasTreeError(errs, tc.code) {
				t.Fatalf("status=%s errors=%+v", status, errs)
			}
		})
	}
}

func TestTreeLimitExactBoundariesAreComplete(t *testing.T) {
	rootPath := t.TempDir()
	writeTreeFile(t, rootPath, "a", "12", 0o600)
	limits := TreeLimits{MaxDepth: 0, MaxEntries: 1, MaxFileBytes: 2, MaxTotalBytes: 2, MaxErrors: 1, Timeout: time.Second}
	_, status, errs := hashTreeRaw(t, rootPath, limits)
	if status != model.EvidenceComplete || len(errs) != 0 {
		t.Fatalf("status=%s errors=%+v", status, errs)
	}
}

func TestHashTreeRejectsInvalidNamesAndStopsAtErrorLimit(t *testing.T) {
	rootPath := t.TempDir()
	writeTreeFile(t, rootPath, "one", "x", 0o600)
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	invalid := invalidNameRoot{RootedDirectory: root}
	_, status, errs, _ := HashTree(context.Background(), invalid, "", TreeLimits{MaxDepth: 2, MaxEntries: 4, MaxFileBytes: 10, MaxTotalBytes: 10, MaxErrors: 1, Timeout: time.Second}, nil)
	if status != model.EvidencePartial || !hasTreeError(errs, "path_invalid") || len(errs) != 1 {
		t.Fatalf("status=%s errors=%+v", status, errs)
	}
}

func TestTreeErrorLimitIsAnOversizeBoundary(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Symlink("one", filepath.Join(rootPath, "one")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("two", filepath.Join(rootPath, "two")); err != nil {
		t.Fatal(err)
	}
	limits := TreeLimits{MaxDepth: 2, MaxEntries: 4, MaxFileBytes: 10, MaxTotalBytes: 10, MaxErrors: 1, Timeout: time.Second}
	_, status, errs := hashTreeRaw(t, rootPath, limits)
	if status != model.EvidenceOversize || len(errs) != 1 || !hasTreeError(errs, "symlink_rejected") {
		t.Fatalf("status=%s errors=%+v", status, errs)
	}
}

func TestHashTreeIsDeterministicForRawAndUnicodeNames(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, string([]byte{'x', 0xff})), []byte("one"), 0o600); err != nil && !errors.Is(err, syscall.EILSEQ) {
		t.Fatal(err)
	}
	writeTreeFile(t, rootPath, "e\u0301", "two", 0o600)
	first := hashTreeFixture(t, rootPath, DefaultTreeLimits)
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	second, status, errs, _ := HashTree(context.Background(), reversedReadRoot{RootedDirectory: root}, "", DefaultTreeLimits, nil)
	if status != model.EvidenceComplete || len(errs) != 0 || first.Digest != second.Digest {
		t.Fatalf("first=%+v second=%+v status=%s errors=%+v", first, second, status, errs)
	}
}

func TestHashTreeHonorsCancellationAndDeadline(t *testing.T) {
	rootPath := t.TempDir()
	writeTreeFile(t, rootPath, "a", "x", 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, status, errs := hashTreeRawContext(t, ctx, rootPath, DefaultTreeLimits)
	if status != model.EvidencePartial || !hasTreeError(errs, "time_limit") {
		t.Fatalf("status=%s errors=%+v", status, errs)
	}
	_, status, errs = hashTreeRawContext(t, context.Background(), rootPath, TreeLimits{MaxDepth: 2, MaxEntries: 2, MaxFileBytes: 10, MaxTotalBytes: 10, MaxErrors: 2, Timeout: -time.Second})
	if status != model.EvidencePartial || !hasTreeError(errs, "time_limit") {
		t.Fatalf("status=%s errors=%+v", status, errs)
	}
}

func TestTreeRaceHashesIndependentRoots(t *testing.T) {
	results := make(chan TreeDigest, 2)
	for _, content := range []string{"first", "second"} {
		rootPath := t.TempDir()
		writeTreeFile(t, rootPath, "a", content, 0o600)
		go func() { results <- hashTreeFixture(t, rootPath, DefaultTreeLimits) }()
	}
	if first, second := <-results, <-results; first.Digest == second.Digest {
		t.Fatal("independent trees unexpectedly matched")
	}
}

func hashTreeFixture(t *testing.T, rootPath string, limits TreeLimits) TreeDigest {
	t.Helper()
	got, status, errs := hashTreeRaw(t, rootPath, limits)
	if status != model.EvidenceComplete || len(errs) != 0 {
		t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
	}
	return got
}
func hashTreeRaw(t *testing.T, rootPath string, limits TreeLimits) (TreeDigest, model.EvidenceStatus, []model.EvidenceError) {
	return hashTreeRawContext(t, context.Background(), rootPath, limits)
}
func hashTreeRawContext(t *testing.T, ctx context.Context, rootPath string, limits TreeLimits) (TreeDigest, model.EvidenceStatus, []model.EvidenceError) {
	t.Helper()
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, status, errs, _ := HashTree(ctx, root, "", limits, nil)
	return got, status, errs
}
func writeTreeFile(t *testing.T, root, name, contents string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
func hasTreeError(errs []model.EvidenceError, code string) bool {
	for _, err := range errs {
		if err.Code == code {
			return true
		}
	}
	return false
}

type invalidNameRoot struct{ platform.RootedDirectory }

func (r invalidNameRoot) Open(name string) (platform.RootedFile, error) {
	if name == "." {
		return &invalidNameFile{RootedFile: mustOpenRootedFile(r.RootedDirectory, name)}, nil
	}
	return r.RootedDirectory.Open(name)
}

type invalidNameFile struct{ platform.RootedFile }

func (f *invalidNameFile) ReadDir(n int) ([]os.DirEntry, error) {
	return []os.DirEntry{invalidEntry{}}, nil
}

type invalidEntry struct{}

func (invalidEntry) Name() string               { return "../bad" }
func (invalidEntry) IsDir() bool                { return false }
func (invalidEntry) Type() os.FileMode          { return 0 }
func (invalidEntry) Info() (os.FileInfo, error) { return nil, errors.New("not used") }
func mustOpenRootedFile(root platform.RootedDirectory, name string) platform.RootedFile {
	f, err := root.Open(name)
	if err != nil {
		panic(err)
	}
	return f
}

type reversedReadRoot struct{ platform.RootedDirectory }

func (r reversedReadRoot) Open(name string) (platform.RootedFile, error) {
	f, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	return &reversedReadFile{RootedFile: f}, nil
}

type reversedReadFile struct{ platform.RootedFile }

func (f *reversedReadFile) ReadDir(n int) ([]os.DirEntry, error) {
	entries, err := f.RootedFile.ReadDir(n)
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	return entries, err
}
