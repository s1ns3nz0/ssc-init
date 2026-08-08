package inventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

func TestHashFileHashesCompleteFile(t *testing.T) {
	path := filepath.Join(canonicalTempDir(t), "artifact")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	digest, status, err := HashFile(context.Background(), platform.OSFileSystem{}, path, 6)
	want := sha256.Sum256([]byte("abcdef"))
	if err != nil || status != model.HashComplete || digest != "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721" {
		t.Fatalf("digest=%q want=%x status=%s err=%v", digest, want, status, err)
	}
}

func TestHashFileHashesEmptyFile(t *testing.T) {
	path := filepath.Join(canonicalTempDir(t), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	digest, status, err := HashFile(context.Background(), platform.OSFileSystem{}, path, 1)
	if err != nil || status != model.HashComplete || digest != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("digest=%q status=%s err=%v", digest, status, err)
	}
}

func TestHashFileReadsAtMostLimitPlusOneAndReportsOversize(t *testing.T) {
	path := filepath.Join(canonicalTempDir(t), "artifact")
	if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	tracked := &trackingFileSystem{FileSystem: platform.OSFileSystem{}}

	digest, status, err := HashFile(context.Background(), tracked, path, 4)
	if err != nil || status != model.HashOversize || digest != "" {
		t.Fatalf("digest=%q status=%s err=%v", digest, status, err)
	}
	if tracked.bytesRead != 5 {
		t.Fatalf("bytes read=%d want=5", tracked.bytesRead)
	}
	if tracked.rootCloses != tracked.rootsOpened || tracked.fileCloses != 1 {
		t.Fatalf("roots opened=%d closed=%d; files closed=%d", tracked.rootsOpened, tracked.rootCloses, tracked.fileCloses)
	}
}

func TestHashFileRejectsInvalidLimits(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		limit int64
	}{{name: "negative", limit: -1}, {name: "zero", limit: 0}} {
		t.Run(testCase.name, func(t *testing.T) {
			limit := testCase.limit
			_, status, err := HashFile(context.Background(), platform.OSFileSystem{}, "unused", limit)
			if err == nil || status != model.HashUnavailable {
				t.Fatalf("limit=%d status=%s err=%v", limit, status, err)
			}
		})
	}
}

func TestHashFileRejectsSymlink(t *testing.T) {
	directory := canonicalTempDir(t)
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, status, err := HashFile(context.Background(), platform.OSFileSystem{}, link, 20)
	if !errors.Is(err, platform.ErrUnsafeRootedPath) || status != model.HashUnavailable {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestHashFileRejectsIntermediateParentSymlink(t *testing.T) {
	directory := canonicalTempDir(t)
	realParent := filepath.Join(directory, "real-parent")
	if err := os.MkdirAll(filepath.Join(realParent, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realParent, "child", "artifact"), []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}

	_, status, err := HashFile(context.Background(), platform.OSFileSystem{}, filepath.Join(linkedParent, "child", "artifact"), 20)
	if !errors.Is(err, platform.ErrUnsafeRootedPath) || status != model.HashUnavailable {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestHashFileRejectsIdentitySwap(t *testing.T) {
	directory := canonicalTempDir(t)
	target := filepath.Join(directory, "target")
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(target, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	filesystem := &swapFileSystem{FileSystem: platform.OSFileSystem{}, replacement: filepath.Base(replacement)}

	_, status, err := HashFile(context.Background(), filesystem, target, 20)
	if !errors.Is(err, platform.ErrUnsafeRootedPath) || status != model.HashUnavailable {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestHashFileRejectsIntermediateParentIdentitySwap(t *testing.T) {
	directory := canonicalTempDir(t)
	expectedName := "expected-parent-ssc"
	replacementName := "replacement-parent-ssc"
	expectedParent := filepath.Join(directory, expectedName)
	replacementParent := filepath.Join(directory, replacementName)
	for _, parent := range []string{expectedParent, replacementParent} {
		if err := os.MkdirAll(filepath.Join(parent, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, "child", "artifact"), []byte("abcdef"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	filesystem := &parentSwapFileSystem{
		FileSystem:      platform.OSFileSystem{},
		expectedName:    expectedName,
		replacementName: replacementName,
	}

	_, status, err := HashFile(context.Background(), filesystem, filepath.Join(expectedParent, "child", "artifact"), 20)
	if !errors.Is(err, platform.ErrUnsafeRootedPath) || status != model.HashUnavailable {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

func TestHashFileFailsClosedWithoutRootedBoundary(t *testing.T) {
	filesystem := &unrootedFileSystem{}
	_, status, err := HashFile(context.Background(), filesystem, "artifact", 20)
	if err == nil || status != model.HashUnavailable || filesystem.readFileCalled {
		t.Fatalf("status=%s err=%v readFileCalled=%t", status, err, filesystem.readFileCalled)
	}
}

func TestHashFileChecksCancellationWhileReading(t *testing.T) {
	path := filepath.Join(canonicalTempDir(t), "artifact")
	if err := os.WriteFile(path, make([]byte, 128*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	filesystem := &trackingFileSystem{FileSystem: platform.OSFileSystem{}, cancelAfterRead: cancel}

	_, status, err := HashFile(ctx, filesystem, path, 128*1024)
	if !errors.Is(err, context.Canceled) || status != model.HashUnavailable {
		t.Fatalf("status=%s err=%v", status, err)
	}
}

type trackingFileSystem struct {
	platform.FileSystem
	bytesRead       int64
	cancelAfterRead context.CancelFunc
	rootsOpened     int
	rootCloses      int
	fileCloses      int
}

func (f *trackingFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := platform.OSFileSystem{}.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	f.rootsOpened++
	return &trackingRoot{RootedDirectory: root, filesystem: f}, nil
}

type trackingRoot struct {
	platform.RootedDirectory
	filesystem *trackingFileSystem
}

func (r *trackingRoot) Close() error {
	r.filesystem.rootCloses++
	return r.RootedDirectory.Close()
}

func (r *trackingRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	r.filesystem.rootsOpened++
	return &trackingRoot{RootedDirectory: root, filesystem: r.filesystem}, nil
}

func (r *trackingRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	return &trackingFile{RootedFile: file, filesystem: r.filesystem}, nil
}

type trackingFile struct {
	platform.RootedFile
	filesystem *trackingFileSystem
}

func (f *trackingFile) Close() error {
	f.filesystem.fileCloses++
	return f.RootedFile.Close()
}

func (f *trackingFile) Read(buffer []byte) (int, error) {
	n, err := f.RootedFile.Read(buffer)
	f.filesystem.bytesRead += int64(n)
	if n > 0 && f.filesystem.cancelAfterRead != nil {
		f.filesystem.cancelAfterRead()
		f.filesystem.cancelAfterRead = nil
	}
	return n, err
}

type unrootedFileSystem struct {
	readFileCalled bool
}

func (f *unrootedFileSystem) ReadFile(string) ([]byte, error) {
	f.readFileCalled = true
	return nil, errors.New("unexpected ReadFile")
}

func (*unrootedFileSystem) ReadDir(string) ([]os.DirEntry, error) { return nil, fs.ErrNotExist }
func (*unrootedFileSystem) Stat(string) (os.FileInfo, error)      { return nil, fs.ErrNotExist }
func (*unrootedFileSystem) WalkDir(string, fs.WalkDirFunc) error  { return fs.ErrNotExist }

type swapFileSystem struct {
	platform.FileSystem
	replacement string
}

func (f *swapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := platform.OSFileSystem{}.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &swapRoot{RootedDirectory: root, replacement: f.replacement}, nil
}

type swapRoot struct {
	platform.RootedDirectory
	replacement string
}

func (r *swapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &swapRoot{RootedDirectory: root, replacement: r.replacement}, nil
}

func (r *swapRoot) Open(string) (platform.RootedFile, error) {
	return r.RootedDirectory.Open(r.replacement)
}

type parentSwapFileSystem struct {
	platform.FileSystem
	expectedName    string
	replacementName string
}

func (f *parentSwapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := platform.OSFileSystem{}.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	volumeRoot := filepath.VolumeName(name) + string(filepath.Separator)
	if name != volumeRoot {
		return root, nil
	}
	return &parentSwapRoot{RootedDirectory: root, expectedName: f.expectedName, replacementName: f.replacementName}, nil
}

type parentSwapRoot struct {
	platform.RootedDirectory
	expectedName    string
	replacementName string
}

func (r *parentSwapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	openedName := name
	if name == r.expectedName {
		openedName = r.replacementName
	}
	root, err := r.RootedDirectory.OpenRoot(openedName)
	if err != nil {
		return nil, err
	}
	return &parentSwapRoot{RootedDirectory: root, expectedName: r.expectedName, replacementName: r.replacementName}, nil
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

var _ io.Reader = (*trackingFile)(nil)
