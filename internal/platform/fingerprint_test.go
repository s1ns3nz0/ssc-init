package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFingerprintChangesWhenCTimeChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	before, ok := Fingerprint(beforeInfo)
	if runtime.GOOS == "darwin" && !ok {
		t.Fatal("Darwin fingerprint unavailable")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := Fingerprint(afterInfo)
	if runtime.GOOS == "darwin" && before == after {
		t.Fatal("fingerprint did not change")
	}
}
