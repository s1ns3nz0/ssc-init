// Package evidence provides bounded, descriptor-anchored content evidence.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

// FileDigest is content evidence produced from one verified regular file.
type FileDigest struct {
	SHA256      string
	Size        int64
	Fingerprint platform.FileFingerprint
}

var fixedFileErrors = map[string]model.EvidenceError{
	"identity": {Code: "identity_changed", Message: "evidence file identity changed"},
	"symlink":  {Code: "symlink_rejected", Message: "symbolic link was not followed"},
	"oversize": {Code: "byte_limit", Message: "evidence file exceeds the byte limit"},
	"read":     {Code: "read_unavailable", Message: "evidence file is unavailable"},
}

// afterOpenFile is a deterministic test seam for mutations between opening and
// hashing. Production leaves it nil.
var afterOpenFile func()

// HashVerifiedFile hashes a regular file relative to root without following
// symbolic links. It returns evidence only if the file identity remains stable
// throughout the read.
func HashVerifiedFile(ctx context.Context, root platform.RootedDirectory, relativePath string, maxBytes int64) (FileDigest, model.EvidenceStatus, []model.EvidenceError) {
	if root == nil || maxBytes <= 0 || maxBytes == math.MaxInt64 || ctx.Err() != nil {
		return unavailableFile("read")
	}
	components, ok := filePathComponents(relativePath)
	if !ok {
		return unavailableFile("symlink")
	}

	parent := root
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			return unavailableForOpen(err)
		}
		defer parent.Close()
	}
	if err := ctx.Err(); err != nil {
		return unavailableFile("read")
	}

	file, expected, opened, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil {
		return unavailableForOpen(err)
	}
	defer file.Close()
	before, ok := platform.Fingerprint(opened)
	if !ok {
		return unavailableFile("read")
	}
	if afterOpenFile != nil {
		afterOpenFile()
	}

	hasher := sha256.New()
	count, err := io.Copy(hasher, &io.LimitedReader{R: &fileContextReader{ctx: ctx, reader: file}, N: maxBytes + 1})
	if err != nil || ctx.Err() != nil {
		return unavailableFile("read")
	}
	if count > maxBytes {
		return FileDigest{}, model.EvidenceOversize, []model.EvidenceError{fixedFileErrors["oversize"]}
	}

	postRead, err := file.Stat()
	if err != nil {
		return unavailableFile("read")
	}
	postName, err := parent.Lstat(components[len(components)-1])
	if err != nil || postName == nil || !os.SameFile(expected, postName) {
		return unavailableFile("identity")
	}
	after, ok := platform.Fingerprint(postRead)
	if !ok || before != after || postRead.Size() != opened.Size() || postRead.Size() != count {
		return unavailableFile("identity")
	}
	return FileDigest{SHA256: hex.EncodeToString(hasher.Sum(nil)), Size: count, Fingerprint: before}, model.EvidenceComplete, nil
}

func unavailableForOpen(err error) (FileDigest, model.EvidenceStatus, []model.EvidenceError) {
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		return unavailableFile("symlink")
	}
	return unavailableFile("read")
}

func unavailableFile(kind string) (FileDigest, model.EvidenceStatus, []model.EvidenceError) {
	return FileDigest{}, model.EvidenceUnavailable, []model.EvidenceError{fixedFileErrors[kind]}
}

func filePathComponents(relativePath string) ([]string, bool) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return nil, false
	}
	components := strings.Split(relativePath, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component || strings.ContainsRune(component, '\x00') {
			return nil, false
		}
	}
	return components, true
}

type fileContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *fileContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
