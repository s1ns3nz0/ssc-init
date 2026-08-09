// Package evidence provides bounded, descriptor-anchored content evidence.
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
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

// afterOpenFileContextKey scopes deterministic mutation hooks to one hash
// operation. Production callers do not set it.
type afterOpenFileContextKey struct{}

// HashVerifiedFile hashes a regular file relative to root without following
// symbolic links. It returns evidence only if the file identity remains stable
// throughout the read.
func HashVerifiedFile(ctx context.Context, root platform.RootedDirectory, relativePath string, maxBytes int64) (FileDigest, model.EvidenceStatus, []model.EvidenceError) {
	digest, _, status, errs := hashVerifiedFileContent(ctx, root, relativePath, maxBytes, 0)
	return digest, status, errs
}

func hashVerifiedFileContent(ctx context.Context, root platform.RootedDirectory, relativePath string, maxBytes, captureMax int64) (FileDigest, []byte, model.EvidenceStatus, []model.EvidenceError) {
	if root == nil || maxBytes <= 0 || maxBytes == math.MaxInt64 || ctx.Err() != nil {
		digest, status, errs := unavailableFile("read")
		return digest, nil, status, errs
	}
	components, ok := filePathComponents(relativePath)
	if !ok {
		digest, status, errs := unavailableFile("symlink")
		return digest, nil, status, errs
	}

	parent := root
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			digest, status, errs := unavailableForOpen(err)
			return digest, nil, status, errs
		}
		defer parent.Close()
	}
	if err := ctx.Err(); err != nil {
		digest, status, errs := unavailableFile("read")
		return digest, nil, status, errs
	}

	file, expected, opened, err := platform.OpenVerifiedFile(parent, components[len(components)-1])
	if err != nil {
		digest, status, errs := unavailableForOpen(err)
		return digest, nil, status, errs
	}
	defer file.Close()
	before, ok := platform.Fingerprint(opened)
	if !ok {
		digest, status, errs := unavailableFile("read")
		return digest, nil, status, errs
	}
	if afterOpen, ok := ctx.Value(afterOpenFileContextKey{}).(func()); ok {
		afterOpen()
	}

	hasher := sha256.New()
	var captured bytes.Buffer
	writer := io.Writer(hasher)
	if captureMax > 0 && opened.Size() <= captureMax {
		writer = io.MultiWriter(hasher, &captured)
	}
	count, err := io.Copy(writer, &io.LimitedReader{R: &fileContextReader{ctx: ctx, reader: file}, N: maxBytes + 1})
	if err != nil || ctx.Err() != nil {
		digest, status, errs := unavailableFile("read")
		return digest, nil, status, errs
	}
	if count > maxBytes {
		return FileDigest{}, nil, model.EvidenceOversize, []model.EvidenceError{fixedFileErrors["oversize"]}
	}

	postRead, err := file.Stat()
	if err != nil {
		digest, status, errs := unavailableFile("read")
		return digest, nil, status, errs
	}
	postName, err := parent.Lstat(components[len(components)-1])
	if err != nil || postName == nil || !os.SameFile(expected, postName) {
		digest, status, errs := unavailableFile("identity")
		return digest, nil, status, errs
	}
	after, ok := platform.Fingerprint(postRead)
	if !ok || before != after || postRead.Size() != opened.Size() || postRead.Size() != count {
		digest, status, errs := unavailableFile("identity")
		return digest, nil, status, errs
	}
	return FileDigest{SHA256: hex.EncodeToString(hasher.Sum(nil)), Size: count, Fingerprint: before}, captured.Bytes(), model.EvidenceComplete, nil
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
