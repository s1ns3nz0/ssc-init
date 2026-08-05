package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

var errRootedHashingUnavailable = errors.New("rooted file access is unavailable")

// HashFile hashes a verified regular file while reading at most maxBytes+1.
func HashFile(ctx context.Context, filesystem platform.FileSystem, path string, maxBytes int64) (string, model.HashStatus, error) {
	if maxBytes <= 0 {
		return "", model.HashUnavailable, errors.New("hash byte limit must be positive")
	}
	if err := ctx.Err(); err != nil {
		return "", model.HashUnavailable, err
	}
	rooted, ok := filesystem.(platform.RootedFileSystem)
	if !ok {
		return "", model.HashUnavailable, errRootedHashingUnavailable
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", model.HashUnavailable, err
	}
	absolute = filepath.Clean(absolute)
	directory, name := filepath.Dir(absolute), filepath.Base(absolute)
	if name == "." || name == string(filepath.Separator) {
		return "", model.HashUnavailable, platform.ErrUnsafeRootedPath
	}

	root, err := rooted.OpenRoot(directory)
	if err != nil {
		return "", model.HashUnavailable, err
	}
	defer root.Close()
	if err := ctx.Err(); err != nil {
		return "", model.HashUnavailable, err
	}
	file, _, _, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		return "", model.HashUnavailable, err
	}
	defer file.Close()

	reader := &contextReader{ctx: ctx, reader: file}
	hasher := sha256.New()
	limited := &io.LimitedReader{R: reader, N: maxBytes}
	bytesHashed, err := io.Copy(hasher, limited)
	if err != nil {
		return "", model.HashUnavailable, err
	}
	if bytesHashed == maxBytes {
		var extra [1]byte
		for {
			count, readErr := reader.Read(extra[:])
			if count > 0 {
				return "", model.HashOversize, nil
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					break
				}
				return "", model.HashUnavailable, readErr
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return "", model.HashUnavailable, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), model.HashComplete, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
