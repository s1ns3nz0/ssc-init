package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

var errRootedHashingUnavailable = errors.New("rooted file access is unavailable")
var errVerifiedHashingUnavailable = errors.New("verified file hashing is unavailable")

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
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	relative, err := filepath.Rel(volumeRoot, absolute)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", model.HashUnavailable, platform.ErrUnsafeRootedPath
	}
	root, err := rooted.OpenRoot(volumeRoot)
	if err != nil {
		return "", model.HashUnavailable, err
	}
	defer root.Close()
	digest, status, evidenceErrors := evidence.HashVerifiedFile(ctx, root, relative, maxBytes)
	if err := ctx.Err(); err != nil {
		return "", model.HashUnavailable, err
	}
	switch status {
	case model.EvidenceComplete:
		return digest.SHA256, model.HashComplete, nil
	case model.EvidenceOversize:
		return "", model.HashOversize, nil
	default:
		if len(evidenceErrors) == 1 && (evidenceErrors[0].Code == "symlink_rejected" || evidenceErrors[0].Code == "identity_changed") {
			return "", model.HashUnavailable, platform.ErrUnsafeRootedPath
		}
		return "", model.HashUnavailable, errVerifiedHashingUnavailable
	}
}
