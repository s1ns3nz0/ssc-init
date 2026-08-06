package platform

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const (
	absoluteExecutableSymlinkLimit = 16
	absoluteExecutableHashLimit    = 64 << 20
)

var errExecutableChanged = errors.New("executable identity changed")

// FileIdentity is execution-only file identity used to detect replacement.
type FileIdentity struct {
	Device          uint64
	Inode           uint64
	Size            int64
	ModTimeUnixNano int64
}

// ExecutableEvidence is bounded evidence for the executable selected from PATH.
// Path and Identity are execution-only and must never enter persisted inventory.
type ExecutableEvidence struct {
	Command     string       `json:"command"`
	Path        string       `json:"-"`
	LocationRef string       `json:"locationRef"`
	SymlinkRefs []string     `json:"symlinkRefs,omitempty"`
	SHA256      string       `json:"sha256"`
	Mode        uint32       `json:"mode"`
	Identity    FileIdentity `json:"-"`
}

// ExecutableInspector resolves, inspects, and later verifies executable identity.
type ExecutableInspector interface {
	Inspect(context.Context, string, string) (ExecutableEvidence, error)
	Verify(ExecutableEvidence) error
}

type boundedExecutableInspector struct {
	maxSymlinks int
	maxBytes    int64
	afterOpen   func(string)
}

// NewExecutableInspector constructs an inspector with explicit symlink and hash bounds.
func NewExecutableInspector(maxSymlinks int, maxBytes int64) ExecutableInspector {
	if maxSymlinks < 0 {
		maxSymlinks = 0
	}
	if maxSymlinks > absoluteExecutableSymlinkLimit {
		maxSymlinks = absoluteExecutableSymlinkLimit
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	if maxBytes > absoluteExecutableHashLimit {
		maxBytes = absoluteExecutableHashLimit
	}
	return &boundedExecutableInspector{maxSymlinks: maxSymlinks, maxBytes: maxBytes}
}

func (i *boundedExecutableInspector) Inspect(ctx context.Context, home, command string) (ExecutableEvidence, error) {
	if err := ctx.Err(); err != nil {
		return ExecutableEvidence{}, err
	}
	candidate, err := exec.LookPath(command)
	if err != nil {
		return ExecutableEvidence{}, err
	}
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return ExecutableEvidence{}, errors.New("resolve executable candidate")
	}
	absolute = filepath.Clean(absolute)
	absolute, symlinkRefs, before, err := i.resolve(ctx, home, absolute)
	if err != nil {
		return ExecutableEvidence{}, err
	}
	if !before.Mode().IsRegular() {
		return ExecutableEvidence{}, errors.New("executable is not a regular file")
	}
	if before.Mode().Perm()&0o111 == 0 {
		return ExecutableEvidence{}, errors.New("file is not executable")
	}
	if before.Size() < 0 || before.Size() > i.maxBytes {
		return ExecutableEvidence{}, errors.New("executable exceeds hash limit")
	}

	file, err := os.Open(absolute)
	if err != nil {
		return ExecutableEvidence{}, errors.New("open executable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameExecutableSnapshot(before, opened) {
		return ExecutableEvidence{}, errExecutableChanged
	}
	if i.afterOpen != nil {
		i.afterOpen(absolute)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(&executableContextReader{ctx: ctx, reader: file}, i.maxBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ExecutableEvidence{}, ctxErr
		}
		return ExecutableEvidence{}, errors.New("hash executable")
	}
	if written > i.maxBytes {
		return ExecutableEvidence{}, errors.New("executable exceeds hash limit")
	}
	after, err := file.Stat()
	if err != nil || !sameExecutableSnapshot(opened, after) || written != opened.Size() {
		return ExecutableEvidence{}, errExecutableChanged
	}
	pathAfter, err := os.Lstat(absolute)
	if err != nil || !sameExecutableSnapshot(opened, pathAfter) {
		return ExecutableEvidence{}, errExecutableChanged
	}
	fileIdentity, err := executableFileIdentity(opened)
	if err != nil {
		return ExecutableEvidence{}, err
	}
	return ExecutableEvidence{
		Command: filepath.Base(command), Path: absolute,
		LocationRef: SafeLocationRef(home, absolute, fmt.Sprintf("external-executable:%d", len(symlinkRefs)+1)),
		SymlinkRefs: symlinkRefs, SHA256: fmt.Sprintf("%x", hash.Sum(nil)), Mode: uint32(opened.Mode()), Identity: fileIdentity,
	}, nil
}

func (i *boundedExecutableInspector) resolve(ctx context.Context, home, candidate string) (string, []string, os.FileInfo, error) {
	current := candidate
	seen := make(map[string]struct{})
	var refs []string
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, nil, err
		}
		current = filepath.Clean(current)
		if !filepath.IsAbs(current) {
			return "", nil, nil, errors.New("executable target is not absolute")
		}
		if _, duplicate := seen[current]; duplicate {
			return "", nil, nil, errors.New("executable symlink loop")
		}
		seen[current] = struct{}{}
		info, err := os.Lstat(current)
		if err != nil {
			return "", nil, nil, errors.New("inspect executable")
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return current, refs, info, nil
		}
		if len(refs) >= i.maxSymlinks {
			return "", nil, nil, errors.New("executable symlink limit exceeded")
		}
		refs = append(refs, SafeLocationRef(home, current, fmt.Sprintf("external-executable:%d", len(refs)+1)))
		target, err := os.Readlink(current)
		if err != nil {
			return "", nil, nil, errors.New("read executable symlink")
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(current), target)
		}
		current = target
	}
}

func (i *boundedExecutableInspector) Verify(evidence ExecutableEvidence) error {
	info, err := os.Lstat(evidence.Path)
	if err != nil {
		return errExecutableChanged
	}
	got, err := executableFileIdentity(info)
	if err != nil || got != evidence.Identity || uint32(info.Mode()) != evidence.Mode {
		return errExecutableChanged
	}
	return nil
}

func sameExecutableSnapshot(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() &&
		left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

func executableFileIdentity(info os.FileInfo) (FileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileIdentity{}, errors.New("executable identity unavailable")
	}
	return FileIdentity{
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Size: info.Size(),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}, nil
}

type executableContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *executableContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
