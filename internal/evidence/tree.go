package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const treeReadDirBatchSize = 256

const (
	treeDomain           = "ssc-init.tree.v1"
	recordDirectory byte = 'd'
	recordFile      byte = 'f'
	recordSymlink   byte = 'l'
	recordSpecial   byte = 's'
)

// TreeLimits are non-negotiable bounds for one tree evidence target.
type TreeLimits struct {
	MaxDepth      int
	MaxEntries    int
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxErrors     int
	Timeout       time.Duration
}

var DefaultTreeLimits = TreeLimits{
	MaxDepth: 32, MaxEntries: 4096, MaxFileBytes: 64 << 20,
	MaxTotalBytes: 256 << 20, MaxErrors: 64, Timeout: 30 * time.Second,
}

// TreeDigest is the non-sensitive result of a tree manifest computation.
type TreeDigest struct {
	Digest      string
	Size        int64
	Files       int
	Directories int
	Symlinks    int
}

// CacheKey, CacheEntry and CacheWrite reserve the tree cache contract. Tree
// hashing deliberately does not trust or write cache values until Task 5.
type CacheKey [32]byte
type CacheEntry struct{}
type CacheWrite struct{}

type LeafCache interface {
	Lookup(context.Context, CacheKey) (CacheEntry, bool, error)
}

// DisabledLeafCache is the explicit no-cache implementation.
type DisabledLeafCache struct{}

func (DisabledLeafCache) Lookup(context.Context, CacheKey) (CacheEntry, bool, error) {
	return CacheEntry{}, false, nil
}

type treeState struct {
	ctx      context.Context
	limits   TreeLimits
	hasher   hash.Hash
	digest   TreeDigest
	entries  int
	pending  int
	errors   []model.EvidenceError
	partial  bool
	oversize bool
	stopped  bool
}

// HashTree produces a deterministic, descriptor-anchored manifest. It does
// not follow symbolic links and retains no path or leaf data after returning.
func HashTree(ctx context.Context, root platform.RootedDirectory, relativePath string, limits TreeLimits, _ LeafCache) (TreeDigest, model.EvidenceStatus, []model.EvidenceError, []CacheWrite) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	h := sha256.New()
	state := treeState{ctx: ctx, limits: limits, hasher: h}
	state.writeHeader()

	if root == nil || !validTreeLimits(limits) {
		state.addPartial("read")
		return state.result()
	}
	current := root
	owned := false
	if relativePath != "" {
		components, ok := filePathComponents(relativePath)
		if !ok {
			state.addPartial("path")
			return state.result()
		}
		var err error
		current, err = platform.OpenVerifiedRoot(ctx, root, components...)
		if err != nil {
			state.addOpenError(err)
			return state.result()
		}
		owned = true
	}
	if owned {
		defer current.Close()
	}
	state.walk(current, "", 0, true)
	return state.result()
}

func validTreeLimits(l TreeLimits) bool {
	return l.MaxDepth >= 0 && l.MaxEntries > 0 && l.MaxFileBytes > 0 && l.MaxFileBytes < math.MaxInt64 &&
		l.MaxTotalBytes > 0 && l.MaxTotalBytes < math.MaxInt64 && l.MaxErrors > 0 && l.Timeout != 0
}

func (s *treeState) walk(root platform.RootedDirectory, relative string, depth int, targetRoot bool) {
	if s.stopped || s.expired() {
		return
	}
	info, err := root.Lstat(".")
	if err != nil || info == nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		s.addOpenError(err)
		return
	}
	if !targetRoot {
		s.digest.Directories++
	}
	s.write(recordDirectory, []byte(relative), uint32Bytes(uint32(info.Mode().Perm())))
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		s.addOpenError(err)
		return
	}
	entries, err := s.readDirectory(directory)
	_ = directory.Close()
	if s.stopped {
		return
	}
	if err != nil {
		if s.ctx.Err() != nil {
			return
		}
		s.addPartial("read")
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	s.pending += len(entries)
	for _, entry := range entries {
		s.pending--
		if s.stopped || s.expired() {
			return
		}
		name := entry.Name()
		if !validTreeName(name) {
			s.entries++
			s.addPartial("path")
			continue
		}
		s.digestEntry(root, joinTreePath(relative, name), name, depth)
	}
}

func (s *treeState) readDirectory(directory platform.RootedFile) ([]os.DirEntry, error) {
	remaining := s.limits.MaxEntries - s.entries - s.pending
	entries := make([]os.DirEntry, 0, min(remaining, treeReadDirBatchSize))
	for {
		if s.expired() {
			return nil, s.ctx.Err()
		}
		request := min(treeReadDirBatchSize, remaining+1-len(entries))
		chunk, err := directory.ReadDir(request)
		entries = append(entries, chunk...)
		if len(entries) > remaining {
			s.addOversize("entries")
			return nil, nil
		}
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return nil, io.ErrNoProgress
		}
	}
}

func (s *treeState) digestEntry(root platform.RootedDirectory, relative, name string, parentDepth int) {
	if s.entries >= s.limits.MaxEntries {
		s.addOversize("entries")
		return
	}
	s.entries++
	info, err := root.Lstat(name)
	if err != nil || info == nil {
		s.addOpenError(err)
		return
	}
	mode := info.Mode()
	if mode&fs.ModeSymlink != 0 {
		s.digest.Symlinks++
		target, readErr := root.Readlink(name)
		if readErr != nil {
			s.addPartial("read")
			return
		}
		targetDigest := sha256.Sum256([]byte(target))
		s.write(recordSymlink, []byte(relative), targetDigest[:])
		s.addPartial("symlink")
		return
	}
	if info.IsDir() {
		depth := parentDepth + 1
		if depth > s.limits.MaxDepth {
			s.addOversize("depth")
			return
		}
		child, openErr := platform.OpenVerifiedRoot(s.ctx, root, name)
		if openErr != nil {
			s.addOpenError(openErr)
			return
		}
		defer child.Close()
		s.walk(child, relative, depth, false)
		return
	}
	if !mode.IsRegular() {
		s.write(recordSpecial, []byte(relative), uint32Bytes(uint32(mode.Type())))
		s.addPartial("special")
		return
	}
	s.digest.Files++
	if info.Size() > s.limits.MaxFileBytes || info.Size() < 0 {
		s.addOversize("bytes")
		return
	}
	if info.Size() > s.limits.MaxTotalBytes-s.digest.Size {
		s.addOversize("bytes")
		return
	}
	initialFingerprint, fingerprintOK := platform.Fingerprint(info)
	if !fingerprintOK {
		s.addPartial("read")
		return
	}
	file, status, errs := HashVerifiedFile(s.ctx, root, name, s.limits.MaxFileBytes)
	if status != model.EvidenceComplete {
		if s.ctx.Err() != nil {
			s.addPartial("time")
			return
		}
		if status == model.EvidenceOversize {
			s.addOversize("bytes")
			return
		}
		for _, evidenceErr := range errs {
			s.addError(evidenceErr, false)
		}
		if len(errs) == 0 {
			s.addPartial("read")
		}
		return
	}
	if file.Size > s.limits.MaxTotalBytes-s.digest.Size {
		s.addOversize("bytes")
		return
	}
	if initialFingerprint != file.Fingerprint {
		s.addError(model.EvidenceError{Code: "identity_changed", Message: "evidence file identity changed"}, false)
		return
	}
	s.digest.Size += file.Size
	decoded, decodeErr := hex.DecodeString(file.SHA256)
	if decodeErr != nil || len(decoded) != sha256.Size {
		s.addPartial("read")
		return
	}
	s.write(recordFile, []byte(relative), uint32Bytes(file.Fingerprint.Mode&0o777), uint64Bytes(uint64(file.Size)), decoded)
}

func (s *treeState) expired() bool {
	if s.stopped {
		return true
	}
	if s.ctx.Err() != nil {
		s.addPartial("time")
		return true
	}
	return false
}

func (s *treeState) addOpenError(err error) {
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		s.addError(model.EvidenceError{Code: "identity_changed", Message: "evidence tree identity changed"}, false)
		return
	}
	if errors.Is(err, fs.ErrInvalid) {
		s.addPartial("path")
		return
	}
	s.addPartial("read")
}

func (s *treeState) addPartial(kind string)  { s.addError(treeError(kind), false) }
func (s *treeState) addOversize(kind string) { s.addError(treeError(kind), true) }

func (s *treeState) addError(err model.EvidenceError, oversize bool) {
	if s.stopped {
		return
	}
	if len(s.errors) >= s.limits.MaxErrors {
		s.oversize = true
		s.stopped = true
		return
	}
	s.errors = append(s.errors, err)
	if oversize {
		s.oversize = true
		s.stopped = true
	} else {
		s.partial = true
	}
}

func treeError(kind string) model.EvidenceError {
	switch kind {
	case "symlink":
		return model.EvidenceError{Code: "symlink_rejected", Message: "symbolic link was not followed"}
	case "special":
		return model.EvidenceError{Code: "special_file_rejected", Message: "special file was not read"}
	case "entries":
		return model.EvidenceError{Code: "file_limit", Message: "evidence tree exceeds the entry limit"}
	case "bytes":
		return model.EvidenceError{Code: "byte_limit", Message: "evidence tree exceeds the byte limit"}
	case "depth":
		return model.EvidenceError{Code: "depth_limit", Message: "evidence tree exceeds the depth limit"}
	case "time":
		return model.EvidenceError{Code: "time_limit", Message: "evidence tree deadline exceeded"}
	case "path":
		return model.EvidenceError{Code: "path_invalid", Message: "evidence tree path is invalid"}
	default:
		return model.EvidenceError{Code: "read_unavailable", Message: "evidence tree entry is unavailable"}
	}
}

func (s *treeState) write(kind byte, fields ...[]byte) {
	var record []byte
	record = append(record, kind)
	for _, field := range fields {
		record = binary.BigEndian.AppendUint32(record, uint32(len(field)))
		record = append(record, field...)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(record)))
	_, _ = s.hasher.Write(length[:])
	_, _ = s.hasher.Write(record)
}

func (s *treeState) writeHeader() {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(treeDomain)))
	_, _ = s.hasher.Write(length[:])
	_, _ = s.hasher.Write([]byte(treeDomain))
}

func (s *treeState) result() (TreeDigest, model.EvidenceStatus, []model.EvidenceError, []CacheWrite) {
	s.digest.Digest = hex.EncodeToString(s.hasher.Sum(nil))
	status := model.EvidenceComplete
	if s.oversize {
		status = model.EvidenceOversize
	} else if s.partial {
		status = model.EvidencePartial
	}
	return s.digest, status, s.errors, nil
}

func validTreeName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsRune(name, '/') &&
		!strings.ContainsRune(name, '\\') && !strings.ContainsRune(name, '\x00')
}

func joinTreePath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}
func uint32Bytes(value uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out[:]
}
func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}
