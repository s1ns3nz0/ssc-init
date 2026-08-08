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

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const treeReadDirBatchSize = 256

const (
	treeDomain           = "ssc-init.tree.v1"
	recordDirectory byte = 'd'
	recordFile      byte = 'f'
	recordSymlink   byte = 'l'
	recordSpecial   byte = 's'
	cacheDisabled        = "disabled"
	cacheHit             = "hit"
	cacheMiss            = "miss"
	cacheRejected        = "rejected"
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
	Cache       string
}

type treeState struct {
	ctx          context.Context
	limits       TreeLimits
	hasher       hash.Hash
	digest       TreeDigest
	entries      int
	pending      int
	errors       []model.EvidenceError
	partial      bool
	oversize     bool
	stopped      bool
	timeLimited  bool
	cache        LeafCache
	cacheEnabled bool
	target       model.LocalEvidenceTarget
	writes       []CacheWrite
}

// HashTree produces a deterministic, descriptor-anchored manifest. It does
// not follow symbolic links and retains no path or leaf data after returning.
func HashTree(ctx context.Context, root platform.RootedDirectory, relativePath string, limits TreeLimits, cache LeafCache) (TreeDigest, model.EvidenceStatus, []model.EvidenceError, []CacheWrite) {
	return hashTree(ctx, model.LocalEvidenceTarget{}, root, relativePath, limits, cache)
}

// HashTreeForTarget hashes a tree while binding any reusable leaf summaries to
// the target's observation, kind, and subject.
func HashTreeForTarget(ctx context.Context, target model.LocalEvidenceTarget, root platform.RootedDirectory, relativePath string, limits TreeLimits, cache LeafCache) (TreeDigest, model.EvidenceStatus, []model.EvidenceError, []CacheWrite) {
	return hashTree(ctx, target, root, relativePath, limits, cache)
}

func hashTree(ctx context.Context, target model.LocalEvidenceTarget, root platform.RootedDirectory, relativePath string, limits TreeLimits, cache LeafCache) (TreeDigest, model.EvidenceStatus, []model.EvidenceError, []CacheWrite) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	h := sha256.New()
	cacheEnabled := completeCacheTarget(target) && cache != nil && !disabledLeafCache(cache)
	if cache == nil {
		cache = DisabledLeafCache{}
	}
	state := treeState{ctx: ctx, limits: limits, hasher: h, cache: cache, cacheEnabled: cacheEnabled, target: target}
	state.digest.Cache = cacheDisabled
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

func completeCacheTarget(target model.LocalEvidenceTarget) bool {
	return target.ObservationID != "" && target.Kind != "" && target.Subject != ""
}

func disabledLeafCache(cache LeafCache) bool {
	switch cache.(type) {
	case DisabledLeafCache, *DisabledLeafCache:
		return true
	default:
		return false
	}
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
		room := remaining - len(entries)
		request := treeReadDirBatchSize
		if room < treeReadDirBatchSize {
			request = room + 1
		}
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
			if s.ctx.Err() != nil {
				s.addPartial("time")
				return
			}
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
	file, hit, cacheEligible := s.cachedLeaf(root, name, relative, info, initialFingerprint)
	if s.ctx.Err() != nil {
		s.addPartial("time")
		return
	}
	status := model.EvidenceComplete
	var errs []model.EvidenceError
	if !hit {
		file, status, errs = HashVerifiedFile(s.ctx, root, name, s.limits.MaxFileBytes)
	}
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
	if !hit && cacheEligible {
		key := NewCacheKey(s.target, relative, file.Fingerprint)
		s.writes = append(s.writes, CacheWrite{Key: key, Entry: CacheEntry{
			Key: key, Status: model.EvidenceComplete,
			Algorithm: "sha256", Format: contentCacheFormat, Digest: file.SHA256, Size: file.Size,
		}})
	}
	s.digest.Size += file.Size
	decoded, decodeErr := hex.DecodeString(file.SHA256)
	if decodeErr != nil || len(decoded) != sha256.Size {
		s.addPartial("read")
		return
	}
	s.write(recordFile, []byte(relative), uint32Bytes(file.Fingerprint.Mode&0o777), uint64Bytes(uint64(file.Size)), decoded)
}

// cachedLeaf opens the candidate before lookup and repeats its identity check
// after a cache hit. It never returns an unvalidated cache value.
func (s *treeState) cachedLeaf(root platform.RootedDirectory, name, relative string, initialInfo os.FileInfo, initial platform.FileFingerprint) (FileDigest, bool, bool) {
	if !s.cacheEnabled {
		return FileDigest{}, false, false
	}
	file, expected, opened, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		return FileDigest{}, false, false
	}
	defer file.Close()
	localFile, ok := file.(platform.LocalRootedFile)
	if !ok {
		return FileDigest{}, false, false
	}
	local, known := localFile.LocalFilesystem()
	if !known || !local {
		return FileDigest{}, false, false
	}
	before, ok := platform.Fingerprint(opened)
	if !ok || before != initial || !os.SameFile(initialInfo, expected) {
		return FileDigest{}, false, false
	}
	key := NewCacheKey(s.target, relative, before)
	entry, found, err := s.cache.Lookup(s.ctx, key)
	if s.ctx.Err() != nil {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, false
	}
	if err != nil {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, true
	}
	if !found {
		s.noteCache(cacheMiss)
		return FileDigest{}, false, true
	}
	if !validCacheEntry(entry, key, before) {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, true
	}
	after, err := file.Stat()
	if err != nil {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, true
	}
	afterFingerprint, ok := platform.Fingerprint(after)
	postName, err := root.Lstat(name)
	if err != nil || !ok || before != afterFingerprint || !os.SameFile(expected, postName) {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, true
	}
	if s.ctx.Err() != nil {
		s.noteCache(cacheRejected)
		return FileDigest{}, false, false
	}
	s.noteCache(cacheHit)
	return FileDigest{SHA256: entry.Digest, Size: entry.Size, Fingerprint: before}, true, true
}

func (s *treeState) noteCache(status string) {
	if cacheStatusRank(status) > cacheStatusRank(s.digest.Cache) {
		s.digest.Cache = status
	}
}

func cacheStatusRank(status string) int {
	switch status {
	case cacheHit:
		return 1
	case cacheMiss:
		return 2
	case cacheRejected:
		return 3
	default:
		return 0
	}
}

func validCacheEntry(entry CacheEntry, key CacheKey, fingerprint platform.FileFingerprint) bool {
	if entry.Key != key || entry.Status != model.EvidenceComplete ||
		entry.Algorithm != "sha256" || entry.Format != contentCacheFormat || entry.Size < 0 || entry.Size != fingerprint.Size ||
		len(entry.Digest) != sha256.Size*2 || entry.Digest != strings.ToLower(entry.Digest) {
		return false
	}
	decoded, err := hex.DecodeString(entry.Digest)
	return err == nil && len(decoded) == sha256.Size
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
	if s.ctx.Err() != nil {
		s.addPartial("time")
		return
	}
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

func (s *treeState) addPartial(kind string) {
	if kind == "time" {
		s.markTimeLimit()
		return
	}
	s.addError(treeError(kind), false)
}
func (s *treeState) addOversize(kind string) { s.addError(treeError(kind), true) }

func (s *treeState) markTimeLimit() {
	s.timeLimited = true
	s.partial = true
	for _, err := range s.errors {
		if err.Code == "time_limit" {
			return
		}
	}
	err := treeError("time")
	if len(s.errors) < s.limits.MaxErrors || len(s.errors) == 0 {
		s.errors = append(s.errors, err)
		return
	}
	s.errors[len(s.errors)-1] = err
}

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
	if s.ctx.Err() != nil {
		s.markTimeLimit()
	}
	if s.timeLimited {
		s.writes = nil
	}
	s.digest.Digest = hex.EncodeToString(s.hasher.Sum(nil))
	status := model.EvidenceComplete
	if s.oversize {
		status = model.EvidenceOversize
	} else if s.partial {
		status = model.EvidencePartial
	}
	return s.digest, status, s.errors, s.writes
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
