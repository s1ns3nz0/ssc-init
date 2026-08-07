package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestCacheKeyContainsNoPathAndChangesWithFingerprint(t *testing.T) {
	target := model.LocalEvidenceTarget{
		AssetID: "a", ObservationID: "o", Kind: model.EvidenceTreeSHA256,
		Subject: model.EvidenceSubjectPayloadTree,
	}
	first := NewCacheKey(target, "src/private-name.js", platform.FileFingerprint{Device: 1, Inode: 2, Size: 3, ChangeTimeNS: 4})
	second := NewCacheKey(target, "src/private-name.js", platform.FileFingerprint{Device: 1, Inode: 2, Size: 3, ChangeTimeNS: 5})
	if first == second || strings.Contains(string(first[:]), "private-name") {
		t.Fatalf("keys=%x %x", first, second)
	}
}

func TestCacheKeyChangesForEveryFingerprintField(t *testing.T) {
	target := model.LocalEvidenceTarget{ObservationID: "observation", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree}
	base := platform.FileFingerprint{Device: 1, Inode: 2, Mode: 3, Size: 4, ModTimeNS: 5, ChangeTimeNS: 6}
	first := NewCacheKey(target, "leaf", base)
	for _, mutate := range []func(*platform.FileFingerprint){
		func(v *platform.FileFingerprint) { v.Device++ }, func(v *platform.FileFingerprint) { v.Inode++ },
		func(v *platform.FileFingerprint) { v.Mode++ }, func(v *platform.FileFingerprint) { v.Size++ },
		func(v *platform.FileFingerprint) { v.ModTimeNS++ }, func(v *platform.FileFingerprint) { v.ChangeTimeNS++ },
	} {
		candidate := base
		mutate(&candidate)
		if got := NewCacheKey(target, "leaf", candidate); got == first {
			t.Fatalf("fingerprint mutation did not change key: %+v", candidate)
		}
	}
}

func TestTreeCacheHitStillEnumeratesAndRebuildsRoot(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "first.js"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	cache.install(first.writes)
	cache.resetCounters()
	if err := os.WriteFile(filepath.Join(rootPath, "second.js"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if first.digest.Digest == second.digest.Digest || cache.hits != 1 || cache.misses != 1 || cache.readDirCalls == 0 {
		t.Fatalf("first=%+v second=%+v hits=%d misses=%d reads=%d", first, second, cache.hits, cache.misses, cache.readDirCalls)
	}
}

func TestHashTreeForTargetScopesCacheKeysToObservation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	first := hashTreeForTargetWithCache(t, rootPath, cache, localityKnownLocal, "observation-a")
	cache.install(first.writes)
	cache.resetCounters()
	second := hashTreeForTargetWithCache(t, rootPath, cache, localityKnownLocal, "observation-b")
	if first.digest.Digest != second.digest.Digest || cache.hits != 0 || cache.misses != 1 {
		t.Fatalf("first=%+v second=%+v hits=%d misses=%d", first, second, cache.hits, cache.misses)
	}
}

func TestTreeCacheRejectsCorruptEntryAndRehashes(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	cache.install(first.writes)
	for key, entry := range cache.entries {
		entry.Digest = strings.ToUpper(entry.Digest)
		cache.entries[key] = entry
	}
	cache.resetCounters()
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if second.digest.Digest != first.digest.Digest || cache.hits != 1 || len(second.writes) != 1 {
		t.Fatalf("first=%+v second=%+v hits=%d writes=%+v", first, second, cache.hits, second.writes)
	}
}

func TestTreeCacheDisablesRemoteOrUnknownLocality(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	for _, locality := range []cacheLocality{localityKnownRemote, localityUnknown} {
		t.Run(locality.name, func(t *testing.T) {
			rootPath := t.TempDir()
			if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
				t.Fatal(err)
			}
			cache := newRecordingLeafCache()
			result := hashTreeWithCache(t, rootPath, cache, locality)
			if cache.lookups != 0 || len(result.writes) != 0 || result.digest.Files != 1 {
				t.Fatalf("lookups=%d writes=%+v result=%+v", cache.lookups, result.writes, result.digest)
			}
		})
	}
}

func TestTreeCacheLookupErrorFallsBackToHash(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	cache.err = errors.New("controlled cache error")
	result := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if result.status != model.EvidenceComplete || result.digest.Files != 1 || len(result.writes) != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestTreeCacheRejectsSizeAndMTimePreservingReplacement(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "leaf")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	cache.install(first.writes)
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	cache.resetCounters()
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if first.digest.Digest == second.digest.Digest || cache.hits != 0 || cache.misses != 1 {
		t.Fatalf("first=%+v second=%+v hits=%d misses=%d", first, second, cache.hits, cache.misses)
	}
}

func TestTreeCacheInvalidatesWhenCTimeChangesWithMTimePreserved(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "leaf")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	cache.install(first.writes)
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatalf("before=%+v after=%+v err=%v", before, after, err)
	}
	cache.resetCounters()
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if second.digest.Digest != first.digest.Digest || cache.hits != 0 || cache.misses != 1 {
		t.Fatalf("first=%+v second=%+v hits=%d misses=%d", first, second, cache.hits, cache.misses)
	}
}

func TestTreeCacheWritesAreDeterministicAndConcurrentSafe(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := hashTreeWithCache(t, rootPath, newRecordingLeafCache(), localityKnownLocal)
	second := hashTreeWithCache(t, rootPath, newRecordingLeafCache(), localityKnownLocal)
	if !reflect.DeepEqual(first.writes, second.writes) {
		t.Fatalf("first=%+v second=%+v", first.writes, second.writes)
	}

	cache := newRecordingLeafCache()
	results := make(chan cachedTreeResult, 2)
	for range 2 {
		go func() { results <- hashTreeWithCache(t, rootPath, cache, localityKnownLocal) }()
	}
	for range 2 {
		result := <-results
		if result.status != model.EvidenceComplete || result.digest.Files != 1 {
			t.Fatalf("result=%+v", result)
		}
	}
}

type cachedTreeResult struct {
	digest TreeDigest
	status model.EvidenceStatus
	writes []CacheWrite
}

func hashTreeWithCache(t *testing.T, rootPath string, cache LeafCache, locality cacheLocality) cachedTreeResult {
	return hashTreeForTargetWithCache(t, rootPath, cache, locality, "")
}

func hashTreeForTargetWithCache(t *testing.T, rootPath string, cache LeafCache, locality cacheLocality, observationID string) cachedTreeResult {
	t.Helper()
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	recording, ok := cache.(*recordingLeafCache)
	if !ok {
		t.Fatal("cache test requires recording cache")
	}
	wrapped := &cacheTestRoot{RootedDirectory: root, locality: locality, cache: recording}
	target := model.LocalEvidenceTarget{ObservationID: observationID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree}
	digest, status, errs, writes := HashTreeForTarget(context.Background(), target, wrapped, "", DefaultTreeLimits, cache)
	if status != model.EvidenceComplete || len(errs) != 0 {
		t.Fatalf("digest=%+v status=%s errors=%+v", digest, status, errs)
	}
	return cachedTreeResult{digest: digest, status: status, writes: writes}
}

type recordingLeafCache struct {
	mu           sync.Mutex
	entries      map[CacheKey]CacheEntry
	err          error
	hits         int
	misses       int
	lookups      int
	readDirCalls int
}

func newRecordingLeafCache() *recordingLeafCache {
	return &recordingLeafCache{entries: make(map[CacheKey]CacheEntry)}
}

func (c *recordingLeafCache) Lookup(_ context.Context, key CacheKey) (CacheEntry, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups++
	if c.err != nil {
		return CacheEntry{}, false, c.err
	}
	entry, ok := c.entries[key]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	return entry, ok, nil
}

func (c *recordingLeafCache) install(writes []CacheWrite) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, write := range writes {
		if write.Entry.Status == model.EvidenceComplete {
			c.entries[write.Key] = write.Entry
		}
	}
}

func (c *recordingLeafCache) resetCounters() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits, c.misses, c.lookups, c.readDirCalls = 0, 0, 0, 0
}

type cacheLocality struct {
	name         string
	local, known bool
}

var (
	localityKnownLocal  = cacheLocality{name: "local", local: true, known: true}
	localityKnownRemote = cacheLocality{name: "remote", known: true}
	localityUnknown     = cacheLocality{name: "unknown"}
)

type cacheTestRoot struct {
	platform.RootedDirectory
	locality cacheLocality
	cache    *recordingLeafCache
}

func (r *cacheTestRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if name == "." {
		return &cacheTestFile{RootedFile: file, locality: r.locality, cache: r.cache, directory: true}, nil
	}
	return &cacheTestFile{RootedFile: file, locality: r.locality, cache: r.cache}, nil
}
func (r *cacheTestRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &cacheTestRoot{RootedDirectory: child, locality: r.locality, cache: r.cache}, nil
}

type cacheTestFile struct {
	platform.RootedFile
	locality  cacheLocality
	cache     *recordingLeafCache
	directory bool
}

func (f *cacheTestFile) LocalFilesystem() (bool, bool) { return f.locality.local, f.locality.known }
func (f *cacheTestFile) ReadDir(n int) ([]os.DirEntry, error) {
	if f.directory {
		f.cache.mu.Lock()
		f.cache.readDirCalls++
		f.cache.mu.Unlock()
	}
	return f.RootedFile.ReadDir(n)
}
