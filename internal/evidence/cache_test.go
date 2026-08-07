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
	"time"

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
	if first.digest.Digest == second.digest.Digest || second.digest.Cache != "miss" || cache.hits != 1 || cache.misses != 1 || cache.readDirCalls == 0 {
		t.Fatalf("first=%+v second=%+v hits=%d misses=%d reads=%d", first, second, cache.hits, cache.misses, cache.readDirCalls)
	}
}

func TestLegacyAndIncompleteTreeTargetsDisableCache(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		legacy bool
		target model.LocalEvidenceTarget
	}{
		{name: "legacy", legacy: true},
		{name: "missing-observation", target: model.LocalEvidenceTarget{Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree}},
		{name: "missing-kind", target: model.LocalEvidenceTarget{ObservationID: "observation", Subject: model.EvidenceSubjectPayloadTree}},
		{name: "missing-subject", target: model.LocalEvidenceTarget{ObservationID: "observation", Kind: model.EvidenceTreeSHA256}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := newRecordingLeafCache()
			root, wrapped := openCacheTestRoot(t, rootPath, localityKnownLocal, cache)
			defer root.Close()
			var digest TreeDigest
			var status model.EvidenceStatus
			var errs []model.EvidenceError
			var writes []CacheWrite
			if test.legacy {
				digest, status, errs, writes = HashTree(context.Background(), wrapped, "", DefaultTreeLimits, cache)
			} else {
				digest, status, errs, writes = HashTreeForTarget(context.Background(), test.target, wrapped, "", DefaultTreeLimits, cache)
			}
			if status != model.EvidenceComplete || len(errs) != 0 || digest.Cache != "disabled" || cache.lookups != 0 || len(writes) != 0 {
				t.Fatalf("digest=%+v status=%s errors=%+v lookups=%d writes=%+v", digest, status, errs, cache.lookups, writes)
			}
		})
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

func TestTreeCacheReportsHitWhenEveryEligibleLeafHits(t *testing.T) {
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
	cache.resetCounters()
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if first.digest.Cache != "miss" || second.digest.Cache != "hit" || cache.hits != 1 || len(second.writes) != 0 {
		t.Fatalf("first=%+v second=%+v hits=%d writes=%+v", first, second, cache.hits, second.writes)
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
	if second.digest.Digest != first.digest.Digest || second.digest.Cache != "rejected" || cache.hits != 1 || len(second.writes) != 1 {
		t.Fatalf("first=%+v second=%+v hits=%d writes=%+v", first, second, cache.hits, second.writes)
	}
}

func TestTreeCacheRejectedPrecedesHitAcrossLeaves(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(rootPath, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cache := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	cache.install(first.writes)
	for key, entry := range cache.entries {
		entry.Format = "ssc-init.content-cache.v2"
		cache.entries[key] = entry
		break
	}
	cache.resetCounters()
	second := hashTreeWithCache(t, rootPath, cache, localityKnownLocal)
	if second.digest.Cache != "rejected" || cache.hits != 2 || len(second.writes) != 1 {
		t.Fatalf("result=%+v hits=%d writes=%+v", second, cache.hits, second.writes)
	}
}

func TestTreeCacheRejectsHitWhenPostLookupStatFails(t *testing.T) {
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
	cache.resetCounters()
	root, wrapped := openCacheTestRoot(t, rootPath, localityKnownLocal, cache)
	defer root.Close()
	failing := &postLookupStatErrorRoot{RootedDirectory: wrapped, target: "leaf"}
	digest, status, errs, writes := HashTreeForTarget(context.Background(), cacheTargetFixture("observation"), failing, "", DefaultTreeLimits, cache)
	if status != model.EvidenceComplete || len(errs) != 0 || digest.Cache != "rejected" || cache.hits != 1 || len(writes) != 1 {
		t.Fatalf("digest=%+v status=%s errors=%+v hits=%d writes=%+v", digest, status, errs, cache.hits, writes)
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
			if cache.lookups != 0 || len(result.writes) != 0 || result.digest.Files != 1 || result.digest.Cache != "disabled" {
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
	if result.status != model.EvidenceComplete || result.digest.Files != 1 || result.digest.Cache != "rejected" || len(result.writes) != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestTreeCacheHitReturnedAfterCancellationIsRejected(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "leaf"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	recording := newRecordingLeafCache()
	first := hashTreeWithCache(t, rootPath, recording, localityKnownLocal)
	if len(first.writes) != 1 {
		t.Fatalf("writes=%+v", first.writes)
	}
	blocking := &blockingLeafCache{entry: first.writes[0].Entry, started: make(chan struct{}), release: make(chan struct{})}
	root, wrapped := openCacheTestRoot(t, rootPath, localityKnownLocal, nil)
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type treeResult struct {
		digest TreeDigest
		status model.EvidenceStatus
		errs   []model.EvidenceError
		writes []CacheWrite
	}
	results := make(chan treeResult, 1)
	go func() {
		digest, status, errs, writes := HashTreeForTarget(ctx, cacheTargetFixture("observation"), wrapped, "", DefaultTreeLimits, blocking)
		results <- treeResult{digest: digest, status: status, errs: errs, writes: writes}
	}()
	select {
	case <-blocking.started:
	case <-time.After(5 * time.Second):
		t.Fatal("cache lookup did not block")
	}
	cancel()
	close(blocking.release)
	var result treeResult
	select {
	case result = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("tree hash did not return after cancellation")
	}
	if result.status != model.EvidencePartial || !hasTreeError(result.errs, "time_limit") || result.digest.Cache != "rejected" || len(result.writes) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func TestTreeCacheCancellationClearsEarlierLeafWrites(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	for _, name := range []string{"first", "second"} {
		if err := os.WriteFile(filepath.Join(rootPath, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cache := &blockingSecondLookupCache{started: make(chan struct{}), release: make(chan struct{})}
	root, wrapped := openCacheTestRoot(t, rootPath, localityKnownLocal, nil)
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type treeResult struct {
		digest TreeDigest
		status model.EvidenceStatus
		errs   []model.EvidenceError
		writes []CacheWrite
	}
	results := make(chan treeResult, 1)
	go func() {
		digest, status, errs, writes := HashTreeForTarget(ctx, cacheTargetFixture("observation"), wrapped, "", DefaultTreeLimits, cache)
		results <- treeResult{digest: digest, status: status, errs: errs, writes: writes}
	}()
	select {
	case <-cache.started:
	case <-time.After(5 * time.Second):
		t.Fatal("second cache lookup did not block")
	}
	cancel()
	close(cache.release)
	var result treeResult
	select {
	case result = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("tree hash did not return after cancellation")
	}
	if cache.calls != 2 || result.status != model.EvidencePartial || !hasTreeError(result.errs, "time_limit") || result.digest.Cache != "rejected" || len(result.writes) != 0 {
		t.Fatalf("calls=%d result=%+v", cache.calls, result)
	}
}

func TestTreeCachePreservesCompleteLeafWritesForNonCancellationPartialSibling(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("cache trust is Darwin-specific")
	}
	rootPath := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootPath, "file"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(rootPath, "link")); err != nil {
		t.Fatal(err)
	}
	cache := newRecordingLeafCache()
	root, wrapped := openCacheTestRoot(t, rootPath, localityKnownLocal, cache)
	defer root.Close()
	digest, status, errs, writes := HashTreeForTarget(context.Background(), cacheTargetFixture("observation"), wrapped, "", DefaultTreeLimits, cache)
	if status != model.EvidencePartial || !hasTreeError(errs, "symlink_rejected") || digest.Cache != "miss" || len(writes) != 1 {
		t.Fatalf("digest=%+v status=%s errors=%+v writes=%+v", digest, status, errs, writes)
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
	return hashTreeForTargetWithCache(t, rootPath, cache, locality, "observation")
}

func hashTreeForTargetWithCache(t *testing.T, rootPath string, cache LeafCache, locality cacheLocality, observationID string) cachedTreeResult {
	t.Helper()
	var recording *recordingLeafCache
	if value, ok := cache.(*recordingLeafCache); ok {
		recording = value
	}
	root, wrapped := openCacheTestRoot(t, rootPath, locality, recording)
	defer root.Close()
	target := cacheTargetFixture(observationID)
	digest, status, errs, writes := HashTreeForTarget(context.Background(), target, wrapped, "", DefaultTreeLimits, cache)
	if status != model.EvidenceComplete || len(errs) != 0 {
		t.Fatalf("digest=%+v status=%s errors=%+v", digest, status, errs)
	}
	return cachedTreeResult{digest: digest, status: status, writes: writes}
}

func cacheTargetFixture(observationID string) model.LocalEvidenceTarget {
	return model.LocalEvidenceTarget{ObservationID: observationID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree}
}

func openCacheTestRoot(t *testing.T, rootPath string, locality cacheLocality, cache *recordingLeafCache) (platform.RootedDirectory, platform.RootedDirectory) {
	t.Helper()
	root, err := (platform.OSFileSystem{}).OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	return root, &cacheTestRoot{RootedDirectory: root, locality: locality, cache: cache}
}

type blockingLeafCache struct {
	entry   CacheEntry
	started chan struct{}
	release chan struct{}
}

type blockingSecondLookupCache struct {
	started chan struct{}
	release chan struct{}
	calls   int
}

func (c *blockingSecondLookupCache) Lookup(_ context.Context, _ CacheKey) (CacheEntry, bool, error) {
	c.calls++
	if c.calls == 1 {
		return CacheEntry{}, false, nil
	}
	close(c.started)
	<-c.release
	return CacheEntry{}, false, nil
}

type postLookupStatErrorRoot struct {
	platform.RootedDirectory
	target string
	opens  int
}

func (r *postLookupStatErrorRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if name == r.target {
		r.opens++
		if r.opens == 1 {
			return &postLookupStatErrorFile{RootedFile: file}, nil
		}
	}
	return file, nil
}

type postLookupStatErrorFile struct {
	platform.RootedFile
	stats int
}

func (f *postLookupStatErrorFile) Stat() (os.FileInfo, error) {
	f.stats++
	if f.stats == 2 {
		return nil, errors.New("controlled post-lookup stat failure")
	}
	return f.RootedFile.Stat()
}

func (f *postLookupStatErrorFile) LocalFilesystem() (bool, bool) {
	local, ok := f.RootedFile.(platform.LocalRootedFile)
	if !ok {
		return false, false
	}
	return local.LocalFilesystem()
}

func (c *blockingLeafCache) Lookup(_ context.Context, _ CacheKey) (CacheEntry, bool, error) {
	close(c.started)
	<-c.release
	return c.entry, true, nil
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
	if f.directory && f.cache != nil {
		f.cache.mu.Lock()
		f.cache.readDirCalls++
		f.cache.mu.Unlock()
	}
	return f.RootedFile.ReadDir(n)
}
