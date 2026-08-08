package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func validCacheWrite() evidence.CacheWrite {
	return cacheWriteWithSeed(1)
}

func cacheWriteWithSeed(seed byte) evidence.CacheWrite {
	var key evidence.CacheKey
	for index := range key {
		key[index] = seed
	}
	return evidence.CacheWrite{Key: key, Entry: evidence.CacheEntry{
		Key:       key,
		Status:    model.EvidenceComplete,
		Algorithm: "sha256",
		Format:    "ssc-init.content-cache.v1",
		Digest:    strings.Repeat("d", 64),
		Size:      42,
	}}
}

func countContentCacheRows(t *testing.T, s *Store) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT count(*) FROM content_cache`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestCacheWriteFailureDoesNotRollbackCommittedSnapshot(t *testing.T) {
	store := openTestStore(t)
	saveValidV3Snapshot(t, store, "scan-one")
	if _, err := store.db.Exec(`DROP TABLE content_cache`); err != nil {
		t.Fatal(err)
	}
	err := store.StoreContentCache(context.Background(), []evidence.CacheWrite{validCacheWrite()})
	if err == nil {
		t.Fatal("cache failure not reported")
	}
	if _, ok, err := store.LatestSnapshot(context.Background()); err != nil || !ok {
		t.Fatalf("snapshot lost: ok=%v err=%v", ok, err)
	}
}

func TestContentCacheLookupRoundTrip(t *testing.T) {
	s := openTestStore(t)
	write := validCacheWrite()
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{write}); err != nil {
		t.Fatal(err)
	}
	entry, found, err := s.Lookup(context.Background(), write.Key)
	if err != nil || !found || !reflect.DeepEqual(entry, write.Entry) {
		t.Fatalf("found=%v entry=%#v want=%#v err=%v", found, entry, write.Entry, err)
	}
	miss := cacheWriteWithSeed(9)
	if entry, found, err := s.Lookup(context.Background(), miss.Key); err != nil || found {
		t.Fatalf("unknown key: found=%v entry=%#v err=%v", found, entry, err)
	}
}

func TestContentCacheLookupRejectsCorruptRowsWithoutTrustedContent(t *testing.T) {
	for _, tt := range []struct {
		name     string
		mutation string
	}{
		{name: "uppercase digest", mutation: `UPDATE content_cache SET digest = upper(digest)`},
		{name: "short digest", mutation: `UPDATE content_cache SET digest = 'abc123'`},
		{name: "non-hex digest", mutation: `UPDATE content_cache SET digest = replace(digest, 'd', 'z')`},
		{name: "future format", mutation: `UPDATE content_cache SET format = 'ssc-init.content-cache.v2'`},
		{name: "unknown algorithm", mutation: `UPDATE content_cache SET algorithm = 'md5'`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			write := validCacheWrite()
			if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{write}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(tt.mutation); err != nil {
				t.Fatal(err)
			}
			entry, found, err := s.Lookup(context.Background(), write.Key)
			if err != nil || found || !reflect.DeepEqual(entry, evidence.CacheEntry{}) {
				t.Fatalf("corrupt row must miss: found=%v entry=%#v err=%v", found, entry, err)
			}
		})
	}
}

func TestStoreContentCachePrunesRowsUnusedNinetyDays(t *testing.T) {
	s := openTestStore(t)
	old := cacheWriteWithSeed(7)
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{old}); err != nil {
		t.Fatal(err)
	}
	stale := formatTime(time.Now().UTC().Add(-91 * 24 * time.Hour))
	if _, err := s.db.Exec(`UPDATE content_cache SET last_used_at = ?`, stale); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{validCacheWrite()}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Lookup(context.Background(), old.Key); err != nil || found {
		t.Fatalf("stale row survived retention: found=%v err=%v", found, err)
	}
	if _, found, err := s.Lookup(context.Background(), validCacheWrite().Key); err != nil || !found {
		t.Fatalf("fresh row missing after retention: found=%v err=%v", found, err)
	}
	if got := countContentCacheRows(t, s); got != 1 {
		t.Fatalf("rows=%d want=1", got)
	}
}

func TestStoreContentCachePrunesOldestRowsAboveReducedCap(t *testing.T) {
	s := openTestStore(t)
	s.contentCacheRowLimit = 2
	older := []evidence.CacheWrite{cacheWriteWithSeed(1), cacheWriteWithSeed(2)}
	if err := s.StoreContentCache(context.Background(), older); err != nil {
		t.Fatal(err)
	}
	aged := formatTime(time.Now().UTC().Add(-time.Hour))
	if _, err := s.db.Exec(`UPDATE content_cache SET last_used_at = ?`, aged); err != nil {
		t.Fatal(err)
	}
	newer := []evidence.CacheWrite{cacheWriteWithSeed(3), cacheWriteWithSeed(4)}
	if err := s.StoreContentCache(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	if got := countContentCacheRows(t, s); got != 2 {
		t.Fatalf("rows=%d want=2", got)
	}
	for _, write := range older {
		if _, found, err := s.Lookup(context.Background(), write.Key); err != nil || found {
			t.Fatalf("oldest row survived cap prune: found=%v err=%v", found, err)
		}
	}
	for _, write := range newer {
		if _, found, err := s.Lookup(context.Background(), write.Key); err != nil || !found {
			t.Fatalf("newest row lost by cap prune: found=%v err=%v", found, err)
		}
	}
}

func TestStoreContentCacheSkipsInvalidWrites(t *testing.T) {
	wrongFormat := validCacheWrite()
	wrongFormat.Entry.Format = "ssc-init.content-cache.v2"
	wrongDigest := cacheWriteWithSeed(2)
	wrongDigest.Entry.Digest = strings.ToUpper(wrongDigest.Entry.Digest)
	wrongStatus := cacheWriteWithSeed(3)
	wrongStatus.Entry.Status = model.EvidencePartial
	wrongKey := cacheWriteWithSeed(4)
	wrongKey.Entry.Key = cacheWriteWithSeed(5).Key
	negativeSize := cacheWriteWithSeed(6)
	negativeSize.Entry.Size = -1
	wrongAlgorithm := cacheWriteWithSeed(7)
	wrongAlgorithm.Entry.Algorithm = "sha512"

	s := openTestStore(t)
	err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{
		wrongFormat, wrongDigest, wrongStatus, wrongKey, negativeSize, wrongAlgorithm,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := countContentCacheRows(t, s); got != 0 {
		t.Fatalf("invalid writes persisted %d rows", got)
	}
}

func TestStoreContentCacheTouchesReusedEntries(t *testing.T) {
	s := openTestStore(t)
	write := validCacheWrite()
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{write}); err != nil {
		t.Fatal(err)
	}
	aged := formatTime(time.Now().UTC().Add(-48 * time.Hour))
	if _, err := s.db.Exec(`UPDATE content_cache SET last_used_at = ?`, aged); err != nil {
		t.Fatal(err)
	}
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{write}); err != nil {
		t.Fatal(err)
	}
	var lastUsed string
	if err := s.db.QueryRow(`SELECT last_used_at FROM content_cache`).Scan(&lastUsed); err != nil {
		t.Fatal(err)
	}
	if lastUsed <= aged {
		t.Fatalf("reused entry was not touched: last_used_at=%q", lastUsed)
	}
	if got := countContentCacheRows(t, s); got != 1 {
		t.Fatalf("rows=%d want=1", got)
	}
}

func TestStoreContentCacheEmptyWritesAreNoOp(t *testing.T) {
	s := openTestStore(t)
	if err := s.StoreContentCache(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := countContentCacheRows(t, s); got != 0 {
		t.Fatalf("rows=%d want=0", got)
	}
}

func TestContentCacheHonorsCancelledContextAndClosedStore(t *testing.T) {
	s := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Lookup(ctx, validCacheWrite().Key); !errorsIsContext(err) {
		t.Fatalf("Lookup error = %v", err)
	}
	if err := s.StoreContentCache(ctx, []evidence.CacheWrite{validCacheWrite()}); !errorsIsContext(err) {
		t.Fatalf("StoreContentCache error = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Lookup(context.Background(), validCacheWrite().Key); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Lookup after close error = %v", err)
	}
	if err := s.StoreContentCache(context.Background(), []evidence.CacheWrite{validCacheWrite()}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("StoreContentCache after close error = %v", err)
	}
}
