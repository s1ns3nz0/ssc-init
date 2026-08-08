package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const contentCacheFormat = "ssc-init.content-cache.v1"

// CacheKey is an opaque identifier for one unchanged evidence leaf.
type CacheKey [sha256.Size]byte

// CacheEntry is the non-sensitive summary retained for a complete leaf.
// Its opaque key binds the summary to the fingerprint used at lookup.
type CacheEntry struct {
	Key       CacheKey
	Status    model.EvidenceStatus
	Algorithm string
	Format    string
	Digest    string
	Size      int64
}

// CacheWrite is a complete leaf summary to persist after its scan commits.
type CacheWrite struct {
	Key   CacheKey
	Entry CacheEntry
}

// LeafCache is a best-effort source of opaque cached leaf summaries.
type LeafCache interface {
	Lookup(context.Context, CacheKey) (CacheEntry, bool, error)
}

// CacheWriter persists opaque cache summaries separately from a snapshot.
type CacheWriter interface {
	StoreContentCache(context.Context, []CacheWrite) error
}

// DisabledLeafCache is the explicit no-cache implementation.
type DisabledLeafCache struct{}

func (DisabledLeafCache) Lookup(context.Context, CacheKey) (CacheEntry, bool, error) {
	return CacheEntry{}, false, nil
}

// NewCacheKey derives an opaque v1 cache key. The runtime path is represented
// only by its SHA-256 digest; it is never embedded in the key input directly.
func NewCacheKey(target model.LocalEvidenceTarget, relativePath string, fingerprint platform.FileFingerprint) CacheKey {
	pathDigest := sha256.Sum256([]byte(relativePath))
	h := sha256.New()
	writeCacheKeyField(h, []byte(contentCacheFormat))
	writeCacheKeyField(h, []byte(target.ObservationID))
	writeCacheKeyField(h, []byte(target.Kind))
	writeCacheKeyField(h, []byte(target.Subject))
	writeCacheKeyField(h, pathDigest[:])
	writeCacheKeyField(h, uint64CacheKeyField(fingerprint.Device))
	writeCacheKeyField(h, uint64CacheKeyField(fingerprint.Inode))
	writeCacheKeyField(h, uint32CacheKeyField(fingerprint.Mode))
	writeCacheKeyField(h, uint64CacheKeyField(uint64(fingerprint.Size)))
	writeCacheKeyField(h, uint64CacheKeyField(uint64(fingerprint.ModTimeNS)))
	writeCacheKeyField(h, uint64CacheKeyField(uint64(fingerprint.ChangeTimeNS)))
	var key CacheKey
	copy(key[:], h.Sum(nil))
	return key
}

func writeCacheKeyField(h interface{ Write([]byte) (int, error) }, field []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(field)
}

func uint64CacheKeyField(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

func uint32CacheKeyField(value uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out[:]
}
