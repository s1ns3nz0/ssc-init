package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// The store is the SQLite-backed leaf cache used by the evidence engine.
var (
	_ evidence.LeafCache   = (*Store)(nil)
	_ evidence.CacheWriter = (*Store)(nil)
)

const (
	contentCacheFormat       = "ssc-init.content-cache.v1"
	contentCacheRetention    = 90 * 24 * time.Hour
	contentCacheDefaultLimit = 250000
)

// Lookup returns the previously complete leaf summary stored under an opaque
// cache key. Corrupt, malformed, or future-format rows are reported as misses,
// never as trusted content and never as a scan failure.
func (s *Store) Lookup(ctx context.Context, key evidence.CacheKey) (evidence.CacheEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return evidence.CacheEntry{}, false, err
	}
	db, _, release, err := s.beginOperation()
	if err != nil {
		return evidence.CacheEntry{}, false, err
	}
	defer release()
	var algorithm, format, digest string
	var size int64
	err = db.QueryRowContext(ctx, `SELECT algorithm, format, digest, size FROM content_cache WHERE cache_key = ?`, key[:]).
		Scan(&algorithm, &format, &digest, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return evidence.CacheEntry{}, false, nil
	}
	if err != nil {
		return evidence.CacheEntry{}, false, fmt.Errorf("query content cache: %w", err)
	}
	entry := evidence.CacheEntry{Key: key, Status: model.EvidenceComplete, Algorithm: algorithm, Format: format, Digest: digest, Size: size}
	if !validContentCacheEntry(entry) {
		return evidence.CacheEntry{}, false, nil
	}
	return entry, true, nil
}

// StoreContentCache persists complete leaf summaries in a best-effort
// transaction that is entirely separate from any snapshot transaction. It
// upserts valid entries, refreshes their use time, prunes rows unused for the
// retention window, and then prunes the oldest rows above the row cap. A
// failure rolls back only this cache transaction; committed snapshots are
// never affected. Only the opaque 32-byte key and the digest summary columns
// are stored: no target path, observation ID, subject, fingerprint, or source
// content ever reaches a cache row.
func (s *Store) StoreContentCache(ctx context.Context, writes []evidence.CacheWrite) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(writes) == 0 {
		return nil
	}
	db, guard, release, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin content cache transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	now := time.Now().UTC()
	stamp := formatTime(now)
	for _, write := range writes {
		if write.Entry.Key != write.Key || !validContentCacheEntry(write.Entry) {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO content_cache(cache_key, algorithm, format, digest, size, last_used_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(cache_key) DO UPDATE SET algorithm = excluded.algorithm, format = excluded.format, digest = excluded.digest, size = excluded.size, last_used_at = excluded.last_used_at`,
			write.Key[:], write.Entry.Algorithm, write.Entry.Format, write.Entry.Digest, write.Entry.Size, stamp); err != nil {
			return fmt.Errorf("upsert content cache entry: %w", err)
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM content_cache WHERE last_used_at < ?`, formatTime(now.Add(-contentCacheRetention))); err != nil {
		return fmt.Errorf("prune content cache retention: %w", err)
	}
	limit := s.contentCacheRowLimit
	if limit <= 0 {
		limit = contentCacheDefaultLimit
	}
	var rows int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM content_cache`).Scan(&rows); err != nil {
		return fmt.Errorf("count content cache rows: %w", err)
	}
	if rows > limit {
		if _, err = tx.ExecContext(ctx, `DELETE FROM content_cache WHERE cache_key IN (
SELECT cache_key FROM content_cache ORDER BY last_used_at ASC, cache_key ASC LIMIT ?)`, rows-limit); err != nil {
			return fmt.Errorf("prune content cache rows: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit content cache transaction: %w", err)
	}
	return secureSQLiteFiles(s.path, guard)
}

// validContentCacheEntry accepts only a complete summary carrying the exact
// v1 cache format and an exact lowercase SHA-256 digest.
func validContentCacheEntry(entry evidence.CacheEntry) bool {
	return entry.Status == model.EvidenceComplete &&
		entry.Algorithm == "sha256" &&
		entry.Format == contentCacheFormat &&
		lowercaseSHA256Hex(entry.Digest) &&
		entry.Size >= 0
}
