package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type BundleIndex struct {
	Family     string
	Sequence   uint64
	Version    string
	Digest     string
	Freshness  string
	ValidUntil time.Time
}

type BundleAudit struct {
	Family   string
	Action   string
	Sequence uint64
	Digest   string
}

func (s *Store) ReplaceBundleIndex(ctx context.Context, index BundleIndex, indexedAt time.Time) error {
	if !validBundleFamily(index.Family) || index.Sequence == 0 || index.Version == "" || len(index.Version) > 128 ||
		!validPolicyDigest(index.Digest) || !oneOfStore(index.Freshness, "fresh", "stale", "expired", "unavailable") || index.ValidUntil.IsZero() || indexedAt.IsZero() {
		return errors.New("bundle index is invalid")
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	_, err = db.ExecContext(ctx, `INSERT INTO bundle_index(family,sequence,version,digest,freshness,valid_until,indexed_at) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(family) DO UPDATE SET sequence=excluded.sequence,version=excluded.version,digest=excluded.digest,freshness=excluded.freshness,valid_until=excluded.valid_until,indexed_at=excluded.indexed_at`,
		index.Family, index.Sequence, index.Version, index.Digest, index.Freshness, formatTime(index.ValidUntil), formatTime(indexedAt))
	return err
}

func (s *Store) BundleIndex(ctx context.Context, family string) (BundleIndex, bool, error) {
	if !validBundleFamily(family) {
		return BundleIndex{}, false, errors.New("bundle family is invalid")
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return BundleIndex{}, false, err
	}
	defer done()
	var result BundleIndex
	var validUntil string
	err = db.QueryRowContext(ctx, `SELECT family,sequence,version,digest,freshness,valid_until FROM bundle_index WHERE family=?`, family).Scan(&result.Family, &result.Sequence, &result.Version, &result.Digest, &result.Freshness, &validUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return BundleIndex{}, false, nil
		}
		return BundleIndex{}, false, err
	}
	result.ValidUntil, err = parseTime(validUntil)
	return result, err == nil, err
}

func (s *Store) ClearBundleIndex(ctx context.Context, family string) error {
	if !validBundleFamily(family) {
		return errors.New("bundle family is invalid")
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	_, err = db.ExecContext(ctx, `DELETE FROM bundle_index WHERE family=?`, family)
	return err
}

func (s *Store) RecordBundleAudit(ctx context.Context, event BundleAudit, recordedAt time.Time) error {
	if !validBundleFamily(event.Family) || !oneOfStore(event.Action, "install", "rollback") || event.Sequence == 0 || !validPolicyDigest(event.Digest) || recordedAt.IsZero() {
		return errors.New("bundle audit event is invalid")
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	_, err = db.ExecContext(ctx, `INSERT INTO bundle_audit(family,action,sequence,digest,recorded_at) VALUES(?,?,?,?,?)`, event.Family, event.Action, event.Sequence, event.Digest, formatTime(recordedAt))
	return err
}

func validBundleFamily(value string) bool { return value == "ti" || value == "policy" }

func oneOfStore(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
