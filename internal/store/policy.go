package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

// PolicyDecision is one bounded audit record. Outcome is a closed local value
// written by this package, never author-controlled text.
type PolicyDecision struct {
	RuleID      string
	AssetID     string
	Level       int
	Outcome     string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

func (s *Store) SavePins(ctx context.Context, pins []policy.Pin, pinnedAt time.Time) error {
	if pinnedAt.IsZero() {
		return errors.New("policy pin timestamp is required")
	}
	for _, pin := range pins {
		if err := validatePolicyStrings(pin.AssetID, pin.Kind, pin.Subject); err != nil {
			return err
		}
		if !validPolicyDigest(pin.Digest) {
			return errors.New("policy pin digest is invalid")
		}
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, pin := range pins {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_pins(asset_id,evidence_kind,subject,digest,pinned_at) VALUES(?,?,?,?,?)
ON CONFLICT(asset_id,evidence_kind,subject) DO UPDATE SET digest=excluded.digest,pinned_at=excluded.pinned_at`, pin.AssetID, pin.Kind, pin.Subject, pin.Digest, formatTime(pinnedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Pins(ctx context.Context) ([]policy.Pin, error) {
	db, _, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := db.QueryContext(ctx, `SELECT asset_id,evidence_kind,subject,digest FROM policy_pins ORDER BY asset_id,evidence_kind,subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []policy.Pin{}
	for rows.Next() {
		var pin policy.Pin
		if err := rows.Scan(&pin.AssetID, &pin.Kind, &pin.Subject, &pin.Digest); err != nil {
			return nil, err
		}
		result = append(result, pin)
	}
	return result, rows.Err()
}

func (s *Store) SaveExceptions(ctx context.Context, exceptions []policy.Exception, createdAt time.Time) error {
	if createdAt.IsZero() {
		return errors.New("policy exception timestamp is required")
	}
	for _, exception := range exceptions {
		if err := validatePolicyStrings(exception.RuleID, string(exception.Scope), exception.AssetID, exception.Digest, exception.ProjectID, exception.Reason); err != nil {
			return err
		}
		if exception.ExpiresAt.IsZero() {
			return errors.New("policy exception expiry is required")
		}
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, exception := range exceptions {
		subject := exceptionSubject(exception)
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_exceptions(rule_id,scope,subject_ref,reason,created_at,expires_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(rule_id,scope,subject_ref) DO UPDATE SET reason=excluded.reason,created_at=excluded.created_at,expires_at=excluded.expires_at`, exception.RuleID, exception.Scope, subject, exception.Reason, formatTime(createdAt), formatTime(exception.ExpiresAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Exceptions(ctx context.Context) ([]policy.Exception, error) {
	db, _, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := db.QueryContext(ctx, `SELECT rule_id,scope,subject_ref,reason,expires_at FROM policy_exceptions ORDER BY rule_id,scope,subject_ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []policy.Exception{}
	for rows.Next() {
		var exception policy.Exception
		var scope, subject, expiry string
		if err := rows.Scan(&exception.RuleID, &scope, &subject, &exception.Reason, &expiry); err != nil {
			return nil, err
		}
		exception.Scope = policy.Scope(scope)
		exception.ExpiresAt, err = parseTime(expiry)
		if err != nil {
			return nil, err
		}
		parseExceptionSubject(&exception, subject)
		result = append(result, exception)
	}
	return result, rows.Err()
}

func (s *Store) RecordDecisions(ctx context.Context, violations []policy.Violation, now time.Time) error {
	if now.IsZero() {
		return errors.New("policy decision timestamp is required")
	}
	for _, violation := range violations {
		if violation.Level < 1 || violation.Level > 5 {
			return errors.New("policy decision level is invalid")
		}
		if err := validatePolicyStrings(violation.RuleID, violation.AssetID); err != nil {
			return err
		}
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	for _, violation := range violations {
		if _, err := db.ExecContext(ctx, `INSERT INTO policy_decisions(rule_id,asset_id,level,outcome,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(rule_id,asset_id) DO UPDATE SET level=excluded.level,outcome=excluded.outcome,last_seen_at=excluded.last_seen_at`, violation.RuleID, violation.AssetID, violation.Level, "violation", formatTime(now), formatTime(now)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Decisions(ctx context.Context) ([]PolicyDecision, error) {
	db, _, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := db.QueryContext(ctx, `SELECT rule_id,asset_id,level,outcome,first_seen_at,last_seen_at FROM policy_decisions ORDER BY rule_id,asset_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PolicyDecision{}
	for rows.Next() {
		var decision PolicyDecision
		var first, last string
		if err := rows.Scan(&decision.RuleID, &decision.AssetID, &decision.Level, &decision.Outcome, &first, &last); err != nil {
			return nil, err
		}
		decision.FirstSeenAt, err = parseTime(first)
		if err != nil {
			return nil, err
		}
		decision.LastSeenAt, err = parseTime(last)
		if err != nil {
			return nil, err
		}
		result = append(result, decision)
	}
	return result, rows.Err()
}

func (s *Store) PruneDecisions(ctx context.Context, now time.Time, window time.Duration) error {
	if window <= 0 {
		return errors.New("policy decision retention is invalid")
	}
	db, _, done, err := s.beginOperation()
	if err != nil {
		return err
	}
	defer done()
	_, err = db.ExecContext(ctx, `DELETE FROM policy_decisions WHERE last_seen_at < ?`, formatTime(now.Add(-window)))
	return err
}

func validatePolicyStrings(values ...string) error {
	for _, value := range values {
		if err := validatePersistenceSafePath("policy value", value); err != nil {
			return err
		}
	}
	return nil
}

func validPolicyDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func exceptionSubject(exception policy.Exception) string {
	switch exception.Scope {
	case policy.ScopeAsset:
		return exception.AssetID + "@digest:" + exception.Digest
	case policy.ScopeProject:
		return exception.ProjectID
	default:
		return "run"
	}
}

func parseExceptionSubject(exception *policy.Exception, subject string) {
	switch exception.Scope {
	case policy.ScopeAsset:
		if index := strings.LastIndex(subject, "@digest:"); index >= 0 {
			exception.AssetID, exception.Digest = subject[:index], subject[index+8:]
		}
	case policy.ScopeProject:
		exception.ProjectID = subject
	}
}
