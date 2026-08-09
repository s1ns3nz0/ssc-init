package bundle

import (
	"encoding/hex"
	"time"
)

const maxOrganizationException = 90 * 24 * time.Hour

func validatePolicyPayload(payload PolicyPayload, generatedAt time.Time) error {
	if len(payload.Denies) > 10_000 || len(payload.Allows) > 10_000 || len(payload.Exceptions) > 10_000 || len(payload.Tests) > 10_000 {
		return ErrMalformed
	}
	ids := map[string]struct{}{}
	deniedAssets := map[string]struct{}{}
	for _, rule := range payload.Denies {
		if !validPolicyIdentity(rule.ID, rule.AssetID, ids) {
			return ErrMalformed
		}
		deniedAssets[rule.AssetID] = struct{}{}
	}
	for _, allow := range payload.Allows {
		if !validPolicyIdentity(allow.ID, allow.AssetID, ids) || !validSHA256(allow.SHA256) {
			return ErrMalformed
		}
		if _, conflict := deniedAssets[allow.AssetID]; conflict {
			return ErrMalformed
		}
	}
	for _, exception := range payload.Exceptions {
		if !validPolicyIdentity(exception.ID, exception.AssetID, ids) || !boundedPublicValue(exception.RuleID, 256) ||
			!boundedPublicValue(exception.Approver, 256) || !boundedPublicValue(exception.Reason, 1024) || !boundedPublicValue(exception.Ticket, 256) ||
			exception.RuleID == "known-malicious" {
			return ErrMalformed
		}
		expiresAt, err := time.Parse(time.RFC3339, exception.ExpiresAt)
		if err != nil || !expiresAt.After(generatedAt) || expiresAt.Sub(generatedAt) > maxOrganizationException {
			return ErrMalformed
		}
	}
	seenTests := map[string]struct{}{}
	for _, test := range payload.Tests {
		if !boundedPublicValue(test.Name, 256) || !boundedPublicValue(test.AssetID, 1024) || test.WantRule != "" && !boundedPublicValue(test.WantRule, 256) {
			return ErrMalformed
		}
		if _, duplicate := seenTests[test.Name]; duplicate {
			return ErrMalformed
		}
		seenTests[test.Name] = struct{}{}
	}
	if payload.Retention != nil {
		if payload.Retention.SnapshotsDays < 1 || payload.Retention.SnapshotsDays > 3650 ||
			payload.Retention.HistoryDays < 1 || payload.Retention.HistoryDays > 3650 ||
			payload.Retention.IncidentsDays < 1 || payload.Retention.IncidentsDays > 3650 {
			return ErrMalformed
		}
	}
	return nil
}

func validPolicyIdentity(id, assetID string, seen map[string]struct{}) bool {
	if !boundedPublicValue(id, 256) || !boundedPublicValue(assetID, 1024) {
		return false
	}
	if _, duplicate := seen[id]; duplicate {
		return false
	}
	seen[id] = struct{}{}
	return true
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
