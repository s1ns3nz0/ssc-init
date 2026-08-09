package bundle

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

var attackTechniquePattern = regexp.MustCompile(`\AT[0-9]{4}(?:\.[0-9]{3})?\z`)

func validateTIPayload(payload TIPayload) error {
	if len(payload.Records) > 100_000 {
		return ErrMalformed
	}
	seen := make(map[string]struct{}, len(payload.Records))
	for _, record := range payload.Records {
		if !boundedPublicValue(record.ID, 256) || !boundedPublicValue(record.AssetID, 1024) ||
			!oneOf(record.Verdict, "known-malicious", "behaviorally-malicious", "suspicious", "needs-review", "no-finding") ||
			!oneOf(record.Confidence, "low", "medium", "high") || !boundedPublicValue(record.License, 256) ||
			len(record.SourceURLs) == 0 || len(record.SourceURLs) > 32 || len(record.CampaignIDs) > 64 || len(record.AttackTechniques) > 64 {
			return ErrMalformed
		}
		if _, duplicate := seen[record.ID]; duplicate {
			return ErrMalformed
		}
		seen[record.ID] = struct{}{}
		if record.SHA256 != "" {
			decoded, err := hex.DecodeString(record.SHA256)
			if err != nil || len(decoded) != 32 {
				return ErrMalformed
			}
		}
		retrieved, retrievedErr := time.Parse(time.RFC3339, record.RetrievedAt)
		validUntil, validErr := time.Parse(time.RFC3339, record.ValidUntil)
		if retrievedErr != nil || validErr != nil || validUntil.Before(retrieved) {
			return ErrMalformed
		}
		for _, source := range record.SourceURLs {
			parsed, err := url.Parse(source)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || len(source) > 2048 || privacy.ContainsSensitiveValue(source) {
				return ErrMalformed
			}
		}
		for _, value := range record.CampaignIDs {
			if !boundedPublicValue(value, 256) {
				return ErrMalformed
			}
		}
		for _, technique := range record.AttackTechniques {
			if !attackTechniquePattern.MatchString(technique) {
				return ErrMalformed
			}
		}
	}
	return nil
}

func boundedPublicValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !privacy.ContainsSensitiveValue(value)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
