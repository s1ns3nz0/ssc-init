package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const (
	DefaultProjectExpiry = 30 * 24 * time.Hour
	MaxLocalExpiry       = 90 * 24 * time.Hour
)

var errKnownMaliciousException = errors.New("exception cannot override known-malicious evidence")

func validateExceptions(document Document) error {
	rules := make(map[string]bool, len(document.Rules))
	for _, rule := range document.Rules {
		rules[rule.ID] = true
	}
	for index, exception := range document.Exceptions {
		at := fmt.Sprintf("exceptions[%d]", index)
		if !rules[exception.RuleID] {
			return fmt.Errorf("%s.ruleId: unknown rule identifier", at)
		}
		if strings.TrimSpace(exception.Reason) == "" {
			return fmt.Errorf("%s.reason: missing exception reason", at)
		}
		if exception.ExpiresAt.IsZero() {
			return fmt.Errorf("%s.expiresAt: permanent trust is prohibited", at)
		}
		switch exception.Scope {
		case ScopeRun:
			if exception.AssetID != "" || exception.Digest != "" || exception.ProjectID != "" {
				return fmt.Errorf("%s: run exception carries an incompatible subject", at)
			}
		case ScopeAsset:
			if exception.AssetID == "" || !validPolicyDigest(exception.Digest) || exception.ProjectID != "" {
				return fmt.Errorf("%s: asset exception requires an exact asset and digest", at)
			}
			assetType, _, _, version := inventory.ParseAssetID(exception.AssetID)
			if versionBearingAssetType(assetType) && version == "" {
				return fmt.Errorf("%s.assetId: all-version trust is prohibited", at)
			}
		case ScopeProject:
			if exception.ProjectID == "" || exception.AssetID != "" || exception.Digest != "" {
				return fmt.Errorf("%s: project exception requires one exact project", at)
			}
		default:
			return fmt.Errorf("%s.scope: unsupported exception scope", at)
		}
	}
	return nil
}

func versionBearingAssetType(assetType string) bool {
	switch assetType {
	case "agent-plugin", "agent-skill", "ide-extension", "pkg":
		return true
	default:
		return false
	}
}

func validPolicyDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, character := range []byte(digest) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// VerifyExceptions applies checks requiring runtime sources. Passing now also
// enforces the local 90-day maximum; omitting it performs the intelligence
// refusal only, preserving a clock-free document parser.
func VerifyExceptions(document Document, intelligence MaliciousIndex, now ...time.Time) error {
	for index, exception := range document.Exceptions {
		if len(now) > 0 && exception.ExpiresAt.After(now[0].Add(MaxLocalExpiry)) {
			return fmt.Errorf("exceptions[%d].expiresAt: exception exceeds the local maximum", index)
		}
		if exception.Scope == ScopeAsset && intelligence != nil && intelligence.KnownMalicious(exception.AssetID, exception.Digest) {
			return fmt.Errorf("exceptions[%d]: %w", index, errKnownMaliciousException)
		}
	}
	return nil
}

func applyExceptions(input Input, violations []Violation) ([]Violation, []Applied, []Applied) {
	exceptions := append(append([]Exception(nil), input.Sources.Document.Exceptions...), input.Exceptions...)
	kept := make([]Violation, 0, len(violations))
	applied := []Applied{}
	expired := []Applied{}
	for _, violation := range violations {
		suppressed := false
		for _, exception := range exceptions {
			if exception.RuleID != violation.RuleID || !exceptionMatches(input.Inventory, exception, violation) {
				continue
			}
			entry := Applied{RuleID: violation.RuleID, AssetID: violation.AssetID}
			if !input.Now.Before(exception.ExpiresAt) {
				expired = appendUniqueApplied(expired, entry)
				continue
			}
			applied = appendUniqueApplied(applied, entry)
			suppressed = true
			break
		}
		if !suppressed {
			kept = append(kept, violation)
		}
	}
	return kept, applied, expired
}

func exceptionMatches(current model.Inventory, exception Exception, violation Violation) bool {
	switch exception.Scope {
	case ScopeRun:
		return true
	case ScopeAsset:
		if exception.AssetID != violation.AssetID {
			return false
		}
		for _, evidence := range current.Evidence {
			if evidence.AssetID == violation.AssetID && evidence.Status == model.EvidenceComplete && evidence.Digest == exception.Digest {
				return true
			}
		}
	case ScopeProject:
		for _, observation := range current.Observations {
			if observation.AssetID == violation.AssetID && observation.ProjectID == exception.ProjectID {
				return true
			}
		}
	}
	return false
}

func appendUniqueApplied(values []Applied, candidate Applied) []Applied {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}
