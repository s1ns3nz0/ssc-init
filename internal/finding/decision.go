package finding

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

// DecisionInput contains only verified or already-evaluated facts. Decide is
// pure and intentionally cannot claim host enforcement.
type DecisionInput struct {
	Inventory model.Inventory
	Findings  []model.Finding
	Policy    *bundle.ActiveBundle
	Local     policy.Result
	Now       time.Time
}

// Decide applies the closed organization precedence ladder and returns one
// winning decision per asset.
func Decide(input DecisionInput) []model.Finding {
	assets := make(map[string]model.Asset, len(input.Inventory.Assets))
	for _, asset := range input.Inventory.Assets {
		assets[asset.ID] = asset
	}
	existing := make(map[string]model.Finding, len(input.Findings))
	for _, item := range input.Findings {
		current, present := existing[item.AssetID]
		if !present || item.Level < current.Level || item.Level == current.Level && verdictRank(item.Verdict) > verdictRank(current.Verdict) {
			existing[item.AssetID] = item
		}
	}
	denies, allows, exceptions := organizationRules(input.Policy, input.Now)
	local := make(map[string][]policy.Violation)
	for _, violation := range input.Local.Violations {
		local[violation.AssetID] = append(local[violation.AssetID], violation)
	}

	ids := make(map[string]struct{}, len(assets)+len(existing)+len(local))
	for id := range assets {
		ids[id] = struct{}{}
	}
	for id := range existing {
		ids[id] = struct{}{}
	}
	for id := range local {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	result := make([]model.Finding, 0, len(ordered))
	for _, assetID := range ordered {
		asset, knownAsset := assets[assetID]
		prior, hasPrior := existing[assetID]
		if hasPrior && prior.Verdict == model.VerdictKnownMalicious {
			prior.Level, prior.Action = 1, model.ActionAdvisory
			result = append(result, prior)
			continue
		}
		if ruleIDs := denies[assetID]; len(ruleIDs) > 0 && knownAsset {
			result = append(result, policyFinding(asset, 2, model.ActionAdvisory, model.VerdictNeedsReview, model.SeverityHigh, ruleIDs, input.Policy, input.Now))
			continue
		}
		if allowIDs := exactAllows(allows[assetID], asset.SHA256); len(allowIDs) > 0 && knownAsset {
			result = append(result, policyFinding(asset, 3, model.ActionAllowed, model.VerdictNoFinding, model.SeverityInformational, allowIDs, input.Policy, input.Now))
			continue
		}
		violations := local[assetID]
		if len(violations) > 0 && knownAsset {
			ruleIDs := violationIDs(violations)
			if exceptionIDs := matchingExceptions(exceptions[assetID], ruleIDs); len(exceptionIDs) > 0 {
				result = append(result, policyFinding(asset, 4, model.ActionExcepted, model.VerdictNeedsReview, model.SeverityLow, append(ruleIDs, exceptionIDs...), input.Policy, input.Now))
			} else {
				result = append(result, policyFinding(asset, 5, model.ActionAdvisory, model.VerdictNeedsReview, model.SeverityMedium, ruleIDs, nil, input.Now))
			}
			continue
		}
		if hasPrior {
			result = append(result, prior)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

type allowRule struct{ id, digest string }
type exceptionRule struct{ id, ruleID string }

func organizationRules(active *bundle.ActiveBundle, now time.Time) (map[string][]string, map[string][]allowRule, map[string][]exceptionRule) {
	denies := map[string][]string{}
	allows := map[string][]allowRule{}
	exceptions := map[string][]exceptionRule{}
	if active == nil || active.Verified.Envelope.Family != bundle.FamilyPolicy || active.Verified.Envelope.Policy == nil {
		return denies, allows, exceptions
	}
	for _, rule := range active.Verified.Envelope.Policy.Denies {
		denies[rule.AssetID] = append(denies[rule.AssetID], rule.ID)
	}
	for _, rule := range active.Verified.Envelope.Policy.Allows {
		allows[rule.AssetID] = append(allows[rule.AssetID], allowRule{rule.ID, strings.ToLower(rule.SHA256)})
	}
	for _, rule := range active.Verified.Envelope.Policy.Exceptions {
		expires, err := time.Parse(time.RFC3339, rule.ExpiresAt)
		if err == nil && now.Before(expires) {
			exceptions[rule.AssetID] = append(exceptions[rule.AssetID], exceptionRule{rule.ID, rule.RuleID})
		}
	}
	return denies, allows, exceptions
}

func exactAllows(rules []allowRule, digest string) []string {
	var ids []string
	for _, rule := range rules {
		if digest != "" && strings.EqualFold(rule.digest, digest) {
			ids = append(ids, rule.id)
		}
	}
	return sortedUnique(ids)
}

func violationIDs(violations []policy.Violation) []string {
	ids := make([]string, 0, len(violations))
	for _, violation := range violations {
		ids = append(ids, violation.RuleID)
	}
	return sortedUnique(ids)
}

func matchingExceptions(rules []exceptionRule, violationIDs []string) []string {
	violations := make(map[string]struct{}, len(violationIDs))
	for _, id := range violationIDs {
		violations[id] = struct{}{}
	}
	var ids []string
	for _, rule := range rules {
		if _, ok := violations[rule.ruleID]; ok {
			ids = append(ids, rule.id)
		}
	}
	return sortedUnique(ids)
}

func policyFinding(asset model.Asset, level int, action model.FindingAction, verdict model.Verdict, severity model.Severity, ruleIDs []string, active *bundle.ActiveBundle, now time.Time) model.Finding {
	ruleIDs = sortedUnique(ruleIDs)
	identity := strings.Join(append([]string{"ssc-init.finding.v1", asset.ID, fmt.Sprintf("level:%d", level)}, ruleIDs...), "\x00")
	digest := sha256.Sum256([]byte(identity))
	confidence := model.ConfidenceHigh
	var references []model.BundleReference
	if active != nil {
		references = []model.BundleReference{{Family: string(bundle.FamilyPolicy), Sequence: active.Verified.Envelope.Sequence, Digest: fmt.Sprintf("%x", active.Verified.Digest)}}
		if active.Status.Freshness == bundle.FreshnessStale || active.Status.Freshness == bundle.FreshnessExpired {
			confidence = model.ConfidenceMedium
		}
	}
	return model.Finding{ID: fmt.Sprintf("finding:sha256:%x", digest), AssetID: asset.ID, AssetType: asset.Type, Version: asset.Version, SHA256: strings.ToLower(asset.SHA256), Verdict: verdict, Severity: severity, Confidence: confidence, Level: level, RuleIDs: ruleIDs, DetectedAt: now.UTC(), Action: action, Bundles: references}
}
