package finding

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestDecideKeepsKnownMaliciousAtUnexceptionableLevelOne(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	asset := decisionAsset("asset:bad", "a")
	input := DecisionInput{
		Inventory: model.Inventory{Assets: []model.Asset{asset}},
		Findings:  []model.Finding{validDecisionFinding(asset, model.VerdictKnownMalicious, 1, "ti:bad", now)},
		Policy:    activePolicy(bundle.PolicyPayload{Denies: []bundle.PolicyRule{}, Allows: []bundle.PolicyAllow{}, Exceptions: []bundle.PolicyException{{ID: "except-bad", RuleID: "known-malicious", AssetID: asset.ID, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}}, Tests: []bundle.PolicyTest{}}),
		Now:       now,
	}
	got := Decide(input)
	if len(got) != 1 || got[0].Level != 1 || got[0].Action != model.ActionAdvisory {
		t.Fatalf("decisions=%+v", got)
	}
}

func TestDecideAppliesDenyBeforeAllowAndLocalException(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	asset := decisionAsset("asset:denied", "b")
	input := DecisionInput{
		Inventory: model.Inventory{Assets: []model.Asset{asset}},
		Policy: activePolicy(bundle.PolicyPayload{
			Denies: []bundle.PolicyRule{{ID: "org-deny", AssetID: asset.ID}}, Allows: []bundle.PolicyAllow{}, Exceptions: []bundle.PolicyException{}, Tests: []bundle.PolicyTest{},
		}),
		Local: policy.Result{Violations: []policy.Violation{{RuleID: "local-rule", Level: 5, AssetID: asset.ID}}},
		Now:   now,
	}
	got := Decide(input)
	if len(got) != 1 || got[0].Level != 2 || got[0].RuleIDs[0] != "org-deny" || got[0].Action != model.ActionAdvisory {
		t.Fatalf("decisions=%+v", got)
	}
}

func TestDecideRequiresExactDigestForOrganizationAllow(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	asset := decisionAsset("asset:allowed", "c")
	base := DecisionInput{Inventory: model.Inventory{Assets: []model.Asset{asset}}, Now: now}
	base.Policy = activePolicy(bundle.PolicyPayload{Denies: []bundle.PolicyRule{}, Allows: []bundle.PolicyAllow{{ID: "org-allow", AssetID: asset.ID, SHA256: asset.SHA256}}, Exceptions: []bundle.PolicyException{}, Tests: []bundle.PolicyTest{}})
	got := Decide(base)
	if len(got) != 1 || got[0].Level != 3 || got[0].Action != model.ActionAllowed {
		t.Fatalf("exact allow=%+v", got)
	}
	base.Inventory.Assets[0].SHA256 = strings.Repeat("d", 64)
	if got = Decide(base); len(got) != 0 {
		t.Fatalf("changed bytes allowed=%+v", got)
	}
}

func TestDecideAppliesSignedExceptionThenFallsBackToLevelFive(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	asset := decisionAsset("asset:review", "e")
	input := DecisionInput{
		Inventory: model.Inventory{Assets: []model.Asset{asset}},
		Policy:    activePolicy(bundle.PolicyPayload{Denies: []bundle.PolicyRule{}, Allows: []bundle.PolicyAllow{}, Exceptions: []bundle.PolicyException{{ID: "org-exception", RuleID: "local-rule", AssetID: asset.ID, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}}, Tests: []bundle.PolicyTest{}}),
		Local:     policy.Result{Violations: []policy.Violation{{RuleID: "local-rule", Level: 5, AssetID: asset.ID}}},
		Now:       now,
	}
	got := Decide(input)
	if len(got) != 1 || got[0].Level != 4 || got[0].Action != model.ActionExcepted || strings.Join(got[0].RuleIDs, ",") != "local-rule,org-exception" {
		t.Fatalf("exception=%+v", got)
	}
	input.Now = now.Add(2 * time.Hour)
	got = Decide(input)
	if len(got) != 1 || got[0].Level != 5 || got[0].Action != model.ActionAdvisory {
		t.Fatalf("expired exception=%+v", got)
	}
}

func decisionAsset(id, hashByte string) model.Asset {
	return model.Asset{ID: id, Type: model.AssetTool, Name: id, SHA256: strings.Repeat(hashByte, 64)}
}

func validDecisionFinding(asset model.Asset, verdict model.Verdict, level int, intelligenceID string, now time.Time) model.Finding {
	return model.Finding{ID: "finding:fixture", AssetID: asset.ID, AssetType: asset.Type, SHA256: asset.SHA256, Verdict: verdict, Severity: severityFor(verdict), Confidence: model.ConfidenceHigh, Level: level, IntelligenceIDs: []string{intelligenceID}, DetectedAt: now, Action: model.ActionAdvisory, Bundles: []model.BundleReference{{Family: "ti", Sequence: 1, Digest: strings.Repeat("f", 64)}}}
}

func activePolicy(payload bundle.PolicyPayload) *bundle.ActiveBundle {
	digest := sha256.Sum256([]byte("policy bundle"))
	return &bundle.ActiveBundle{Verified: bundle.Verified{Envelope: bundle.Envelope{Family: bundle.FamilyPolicy, Sequence: 9, Policy: &payload}, Digest: digest}, Status: bundle.Status{Family: bundle.FamilyPolicy, Freshness: bundle.FreshnessFresh, Sequence: 9}}
}
