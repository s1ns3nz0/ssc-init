package policy_test

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func pinDocument(t *testing.T, mismatch, unpinned bool) policy.Document {
	t.Helper()
	source := `{"schemaVersion":"ssc-init.policy.v1","rules":[` +
		`{"id":"pin-mismatch","family":"pin","enabled":` + boolJSON(mismatch) + `,"description":"d"},` +
		`{"id":"unpinned","family":"pin","enabled":` + boolJSON(unpinned) + `,"description":"d"}]}`
	document, err := policy.Load([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func boolJSON(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func pinFixture(status model.EvidenceStatus, digest string) model.Inventory {
	const assetID = "agent-plugin:claude:helpful-utils@1.0.0"
	return model.Inventory{
		Assets:   []model.Asset{{ID: assetID, Type: model.AssetAgentPlugin, Name: "helpful-utils", Source: "claude"}},
		Evidence: []model.ContentEvidence{{ID: "ev-1", AssetID: assetID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: status, Algorithm: "sha256", Digest: digest}},
	}
}

func TestPinMismatchFiresOnlyOnCompleteEvidence(t *testing.T) {
	const assetID = "agent-plugin:claude:helpful-utils@1.0.0"
	pins := []policy.Pin{{AssetID: assetID, Kind: string(model.EvidenceTreeSHA256), Subject: model.EvidenceSubjectPayloadTree, Digest: strings.Repeat("1", 64)}}
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t, true, true)}, Inventory: pinFixture(model.EvidenceComplete, strings.Repeat("2", 64)), Pins: pins})
	if len(result.Violations) != 1 || result.Violations[0].RuleID != "pin-mismatch" {
		t.Fatalf("unexpected violations: %+v", result.Violations)
	}

	result = policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t, true, true)}, Inventory: pinFixture(model.EvidenceUnavailable, ""), Pins: pins})
	if len(result.Violations) != 0 {
		t.Fatalf("coverage gap produced a pin claim: %+v", result.Violations)
	}
}

func TestUnpinnedAndPinMismatchAreIndependentlyEnabled(t *testing.T) {
	const assetID = "agent-plugin:claude:helpful-utils@1.0.0"
	pins := []policy.Pin{{AssetID: assetID, Kind: string(model.EvidenceTreeSHA256), Subject: model.EvidenceSubjectPayloadTree, Digest: strings.Repeat("1", 64)}}
	mismatch := pinFixture(model.EvidenceComplete, strings.Repeat("2", 64))
	if got := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t, false, true)}, Inventory: mismatch, Pins: pins}); len(got.Violations) != 0 {
		t.Fatalf("unpinned fired despite an existing pin: %+v", got.Violations)
	}
	if got := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t, true, false)}, Inventory: mismatch}); len(got.Violations) != 0 {
		t.Fatalf("pin-mismatch fired without a pin: %+v", got.Violations)
	}
}

func TestUnpinnedNeverFiresOnEvidenceWithNoTrustedDigest(t *testing.T) {
	for _, status := range []model.EvidenceStatus{model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable, model.EvidenceSkipped, model.EvidenceUnsupported} {
		result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t, false, true)}, Inventory: pinFixture(status, "")})
		if len(result.Violations) != 0 {
			t.Fatalf("status %s produced unpinned: %+v", status, result.Violations)
		}
	}
}
