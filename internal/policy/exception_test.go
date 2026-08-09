package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

const exceptionRules = `[{"id":"unpinned","family":"pin","enabled":true,"description":"d"},{"id":"pin-mismatch","family":"pin","enabled":true,"description":"d"}]`

func TestLoadRefusesProhibitedExceptionForms(t *testing.T) {
	for name, exception := range map[string]string{
		"permanent trust": `{"ruleId":"unpinned","scope":"project","projectId":"project:sha256:aa","reason":"r"}`,
		"unscoped":        `{"ruleId":"unpinned","scope":"project","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"all-version":     `{"ruleId":"pin-mismatch","scope":"asset","assetId":"agent-plugin:claude:helpful-utils","digest":"` + strings.Repeat("a", 64) + `","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"no digest":       `{"ruleId":"pin-mismatch","scope":"asset","assetId":"agent-plugin:claude:helpful-utils@1.0.0","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"unknown scope":   `{"ruleId":"unpinned","scope":"publisher","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"unknown rule":    `{"ruleId":"no-such-rule","scope":"run","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
	} {
		source := `{"schemaVersion":"ssc-init.policy.v1","rules":` + exceptionRules + `,"exceptions":[` + exception + `]}`
		if _, err := policy.Load([]byte(source)); err == nil {
			t.Fatalf("%s: Load accepted a prohibited exception", name)
		}
	}
}

type knownDigest string

func (known knownDigest) KnownMalicious(_ string, digest string) bool { return digest == string(known) }

func validAssetExceptionDocument(t *testing.T, expires time.Time) policy.Document {
	t.Helper()
	source := `{"schemaVersion":"ssc-init.policy.v1","rules":` + exceptionRules + `,"exceptions":[{"ruleId":"pin-mismatch","scope":"asset","assetId":"agent-plugin:claude:helpful-utils@1.0.0","digest":"` + strings.Repeat("3", 64) + `","reason":"approved","expiresAt":"` + expires.UTC().Format(time.RFC3339) + `"}]}`
	document, err := policy.Load([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestVerifyExceptionsRefusesKnownMaliciousHash(t *testing.T) {
	document := validAssetExceptionDocument(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err := policy.VerifyExceptions(document, knownDigest(strings.Repeat("3", 64))); err == nil {
		t.Fatal("an exception for a known-malicious hash was accepted")
	} else if strings.Contains(err.Error(), strings.Repeat("3", 64)) {
		t.Fatalf("known-malicious refusal leaked the digest: %v", err)
	}
	if err := policy.VerifyExceptions(document, nil); err != nil {
		t.Fatalf("missing intelligence manufactured a refusal: %v", err)
	}
}

func TestVerifyExceptionsRejectsBeyondLocalMaximum(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	document := validAssetExceptionDocument(t, now.Add(policy.MaxLocalExpiry+time.Second))
	if err := policy.VerifyExceptions(document, nil, now); err == nil {
		t.Fatal("exception beyond the local maximum was accepted")
	}
}

func TestExpiredExceptionStopsApplyingAndIsReported(t *testing.T) {
	const assetID = "agent-plugin:claude:helpful-utils@1.0.0"
	expires := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	document := validAssetExceptionDocument(t, expires)
	inventory := pinFixture(model.EvidenceComplete, strings.Repeat("3", 64))
	pins := []policy.Pin{{AssetID: assetID, Kind: string(model.EvidenceTreeSHA256), Subject: model.EvidenceSubjectPayloadTree, Digest: strings.Repeat("1", 64)}}

	before := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: document}, Inventory: inventory, Pins: pins, Now: expires.Add(-time.Second)})
	if len(before.Violations) != 0 || len(before.Applied) != 1 || len(before.Expired) != 0 {
		t.Fatalf("active exception did not suppress: %+v", before)
	}
	after := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: document}, Inventory: inventory, Pins: pins, Now: expires})
	if len(after.Violations) != 1 || len(after.Applied) != 0 || len(after.Expired) != 1 {
		t.Fatalf("expired exception did not restore violation: %+v", after)
	}
}

func TestProjectExceptionDefaultsToThirtyDays(t *testing.T) {
	if policy.DefaultProjectExpiry != 30*24*time.Hour {
		t.Fatalf("default project expiry = %s", policy.DefaultProjectExpiry)
	}
	if policy.MaxLocalExpiry != 90*24*time.Hour {
		t.Fatalf("max local expiry = %s", policy.MaxLocalExpiry)
	}
}
