package bundle

import (
	"strings"
	"testing"
	"time"
)

func TestOrganizationPolicyValidationAcceptsBoundedPrecedenceFacts(t *testing.T) {
	generated := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	payload := PolicyPayload{
		Denies:     []PolicyRule{{ID: "deny-bad", AssetID: "pkg:npm/bad@1.0.0"}},
		Allows:     []PolicyAllow{{ID: "allow-good", AssetID: "pkg:npm/good@1.0.0", SHA256: strings.Repeat("a", 64)}},
		Exceptions: []PolicyException{{ID: "exception-1", RuleID: "deny-review", AssetID: "pkg:npm/review@1.0.0", Approver: "security-team", Reason: "ticketed investigation", Ticket: "SEC-123", ExpiresAt: "2026-09-01T00:00:00Z"}},
		Tests:      []PolicyTest{{Name: "bad denied", AssetID: "pkg:npm/bad@1.0.0", WantRule: "deny-bad"}},
		Retention:  &Retention{SnapshotsDays: 30, HistoryDays: 90, IncidentsDays: 365},
	}
	if err := validatePolicyPayload(payload, generated); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationPolicyValidationRejectsConflictAndProhibitedExceptionWithoutEcho(t *testing.T) {
	generated := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	secret := "GITHUB_TOKEN=raw-secret"
	cases := []PolicyPayload{
		{Denies: []PolicyRule{{ID: "deny", AssetID: "asset"}}, Allows: []PolicyAllow{{ID: "allow", AssetID: "asset", SHA256: strings.Repeat("a", 64)}}, Exceptions: []PolicyException{}, Tests: []PolicyTest{}},
		{Denies: []PolicyRule{}, Allows: []PolicyAllow{}, Exceptions: []PolicyException{{ID: "e", RuleID: "known-malicious", AssetID: "asset", Approver: "a", Reason: "r", Ticket: "t", ExpiresAt: "2026-08-20T00:00:00Z"}}, Tests: []PolicyTest{}},
		{Denies: []PolicyRule{}, Allows: []PolicyAllow{}, Exceptions: []PolicyException{{ID: "e", RuleID: "review", AssetID: "asset", Approver: secret, Reason: "r", Ticket: "t", ExpiresAt: "2026-08-20T00:00:00Z"}}, Tests: []PolicyTest{}},
		{Denies: []PolicyRule{}, Allows: []PolicyAllow{}, Exceptions: []PolicyException{{ID: "e", RuleID: "review", AssetID: "asset", Approver: "a", Reason: "r", Ticket: "t", ExpiresAt: "2027-08-20T00:00:00Z"}}, Tests: []PolicyTest{}},
	}
	for _, payload := range cases {
		if err := validatePolicyPayload(payload, generated); err != ErrMalformed || strings.Contains(err.Error(), secret) {
			t.Fatalf("payload accepted or echoed: err=%v", err)
		}
	}
}
