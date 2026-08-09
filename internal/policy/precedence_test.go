package policy_test

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestPrecedenceLevelsAreAllPresentAndOrdered(t *testing.T) {
	levels := policy.Levels(policy.Sources{})
	want := []policy.Level{
		{Number: 1, Name: "known-malicious-evidence", Active: false, Reason: "no evidence available"},
		{Number: 2, Name: "organization-deny", Active: false, Reason: "no bundle present"},
		{Number: 3, Name: "organization-allow", Active: false, Reason: "no bundle present"},
		{Number: 4, Name: "user-exceptions", Active: true},
		{Number: 5, Name: "default-product-policy", Active: true},
	}
	if len(levels) != len(want) {
		t.Fatalf("got %d precedence levels, want %d", len(levels), len(want))
	}
	for index := range want {
		if levels[index] != want[index] {
			t.Fatalf("level %d: got %+v, want %+v", index+1, levels[index], want[index])
		}
	}
}

func TestKnownMaliciousLevelIsInertWithoutIntelligence(t *testing.T) {
	decided, reason := policy.KnownMalicious(policy.Sources{}, "agent-plugin:claude:helpful-utils@1.0.0", "sha256:00")
	if decided {
		t.Fatal("level 1 decided without any intelligence")
	}
	if reason != "no evidence available" {
		t.Fatalf("level 1 reason = %q, want %q", reason, "no evidence available")
	}
}

type maliciousIndex bool

func (index maliciousIndex) KnownMalicious(string, string) bool { return bool(index) }

func TestKnownMaliciousLevelDelegatesToIntelligence(t *testing.T) {
	decided, reason := policy.KnownMalicious(policy.Sources{Intelligence: maliciousIndex(true)}, "asset", "digest")
	if !decided || reason != "" {
		t.Fatalf("KnownMalicious = %v %q, want true and no inert reason", decided, reason)
	}
}

func TestLocalDocumentCannotActivateOrganizationLevels(t *testing.T) {
	document, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	levels := policy.Levels(policy.Sources{Document: document})
	if levels[1].Active || levels[2].Active {
		t.Fatalf("local document activated organization authority: %+v", levels)
	}
}
