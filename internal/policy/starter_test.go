package policy_test

import (
	"bytes"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestStarterDocumentShipsEveryRuleDisabled(t *testing.T) {
	document, err := policy.Load(policy.Starter())
	if err != nil {
		t.Fatalf("starter does not parse: %v", err)
	}
	if len(document.Rules) < 5 {
		t.Fatalf("starter ships %d rules, want at least five", len(document.Rules))
	}
	required := map[string]bool{"pin-mismatch": false, "unpinned": false, "mcp-shell-command": false, "mutable-version": false, "remote-script-execution": false}
	for _, rule := range document.Rules {
		if rule.Enabled {
			t.Fatalf("starter rule %q ships enabled", rule.ID)
		}
		if len(rule.Description) < 20 {
			t.Fatalf("starter rule %q has no usable description", rule.ID)
		}
		if _, ok := required[rule.ID]; ok {
			required[rule.ID] = true
		}
	}
	for rule, found := range required {
		if !found {
			t.Fatalf("starter is missing %q", rule)
		}
	}
	if len(document.Exceptions) != 0 {
		t.Fatal("starter ships an exception")
	}
}

func TestStarterIsByteStableAndReturnsAClone(t *testing.T) {
	first, second := policy.Starter(), policy.Starter()
	if !bytes.Equal(first, second) || !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatal("Starter is not byte-stable or lacks its final newline")
	}
	first[0] = 'x'
	if bytes.Equal(first, policy.Starter()) {
		t.Fatal("Starter exposed mutable embedded storage")
	}
}
