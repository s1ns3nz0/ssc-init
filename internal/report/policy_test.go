package report

import (
	"bytes"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestWritePolicyUsesTheSharedAssetColumns(t *testing.T) {
	var output bytes.Buffer
	result := policy.Result{Violations: []policy.Violation{{
		RuleID: "unpinned", AssetType: "agent-plugin", AssetName: "helpful-utils", Host: "claude",
	}}}
	if err := WritePolicy(&output, result); err != nil {
		t.Fatal(err)
	}
	want := "POLICY (1 violations)\n  unpinned            agent-plugin  helpful-utils (claude)\n"
	if output.String() != want {
		t.Fatalf("output=%q want=%q", output.String(), want)
	}
}
