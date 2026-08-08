package report_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

func hookFixture() (model.Inventory, model.Delta) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
			{ID: "evidence:sha256:bbbb", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1},
			{ID: "evidence:sha256:cccc", AssetID: "pkg:pypi/charlie@3.0.0", ObservationID: "observation:sha256:3333", Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:bravo@2.0.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:gone"},
	}}
	return inventory, delta
}

func TestWriteHookSummaryRendersCappedGroupedDrift(t *testing.T) {
	inventory, delta := hookFixture()
	var first, second bytes.Buffer
	if err := report.WriteHookSummary(&first, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteHookSummary(&second, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("hook summary not deterministic:\n%q\n%q", first.String(), second.String())
	}
	output := first.String()
	for _, pattern := range []string{
		`^ssc-init: toolchain drift since last snapshot\n`,
		`(?m)^  added\s+ide-extension bravo@2\.0\.0 \(vscode\)$`,
		`(?m)^  removed\s+mcp github \(claude-code\)$`,
		`(?m)^  changed\s+2 evidence records \(alpha\)$`,
		`(?m)^  removed\s+1 evidence records$`,
		`(?m)^  issues: 1 non-complete evidence records \(partial 1\)$`,
	} {
		if !regexp.MustCompile(pattern).MatchString(output) {
			t.Fatalf("missing pattern %q in:\n%s", pattern, output)
		}
	}
	if strings.Contains(output, strings.Repeat("a", 64)) || strings.Contains(output, "unsupported") {
		t.Fatalf("summary leaks digests or counts unsupported:\n%s", output)
	}
}

func TestWriteHookSummaryIsSilentOnEmptyDelta(t *testing.T) {
	inventory, _ := hookFixture()
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, model.Delta{}); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("expected silence, got:\n%s", buffer.String())
	}
}

func TestWriteHookSummaryCapsDetailRows(t *testing.T) {
	var delta model.Delta
	for index := 0; index < 25; index++ {
		delta.Changes = append(delta.Changes, model.Change{
			Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset,
			EntityID: "agent-skill:claude:" + string(rune('a'+index)),
		})
	}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, model.Inventory{}, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if got := strings.Count(output, "\n  added"); got != 20 {
		t.Fatalf("detail rows=%d want 20:\n%s", got, output)
	}
	if !strings.Contains(output, "…and 5 more changes") {
		t.Fatalf("missing overflow line:\n%s", output)
	}
}
