package collector

import (
	"context"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type targetedFakeCollector struct{}

func (targetedFakeCollector) Name() string { return "mcp" }

func (targetedFakeCollector) Collect(context.Context, Environment) (model.CollectorResult, error) {
	return model.CollectorResult{}, nil
}

func (targetedFakeCollector) Targets() []model.TargetSpec { return nil }

var _ TargetedCollector = targetedFakeCollector{}

func TestApplyTargetContractSynthesizesMissingTarget(t *testing.T) {
	specs := []model.TargetSpec{{
		ID: "mcp.codex.user", Collector: "mcp", Platform: "darwin",
		Scope: model.ScopeUser, Method: model.TargetFile,
	}}
	got := ApplyTargetContract("mcp", specs, model.CollectorResult{Collector: "mcp"})
	if got.Status != model.CoveragePartial {
		t.Fatalf("status=%q", got.Status)
	}
	if len(got.Targets) != 1 || got.Targets[0].Status != model.TargetUnsupported {
		t.Fatalf("targets=%+v", got.Targets)
	}
	if len(got.Targets[0].Errors) != 1 || got.Targets[0].Errors[0].Code != "target_not_reported" {
		t.Fatalf("errors=%+v", got.Targets[0].Errors)
	}
}

func TestApplyTargetContractRejectsUnknownAndDuplicateInstances(t *testing.T) {
	specs := []model.TargetSpec{{
		ID: "mcp.codex.user", Collector: "mcp", Platform: "darwin",
		Scope: model.ScopeUser, Method: model.TargetFile,
	}}
	tests := []struct {
		name    string
		targets []model.TargetCoverage
	}{
		{
			name: "unknown target",
			targets: []model.TargetCoverage{{
				TargetID: "mcp.unknown.user", Status: model.TargetComplete,
			}},
		},
		{
			name: "duplicate instance",
			targets: []model.TargetCoverage{
				{TargetID: "mcp.codex.user", InstanceRef: "default", Status: model.TargetComplete},
				{TargetID: "mcp.codex.user", InstanceRef: "default", Status: model.TargetNotPresent},
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := ApplyTargetContract("mcp", specs, model.CollectorResult{
				Collector: "mcp", Status: model.CoverageComplete, Targets: testCase.targets,
			})
			assertContractViolation(t, got)
		})
	}
}

func TestApplyTargetContractRejectsInvalidSpecsAndResults(t *testing.T) {
	validSpec := model.TargetSpec{
		ID: "mcp.codex.user", Collector: "mcp", Platform: "darwin",
		Scope: model.ScopeUser, Method: model.TargetFile,
	}
	validTarget := model.TargetCoverage{TargetID: validSpec.ID, Status: model.TargetComplete}
	tests := []struct {
		name    string
		specs   []model.TargetSpec
		targets []model.TargetCoverage
	}{
		{name: "empty target id", specs: []model.TargetSpec{{Collector: "mcp", Platform: "darwin", Scope: model.ScopeUser, Method: model.TargetFile}}},
		{name: "wrong owner", specs: []model.TargetSpec{{ID: validSpec.ID, Collector: "agents", Platform: "darwin", Scope: model.ScopeUser, Method: model.TargetFile}}},
		{name: "empty platform", specs: []model.TargetSpec{{ID: validSpec.ID, Collector: "mcp", Scope: model.ScopeUser, Method: model.TargetFile}}},
		{name: "unknown scope", specs: []model.TargetSpec{{ID: validSpec.ID, Collector: "mcp", Platform: "darwin", Scope: "unknown", Method: model.TargetFile}}},
		{name: "unknown method", specs: []model.TargetSpec{{ID: validSpec.ID, Collector: "mcp", Platform: "darwin", Scope: model.ScopeUser, Method: "unknown"}}},
		{name: "duplicate spec", specs: []model.TargetSpec{validSpec, validSpec}},
		{name: "empty result target id", specs: []model.TargetSpec{validSpec}, targets: []model.TargetCoverage{{Status: model.TargetComplete}}},
		{name: "unknown status", specs: []model.TargetSpec{validSpec}, targets: []model.TargetCoverage{{TargetID: validSpec.ID, Status: "unknown"}}},
		{name: "negative asset count", specs: []model.TargetSpec{validSpec}, targets: []model.TargetCoverage{{TargetID: validSpec.ID, Status: model.TargetComplete, Assets: -1}}},
		{name: "negative observation count", specs: []model.TargetSpec{validSpec}, targets: []model.TargetCoverage{{TargetID: validSpec.ID, Status: model.TargetComplete, Observations: -1}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			targets := testCase.targets
			if targets == nil && len(testCase.specs) > 0 && testCase.specs[0] == validSpec {
				targets = []model.TargetCoverage{validTarget}
			}
			got := ApplyTargetContract("mcp", testCase.specs, model.CollectorResult{
				Collector: "mcp", Status: model.CoverageComplete, Targets: targets,
			})
			assertContractViolation(t, got)
		})
	}
}

func TestApplyTargetContractRejectsMissingCollectorOwnership(t *testing.T) {
	got := ApplyTargetContract("", []model.TargetSpec{{
		ID: "mcp.codex.user", Platform: "darwin", Scope: model.ScopeUser, Method: model.TargetFile,
	}}, model.CollectorResult{Targets: []model.TargetCoverage{{
		TargetID: "mcp.codex.user", Status: model.TargetComplete,
	}}})
	if got.Status != model.CoverageFailed || len(got.Errors) != 1 || got.Errors[0].Code != "coverage_contract_violation" {
		t.Fatalf("got=%+v", got)
	}
}

func TestApplyTargetContractSortsSpecsAndInstances(t *testing.T) {
	specs := []model.TargetSpec{
		{ID: "mcp.zed.user", Collector: "mcp", Platform: "darwin", Scope: model.ScopeUser, Method: model.TargetFile},
		{ID: "mcp.codex.project", Collector: "mcp", Platform: "darwin", Scope: model.ScopeProject, Method: model.TargetFile},
	}
	got := ApplyTargetContract("mcp", specs, model.CollectorResult{
		Status: model.CoverageComplete,
		Targets: []model.TargetCoverage{
			{TargetID: "mcp.zed.user", Status: model.TargetNotPresent},
			{TargetID: "mcp.codex.project", InstanceRef: "project-b", Status: model.TargetComplete},
			{TargetID: "mcp.codex.project", InstanceRef: "project-a", Status: model.TargetComplete},
		},
	})
	want := [][2]string{
		{"mcp.codex.project", "project-a"},
		{"mcp.codex.project", "project-b"},
		{"mcp.zed.user", ""},
	}
	if got.Collector != "mcp" || got.Status != model.CoverageComplete || len(got.Targets) != len(want) {
		t.Fatalf("got=%+v", got)
	}
	for index := range want {
		if got.Targets[index].TargetID != want[index][0] || got.Targets[index].InstanceRef != want[index][1] {
			t.Fatalf("targets=%+v", got.Targets)
		}
	}
}

func TestAggregateTargetStatus(t *testing.T) {
	tests := []struct {
		name    string
		targets []model.TargetCoverage
		want    model.CoverageStatus
	}{
		{name: "complete and absent", targets: []model.TargetCoverage{{Status: model.TargetComplete}, {Status: model.TargetNotPresent}}, want: model.CoverageComplete},
		{name: "all skipped", targets: []model.TargetCoverage{{Status: model.TargetSkipped}}, want: model.CoverageSkipped},
		{name: "skipped mixed with performed", targets: []model.TargetCoverage{{Status: model.TargetSkipped}, {Status: model.TargetComplete}}, want: model.CoveragePartial},
		{name: "unsupported", targets: []model.TargetCoverage{{Status: model.TargetComplete}, {Status: model.TargetUnsupported}}, want: model.CoveragePartial},
		{name: "all unavailable", targets: []model.TargetCoverage{{Status: model.TargetUnavailable}, {Status: model.TargetUnavailable}}, want: model.CoverageUnavailable},
		{name: "unavailable mixed with absent", targets: []model.TargetCoverage{{Status: model.TargetNotPresent}, {Status: model.TargetUnavailable}}, want: model.CoveragePartial},
		{name: "partial", targets: []model.TargetCoverage{{Status: model.TargetPartial}}, want: model.CoveragePartial},
		{name: "empty", targets: nil, want: model.CoveragePartial},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := AggregateTargetStatus(testCase.targets); got != testCase.want {
				t.Fatalf("status=%q want=%q", got, testCase.want)
			}
		})
	}
}

func assertContractViolation(t *testing.T, got model.CollectorResult) {
	t.Helper()
	if got.Collector != "mcp" || got.Status != model.CoverageFailed {
		t.Fatalf("got=%+v", got)
	}
	if len(got.Errors) != 1 || got.Errors[0].Code != "coverage_contract_violation" {
		t.Fatalf("errors=%+v", got.Errors)
	}
}
