package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestRuntimeCollectorIsSkippedWithoutExternalProbes(t *testing.T) {
	env := testutil.Environment(t, t.TempDir())
	env.Runner = panicRuntimeRunner{}
	got, err := New().Collect(context.Background(), env)
	if err != nil || got.Status != model.CoverageSkipped || len(got.Assets) != 0 || len(got.Targets) != 2 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	for _, target := range got.Targets {
		if target.Status != model.TargetSkipped {
			t.Fatalf("target=%+v", target)
		}
	}
}

func TestRuntimeCollectorUsesExactCommandsAndPersistsOnlyNormalizedFacts(t *testing.T) {
	runner := &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		strings.Join([]string{psPath, "-axo", "pid=,comm="}, "\x1f"):                      {Stdout: "42 /Users/private/bin/node\n"},
		strings.Join([]string{lsofPath, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"}, "\x1f"): {Stdout: "p42\ncnode\nn*:3000\n"},
	}}
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = true
	env.Runner = runner
	got, err := New().Collect(context.Background(), env)
	if err != nil || got.Status != model.CoverageComplete || len(got.Assets) != 2 || len(got.Observations) != 2 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if len(runner.Calls) != 2 || runner.Calls[0] != strings.Join([]string{psPath, "-axo", "pid=,comm="}, "\x1f") || runner.Calls[1] != strings.Join([]string{lsofPath, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"}, "\x1f") {
		t.Fatalf("calls=%q", runner.Calls)
	}
	for _, asset := range got.Assets {
		if strings.Contains(asset.ID+asset.Name+asset.Path, "/Users/private") {
			t.Fatalf("asset leaked path: %+v", asset)
		}
	}
}

type panicRuntimeRunner struct{}

func (panicRuntimeRunner) Run(context.Context, string, ...string) (platform.CommandResult, error) {
	panic("runtime runner called")
}
