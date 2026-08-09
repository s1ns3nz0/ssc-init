package runtime

import (
	"context"
	"errors"
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

func TestRuntimeCollectorConnectsListenersOnlyToObservedProcesses(t *testing.T) {
	runner := &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		strings.Join([]string{psPath, "-axo", "pid=,comm="}, "\x1f"):                      {Stdout: "42 /usr/bin/node\n"},
		strings.Join([]string{lsofPath, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"}, "\x1f"): {Stdout: "p42\ncnode\nn*:3000\np99\ncghost\nn*:4000\n"},
	}}
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = true
	env.Runner = runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Relationships) != 1 {
		t.Fatalf("relationships=%+v", got.Relationships)
	}
	relationship := got.Relationships[0]
	if relationship.Kind != model.RelationshipConnectsTo {
		t.Fatalf("relationship=%+v", relationship)
	}
	var processID, matchedListenerID string
	for _, asset := range got.Assets {
		switch {
		case asset.Type == model.AssetProcess && asset.Metadata["pid"] == "42":
			processID = asset.ID
		case asset.Type == model.AssetListeningEndpoint && asset.Metadata["pid"] == "42":
			matchedListenerID = asset.ID
		}
	}
	if relationship.From != matchedListenerID || relationship.To != processID {
		t.Fatalf("relationship=%+v process=%q listener=%q", relationship, processID, matchedListenerID)
	}
}

func TestRuntimeCollectorDegradesTruncatedTargetsIndependentlyWithoutEcho(t *testing.T) {
	privateValue := "GITHUB_TOKEN=raw-secret"
	runner := &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		strings.Join([]string{psPath, "-axo", "pid=,comm="}, "\x1f"):                      {Stdout: privateValue, Truncated: true},
		strings.Join([]string{lsofPath, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"}, "\x1f"): {Stdout: "p42\ncnode\nnremote.example:3000\n"},
	}}
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = true
	env.Runner = runner

	got, err := New().Collect(context.Background(), env)
	if err != nil || got.Status != model.CoveragePartial || len(got.Assets) != 1 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if got.Targets[0].Status != model.TargetPartial || got.Targets[1].Status != model.TargetComplete {
		t.Fatalf("targets=%+v", got.Targets)
	}
	if strings.Contains(strings.Join([]string{got.Targets[0].Errors[0].Code, got.Targets[0].Errors[0].Message}, "\x00"), privateValue) {
		t.Fatalf("private probe output echoed: %+v", got.Targets[0])
	}
}

func TestRuntimeCollectorCancellationReturnsNoFalseSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = true
	env.Runner = cancelRuntimeRunner{cancel: cancel}

	got, err := New().Collect(ctx, env)
	if !errors.Is(err, context.Canceled) || len(got.Assets) != 0 || len(got.Targets) != 0 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

type panicRuntimeRunner struct{}

func (panicRuntimeRunner) Run(context.Context, string, ...string) (platform.CommandResult, error) {
	panic("runtime runner called")
}

type cancelRuntimeRunner struct{ cancel context.CancelFunc }

func (r cancelRuntimeRunner) Run(context.Context, string, ...string) (platform.CommandResult, error) {
	r.cancel()
	return platform.CommandResult{Stdout: "42 /private/tool\n"}, nil
}
