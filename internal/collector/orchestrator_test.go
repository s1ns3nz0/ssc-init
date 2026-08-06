package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

type fakeCollector struct {
	name   string
	result model.CollectorResult
	err    error
}

type collectorFunc struct {
	name string
	fn   func(context.Context, Environment) (model.CollectorResult, error)
}

func (f collectorFunc) Name() string { return f.name }

func (f collectorFunc) Collect(ctx context.Context, env Environment) (model.CollectorResult, error) {
	return f.fn(ctx, env)
}

func (f fakeCollector) Name() string { return f.name }

func (f fakeCollector) Collect(context.Context, Environment) (model.CollectorResult, error) {
	return f.result, f.err
}

func TestOrchestratorContainsPanicsAndDeadlines(t *testing.T) {
	o := Orchestrator{Timeout: 10 * time.Millisecond, MaxConcurrent: 3, Collectors: []Collector{
		collectorFunc{name: "panic", fn: func(context.Context, Environment) (model.CollectorResult, error) {
			panic("unexpected")
		}},
		collectorFunc{name: "timeout", fn: func(ctx context.Context, _ Environment) (model.CollectorResult, error) {
			<-ctx.Done()
			return model.CollectorResult{}, ctx.Err()
		}},
		fakeCollector{name: "ok", result: model.CollectorResult{Status: model.CoverageComplete}},
	}}

	got := o.Collect(context.Background(), Environment{})
	if len(got) != 3 {
		t.Fatalf("got=%+v", got)
	}
	if got[0].Collector != "ok" || got[0].Status != model.CoverageComplete {
		t.Fatalf("got=%+v", got)
	}
	if got[1].Collector != "panic" || got[1].Status != model.CoverageFailed {
		t.Fatalf("got=%+v", got)
	}
	if got[2].Collector != "timeout" || got[2].Status != model.CoverageFailed {
		t.Fatalf("got=%+v", got)
	}
}

func TestOrchestratorSanitizesCollectorFailures(t *testing.T) {
	const secretMarker = "ssc-init-secret-marker-4e5d7c"
	o := Orchestrator{Collectors: []Collector{
		fakeCollector{name: "error", err: fmt.Errorf("command failed: %s", secretMarker)},
		collectorFunc{name: "panic", fn: func(context.Context, Environment) (model.CollectorResult, error) {
			panic(secretMarker)
		}},
	}}

	got := o.Collect(context.Background(), Environment{})
	if strings.Contains(fmt.Sprintf("%+v", got), secretMarker) {
		t.Fatalf("collector result leaked secret marker: %+v", got)
	}
	if got[0].Collector != "error" || got[0].Errors[0].Code != "collector_error" || got[0].Errors[0].Message != "collector failed" {
		t.Fatalf("got=%+v", got)
	}
	if got[1].Collector != "panic" || got[1].Errors[0].Code != "collector_panic" || got[1].Errors[0].Message != "collector panicked" {
		t.Fatalf("got=%+v", got)
	}
}

func TestOrchestratorBoundsConcurrentCollectors(t *testing.T) {
	const collectorCount = 4
	started := make(chan struct{}, collectorCount)
	release := make(chan struct{})
	var running atomic.Int32
	var maximum atomic.Int32

	collectors := make([]Collector, collectorCount)
	for i := range collectors {
		collectors[i] = collectorFunc{name: string(rune('a' + i)), fn: func(context.Context, Environment) (model.CollectorResult, error) {
			current := running.Add(1)
			for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
			}
			started <- struct{}{}
			<-release
			running.Add(-1)
			return model.CollectorResult{Status: model.CoverageComplete}, nil
		}}
	}

	done := make(chan []model.CollectorResult, 1)
	go func() {
		done <- Orchestrator{Collectors: collectors, MaxConcurrent: 2}.Collect(context.Background(), Environment{})
	}()
	for range 2 {
		<-started
	}
	select {
	case <-started:
		close(release)
		t.Fatal("started more than two collectors concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	got := <-done
	if maximum.Load() != 2 || len(got) != collectorCount {
		t.Fatalf("maximum=%d got=%+v", maximum.Load(), got)
	}
}

func TestOrchestratorContainsCollectorFailure(t *testing.T) {
	o := Orchestrator{Timeout: 50 * time.Millisecond, MaxConcurrent: 2, Collectors: []Collector{
		fakeCollector{name: "ok", result: model.CollectorResult{Collector: "ok", Status: model.CoverageComplete}},
		fakeCollector{name: "bad", err: errors.New("denied")},
	}}

	got := o.Collect(context.Background(), Environment{})
	if len(got) != 2 || got[0].Collector != "bad" || got[0].Status != model.CoverageFailed {
		t.Fatalf("got=%+v", got)
	}
	if got[1].Collector != "ok" || got[1].Status != model.CoverageComplete {
		t.Fatalf("got=%+v", got)
	}
}

func TestOrchestratorAppliesTargetContractOnlyToTargetedCollectors(t *testing.T) {
	targeted := targetedCollectorWithResult{
		fakeCollector: fakeCollector{name: "targeted", result: model.CollectorResult{Status: model.CoverageComplete}},
		specs: []model.TargetSpec{{
			ID: "targeted.user", Collector: "targeted", Platform: "darwin",
			Scope: model.ScopeUser, Method: model.TargetFile,
		}},
	}
	untargeted := fakeCollector{name: "untargeted", result: model.CollectorResult{Status: model.CoverageComplete}}

	got := (Orchestrator{Collectors: []Collector{untargeted, targeted}, MaxConcurrent: 2}).Collect(context.Background(), Environment{})
	if len(got) != 2 {
		t.Fatalf("got=%+v", got)
	}
	if got[0].Collector != "targeted" || got[0].Status != model.CoveragePartial || len(got[0].Targets) != 1 || got[0].Targets[0].Status != model.TargetUnsupported {
		t.Fatalf("targeted=%+v", got[0])
	}
	if got[1].Collector != "untargeted" || got[1].Status != model.CoverageComplete || got[1].Targets != nil {
		t.Fatalf("untargeted=%+v", got[1])
	}
}

type targetedCollectorWithResult struct {
	fakeCollector
	specs []model.TargetSpec
}

func (c targetedCollectorWithResult) Targets() []model.TargetSpec { return c.specs }
