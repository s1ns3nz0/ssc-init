package collector

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

// Orchestrator runs collectors independently while keeping their failures local.
type Orchestrator struct {
	Collectors    []Collector
	Timeout       time.Duration
	MaxConcurrent int
}

// Collect runs every collector and returns one deterministic coverage record per
// collector. A collector's failure never prevents its siblings from completing.
func (o Orchestrator) Collect(ctx context.Context, env Environment) []model.CollectorResult {
	if len(o.Collectors) == 0 {
		return nil
	}

	maxConcurrent := o.MaxConcurrent
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxConcurrent > len(o.Collectors) {
		maxConcurrent = len(o.Collectors)
	}

	type indexedResult struct {
		index  int
		result model.CollectorResult
	}
	results := make(chan indexedResult, len(o.Collectors))
	semaphore := make(chan struct{}, maxConcurrent)
	var workers sync.WaitGroup
	workers.Add(len(o.Collectors))
	for index, c := range o.Collectors {
		collectorIndex := index
		collector := c
		go func() {
			defer workers.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results <- indexedResult{index: collectorIndex, result: o.collectOne(ctx, env, collector)}
		}()
	}

	workers.Wait()
	close(results)

	collected := make([]indexedResult, 0, len(o.Collectors))
	for result := range results {
		collected = append(collected, result)
	}
	sort.Slice(collected, func(i, j int) bool {
		if collected[i].result.Collector == collected[j].result.Collector {
			return collected[i].index < collected[j].index
		}
		return collected[i].result.Collector < collected[j].result.Collector
	})
	sorted := make([]model.CollectorResult, len(collected))
	for i, result := range collected {
		sorted[i] = result.result
	}
	return sorted
}

func (o Orchestrator) collectOne(parent context.Context, env Environment, c Collector) (result model.CollectorResult) {
	name := ""
	defer func() {
		if recovered := recover(); recovered != nil {
			result = failedResult(name, "collector_panic", fmt.Sprintf("collector panicked: %v", recovered))
		}
	}()

	name = c.Name()
	result.Collector = name

	ctx := parent
	cancel := func() {}
	if o.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, o.Timeout)
	}
	defer cancel()

	result, err := c.Collect(ctx, env)
	result.Collector = name
	if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		return failedResult(name, "collector_timeout", "collector deadline exceeded")
	}
	if err != nil {
		return failedResult(name, "collector_error", err.Error())
	}
	return result
}

func failedResult(name, code, message string) model.CollectorResult {
	return model.CollectorResult{
		Collector: name,
		Status:    model.CoverageFailed,
		Errors: []model.CoverageError{{
			Code:    code,
			Message: message,
		}},
	}
}
