// Package collector defines discovery collectors and their execution environment.
package collector

import (
	"context"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

// Environment contains the bounded host access available to collectors.
type Environment struct {
	Home      string
	Platform  string
	Scope     model.ScanScope
	FS        platform.FileSystem
	Runner    platform.Runner
	Inspector platform.ExecutableInspector
	Now       func() time.Time
}

// Collector discovers one portion of the local software supply chain.
// Implementations must promptly return when ctx.Done() is closed.
type Collector interface {
	Name() string
	Collect(context.Context, Environment) (model.CollectorResult, error)
}

// ClearLocalEvidenceTargets removes runtime-only paths and provenance from
// collector results and their backing arrays. It is safe to call repeatedly.
func ClearLocalEvidenceTargets(results []model.CollectorResult) {
	for index := range results {
		targets := results[index].LocalEvidenceTargets
		for targetIndex := range targets {
			targets[targetIndex] = model.LocalEvidenceTarget{}
		}
		results[index].LocalEvidenceTargets = nil
	}
}
