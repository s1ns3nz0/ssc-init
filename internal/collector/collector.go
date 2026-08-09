// Package collector defines discovery collectors and their execution environment.
package collector

import (
	"context"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

// Environment contains the bounded host access available to collectors.
type Environment struct {
	Home               string
	Platform           string
	Scope              model.ScanScope
	FS                 platform.FileSystem
	Runner             platform.Runner
	Inspector          platform.ExecutableInspector
	SignatureInspector platform.SignatureInspector
	Now                func() time.Time
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
		if cap(targets) > 0 {
			full := targets[:cap(targets)]
			for targetIndex := range full {
				if clearer, ok := full[targetIndex].Provenance.(model.RuntimeEvidenceClearer); ok {
					clearer.ClearRuntimeEvidence()
				}
				full[targetIndex] = model.LocalEvidenceTarget{}
			}
		}
		results[index].LocalEvidenceTargets = nil
		if results[index].LocalEvidenceIssuer != nil {
			results[index].LocalEvidenceIssuer.ClearRuntimeEvidence()
		}
		results[index].LocalEvidenceIssuer = nil
	}
}
