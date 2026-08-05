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
	Home   string
	FS     platform.FileSystem
	Runner platform.Runner
	Now    func() time.Time
}

// Collector discovers one portion of the local software supply chain.
type Collector interface {
	Name() string
	Collect(context.Context, Environment) (model.CollectorResult, error)
}
