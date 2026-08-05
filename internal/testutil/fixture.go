// Package testutil provides shared fixtures for collector tests.
package testutil

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/platform"
)

// Environment creates a collector environment with an explicit synthetic home.
func Environment(t *testing.T, relativeRoot string) collector.Environment {
	t.Helper()
	home, err := filepath.Abs(relativeRoot)
	if err != nil {
		t.Fatal(err)
	}
	return collector.Environment{
		Home:   home,
		FS:     platform.OSFileSystem{},
		Runner: &FakeRunner{},
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
	}
}

// FakeRunner returns configured command results without executing a process.
type FakeRunner struct {
	Results map[string]platform.CommandResult
	Errors  map[string]error
	Calls   []string

	mu sync.Mutex
}

// Run records a command and returns its configured result.
func (r *FakeRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult, error) {
	key := strings.Join(append([]string{command}, args...), "\x1f")
	r.mu.Lock()
	r.Calls = append(r.Calls, key)
	r.mu.Unlock()
	return r.Results[key], r.Errors[key]
}
