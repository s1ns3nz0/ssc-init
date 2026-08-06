package acceptance

import (
	"context"
	"sync"

	"github.com/ssc-init/ssc-init/internal/model"
)

type memorySnapshots struct {
	mu          sync.Mutex
	snapshot    model.Snapshot
	initialized bool
	saves       int
}

func newMemorySnapshots() *memorySnapshots {
	return &memorySnapshots{}
}

func (s *memorySnapshots) SaveScan(ctx context.Context, scan model.ScanResult, inventory model.Inventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = model.Snapshot{Scan: scan, Inventory: inventory}
	s.initialized = true
	s.saves++
	return nil
}

func (s *memorySnapshots) LatestSnapshot(ctx context.Context) (model.Snapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot, s.initialized, nil
}

func (s *memorySnapshots) saveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}
