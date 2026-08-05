package acceptance

import (
	"context"
	"sync"

	"github.com/ssc-init/ssc-init/internal/model"
)

type memorySnapshots struct {
	mu          sync.Mutex
	inventory   model.Inventory
	initialized bool
	saves       int
}

func newMemorySnapshots() *memorySnapshots {
	return &memorySnapshots{}
}

func (s *memorySnapshots) SaveScan(ctx context.Context, _ model.ScanResult, inventory model.Inventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inventory = inventory
	s.initialized = true
	s.saves++
	return nil
}

func (s *memorySnapshots) LatestInventory(ctx context.Context) (model.Inventory, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inventory, s.initialized, nil
}

func (s *memorySnapshots) saveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}
