package testutil

import (
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
)

// AssertAsset returns the asset with id or fails the test when none exists.
func AssertAsset(t *testing.T, assets []model.Asset, id string) model.Asset {
	t.Helper()
	for _, asset := range assets {
		if asset.ID == id {
			return asset
		}
	}
	t.Fatalf("asset %s not found", id)
	return model.Asset{}
}
