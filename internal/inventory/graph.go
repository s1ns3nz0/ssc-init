// Package inventory normalizes collector output into deterministic asset graphs.
package inventory

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/model"
)

const maxConflictComponentRunes = 256

// Build merges collector output without mutating the supplied results.
func Build(results []model.CollectorResult) model.Inventory {
	type accumulatedAsset struct {
		asset          model.Asset
		canonical      []byte
		metadataValues map[string]map[string]struct{}
	}

	assetsByID := make(map[string]*accumulatedAsset)
	for _, result := range results {
		for _, candidate := range result.Assets {
			base, canonical := canonicalAssetWithoutMetadata(candidate)
			accumulated, exists := assetsByID[candidate.ID]
			if !exists {
				accumulated = &accumulatedAsset{
					asset:          base,
					canonical:      canonical,
					metadataValues: make(map[string]map[string]struct{}),
				}
				assetsByID[candidate.ID] = accumulated
			} else if bytes.Compare(canonical, accumulated.canonical) < 0 {
				accumulated.asset = base
				accumulated.canonical = canonical
			}
			for key, value := range candidate.Metadata {
				values := accumulated.metadataValues[key]
				if values == nil {
					values = make(map[string]struct{})
					accumulated.metadataValues[key] = values
				}
				values[value] = struct{}{}
			}
		}
	}

	assetIDs := make([]string, 0, len(assetsByID))
	for id := range assetsByID {
		assetIDs = append(assetIDs, id)
	}
	sort.Strings(assetIDs)

	inventory := model.Inventory{Assets: make([]model.Asset, 0, len(assetIDs))}
	for _, id := range assetIDs {
		accumulated := assetsByID[id]
		keys := make([]string, 0, len(accumulated.metadataValues))
		for key := range accumulated.metadataValues {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		metadata := make(map[string]string, len(keys))
		for _, key := range keys {
			values := accumulated.metadataValues[key]
			if len(values) != 1 {
				inventory.Errors = append(inventory.Errors, model.CoverageError{
					Code:    "metadata-conflict",
					Message: "conflicting metadata values omitted",
					Path:    sanitizeConflictComponent(id) + "#" + sanitizeConflictComponent(key),
				})
				continue
			}
			for value := range values {
				metadata[key] = value
			}
		}
		if len(metadata) > 0 {
			accumulated.asset.Metadata = metadata
		}
		inventory.Assets = append(inventory.Assets, accumulated.asset)
	}

	validAssets := make(map[string]struct{}, len(assetIDs))
	for _, id := range assetIDs {
		validAssets[id] = struct{}{}
	}
	relationships := make(map[model.Relationship]struct{})
	for _, result := range results {
		for _, relationship := range result.Relationships {
			if _, exists := validAssets[relationship.From]; !exists {
				continue
			}
			if _, exists := validAssets[relationship.To]; !exists {
				continue
			}
			relationships[relationship] = struct{}{}
		}
	}
	inventory.Relationships = make([]model.Relationship, 0, len(relationships))
	for relationship := range relationships {
		inventory.Relationships = append(inventory.Relationships, relationship)
	}
	sort.Slice(inventory.Relationships, func(i, j int) bool {
		left, right := inventory.Relationships[i], inventory.Relationships[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.To < right.To
	})
	return inventory
}

// Diff compares normalized inventory assets in deterministic AssetID order.
func Diff(previous, current model.Inventory) model.Delta {
	previousByID := deterministicAssetsByID(previous.Assets)
	currentByID := deterministicAssetsByID(current.Assets)
	ids := make(map[string]struct{}, len(previousByID)+len(currentByID))
	for id := range previousByID {
		ids[id] = struct{}{}
	}
	for id := range currentByID {
		ids[id] = struct{}{}
	}
	orderedIDs := make([]string, 0, len(ids))
	for id := range ids {
		orderedIDs = append(orderedIDs, id)
	}
	sort.Strings(orderedIDs)

	delta := model.Delta{Changes: make([]model.Change, 0)}
	for _, id := range orderedIDs {
		before, existedBefore := previousByID[id]
		after, existsNow := currentByID[id]
		switch {
		case !existedBefore:
			delta.Changes = append(delta.Changes, model.Change{Kind: model.ChangeAdded, AssetID: id})
		case !existsNow:
			delta.Changes = append(delta.Changes, model.Change{Kind: model.ChangeRemoved, AssetID: id})
		case !bytes.Equal(canonicalAssetForDiff(before), canonicalAssetForDiff(after)):
			delta.Changes = append(delta.Changes, model.Change{Kind: model.ChangeChanged, AssetID: id})
		}
	}
	return delta
}

func canonicalAssetWithoutMetadata(asset model.Asset) (model.Asset, []byte) {
	asset.Metadata = nil
	canonical, _ := json.Marshal(asset)
	return asset, canonical
}

func canonicalAssetForDiff(asset model.Asset) []byte {
	asset.ObservedAt = model.Asset{}.ObservedAt
	if len(asset.Metadata) > 0 {
		metadata := make(map[string]string, len(asset.Metadata))
		for key, value := range asset.Metadata {
			if key != model.MetadataObservedAt {
				metadata[key] = value
			}
		}
		asset.Metadata = metadata
		if len(metadata) == 0 {
			asset.Metadata = nil
		}
	}
	canonical, _ := json.Marshal(asset)
	return canonical
}

func deterministicAssetsByID(assets []model.Asset) map[string]model.Asset {
	byID := make(map[string]model.Asset, len(assets))
	canonicalByID := make(map[string][]byte, len(assets))
	for _, asset := range assets {
		canonical := canonicalAssetForDiff(asset)
		if existing, exists := canonicalByID[asset.ID]; !exists || bytes.Compare(canonical, existing) < 0 {
			byID[asset.ID] = asset
			canonicalByID[asset.ID] = canonical
		}
	}
	return byID
}

func sanitizeConflictComponent(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return '?'
		}
		return character
	}, value)
	runes := []rune(value)
	if len(runes) > maxConflictComponentRunes {
		return string(runes[:maxConflictComponentRunes])
	}
	return value
}
