// Package inventory normalizes collector output into deterministic asset graphs.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

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

	inventory := model.Inventory{Assets: make([]model.Asset, 0, len(assetIDs)), Evidence: make([]model.ContentEvidence, 0)}
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
					Path:    conflictFingerprintPath(id, key),
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
	observationsByID := make(map[string]model.Observation)
	canonicalObservationsByID := make(map[string][]byte)
	observationConflicts := make(map[string]struct{})
	for _, result := range results {
		for _, candidate := range result.Observations {
			canonical := canonicalObservation(candidate)
			existing, exists := canonicalObservationsByID[candidate.ID]
			if exists && !bytes.Equal(existing, canonical) {
				observationConflicts[candidate.ID] = struct{}{}
			}
			if !exists || bytes.Compare(canonical, existing) < 0 {
				observationsByID[candidate.ID] = candidate
				canonicalObservationsByID[candidate.ID] = canonical
			}
		}
	}

	observationIDs := make([]string, 0, len(observationsByID))
	for id := range observationsByID {
		observationIDs = append(observationIDs, id)
	}
	sort.Strings(observationIDs)
	for _, id := range observationIDs {
		observation := observationsByID[id]
		if _, exists := validAssets[observation.AssetID]; !exists {
			inventory.Errors = append(inventory.Errors, orphanObservationError())
			continue
		}
		inventory.Observations = append(inventory.Observations, observation)
	}
	conflictIDs := make([]string, 0, len(observationConflicts))
	for id := range observationConflicts {
		conflictIDs = append(conflictIDs, id)
	}
	sort.Strings(conflictIDs)
	for _, id := range conflictIDs {
		inventory.Errors = append(inventory.Errors, observationConflict(id))
	}

	relationships := make(map[model.Relationship]struct{})
	for _, result := range results {
		for _, relationship := range result.Relationships {
			if !model.ValidRelationshipKind(relationship.Kind) || relationship.From == relationship.To {
				continue
			}
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

// NormalizeEvidence returns a deterministically ID-ordered copy of evidence.
// Evidence is appended after discovery graph construction, so it is normalized
// separately from Build.
func NormalizeEvidence(evidence []model.ContentEvidence) []model.ContentEvidence {
	normalized := append([]model.ContentEvidence(nil), evidence...)
	sort.SliceStable(normalized, func(i, j int) bool {
		return normalized[i].ID < normalized[j].ID
	})
	return normalized
}

// Diff compares normalized inventory entities in deterministic entity and ID order.
func Diff(previous, current model.Inventory) model.Delta {
	delta := model.Delta{Changes: make([]model.Change, 0)}
	appendEntityChanges(&delta.Changes, model.ChangeEntityAsset, canonicalAssetsByID(previous.Assets), canonicalAssetsByID(current.Assets))
	appendEntityChanges(&delta.Changes, model.ChangeEntityEvidence, canonicalEvidenceByID(previous.Evidence), canonicalEvidenceByID(current.Evidence))
	appendEntityChanges(&delta.Changes, model.ChangeEntityObservation, canonicalObservationsForDiffByID(previous.Observations), canonicalObservationsForDiffByID(current.Observations))
	sort.Slice(delta.Changes, func(i, j int) bool {
		left, right := delta.Changes[i], delta.Changes[j]
		if left.Entity != right.Entity {
			return left.Entity < right.Entity
		}
		if left.EntityID != right.EntityID {
			return left.EntityID < right.EntityID
		}
		return left.Kind < right.Kind
	})
	return delta
}

func appendEntityChanges(changes *[]model.Change, entity model.ChangeEntity, previous, current map[string][]byte) {
	ids := make(map[string]struct{}, len(previous)+len(current))
	for id := range previous {
		ids[id] = struct{}{}
	}
	for id := range current {
		ids[id] = struct{}{}
	}
	for id := range ids {
		before, existedBefore := previous[id]
		after, existsNow := current[id]
		switch {
		case !existedBefore:
			*changes = append(*changes, model.Change{Kind: model.ChangeAdded, Entity: entity, EntityID: id})
		case !existsNow:
			*changes = append(*changes, model.Change{Kind: model.ChangeRemoved, Entity: entity, EntityID: id})
		case !bytes.Equal(before, after):
			*changes = append(*changes, model.Change{Kind: model.ChangeChanged, Entity: entity, EntityID: id})
		}
	}
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

func canonicalAssetsByID(assets []model.Asset) map[string][]byte {
	return canonicalValuesByID(assets, func(asset model.Asset) string { return asset.ID }, canonicalAssetForDiff)
}

func canonicalObservationsForDiffByID(observations []model.Observation) map[string][]byte {
	return canonicalValuesByID(observations, func(observation model.Observation) string { return observation.ID }, canonicalObservation)
}

func canonicalEvidenceByID(evidence []model.ContentEvidence) map[string][]byte {
	return canonicalValuesByID(evidence, func(value model.ContentEvidence) string { return value.ID }, canonicalEvidence)
}

// canonicalEvidence excludes cache provenance the same way canonicalAssetForDiff
// excludes observation timestamps: the cache outcome describes how this run
// obtained the digest, not what the content is. Including it made every content
// change echo on the following run, when the newly-written cache entry hits.
func canonicalEvidence(evidence model.ContentEvidence) []byte {
	if len(evidence.Metadata) > 0 {
		metadata := make(map[string]string, len(evidence.Metadata))
		for key, value := range evidence.Metadata {
			if key != model.MetadataCache {
				metadata[key] = value
			}
		}
		evidence.Metadata = metadata
		if len(metadata) == 0 {
			evidence.Metadata = nil
		}
	}
	canonical, _ := json.Marshal(evidence)
	return canonical
}

func canonicalValuesByID[T any](values []T, id func(T) string, canonicalize func(T) []byte) map[string][]byte {
	canonicalByID := make(map[string][]byte, len(values))
	for _, value := range values {
		canonical := canonicalize(value)
		entityID := id(value)
		if existing, exists := canonicalByID[entityID]; !exists || bytes.Compare(canonical, existing) < 0 {
			canonicalByID[entityID] = canonical
		}
	}
	return canonicalByID
}

func canonicalObservation(observation model.Observation) []byte {
	canonical, _ := json.Marshal(observation)
	return canonical
}

func conflictFingerprintPath(assetID, metadataKey string) string {
	assetDigest := sha256.Sum256([]byte(assetID))
	keyDigest := sha256.Sum256([]byte(metadataKey))
	return fmt.Sprintf("asset-sha256:%x/metadata-key-sha256:%x", assetDigest, keyDigest)
}

func observationConflict(observationID string) model.CoverageError {
	digest := sha256.Sum256([]byte(observationID))
	return model.CoverageError{
		Code:    "observation-conflict",
		Message: "conflicting observation variants normalized",
		Path:    fmt.Sprintf("observation-id-sha256:%x", digest),
	}
}

func orphanObservationError() model.CoverageError {
	return model.CoverageError{
		Code:    "orphan-observation",
		Message: "observation references an absent asset",
	}
}
