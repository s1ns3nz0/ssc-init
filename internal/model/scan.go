package model

import "time"

// CoverageStatus describes a collector's coverage outcome.
type CoverageStatus string

const (
	CoverageComplete    CoverageStatus = "complete"
	CoveragePartial     CoverageStatus = "partial"
	CoverageSkipped     CoverageStatus = "skipped"
	CoverageUnavailable CoverageStatus = "unavailable"
	CoverageFailed      CoverageStatus = "failed"
)

// CoverageError describes a collector error.
type CoverageError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

// CollectorResult contains the discovery output for one collector.
type CollectorResult struct {
	Collector     string          `json:"collector"`
	Status        CoverageStatus  `json:"status"`
	Assets        []Asset         `json:"assets,omitempty"`
	Relationships []Relationship  `json:"relationships,omitempty"`
	Errors        []CoverageError `json:"errors,omitempty"`
}

// Inventory is a normalized asset graph.
type Inventory struct {
	Assets        []Asset         `json:"assets"`
	Relationships []Relationship  `json:"relationships"`
	Errors        []CoverageError `json:"errors,omitempty"`
}

// ChangeKind identifies how an asset changed from the previous inventory.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

// Change is one asset-level inventory change.
type Change struct {
	Kind    ChangeKind `json:"kind"`
	AssetID string     `json:"assetId"`
}

// Delta contains deterministic asset-level inventory changes.
type Delta struct {
	Changes []Change `json:"changes"`
}

// HashStatus describes whether file hashing completed.
type HashStatus string

const (
	HashComplete    HashStatus = "complete"
	HashOversize    HashStatus = "oversize"
	HashUnavailable HashStatus = "unavailable"
)

// ScanResult contains the complete scan result.
type ScanResult struct {
	SchemaVersion string            `json:"schemaVersion"`
	ScanID        string            `json:"scanId"`
	Status        string            `json:"status"`
	StartedAt     time.Time         `json:"startedAt"`
	FinishedAt    time.Time         `json:"finishedAt"`
	Coverage      []CollectorResult `json:"coverage"`
}
