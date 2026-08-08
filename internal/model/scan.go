package model

import "time"

// RuntimeEvidenceClearer removes non-serializable evidence state at the end
// of a collection pass. Implementations must be idempotent because the same
// hook may be reached through more than one runtime slot.
type RuntimeEvidenceClearer interface {
	ClearRuntimeEvidence()
}

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
	Collector            string                 `json:"collector"`
	Status               CoverageStatus         `json:"status"`
	Assets               []Asset                `json:"assets,omitempty"`
	Relationships        []Relationship         `json:"relationships,omitempty"`
	Errors               []CoverageError        `json:"errors,omitempty"`
	Targets              []TargetCoverage       `json:"targets,omitempty"`
	Observations         []Observation          `json:"observations,omitempty"`
	LocalEvidenceIssuer  RuntimeEvidenceClearer `json:"-"`
	LocalEvidenceTargets []LocalEvidenceTarget  `json:"-"`
	LocalTargets         []LocalTarget          `json:"-"`
}

// Inventory is a normalized asset graph.
type Inventory struct {
	Assets        []Asset           `json:"assets"`
	Observations  []Observation     `json:"observations,omitempty"`
	Evidence      []ContentEvidence `json:"evidence"`
	Relationships []Relationship    `json:"relationships"`
	Errors        []CoverageError   `json:"errors,omitempty"`
}

// ChangeKind identifies how an asset changed from the previous inventory.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

// Change is one inventory entity change.
type Change struct {
	Kind     ChangeKind   `json:"kind"`
	Entity   ChangeEntity `json:"entity"`
	EntityID string       `json:"entityId"`
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

// ScanStatus is the closed set of overall scan outcomes (design §11).
type ScanStatus string

const (
	// ScanComplete means every collector and every accepted evidence target
	// reached a terminal successful result.
	ScanComplete ScanStatus = "complete"
	// ScanPartial means discovery or evidence coverage is incomplete; the
	// unscanned targets are named in coverage.
	ScanPartial ScanStatus = "partial"
	// ScanStale means the scan completed but its inputs are past their
	// freshness window. Unreachable until the TI manager ships (design §7.2);
	// present so the vocabulary is complete and cannot be reordered later.
	ScanStale ScanStatus = "stale"
	// ScanBlocked means the scan could not produce a usable result at all.
	ScanBlocked ScanStatus = "blocked"
)

// Valid reports whether status is one of the four documented outcomes.
func (s ScanStatus) Valid() bool {
	switch s {
	case ScanComplete, ScanPartial, ScanStale, ScanBlocked:
		return true
	default:
		return false
	}
}

// ScanResult contains the complete scan result.
type ScanResult struct {
	SchemaVersion    string            `json:"schemaVersion"`
	ScanID           string            `json:"scanId"`
	Status           ScanStatus        `json:"status"`
	StartedAt        time.Time         `json:"startedAt"`
	FinishedAt       time.Time         `json:"finishedAt"`
	Coverage         []CollectorResult `json:"coverage"`
	EvidenceCoverage EvidenceCoverage  `json:"evidenceCoverage"`
	Scope            ScanScope         `json:"scope,omitempty,omitzero"`
}

// Snapshot combines a persisted scan result with its immutable inventory.
type Snapshot struct {
	Scan      ScanResult `json:"scan"`
	Inventory Inventory  `json:"inventory"`
}
