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

// ScanResult contains the complete scan result.
type ScanResult struct {
	SchemaVersion string            `json:"schemaVersion"`
	ScanID        string            `json:"scanId"`
	Status        string            `json:"status"`
	StartedAt     time.Time         `json:"startedAt"`
	FinishedAt    time.Time         `json:"finishedAt"`
	Coverage      []CollectorResult `json:"coverage"`
}
