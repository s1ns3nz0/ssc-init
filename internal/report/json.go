// Package report serializes stable public result contracts.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type baselinePayload struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	ScanID           string                  `json:"scanId"`
	Status           model.ScanStatus        `json:"status"`
	StartedAt        time.Time               `json:"startedAt"`
	FinishedAt       time.Time               `json:"finishedAt"`
	Scope            model.ScanScope         `json:"scope"`
	Coverage         []model.CollectorResult `json:"coverage"`
	EvidenceCoverage model.EvidenceCoverage  `json:"evidenceCoverage"`
	Inventory        inventoryPayload        `json:"inventory"`
	Delta            model.Delta             `json:"delta"`
}

// inventoryPayload keeps the v4 baseline inventory contract explicit: every
// graph slice is always present, including empty observation and evidence
// slices that model.Inventory would otherwise omit.
type inventoryPayload struct {
	Assets        []model.Asset           `json:"assets"`
	Observations  []model.Observation     `json:"observations"`
	Evidence      []model.ContentEvidence `json:"evidence"`
	Relationships []model.Relationship    `json:"relationships"`
	Errors        []model.CoverageError   `json:"errors,omitempty"`
}

// WriteJSON writes one complete baseline result followed by a newline.
func WriteJSON(writer io.Writer, scan model.ScanResult, inventory model.Inventory, delta model.Delta) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(baselinePayload{
		SchemaVersion:    scan.SchemaVersion,
		ScanID:           scan.ScanID,
		Status:           scan.Status,
		StartedAt:        scan.StartedAt,
		FinishedAt:       scan.FinishedAt,
		Scope:            scan.Scope,
		Coverage:         scan.Coverage,
		EvidenceCoverage: scan.EvidenceCoverage,
		Inventory: inventoryPayload{
			Assets:        inventory.Assets,
			Observations:  inventory.Observations,
			Evidence:      inventory.Evidence,
			Relationships: inventory.Relationships,
			Errors:        inventory.Errors,
		},
		Delta: delta,
	})
}
