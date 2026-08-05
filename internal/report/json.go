// Package report serializes stable public result contracts.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

type baselinePayload struct {
	SchemaVersion string                  `json:"schemaVersion"`
	ScanID        string                  `json:"scanId"`
	Status        string                  `json:"status"`
	StartedAt     time.Time               `json:"startedAt"`
	FinishedAt    time.Time               `json:"finishedAt"`
	Coverage      []model.CollectorResult `json:"coverage"`
	Inventory     model.Inventory         `json:"inventory"`
	Delta         model.Delta             `json:"delta"`
}

// WriteJSON writes one complete baseline result followed by a newline.
func WriteJSON(writer io.Writer, scan model.ScanResult, inventory model.Inventory, delta model.Delta) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(baselinePayload{
		SchemaVersion: scan.SchemaVersion,
		ScanID:        scan.ScanID,
		Status:        scan.Status,
		StartedAt:     scan.StartedAt,
		FinishedAt:    scan.FinishedAt,
		Coverage:      scan.Coverage,
		Inventory:     inventory,
		Delta:         delta,
	})
}
