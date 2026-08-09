package report

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

type FindingData struct {
	DeviceID     string
	Intelligence string
	Policy       string
	Findings     []model.Finding
}

type findingPayload struct {
	SchemaVersion string          `json:"schemaVersion"`
	DeviceID      string          `json:"deviceId"`
	Intelligence  string          `json:"intelligence"`
	Policy        string          `json:"policy"`
	Findings      []model.Finding `json:"findings"`
}

func WriteFindingsJSON(writer io.Writer, data FindingData, pretty bool) error {
	if !strings.HasPrefix(data.DeviceID, "device:sha256:") || len(strings.TrimPrefix(data.DeviceID, "device:sha256:")) != 64 || privacy.ContainsSensitiveValue(data.DeviceID) {
		return errors.New("invalid opaque device identity")
	}
	findings := append([]model.Finding(nil), data.Findings...)
	for _, item := range findings {
		if !item.Valid() {
			return errors.New("invalid finding")
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(findingPayload{SchemaVersion: "ssc-init.findings.v1", DeviceID: data.DeviceID, Intelligence: data.Intelligence, Policy: data.Policy, Findings: findings})
}
