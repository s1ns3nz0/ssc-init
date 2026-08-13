package tipublish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const maxSourceBytes = 16 << 20

type osvRecord struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id"`
	Modified         string          `json:"modified"`
	Published        string          `json:"published,omitempty"`
	Withdrawn        string          `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Upstream         []string        `json:"upstream,omitempty"`
	Related          []string        `json:"related,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Affected         []osvAffected   `json:"affected"`
	Severity         []Severity      `json:"severity,omitempty"`
	References       []osvReference  `json:"references,omitempty"`
	Credits          json.RawMessage `json:"credits,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type osvAffected struct {
	Package           osvPackage      `json:"package"`
	Severity          []Severity      `json:"severity,omitempty"`
	Ranges            []osvRange      `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

type osvRange struct {
	Type             string          `json:"type"`
	Repo             string          `json:"repo,omitempty"`
	Events           []osvEvent      `json:"events"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Severity is retained verbatim in the public attribution report. Only a
// valid CVSS v3 vector participates in vulnerability classification.
type Severity struct {
	Type   string `json:"type"`
	Score  string `json:"score"`
	Source string `json:"source,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func readOSV(path string) ([]osvRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxSourceBytes {
		return nil, fmt.Errorf("read source: source exceeds bounds")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("source record: malformed OSV document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var records []osvRecord
	switch raw[0] {
	case '[':
		if err := decoder.Decode(&records); err != nil || records == nil {
			return nil, fmt.Errorf("source record: malformed OSV document")
		}
	case '{':
		var record osvRecord
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("source record: malformed OSV document")
		}
		records = []osvRecord{record}
	default:
		return nil, fmt.Errorf("source record: malformed OSV document")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("source record: malformed OSV document")
	}
	return records, nil
}
