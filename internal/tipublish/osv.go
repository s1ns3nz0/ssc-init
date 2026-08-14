package tipublish

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	maxSourceBytes        = 16 << 20
	maxDecodedElements    = 500_000
	maxDecodedStringBytes = 12 << 20
)

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

func readOSV(path string, remaining decodedBudget) ([]osvRecord, decodedBudget, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, decodedBudget{}, fmt.Errorf("read source: %w", err)
	}
	defer file.Close()
	return readOSVReader(file, remaining)
}

func readOSVReader(source io.Reader, remaining decodedBudget) ([]osvRecord, decodedBudget, error) {
	limited := &io.LimitedReader{R: source, N: maxSourceBytes + 1}
	buffered := bufio.NewReader(limited)
	first, err := firstJSONByte(buffered)
	if err != nil {
		return nil, decodedBudget{}, fmt.Errorf("source record: malformed OSV document")
	}
	decoder := json.NewDecoder(buffered)
	records := make([]osvRecord, 0)
	used := decodedBudget{}
	decodeRecord := func() error {
		if used.elements >= remaining.elements {
			return fmt.Errorf("source record: decoded element budget exceeded")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("source record: malformed OSV document")
		}
		preflightRemaining := decodedBudget{elements: remaining.elements - used.elements, stringBytes: remaining.stringBytes - used.stringBytes}
		if err := preflightOSVRecord(raw, preflightRemaining); err != nil {
			return err
		}
		closedDecoder := json.NewDecoder(bytes.NewReader(raw))
		closedDecoder.DisallowUnknownFields()
		var record osvRecord
		if err := closedDecoder.Decode(&record); err != nil {
			return fmt.Errorf("source record: malformed OSV document")
		}
		if err := requireJSONEOF(closedDecoder); err != nil {
			return err
		}
		recordUsage := measureDecodedBudget([]osvRecord{record})
		if recordUsage.elements > remaining.elements-used.elements {
			return fmt.Errorf("source record: decoded element budget exceeded")
		}
		if recordUsage.stringBytes > remaining.stringBytes-used.stringBytes {
			return fmt.Errorf("source record: decoded string budget exceeded")
		}
		used.elements += recordUsage.elements
		used.stringBytes += recordUsage.stringBytes
		records = append(records, record)
		return nil
	}
	switch first {
	case '[':
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return nil, decodedBudget{}, fmt.Errorf("source record: malformed OSV document")
		}
		for decoder.More() {
			if err := decodeRecord(); err != nil {
				return nil, decodedBudget{}, err
			}
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') || len(records) == 0 {
			return nil, decodedBudget{}, fmt.Errorf("source record: malformed OSV document")
		}
	case '{':
		if err := decodeRecord(); err != nil {
			return nil, decodedBudget{}, err
		}
	default:
		return nil, decodedBudget{}, fmt.Errorf("source record: malformed OSV document")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, decodedBudget{}, err
	}
	if limited.N == 0 {
		return nil, decodedBudget{}, fmt.Errorf("read source: source exceeds bounds")
	}
	return records, used, nil
}

func firstJSONByte(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if value == ' ' || value == '\n' || value == '\r' || value == '\t' {
			continue
		}
		if err := reader.UnreadByte(); err != nil {
			return 0, err
		}
		return value, nil
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("source record: malformed OSV document")
	}
	return nil
}

func preflightOSVRecord(raw []byte, remaining decodedBudget) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	used := decodedBudget{}
	if err := inspectJSONValue(decoder, &used, remaining, true); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func inspectJSONValue(decoder *json.Decoder, used *decodedBudget, remaining decodedBudget, countElement bool) error {
	if countElement {
		used.elements++
		if used.elements > remaining.elements {
			return fmt.Errorf("source record: decoded element budget exceeded")
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("source record: malformed OSV document")
	}
	switch value := token.(type) {
	case string:
		used.stringBytes += len(value)
		if used.stringBytes > remaining.stringBytes {
			return fmt.Errorf("source record: decoded string budget exceeded")
		}
	case json.Delim:
		switch value {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return fmt.Errorf("source record: malformed OSV document")
				}
				if _, duplicate := keys[key]; duplicate {
					return fmt.Errorf("source record: duplicate JSON field")
				}
				keys[key] = struct{}{}
				if err := inspectJSONValue(decoder, used, remaining, false); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("source record: malformed OSV document")
			}
		case '[':
			for decoder.More() {
				if err := inspectJSONValue(decoder, used, remaining, true); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("source record: malformed OSV document")
			}
		default:
			return fmt.Errorf("source record: malformed OSV document")
		}
	}
	return nil
}

type decodedBudget struct {
	elements    int
	stringBytes int
}

func measureDecodedBudget(records []osvRecord) decodedBudget {
	usage := decodedBudget{elements: len(records)}
	addStrings := func(values ...string) {
		for _, value := range values {
			usage.stringBytes += len(value)
		}
	}
	for _, record := range records {
		usage.elements += len(record.Aliases) + len(record.Upstream) + len(record.Related) + len(record.Affected) + len(record.Severity) + len(record.References)
		addStrings(record.SchemaVersion, record.ID, record.Modified, record.Published, record.Withdrawn, record.Summary, record.Details)
		addStrings(record.Aliases...)
		addStrings(record.Upstream...)
		addStrings(record.Related...)
		usage.stringBytes += len(record.Credits) + len(record.DatabaseSpecific)
		for _, severity := range record.Severity {
			addStrings(severity.Type, severity.Score, severity.Source)
		}
		for _, reference := range record.References {
			addStrings(reference.Type, reference.URL)
		}
		for _, affected := range record.Affected {
			usage.elements += len(affected.Severity) + len(affected.Ranges) + len(affected.Versions)
			addStrings(affected.Package.Ecosystem, affected.Package.Name, affected.Package.PURL)
			addStrings(affected.Versions...)
			usage.stringBytes += len(affected.EcosystemSpecific) + len(affected.DatabaseSpecific)
			for _, severity := range affected.Severity {
				addStrings(severity.Type, severity.Score, severity.Source)
			}
			for _, affectedRange := range affected.Ranges {
				usage.elements += len(affectedRange.Events)
				addStrings(affectedRange.Type, affectedRange.Repo)
				usage.stringBytes += len(affectedRange.DatabaseSpecific)
				for _, event := range affectedRange.Events {
					addStrings(event.Introduced, event.Fixed, event.LastAffected, event.Limit)
				}
			}
		}
	}
	return usage
}
