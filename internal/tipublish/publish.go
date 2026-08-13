// Package tipublish builds deterministic unsigned threat-intelligence bundles
// from pinned local OSV and OpenSSF malicious-package source snapshots.
package tipublish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

// Source identifies one pinned local OSV-format snapshot and the reviewed
// redistribution metadata applied to every record in that snapshot.
type Source struct {
	Path          string
	License       string
	PublicURLBase string
}

// Input contains publication metadata and explicit local sources. OSV and
// OpenSSF remain separate so source format cannot decide classification.
type Input struct {
	OSV         []Source
	OpenSSF     []Source
	Version     string
	Sequence    uint64
	KeyID       string
	GeneratedAt time.Time
	ValidFrom   time.Time
	ValidUntil  time.Time
}

// Attribution is safe to publish alongside the bundle; it contains no local
// path and preserves severity formats that do not affect classification.
type Attribution struct {
	ID         string     `json:"id"`
	SourceID   string     `json:"sourceId"`
	Category   string     `json:"category"`
	License    string     `json:"license"`
	PublicURL  string     `json:"publicUrl"`
	ModifiedAt string     `json:"modifiedAt"`
	Withdrawn  bool       `json:"withdrawn"`
	Severities []Severity `json:"severities"`
}

// Report summarizes the exact normalized inputs without exposing local paths.
type Report struct {
	Version          string        `json:"version"`
	Sequence         uint64        `json:"sequence"`
	GeneratedAt      string        `json:"generatedAt"`
	Records          int           `json:"records"`
	Malicious        int           `json:"malicious"`
	Vulnerable       int           `json:"vulnerable"`
	Withdrawn        int           `json:"withdrawn"`
	RejectedAffected int           `json:"rejectedAffected"`
	Duplicates       int           `json:"duplicates"`
	Sources          int           `json:"sources"`
	Attributions     []Attribution `json:"attributions"`
}

type outputEnvelope struct {
	SchemaVersion string           `json:"schemaVersion"`
	Family        bundle.Family    `json:"family"`
	Version       string           `json:"version"`
	Sequence      uint64           `json:"sequence"`
	KeyID         string           `json:"keyId"`
	GeneratedAt   time.Time        `json:"generatedAt"`
	ValidFrom     time.Time        `json:"validFrom"`
	ValidUntil    time.Time        `json:"validUntil"`
	Payload       bundle.TIPayload `json:"payload"`
}

type aggregateRecord struct {
	record       bundle.TIRecord
	attributions []Attribution
}

// Build validates, normalizes, sorts, deduplicates, and encodes an unsigned TI
// bundle. It performs no network access and does not load signing material.
func Build(input Input) ([]byte, Report, error) {
	if err := validateInput(input); err != nil {
		return nil, Report{}, err
	}
	report := Report{
		Version:      input.Version,
		Sequence:     input.Sequence,
		GeneratedAt:  input.GeneratedAt.Format(time.RFC3339),
		Sources:      len(input.OSV) + len(input.OpenSSF),
		Attributions: []Attribution{},
	}
	bySourceID := make(map[string]map[string]aggregateRecord)
	semanticSets := make(map[string][]string)
	for _, group := range []struct {
		sources  []Source
		category sourceCategory
	}{{input.OSV, categoryVulnerable}, {input.OpenSSF, categoryMalicious}} {
		for _, source := range group.sources {
			sourceRecords, err := readOSV(source.Path)
			if err != nil {
				return nil, Report{}, err
			}
			for _, sourceRecord := range sourceRecords {
				document, err := normalizeRecord(sourceRecord, source, group.category, input)
				if err != nil {
					return nil, Report{}, err
				}
				report.RejectedAffected += document.rejectedAffected
				keys := make([]string, len(document.records))
				for index, normalized := range document.records {
					keys[index] = semanticKey(normalized.record)
				}
				if priorKeys, exists := semanticSets[sourceRecord.ID]; exists && !reflect.DeepEqual(priorKeys, keys) {
					return nil, Report{}, fmt.Errorf("conflicting duplicate record id %s", sourceRecord.ID)
				}
				if _, exists := semanticSets[sourceRecord.ID]; !exists {
					semanticSets[sourceRecord.ID] = keys
					bySourceID[sourceRecord.ID] = make(map[string]aggregateRecord, len(keys))
					for _, normalized := range document.records {
						bySourceID[sourceRecord.ID][semanticKey(normalized.record)] = aggregateRecord{record: normalized.record, attributions: []Attribution{normalized.attribution}}
					}
					continue
				}
				for _, normalized := range document.records {
					key := semanticKey(normalized.record)
					aggregate := bySourceID[sourceRecord.ID][key]
					if !compatibleClassification(aggregate, normalized) {
						return nil, Report{}, fmt.Errorf("conflicting duplicate record id %s", sourceRecord.ID)
					}
					aggregate.record.SourceURLs = sortedUnique(append(aggregate.record.SourceURLs, normalized.record.SourceURLs...))
					aggregate.record.License = mergeLicenses(aggregate.record.License, normalized.record.License)
					if normalized.attribution.Category == string(categoryMalicious) {
						aggregate.record.Verdict, aggregate.record.Confidence = "known-malicious", "high"
					}
					if !containsAttribution(aggregate.attributions, normalized.attribution) {
						aggregate.attributions = append(aggregate.attributions, normalized.attribution)
					}
					bySourceID[sourceRecord.ID][key] = aggregate
				}
				report.Duplicates++
			}
		}
	}
	records := make([]bundle.TIRecord, 0)
	for _, sourceRecords := range bySourceID {
		for _, aggregate := range sourceRecords {
			records = append(records, aggregate.record)
			report.Attributions = append(report.Attributions, aggregate.attributions...)
			if aggregate.record.Verdict == "known-malicious" {
				report.Malicious++
			} else {
				report.Vulnerable++
			}
			if aggregate.record.Withdrawn {
				report.Withdrawn++
			}
		}
	}
	sort.Slice(records, func(left, right int) bool { return records[left].ID < records[right].ID })
	sort.Slice(report.Attributions, func(left, right int) bool {
		leftValue, rightValue := report.Attributions[left], report.Attributions[right]
		if leftValue.ID != rightValue.ID {
			return leftValue.ID < rightValue.ID
		}
		if leftValue.Category != rightValue.Category {
			return leftValue.Category < rightValue.Category
		}
		if leftValue.PublicURL != rightValue.PublicURL {
			return leftValue.PublicURL < rightValue.PublicURL
		}
		return leftValue.License < rightValue.License
	})
	report.Records = len(records)
	raw, err := encodeJSON(outputEnvelope{
		SchemaVersion: bundle.SchemaVersion,
		Family:        bundle.FamilyTI,
		Version:       input.Version,
		Sequence:      input.Sequence,
		KeyID:         input.KeyID,
		GeneratedAt:   input.GeneratedAt,
		ValidFrom:     input.ValidFrom,
		ValidUntil:    input.ValidUntil,
		Payload:       bundle.TIPayload{Records: records},
	})
	if err != nil {
		return nil, Report{}, fmt.Errorf("encode bundle: %w", err)
	}
	if _, err := bundle.Load(raw, input.GeneratedAt); err != nil {
		return nil, Report{}, fmt.Errorf("generated bundle is invalid: %w", err)
	}
	return raw, report, nil
}

// EncodeReport emits the canonical public attribution report encoding used by
// the publisher command.
func EncodeReport(report Report) ([]byte, error) {
	return encodeJSON(report)
}

func validateInput(input Input) error {
	if len(input.OSV)+len(input.OpenSSF) == 0 || len(input.OSV)+len(input.OpenSSF) > maxListItems || input.Version == "" || len(input.Version) > 128 || input.Sequence == 0 || input.KeyID == "" || len(input.KeyID) > 128 || input.GeneratedAt.IsZero() || input.ValidFrom.IsZero() || input.ValidUntil.IsZero() || input.GeneratedAt.Location() != time.UTC || input.ValidFrom.Location() != time.UTC || input.ValidUntil.Location() != time.UTC || input.GeneratedAt.Before(input.ValidFrom) || input.GeneratedAt.After(input.ValidUntil) {
		return fmt.Errorf("publication metadata is invalid")
	}
	for _, source := range append(append([]Source(nil), input.OSV...), input.OpenSSF...) {
		if source.Path == "" || filepath.Clean(source.Path) != source.Path {
			return fmt.Errorf("source path is invalid")
		}
		if !approvedLicense(source.License) {
			return fmt.Errorf("redistributable license is absent or not approved")
		}
		if !publicHTTPS(source.PublicURLBase) || source.PublicURLBase[len(source.PublicURLBase)-1] != '/' {
			return fmt.Errorf("public source configuration is invalid")
		}
	}
	return nil
}

func approvedLicense(value string) bool {
	switch value {
	case "Apache-2.0", "CC-BY-4.0", "CC0-1.0":
		return true
	default:
		return false
	}
}

func compatibleClassification(aggregate aggregateRecord, incoming normalizedRecord) bool {
	for _, attribution := range aggregate.attributions {
		if attribution.Category == incoming.attribution.Category {
			return aggregate.record.Verdict == incoming.record.Verdict && aggregate.record.Confidence == incoming.record.Confidence && reflect.DeepEqual(attribution.Severities, incoming.attribution.Severities)
		}
	}
	return true
}

func mergeLicenses(left, right string) string {
	licenses := append(strings.Split(left, " AND "), strings.Split(right, " AND ")...)
	return strings.Join(sortedUnique(licenses), " AND ")
}

func containsAttribution(values []Attribution, candidate Attribution) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, candidate) {
			return true
		}
	}
	return false
}

func encodeJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
