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
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const (
	maxNormalizedRecords = 100_000
	maxBundleBytes       = 16 << 20
	maxReportBytes       = 16 << 20
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
	return buildLimited(input, maxBundleBytes, nil)
}

func buildLimited(input Input, bundleLimit int, onBundleWrite func(int)) ([]byte, Report, error) {
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
	totalSemanticRecords := 0
	totalAttributions := 0
	totalDecoded := decodedBudget{}
	for _, group := range []struct {
		sources  []Source
		category sourceCategory
	}{{input.OSV, categoryVulnerable}, {input.OpenSSF, categoryMalicious}} {
		for _, source := range group.sources {
			remainingDecoded := decodedBudget{elements: maxDecodedElements - totalDecoded.elements, stringBytes: maxDecodedStringBytes - totalDecoded.stringBytes}
			sourceRecords, usage, err := readOSV(source.Path, remainingDecoded)
			if err != nil {
				return nil, Report{}, err
			}
			totalDecoded.elements += usage.elements
			totalDecoded.stringBytes += usage.stringBytes
			if totalDecoded.elements > maxDecodedElements {
				return nil, Report{}, fmt.Errorf("cumulative decoded element budget exceeded")
			}
			if totalDecoded.stringBytes > maxDecodedStringBytes {
				return nil, Report{}, fmt.Errorf("cumulative decoded string budget exceeded")
			}
			for _, sourceRecord := range sourceRecords {
				recordBudget := maxNormalizedRecords - totalSemanticRecords
				if _, duplicate := semanticSets[sourceRecord.ID]; duplicate {
					recordBudget = maxNormalizedRecords
				}
				document, err := normalizeRecord(sourceRecord, source, group.category, input, recordBudget)
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
					if len(keys) > maxNormalizedRecords-totalSemanticRecords {
						return nil, Report{}, fmt.Errorf("normalized record budget exceeds 100000")
					}
					totalSemanticRecords += len(keys)
					totalAttributions += len(keys)
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
						if totalAttributions >= maxNormalizedRecords {
							return nil, Report{}, fmt.Errorf("attribution record budget exceeds 100000")
						}
						aggregate.attributions = append(aggregate.attributions, normalized.attribution)
						totalAttributions++
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
		return attributionKey(report.Attributions[left]) < attributionKey(report.Attributions[right])
	})
	report.Attributions = dedupeAttributions(report.Attributions)
	report.Records = len(records)
	raw, err := encodeBundleLimited(outputEnvelope{
		SchemaVersion: bundle.SchemaVersion,
		Family:        bundle.FamilyTI,
		Version:       input.Version,
		Sequence:      input.Sequence,
		KeyID:         input.KeyID,
		GeneratedAt:   input.GeneratedAt,
		ValidFrom:     input.ValidFrom,
		ValidUntil:    input.ValidUntil,
		Payload:       bundle.TIPayload{Records: records},
	}, bundleLimit, onBundleWrite)
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
	return encodeReportLimited(report, maxReportBytes, nil)
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
		if !publicHTTPS(source.PublicURLBase) || source.PublicURLBase[len(source.PublicURLBase)-1] != '/' || privacy.ContainsSensitiveValue(source.PublicURLBase) {
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

func attributionKey(value Attribution) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func dedupeAttributions(values []Attribution) []Attribution {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || attributionKey(result[len(result)-1]) != attributionKey(value) {
			result = append(result, value)
		}
	}
	return result
}

type limitedBuffer struct {
	buffer  bytes.Buffer
	limit   int
	name    string
	onWrite func(int)
}

func (writer *limitedBuffer) Write(value []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if remaining <= 0 {
		return 0, fmt.Errorf("%s exceeds %d-byte limit", writer.name, writer.limit)
	}
	writeValue := value
	if len(writeValue) > remaining {
		writeValue = writeValue[:remaining]
	}
	written, err := writer.buffer.Write(writeValue)
	if writer.onWrite != nil {
		writer.onWrite(written)
	}
	if err != nil {
		return written, err
	}
	if written != len(value) {
		return written, fmt.Errorf("%s exceeds %d-byte limit", writer.name, writer.limit)
	}
	return written, nil
}

func encodeJSONLimited(value any, limit int, name string, onWrite func(int)) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", name, limit)
	}
	output := &limitedBuffer{limit: limit, name: name, onWrite: onWrite}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

func encodeBundleLimited(envelope outputEnvelope, limit int, onWrite func(int)) ([]byte, error) {
	output := &limitedBuffer{limit: limit, name: "bundle", onWrite: onWrite}
	if err := writeJSONFields(output, []jsonField{
		{"schemaVersion", envelope.SchemaVersion}, {"family", envelope.Family}, {"version", envelope.Version},
		{"sequence", envelope.Sequence}, {"keyId", envelope.KeyID}, {"generatedAt", envelope.GeneratedAt},
		{"validFrom", envelope.ValidFrom}, {"validUntil", envelope.ValidUntil},
	}); err != nil {
		return nil, err
	}
	if _, err := output.Write([]byte(`,"payload":{"records":[`)); err != nil {
		return nil, err
	}
	for index, record := range envelope.Payload.Records {
		if index > 0 {
			if _, err := output.Write([]byte(",")); err != nil {
				return nil, err
			}
		}
		if err := writeJSONValue(output, record); err != nil {
			return nil, err
		}
	}
	if _, err := output.Write([]byte("]}}\n")); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

func encodeReportLimited(report Report, limit int, onWrite func(int)) ([]byte, error) {
	output := &limitedBuffer{limit: limit, name: "attribution report", onWrite: onWrite}
	if err := writeJSONFields(output, []jsonField{
		{"version", report.Version}, {"sequence", report.Sequence}, {"generatedAt", report.GeneratedAt},
		{"records", report.Records}, {"malicious", report.Malicious}, {"vulnerable", report.Vulnerable},
		{"withdrawn", report.Withdrawn}, {"rejectedAffected", report.RejectedAffected},
		{"duplicates", report.Duplicates}, {"sources", report.Sources},
	}); err != nil {
		return nil, err
	}
	if _, err := output.Write([]byte(`,"attributions":[`)); err != nil {
		return nil, err
	}
	for index, attribution := range report.Attributions {
		if index > 0 {
			if _, err := output.Write([]byte(",")); err != nil {
				return nil, err
			}
		}
		if err := writeJSONValue(output, attribution); err != nil {
			return nil, err
		}
	}
	if _, err := output.Write([]byte("]}\n")); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

type jsonField struct {
	name  string
	value any
}

func writeJSONFields(output *limitedBuffer, fields []jsonField) error {
	if _, err := output.Write([]byte("{")); err != nil {
		return err
	}
	for index, field := range fields {
		if index > 0 {
			if _, err := output.Write([]byte(",")); err != nil {
				return err
			}
		}
		if err := writeJSONValue(output, field.name); err != nil {
			return err
		}
		if _, err := output.Write([]byte(":")); err != nil {
			return err
		}
		if err := writeJSONValue(output, field.value); err != nil {
			return err
		}
	}
	return nil
}

func writeJSONValue(output *limitedBuffer, value any) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	raw := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	_, err := output.Write(raw)
	return err
}
