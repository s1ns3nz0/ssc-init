package tipublish

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	versionmatch "github.com/s1ns3nz0/ssc-init/internal/analyzer/version"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/packageid"
)

const (
	maxRecordIDBytes = 256
	maxListItems     = 10_000
	maxStringBytes   = 2048
	maxIgnoredBytes  = 1 << 20
)

type sourceCategory string

const (
	categoryVulnerable sourceCategory = "vulnerable"
	categoryMalicious  sourceCategory = "malicious"
)

type normalizedRecord struct {
	record      bundle.TIRecord
	attribution Attribution
}

func normalizeRecord(record osvRecord, source Source, category sourceCategory, input Input) (normalizedRecord, error) {
	if record.ID == "" || len(record.ID) > maxRecordIDBytes || strings.ContainsAny(record.ID, "/\\?#\x00") {
		return normalizedRecord{}, fmt.Errorf("source record: invalid id")
	}
	modified, err := time.Parse(time.RFC3339, record.Modified)
	if err != nil || modified.Location() != time.UTC {
		return normalizedRecord{}, fmt.Errorf("source record %s: invalid modified time", record.ID)
	}
	withdrawn := false
	if record.Withdrawn != "" {
		withdrawnAt, err := time.Parse(time.RFC3339, record.Withdrawn)
		if err != nil || withdrawnAt.Location() != time.UTC {
			return normalizedRecord{}, fmt.Errorf("source record %s: invalid withdrawn time", record.ID)
		}
		withdrawn = true
	}
	if err := validateCommonMetadata(record); err != nil {
		return normalizedRecord{}, fmt.Errorf("source record %s: %w", record.ID, err)
	}
	if len(record.Affected) != 1 || len(record.Severity) > 64 || len(record.References) > 64 {
		return normalizedRecord{}, fmt.Errorf("source record %s: affected data is outside the closed subset", record.ID)
	}
	affected := record.Affected[0]
	if len(affected.Package.PURL) > maxStringBytes || len(affected.Severity) > 64 || len(affected.EcosystemSpecific) > maxIgnoredBytes || len(affected.DatabaseSpecific) > maxIgnoredBytes {
		return normalizedRecord{}, fmt.Errorf("source record %s: affected metadata is outside bounds", record.ID)
	}
	coordinate, ok := packageid.FromOSV(affected.Package.Ecosystem, affected.Package.Name)
	if !ok {
		return normalizedRecord{}, fmt.Errorf("unsupported ecosystem or package identity in %s", record.ID)
	}
	versionRange, err := normalizeAffected(coordinate, affected)
	if err != nil {
		return normalizedRecord{}, fmt.Errorf("source record %s: %w", record.ID, err)
	}
	if versionRange == "" {
		return normalizedRecord{}, fmt.Errorf("source record %s: affected versions are empty", record.ID)
	}
	severityInput := record.Severity
	if len(affected.Severity) > 0 {
		if len(record.Severity) > 0 {
			return normalizedRecord{}, fmt.Errorf("source record %s: top-level and affected severity conflict", record.ID)
		}
		severityInput = affected.Severity
	}
	severities, highCVSS, err := normalizeSeverities(severityInput)
	if err != nil {
		return normalizedRecord{}, fmt.Errorf("source record %s: %w", record.ID, err)
	}
	for _, reference := range record.References {
		if reference.Type == "" || len(reference.Type) > 64 || !referenceHTTPS(reference.URL) {
			return normalizedRecord{}, fmt.Errorf("source record %s: invalid public reference", record.ID)
		}
	}
	publicURL := source.PublicURLBase + url.PathEscape(record.ID)
	if !publicHTTPS(publicURL) {
		return normalizedRecord{}, fmt.Errorf("public source configuration is invalid")
	}
	verdict, confidence := "needs-review", "medium"
	if category == categoryMalicious {
		verdict, confidence = "known-malicious", "high"
	} else if highCVSS {
		verdict, confidence = "suspicious", "high"
	}
	normalized := bundle.TIRecord{
		ID:              record.ID,
		AssetID:         coordinate,
		VersionRange:    versionRange,
		Verdict:         verdict,
		Confidence:      confidence,
		SourceURLs:      []string{publicURL},
		RetrievedAt:     input.GeneratedAt.Format(time.RFC3339),
		ValidUntil:      input.ValidUntil.Format(time.RFC3339),
		Withdrawn:       withdrawn,
		License:         source.License,
		Redistributable: true,
	}
	return normalizedRecord{
		record: normalized,
		attribution: Attribution{
			ID:         record.ID,
			Category:   string(category),
			License:    source.License,
			PublicURL:  publicURL,
			ModifiedAt: modified.Format(time.RFC3339),
			Withdrawn:  withdrawn,
			Severities: severities,
		},
	}, nil
}

func normalizeAffected(coordinate string, affected osvAffected) (string, error) {
	if len(affected.Ranges) > 64 || len(affected.Versions) > maxListItems {
		return "", fmt.Errorf("affected lists are outside bounds")
	}
	alternatives := make([]string, 0, len(affected.Ranges)+len(affected.Versions))
	for _, candidate := range affected.Versions {
		if !representableVersion(coordinate, candidate) {
			return "", fmt.Errorf("version %q cannot be represented exactly", candidate)
		}
		alternatives = append(alternatives, "="+candidate)
	}
	for _, affectedRange := range affected.Ranges {
		converted, err := normalizeRange(coordinate, affectedRange)
		if err != nil {
			return "", err
		}
		alternatives = append(alternatives, converted...)
	}
	alternatives = sortedUnique(alternatives)
	if len(alternatives) > 4 {
		return "", fmt.Errorf("affected ranges exceed supported alternatives")
	}
	result := strings.Join(alternatives, " || ")
	if len(result) > 256 {
		return "", fmt.Errorf("affected range exceeds supported length")
	}
	return result, nil
}

func normalizeRange(coordinate string, affectedRange osvRange) ([]string, error) {
	if len(affectedRange.Repo) > maxStringBytes || len(affectedRange.DatabaseSpecific) > maxIgnoredBytes {
		return nil, fmt.Errorf("range metadata is outside bounds")
	}
	if affectedRange.Type != "SEMVER" && affectedRange.Type != "ECOSYSTEM" {
		return nil, fmt.Errorf("range type %q cannot be represented exactly", affectedRange.Type)
	}
	if len(affectedRange.Events) == 0 || len(affectedRange.Events) > 32 {
		return nil, fmt.Errorf("range events are outside bounds")
	}
	var alternatives []string
	introduced := ""
	for _, event := range affectedRange.Events {
		fields := 0
		for _, value := range []string{event.Introduced, event.Fixed, event.LastAffected, event.Limit} {
			if value != "" {
				fields++
			}
		}
		if fields != 1 {
			return nil, fmt.Errorf("range event must contain exactly one boundary")
		}
		if event.Introduced != "" {
			if introduced != "" || !representableVersion(coordinate, event.Introduced) {
				return nil, fmt.Errorf("introduced boundary cannot be represented exactly")
			}
			introduced = event.Introduced
			continue
		}
		if introduced == "" {
			return nil, fmt.Errorf("range closes without an introduced boundary")
		}
		if event.Limit == "*" {
			continue
		}
		boundary, operator := event.Fixed, "<"
		if event.LastAffected != "" {
			boundary, operator = event.LastAffected, "<="
		} else if event.Limit != "" {
			boundary = event.Limit
		}
		if !representableVersion(coordinate, boundary) {
			return nil, fmt.Errorf("closing boundary cannot be represented exactly")
		}
		alternatives = append(alternatives, intervalExpression(introduced, operator, boundary))
		introduced = ""
	}
	if introduced != "" {
		if introduced == "0" {
			alternatives = append(alternatives, ">=0")
		} else {
			alternatives = append(alternatives, ">="+introduced)
		}
	}
	return alternatives, nil
}

func intervalExpression(introduced, closingOperator, closing string) string {
	if introduced == "0" {
		return closingOperator + closing
	}
	return ">=" + introduced + " " + closingOperator + closing
}

func representableVersion(coordinate, candidate string) bool {
	if candidate == "" || len(candidate) > 128 || strings.TrimSpace(candidate) != candidate {
		return false
	}
	_, supported := versionmatch.Match(coordinate, candidate, "="+candidate)
	return supported
}

func normalizeSeverities(values []Severity) ([]Severity, bool, error) {
	result := append([]Severity{}, values...)
	sort.Slice(result, func(left, right int) bool {
		if result[left].Type == result[right].Type {
			if result[left].Score == result[right].Score {
				return result[left].Source < result[right].Source
			}
			return result[left].Score < result[right].Score
		}
		return result[left].Type < result[right].Type
	})
	result = dedupeSeverities(result)
	high := false
	for _, severity := range result {
		if severity.Type == "" || severity.Score == "" || len(severity.Type) > 64 || len(severity.Score) > 256 || len(severity.Source) > maxStringBytes {
			return nil, false, fmt.Errorf("severity is outside bounds")
		}
		if severity.Type != "CVSS_V3" {
			continue
		}
		score, ok := cvss3BaseScore(severity.Score)
		if !ok {
			return nil, false, fmt.Errorf("CVSS v3 vector is invalid")
		}
		high = high || score >= 9.0
	}
	return result, high, nil
}

func validateCommonMetadata(record osvRecord) error {
	if len(record.SchemaVersion) > 32 || len(record.Summary) > 16_384 || len(record.Details) > maxIgnoredBytes || len(record.Credits) > maxIgnoredBytes || len(record.DatabaseSpecific) > maxIgnoredBytes {
		return fmt.Errorf("common metadata is outside bounds")
	}
	if record.Published != "" {
		published, err := time.Parse(time.RFC3339, record.Published)
		if err != nil || published.Location() != time.UTC {
			return fmt.Errorf("published time is invalid")
		}
	}
	for _, values := range [][]string{record.Aliases, record.Upstream, record.Related} {
		if len(values) > 1024 {
			return fmt.Errorf("identifier list is outside bounds")
		}
		for _, value := range values {
			if value == "" || len(value) > maxStringBytes {
				return fmt.Errorf("identifier is outside bounds")
			}
		}
	}
	return nil
}

func dedupeSeverities(values []Severity) []Severity {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func cvss3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) != 9 || parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1" {
		return 0, false
	}
	metrics := make(map[string]string, 8)
	for _, part := range parts[1:] {
		name, value, ok := strings.Cut(part, ":")
		if !ok || name == "" || value == "" {
			return 0, false
		}
		if _, duplicate := metrics[name]; duplicate {
			return 0, false
		}
		metrics[name] = value
	}
	if len(metrics) != 8 {
		return 0, false
	}
	av, okAV := cvssWeight(metrics["AV"], map[string]float64{"N": .85, "A": .62, "L": .55, "P": .20})
	ac, okAC := cvssWeight(metrics["AC"], map[string]float64{"L": .77, "H": .44})
	ui, okUI := cvssWeight(metrics["UI"], map[string]float64{"N": .85, "R": .62})
	c, okC := cvssWeight(metrics["C"], map[string]float64{"H": .56, "L": .22, "N": 0})
	i, okI := cvssWeight(metrics["I"], map[string]float64{"H": .56, "L": .22, "N": 0})
	a, okA := cvssWeight(metrics["A"], map[string]float64{"H": .56, "L": .22, "N": 0})
	changed := metrics["S"] == "C"
	if metrics["S"] != "U" && !changed || !okAV || !okAC || !okUI || !okC || !okI || !okA {
		return 0, false
	}
	prWeights := map[string]float64{"N": .85, "L": .62, "H": .27}
	if changed {
		prWeights = map[string]float64{"N": .85, "L": .68, "H": .50}
	}
	pr, ok := cvssWeight(metrics["PR"], prWeights)
	if !ok {
		return 0, false
	}
	impactBase := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * impactBase
	if changed {
		impact = 7.52*(impactBase-.029) - 3.25*math.Pow(impactBase-.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if changed {
		base *= 1.08
	}
	return math.Ceil((math.Min(base, 10)-1e-10)*10) / 10, true
}

func cvssWeight(value string, weights map[string]float64) (float64, bool) {
	weight, ok := weights[value]
	return weight, ok
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func publicHTTPS(value string) bool {
	if value == "" || len(value) > maxStringBytes {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func referenceHTTPS(value string) bool {
	if value == "" || len(value) > maxStringBytes {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
}
