package tipublish

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	versionmatch "github.com/s1ns3nz0/ssc-init/internal/analyzer/version"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/packageid"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
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

type normalizedDocument struct {
	records          []normalizedRecord
	rejectedAffected int
}

var (
	errAffectedUnrepresentable = errors.New("affected entry cannot be represented exactly")
	errNormalizedRecordBudget  = errors.New("normalized record budget exceeds 100000")
)

func normalizeRecord(record osvRecord, source Source, category sourceCategory, input Input, recordBudget int) (normalizedDocument, error) {
	if recordBudget <= 0 {
		return normalizedDocument{}, errNormalizedRecordBudget
	}
	if record.ID == "" || len(record.ID) > maxRecordIDBytes || strings.ContainsAny(record.ID, "/\\?#\x00") || privacy.ContainsSensitiveValue(record.ID) {
		return normalizedDocument{}, fmt.Errorf("source record: invalid id")
	}
	modified, err := time.Parse(time.RFC3339, record.Modified)
	if err != nil || modified.Location() != time.UTC {
		return normalizedDocument{}, fmt.Errorf("source record %s: invalid modified time", record.ID)
	}
	withdrawn := false
	if record.Withdrawn != "" {
		withdrawnAt, err := time.Parse(time.RFC3339, record.Withdrawn)
		if err != nil || withdrawnAt.Location() != time.UTC {
			return normalizedDocument{}, fmt.Errorf("source record %s: invalid withdrawn time", record.ID)
		}
		withdrawn = true
	}
	if err := validateCommonMetadata(record); err != nil {
		return normalizedDocument{}, fmt.Errorf("source record %s: %w", record.ID, err)
	}
	if len(record.Affected) == 0 || len(record.Affected) > maxListItems || len(record.Severity) > 64 || len(record.References) > 64 {
		return normalizedDocument{}, fmt.Errorf("source record %s: affected data is outside bounds", record.ID)
	}
	for _, reference := range record.References {
		if reference.Type == "" || len(reference.Type) > 64 || !referenceHTTPS(reference.URL) {
			return normalizedDocument{}, fmt.Errorf("source record %s: invalid public reference", record.ID)
		}
	}
	publicURL := source.PublicURLBase + url.PathEscape(record.ID)
	if !publicHTTPS(publicURL) {
		return normalizedDocument{}, fmt.Errorf("public source configuration is invalid")
	}
	document := normalizedDocument{records: []normalizedRecord{}}
	seenSelectors := make(map[string]struct{})
	var lastRejected error
	for _, affected := range record.Affected {
		records, err := normalizeAffectedRecord(record, affected, source, category, input, publicURL, modified, withdrawn, seenSelectors, recordBudget-len(document.records))
		if errors.Is(err, errAffectedUnrepresentable) {
			document.rejectedAffected++
			lastRejected = err
			continue
		}
		if err != nil {
			return normalizedDocument{}, fmt.Errorf("source record %s: %w", record.ID, err)
		}
		for _, normalized := range records {
			key := semanticKey(normalized.record)
			if _, duplicate := seenSelectors[key]; duplicate {
				continue
			}
			seenSelectors[key] = struct{}{}
			document.records = append(document.records, normalized)
		}
	}
	if len(document.records) == 0 {
		return normalizedDocument{}, fmt.Errorf("source record %s: all affected entries are unrepresentable: %w", record.ID, lastRejected)
	}
	sort.Slice(document.records, func(left, right int) bool {
		return semanticKey(document.records[left].record) < semanticKey(document.records[right].record)
	})
	document.records, err = dedupeDocumentRecords(document.records)
	if err != nil {
		return normalizedDocument{}, fmt.Errorf("source record %s: %w", record.ID, err)
	}
	for index := range document.records {
		childID := record.ID
		if len(document.records) > 1 {
			childID = fmt.Sprintf("%s#%03d", record.ID, index+1)
		}
		if len(childID) > maxRecordIDBytes {
			return normalizedDocument{}, fmt.Errorf("source record %s: expanded record id exceeds bundle limit", record.ID)
		}
		document.records[index].record.ID = childID
		document.records[index].attribution.ID = childID
	}
	return document, nil
}

func normalizeAffectedRecord(record osvRecord, affected osvAffected, source Source, category sourceCategory, input Input, publicURL string, modified time.Time, withdrawn bool, seenSelectors map[string]struct{}, recordBudget int) ([]normalizedRecord, error) {
	if affected.Package.Ecosystem == "" || len(affected.Package.Ecosystem) > 64 || affected.Package.Name == "" || len(affected.Package.Name) > maxStringBytes || len(affected.Package.PURL) > maxStringBytes || len(affected.Severity) > 64 || len(affected.EcosystemSpecific) > maxIgnoredBytes || len(affected.DatabaseSpecific) > maxIgnoredBytes {
		return nil, fmt.Errorf("affected metadata is outside bounds")
	}
	coordinate, ok := packageid.FromOSV(affected.Package.Ecosystem, affected.Package.Name)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported ecosystem or package identity", errAffectedUnrepresentable)
	}
	selectors, err := normalizeAffected(coordinate, affected)
	if err != nil {
		return nil, err
	}
	severityInput := record.Severity
	if len(affected.Severity) > 0 {
		if len(record.Severity) > 0 {
			return nil, fmt.Errorf("top-level and affected severity conflict")
		}
		severityInput = affected.Severity
	}
	severities, highCVSS, err := normalizeSeverities(severityInput)
	if err != nil {
		return nil, err
	}
	verdict, confidence := "needs-review", "medium"
	if category == categoryMalicious {
		verdict, confidence = "known-malicious", "high"
	} else if highCVSS {
		verdict, confidence = "suspicious", "high"
	}
	capacity := len(selectors)
	if capacity > recordBudget {
		capacity = recordBudget
	}
	result := make([]normalizedRecord, 0, capacity)
	for _, selector := range selectors {
		normalized := normalizedRecord{
			record: bundle.TIRecord{
				AssetID: coordinate, VersionRange: selector, Verdict: verdict, Confidence: confidence,
				SourceURLs: []string{publicURL}, RetrievedAt: input.GeneratedAt.Format(time.RFC3339), ValidUntil: input.ValidUntil.Format(time.RFC3339),
				Withdrawn: withdrawn, License: source.License, Redistributable: true,
			},
			attribution: Attribution{
				SourceID: record.ID, Category: string(category), License: source.License, PublicURL: publicURL,
				ModifiedAt: modified.Format(time.RFC3339Nano), Withdrawn: withdrawn, Severities: severities,
			},
		}
		if _, duplicate := seenSelectors[semanticKey(normalized.record)]; duplicate {
			continue
		}
		if len(result) >= recordBudget {
			return nil, errNormalizedRecordBudget
		}
		result = append(result, normalized)
	}
	return result, nil
}

func normalizeAffected(coordinate string, affected osvAffected) ([]string, error) {
	if len(affected.Ranges) > 64 || len(affected.Versions) > maxListItems {
		return nil, fmt.Errorf("affected lists are outside bounds")
	}
	alternatives := make([]string, 0, len(affected.Ranges)+len(affected.Versions))
	for _, candidate := range affected.Versions {
		expression, ok := versionmatch.OSVExact(coordinate, candidate)
		if !ok {
			return nil, fmt.Errorf("%w: version %q", errAffectedUnrepresentable, candidate)
		}
		alternatives = append(alternatives, expression)
	}
	for _, affectedRange := range affected.Ranges {
		converted, err := normalizeRange(coordinate, affectedRange)
		if err != nil {
			return nil, err
		}
		alternatives = append(alternatives, converted...)
	}
	alternatives = sortedUnique(alternatives)
	if len(alternatives) == 0 {
		return nil, fmt.Errorf("affected versions are empty")
	}
	return alternatives, nil
}

func normalizeRange(coordinate string, affectedRange osvRange) ([]string, error) {
	if len(affectedRange.Repo) > maxStringBytes || len(affectedRange.DatabaseSpecific) > maxIgnoredBytes {
		return nil, fmt.Errorf("range metadata is outside bounds")
	}
	if affectedRange.Type != "SEMVER" && affectedRange.Type != "ECOSYSTEM" {
		return nil, fmt.Errorf("%w: range type %q", errAffectedUnrepresentable, affectedRange.Type)
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
			if introduced != "" || event.Introduced != "0" && !representableVersion(coordinate, affectedRange.Type, event.Introduced) {
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
		if !representableVersion(coordinate, affectedRange.Type, boundary) {
			return nil, fmt.Errorf("closing boundary cannot be represented exactly")
		}
		expression, ok := versionmatch.OSVExpression(coordinate, affectedRange.Type, intervalExpression(introduced, operator, boundary))
		if !ok {
			return nil, fmt.Errorf("range cannot be represented exactly")
		}
		alternatives = append(alternatives, expression)
		introduced = ""
	}
	if introduced != "" {
		if introduced == "0" {
			expression, ok := versionmatch.OSVOpenStart(coordinate, affectedRange.Type)
			if !ok {
				return nil, fmt.Errorf("open range cannot be represented exactly")
			}
			alternatives = append(alternatives, expression)
			return alternatives, nil
		}
		raw := ">=" + introduced
		expression, ok := versionmatch.OSVExpression(coordinate, affectedRange.Type, raw)
		if !ok {
			return nil, fmt.Errorf("open range cannot be represented exactly")
		}
		alternatives = append(alternatives, expression)
	}
	return alternatives, nil
}

func dedupeDocumentRecords(records []normalizedRecord) ([]normalizedRecord, error) {
	result := records[:0]
	for _, record := range records {
		if len(result) == 0 || semanticKey(result[len(result)-1].record) != semanticKey(record.record) {
			result = append(result, record)
			continue
		}
		prior := result[len(result)-1]
		if prior.record.Verdict != record.record.Verdict || prior.record.Confidence != record.record.Confidence || prior.record.Withdrawn != record.record.Withdrawn {
			return nil, fmt.Errorf("conflicting duplicate affected selector")
		}
	}
	return result, nil
}

func semanticKey(record bundle.TIRecord) string {
	return record.AssetID + "\x00" + record.VersionRange + "\x00" + fmt.Sprint(record.Withdrawn)
}

func intervalExpression(introduced, closingOperator, closing string) string {
	if introduced == "0" {
		return closingOperator + closing
	}
	return ">=" + introduced + " " + closingOperator + closing
}

func representableVersion(coordinate, rangeType, candidate string) bool {
	if candidate == "" || len(candidate) > 128 || strings.TrimSpace(candidate) != candidate {
		return false
	}
	_, supported := versionmatch.OSVExpression(coordinate, rangeType, "="+candidate)
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
		if severity.Type == "" || severity.Score == "" || len(severity.Type) > 64 || len(severity.Score) > 256 || len(severity.Source) > maxStringBytes || privacy.ContainsSensitiveValue(severity.Type) || privacy.ContainsSensitiveValue(severity.Score) || severity.Source != "" && privacy.ContainsSensitiveValue(severity.Source) {
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
