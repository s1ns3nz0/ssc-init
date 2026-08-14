package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	privacyboundary "github.com/s1ns3nz0/ssc-init/internal/privacy"
)

var (
	exportTokenPattern    = regexp.MustCompile(`\Aasset:export-sha256:[0-9a-f]{64}\z`)
	canonicalPURLPattern  = regexp.MustCompile(`\Apkg:[a-z0-9.+-]+/[A-Za-z0-9%._~+-]+(?:/[A-Za-z0-9%._~+-]+)*(?:@[A-Za-z0-9%._~:+-]+)?(?:\?[A-Za-z0-9%._~=&+-]+)?(?:#[A-Za-z0-9%._~+-]+(?:/[A-Za-z0-9%._~+-]+)*)?\z`)
	ruleIDPattern         = regexp.MustCompile(`\A[A-Za-z0-9._~:+-]+(?:/[A-Za-z0-9._~:+-]+)+\z`)
	unsafePathPattern     = regexp.MustCompile(`/(?:[A-Za-z0-9._~-]+)(?:/|$)`)
	uriPattern            = regexp.MustCompile(`(?i)(?:^|[^a-z0-9+.-])[a-z][a-z0-9+.-]*:[^\s]`)
	hostnamePattern       = regexp.MustCompile(`(?i)(?:^|[^a-z0-9.-])(?:(?:[a-z0-9-]+\.)*(?:local|test|internal)(?::[0-9]{1,5})?|(?:localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)+):[0-9]{1,5})(?:$|[^a-z0-9.-])`)
	ipEndpointPattern     = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}:[0-9]{1,5}\b`)
	envValuePattern       = regexp.MustCompile(`(?i)(?:\benv\[[a-z][a-z0-9_]*\]|\b[a-z_][a-z0-9_]*)\s*=`)
	argumentPattern       = regexp.MustCompile(`(?i)(?:^|[\s(\[{,;])-{1,2}[a-z0-9][a-z0-9_-]*`)
	privateIDPattern      = regexp.MustCompile(`(?i)(?:^|[-_:])(?:workspace|worktree|product)[-_](?:id|private|secret|value|path)(?:$|[-_:])`)
	packageSegmentPattern = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._~+-]*\z`)
	updateKeyIDPattern    = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z`)
	dockerSegmentPattern  = regexp.MustCompile(`\A[a-z0-9]+(?:[._-][a-z0-9]+)*\z`)
	domainLabelPattern    = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z`)
)

// Validate checks the closed audit envelope, persisted model vocabularies,
// graph references, normalized order, and privacy boundary.
func Validate(record Record) error {
	if record.SchemaVersion != schemaVersion || !validProfile(record.Profile) || record.Summary != summarize(record) || !validRecordRun(record.Profile, record.State, record.Run) {
		return errors.New("invalid audit record")
	}
	if record.State == StateFailed {
		if record.Failure == nil || record.Intelligence != nil || !validFailure(record.Failure.Stage, record.Failure.Code) || !emptyFailurePayload(record) {
			return errors.New("invalid failed audit record")
		}
		return nil
	}
	if (record.State != StateComplete && record.State != StatePartial) || record.Failure != nil || containsOriginalErrorText(record) {
		return errors.New("invalid completed audit record")
	}
	if !validIntelligenceUpdate(record.Intelligence, record.Run) {
		return errors.New("invalid intelligence update receipt")
	}
	if err := validateInventory(record.Profile, record.Inventory); err != nil {
		return err
	}
	if err := validateCoverage(record.Profile, record.Coverage); err != nil {
		return err
	}
	if err := validateTopLevelGraph(record.Profile, record); err != nil {
		return err
	}
	if record.Profile == ProfileRedacted && !validRedactedDisplay(record) {
		return errors.New("redacted audit record retains display identity")
	}
	return nil
}

func validIntelligenceUpdate(value *IntelligenceUpdate, run Run) bool {
	if value == nil {
		return true
	}
	if value.Family != "ti" || value.RecordedAt.IsZero() || value.RecordedAt.Location() != time.UTC || value.RecordedAt.Before(run.StartedAt) || value.RecordedAt.After(run.FinishedAt) {
		return false
	}
	hasIdentity := value.Sequence > 0 && sha256Hex(value.Digest) && updateKeyIDPattern.MatchString(value.KeyID)
	validCounts := value.Records >= 0 && value.Records <= 100_000 && value.Malicious >= 0 && value.Malicious <= 100_000 && value.Vulnerable >= 0 && value.Vulnerable <= 100_000 && value.Malicious+value.Vulnerable == value.Records
	hasIdentity = hasIdentity && validCounts
	hasNoIdentity := value.Sequence == 0 && value.Digest == "" && value.KeyID == "" && value.Records == 0 && value.Malicious == 0 && value.Vulnerable == 0
	if !hasIdentity && !hasNoIdentity {
		return false
	}
	switch value.Status {
	case "updated", "current":
		return value.ErrorCode == "" && value.Freshness == "fresh" && hasIdentity
	case "degraded":
		return validUpdateErrorCode(value.ErrorCode) && value.Freshness != "expired" && (value.Freshness == "fresh" || value.Freshness == "stale") && hasIdentity
	case "unavailable":
		if !validUpdateErrorCode(value.ErrorCode) {
			return false
		}
		if value.Freshness == "expired" {
			return hasIdentity
		}
		return (value.Freshness == "missing" || value.Freshness == "unavailable") && hasNoIdentity
	default:
		return false
	}
}

func validUpdateErrorCode(value string) bool {
	switch value {
	case "network-unavailable", "redirect-rejected", "response-limit", "manifest-invalid", "signature-invalid", "bundle-invalid", "rollback-rejected", "activation-failed":
		return true
	default:
		return false
	}
}

func validProfile(value Profile) bool { return value == ProfileInternal || value == ProfileRedacted }

func validRecordRun(profile Profile, state State, run Run) bool {
	if !utcRange(run.StartedAt, run.FinishedAt) {
		return false
	}
	if profile == ProfileInternal && (!runIDPattern.MatchString(run.ID) || !deviceIDPattern.MatchString(run.DeviceID)) {
		return false
	}
	if profile == ProfileRedacted && (!exportIdentityToken("run", run.ID) || !exportIdentityToken("device", run.DeviceID)) {
		return false
	}
	if state == StateComplete || state == StatePartial {
		if run.ScanID == "" || profile == ProfileRedacted && !exportIdentityToken("scan", run.ScanID) || profile == ProfileInternal && !safeIdentifier(run.ScanID) {
			return false
		}
	} else if run.ScanID != "" && (profile == ProfileRedacted && !exportIdentityToken("scan", run.ScanID) || profile == ProfileInternal && !safeIdentifier(run.ScanID)) {
		return false
	}
	if profile == ProfileRedacted {
		return run.Label == "redacted" && run.Product == "" && run.Version == ""
	}
	return (run.Label == "" || ValidLabel(run.Label) && safeString(run.Label) && !strings.Contains(strings.ToLower(run.Label), "worktree") && !strings.Contains(strings.ToLower(run.Label), "workspace")) && run.Product == "ssc-init" && validVersion(run.Version)
}

func utcRange(started, finished time.Time) bool {
	return !started.IsZero() && !finished.IsZero() && started.Location() == time.UTC && finished.Location() == time.UTC && !finished.Before(started)
}

func validVersion(value string) bool {
	return value == "dev" || regexp.MustCompile(`\A(?:v[0-9][0-9A-Za-z.+-]*|dev\+git\.[0-9a-f]{40})\z`).MatchString(value)
}

func exportToken(value string) bool { return exportTokenPattern.MatchString(value) }

func exportIdentityToken(kind, value string) bool {
	prefix := kind + ":export-sha256:"
	if !strings.HasPrefix(value, prefix) || len(strings.TrimPrefix(value, prefix)) != 64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && strings.ToLower(strings.TrimPrefix(value, prefix)) == strings.TrimPrefix(value, prefix)
}

func emptyFailurePayload(record Record) bool {
	return len(record.Inventory.Assets) == 0 && len(record.Inventory.Observations) == 0 && len(record.Inventory.Evidence) == 0 &&
		len(record.Inventory.Relationships) == 0 && len(record.Inventory.Errors) == 0 && len(record.Inventory.Findings) == 0 && len(record.Inventory.AnalyzerFacts) == 0 &&
		len(record.Findings) == 0 && len(record.Coverage) == 0 && record.EvidenceCoverage == nil && len(record.Changes.Changes) == 0
}

func containsOriginalErrorText(record Record) bool {
	for _, errorValue := range append(append([]model.CoverageError(nil), record.Inventory.Errors...), coverageErrors(record.Coverage)...) {
		if errorValue.Message != "" || errorValue.Path != "" || !validAuditErrorCode(errorValue.Code) {
			return true
		}
	}
	for _, evidence := range record.Inventory.Evidence {
		for _, errorValue := range evidence.Errors {
			if errorValue.Message != "" || !validAuditErrorCode(errorValue.Code) {
				return true
			}
		}
	}
	return false
}

func coverageErrors(results []model.CollectorResult) []model.CoverageError {
	var errors []model.CoverageError
	for _, result := range results {
		errors = append(errors, result.Errors...)
		for _, target := range result.Targets {
			errors = append(errors, target.Errors...)
		}
	}
	return errors
}

func validateInventory(profile Profile, inventory model.Inventory) error {
	assetIDs := map[string]struct{}{}
	for _, asset := range inventory.Assets {
		if !validAsset(profile, asset) || !addUnique(assetIDs, asset.ID) {
			return errors.New("invalid audit asset")
		}
	}
	observationIDs := map[string]struct{}{}
	for _, observation := range inventory.Observations {
		if !validObservation(profile, observation, assetIDs) || !addUnique(observationIDs, observation.ID) {
			return errors.New("invalid audit observation")
		}
	}
	evidenceIDs := map[string]struct{}{}
	for _, evidence := range inventory.Evidence {
		if !validEvidence(profile, evidence, assetIDs, observationIDs) || !addUnique(evidenceIDs, evidence.ID) {
			return errors.New("invalid audit evidence")
		}
	}
	if !sortedBy(inventory.Assets, func(asset model.Asset) string { return asset.ID }) || !sortedBy(inventory.Observations, func(observation model.Observation) string { return observation.ID }) || !sortedBy(inventory.Evidence, func(evidence model.ContentEvidence) string { return evidence.ID }) {
		return errors.New("unsorted audit inventory")
	}
	for _, relationship := range inventory.Relationships {
		if !validReference(profile, relationship.From) || !validReference(profile, relationship.To) || !model.ValidRelationshipKind(relationship.Kind) || !contains(assetIDs, relationship.From) || !contains(assetIDs, relationship.To) {
			return errors.New("invalid audit relationship")
		}
	}
	if !sort.SliceIsSorted(inventory.Relationships, func(left, right int) bool {
		return relationshipKey(inventory.Relationships[left]) < relationshipKey(inventory.Relationships[right])
	}) || duplicateRelationships(inventory.Relationships) {
		return errors.New("unsorted audit relationships")
	}
	for _, finding := range inventory.Findings {
		if !validFinding(profile, finding, assetIDs, evidenceIDs) {
			return errors.New("invalid audit finding")
		}
	}
	if !sortedBy(inventory.Findings, func(finding model.Finding) string { return finding.ID }) {
		return errors.New("unsorted audit findings")
	}
	factIDs := map[string]struct{}{}
	for _, fact := range inventory.AnalyzerFacts {
		if !validAnalyzerFact(profile, fact, assetIDs, evidenceIDs) || !addUnique(factIDs, fact.ID) {
			return errors.New("invalid audit analyzer fact")
		}
	}
	if !sortedBy(inventory.AnalyzerFacts, func(fact model.AnalyzerFact) string { return fact.ID }) {
		return errors.New("unsorted audit analyzer facts")
	}
	if !validCoverageErrors(inventory.Errors) || !sort.SliceIsSorted(inventory.Errors, func(left, right int) bool {
		return coverageErrorKey(inventory.Errors[left]) < coverageErrorKey(inventory.Errors[right])
	}) {
		return errors.New("invalid audit inventory errors")
	}
	return nil
}

func validateCoverage(profile Profile, coverage []model.CollectorResult) error {
	seen := map[string]struct{}{}
	for _, result := range coverage {
		if !validCollector(result.Collector) || !validCoverageStatus(result.Status) || !addUnique(seen, result.Collector) || !validCoverageErrors(result.Errors) {
			return errors.New("invalid audit collector coverage")
		}
		assetIDs := map[string]struct{}{}
		for _, asset := range result.Assets {
			if !validAsset(profile, asset) || !addUnique(assetIDs, asset.ID) {
				return errors.New("invalid audit collector asset")
			}
		}
		if !sortedBy(result.Assets, func(asset model.Asset) string { return asset.ID }) {
			return errors.New("unsorted audit collector assets")
		}
		for _, relationship := range result.Relationships {
			if !model.ValidRelationshipKind(relationship.Kind) || !contains(assetIDs, relationship.From) || !contains(assetIDs, relationship.To) {
				return errors.New("invalid audit collector relationship")
			}
		}
		if !sort.SliceIsSorted(result.Relationships, func(left, right int) bool {
			return relationshipKey(result.Relationships[left]) < relationshipKey(result.Relationships[right])
		}) || duplicateRelationships(result.Relationships) {
			return errors.New("unsorted audit collector relationships")
		}
		observationIDs := map[string]struct{}{}
		for _, observation := range result.Observations {
			if !validObservation(profile, observation, assetIDs) || !addUnique(observationIDs, observation.ID) {
				return errors.New("invalid audit collector observation")
			}
		}
		if !sortedBy(result.Observations, func(observation model.Observation) string { return observation.ID }) {
			return errors.New("unsorted audit collector observations")
		}
		targets := map[string]struct{}{}
		for _, target := range result.Targets {
			if !validTarget(profile, target) || !addUnique(targets, targetCoverageKey(target)) || !sort.SliceIsSorted(target.Errors, func(left, right int) bool {
				return coverageErrorKey(target.Errors[left]) < coverageErrorKey(target.Errors[right])
			}) {
				return errors.New("invalid audit target")
			}
		}
		if !sortedBy(result.Targets, targetCoverageKey) || !sort.SliceIsSorted(result.Errors, func(left, right int) bool {
			return coverageErrorKey(result.Errors[left]) < coverageErrorKey(result.Errors[right])
		}) {
			return errors.New("unsorted audit collector coverage")
		}
	}
	if !sortedBy(coverage, func(result model.CollectorResult) string { return result.Collector }) {
		return errors.New("unsorted audit collector coverage")
	}
	return nil
}

func validateTopLevelGraph(profile Profile, record Record) error {
	assetIDs, observationIDs, evidenceIDs := inventoryIDs(record.Inventory)
	for _, finding := range record.Findings {
		if !validFinding(profile, finding, assetIDs, evidenceIDs) {
			return errors.New("invalid audit finding")
		}
	}
	if !sortedBy(record.Findings, func(finding model.Finding) string { return finding.ID }) {
		return errors.New("unsorted audit findings")
	}
	for _, change := range record.Changes.Changes {
		if !validChange(profile, change, assetIDs, observationIDs, evidenceIDs) {
			return errors.New("invalid audit change")
		}
	}
	if !sort.SliceIsSorted(record.Changes.Changes, func(left, right int) bool {
		a, b := record.Changes.Changes[left], record.Changes.Changes[right]
		return string(a.Entity)+"\x00"+a.EntityID+"\x00"+string(a.Kind) < string(b.Entity)+"\x00"+b.EntityID+"\x00"+string(b.Kind)
	}) {
		return errors.New("unsorted audit changes")
	}
	if record.EvidenceCoverage == nil {
		return nil
	}
	if !validCoverageStatus(record.EvidenceCoverage.Status) || !validCoverageErrors(record.EvidenceCoverage.Errors) || !sort.SliceIsSorted(record.EvidenceCoverage.Errors, func(left, right int) bool {
		return coverageErrorKey(record.EvidenceCoverage.Errors[left]) < coverageErrorKey(record.EvidenceCoverage.Errors[right])
	}) {
		return errors.New("invalid audit evidence coverage")
	}
	seen := map[string]struct{}{}
	for _, target := range record.EvidenceCoverage.Targets {
		key := evidenceTargetKey(target)
		if !validEvidenceTarget(profile, target, assetIDs, observationIDs, evidenceIDs) || !addUnique(seen, key) {
			return errors.New("invalid audit evidence target")
		}
	}
	if !sortedBy(record.EvidenceCoverage.Targets, evidenceTargetKey) {
		return errors.New("unsorted audit evidence targets")
	}
	return nil
}

func inventoryIDs(inventory model.Inventory) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	assets, observations, evidence := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, value := range inventory.Assets {
		assets[value.ID] = struct{}{}
	}
	for _, value := range inventory.Observations {
		observations[value.ID] = struct{}{}
	}
	for _, value := range inventory.Evidence {
		evidence[value.ID] = struct{}{}
	}
	return assets, observations, evidence
}

func validAsset(profile Profile, asset model.Asset) bool {
	if !validReference(profile, asset.ID) || !validAssetType(asset.Type) || !utcOrZero(asset.ObservedAt) || asset.Path != "" || asset.Source != "" || len(asset.Metadata) != 0 {
		return false
	}
	if profile == ProfileRedacted {
		return redactedAsset(asset) && validSignature(asset.Signature) && validProvenance(asset.Provenance)
	}
	return validAssetName(asset) && validAssetVersion(asset) && (asset.SHA256 == "" || sha256Hex(asset.SHA256)) && validSignature(asset.Signature) && validProvenance(asset.Provenance)
}

func validAssetVersion(asset model.Asset) bool {
	if asset.Version == "" || safeText(asset.Version) {
		return true
	}
	if asset.Type != model.AssetPackage || !sha256Integrity(asset.Version) {
		return false
	}
	prefix := "pkg:docker/"
	if !strings.HasPrefix(asset.ID, prefix) {
		return false
	}
	coordinate := strings.TrimPrefix(asset.ID, prefix)
	if boundary := strings.IndexAny(coordinate, "?#"); boundary >= 0 {
		coordinate = coordinate[:boundary]
	}
	separator := strings.LastIndexByte(coordinate, '@')
	if separator < 1 {
		return false
	}
	version, err := url.PathUnescape(coordinate[separator+1:])
	return err == nil && version == asset.Version
}

func validAssetName(asset model.Asset) bool {
	if !strings.ContainsRune(asset.Name, '/') {
		return safeText(asset.Name)
	}
	switch asset.Type {
	case model.AssetPackage:
		return validPackageAssetName(asset.ID, asset.Name)
	case model.AssetProject:
		return validProjectConfigAssetName(asset.ID, asset.Name)
	default:
		return false
	}
}

func validPackageAssetName(id, name string) bool {
	if name == "" || len(name) > 256 || !safeStructuredString(name) || uriPattern.MatchString(name) {
		return false
	}
	ecosystem, purlName, ok := packagePURLName(id)
	if !ok || purlName != name {
		return false
	}
	parts := strings.Split(name, "/")
	if !validPackageSegments(parts) {
		return false
	}
	switch ecosystem {
	case "npm":
		return len(parts) == 2 && strings.HasPrefix(parts[0], "@") && packageSegmentPattern.MatchString(strings.TrimPrefix(parts[0], "@"))
	case "go":
		return len(parts) >= 2 && validDottedPackageRoot(parts[0])
	case "docker":
		if !allDockerSegments(parts) {
			return false
		}
		return len(parts) == 2 || len(parts) >= 3 && validDottedPackageRoot(parts[0])
	default:
		return false
	}
}

func packagePURLName(id string) (string, string, bool) {
	if !canonicalPURLPattern.MatchString(id) {
		return "", "", false
	}
	coordinate := strings.TrimPrefix(id, "pkg:")
	slash := strings.IndexByte(coordinate, '/')
	if slash <= 0 {
		return "", "", false
	}
	ecosystem, encoded := coordinate[:slash], coordinate[slash+1:]
	if boundary := strings.IndexAny(encoded, "?#"); boundary >= 0 {
		encoded = encoded[:boundary]
	}
	if version := strings.LastIndexByte(encoded, '@'); version >= 0 {
		encoded = encoded[:version]
	}
	encodedParts := strings.Split(encoded, "/")
	decodedParts := make([]string, len(encodedParts))
	for index, part := range encodedParts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || strings.ContainsAny(decoded, `/\\`) {
			return "", "", false
		}
		decodedParts[index] = decoded
	}
	return ecosystem, strings.Join(decodedParts, "/"), true
}

func validPackageSegments(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		plain := part
		if strings.HasPrefix(part, "@") {
			if part != parts[0] {
				return false
			}
			plain = strings.TrimPrefix(part, "@")
		}
		if plain == "" || plain == "." || plain == ".." || !packageSegmentPattern.MatchString(plain) {
			return false
		}
	}
	return true
}

func allDockerSegments(parts []string) bool {
	for _, part := range parts {
		if !dockerSegmentPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func validDottedPackageRoot(value string) bool {
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validProjectConfigAssetName(id, name string) bool {
	if !strings.HasPrefix(id, "project-config:sha256:") || !sha256Hex(strings.TrimPrefix(id, "project-config:sha256:")) {
		return false
	}
	switch name {
	case ".codex/config.toml", ".cursor/mcp.json", ".mcp.json", ".vscode/mcp.json":
		return true
	default:
		return false
	}
}

func validObservation(profile Profile, observation model.Observation, assetIDs map[string]struct{}) bool {
	if !validReference(profile, observation.ID) || !validReference(profile, observation.AssetID) || !contains(assetIDs, observation.AssetID) || !validCollector(observation.Collector) || !validScope(observation.Scope) || observation.Host != "" || observation.LocationRef != "" || observation.Source != "" || len(observation.Consumers) != 0 || len(observation.Metadata) != 0 {
		return false
	}
	return observation.ProjectID == "" || validReference(profile, observation.ProjectID) && contains(assetIDs, observation.ProjectID)
}

func validEvidence(profile Profile, evidence model.ContentEvidence, assetIDs, observationIDs map[string]struct{}) bool {
	return validReference(profile, evidence.ID) && validReference(profile, evidence.AssetID) && validReference(profile, evidence.ObservationID) && contains(assetIDs, evidence.AssetID) && contains(observationIDs, evidence.ObservationID) && validEvidenceKind(evidence.Kind) && validEvidenceSubject(evidence.Subject) && validEvidenceStatus(evidence.Status) && safeOptionalText(evidence.Algorithm) && (evidence.Digest == "" || sha256Hex(evidence.Digest)) && evidence.Size >= 0 && evidence.Files >= 0 && evidence.Directories >= 0 && evidence.Symlinks >= 0 && len(evidence.Metadata) == 0 && validEvidenceErrors(evidence.Errors) && sortedEvidenceErrors(evidence.Errors)
}

func validFinding(profile Profile, finding model.Finding, assetIDs, evidenceIDs map[string]struct{}) bool {
	if !validReference(profile, finding.ID) || !validReference(profile, finding.AssetID) || !contains(assetIDs, finding.AssetID) || !validAssetType(finding.AssetType) || finding.DetectedAt.IsZero() || !utcOrZero(finding.DetectedAt) || finding.Level < 1 || finding.Level > 5 || !validVerdict(finding.Verdict) || !validSeverity(finding.Severity) || !validConfidence(finding.Confidence) || !validAction(finding.Action) || !sortedSafeRuleIDs(finding.RuleIDs) || !sortedSafeStrings(finding.IntelligenceIDs) || !sortedSafeStrings(finding.CampaignIDs) || !sortedSafeStrings(finding.AttackTechniques) {
		return false
	}
	if profile == ProfileRedacted {
		if finding.Version != "" || finding.SHA256 != "" {
			return false
		}
	} else if !safeOptionalText(finding.Version) || finding.SHA256 != "" && !sha256Hex(finding.SHA256) {
		return false
	}
	for _, evidenceID := range finding.EvidenceIDs {
		if !validReference(profile, evidenceID) || !contains(evidenceIDs, evidenceID) {
			return false
		}
	}
	if !sort.StringsAreSorted(finding.EvidenceIDs) || hasDuplicateStrings(finding.EvidenceIDs) {
		return false
	}
	for _, bundle := range finding.Bundles {
		if (bundle.Family != "ti" && bundle.Family != "policy") || bundle.Sequence == 0 || profile == ProfileInternal && !sha256Hex(bundle.Digest) || profile == ProfileRedacted && bundle.Digest != "" {
			return false
		}
	}
	return sort.SliceIsSorted(finding.Bundles, func(left, right int) bool {
		return bundleKey(finding.Bundles[left]) < bundleKey(finding.Bundles[right])
	})
}

func validAnalyzerFact(profile Profile, fact model.AnalyzerFact, assetIDs, evidenceIDs map[string]struct{}) bool {
	return validReference(profile, fact.ID) && validReference(profile, fact.AssetID) && contains(assetIDs, fact.AssetID) && (fact.EvidenceID == "" || validReference(profile, fact.EvidenceID) && contains(evidenceIDs, fact.EvidenceID)) && safeRuleID(fact.RuleID) && validAnalyzerCategory(fact.Category) && validConfidence(fact.Confidence) && fact.Occurrences > 0 && fact.Occurrences <= 10_000
}

func validTarget(profile Profile, target model.TargetCoverage) bool {
	return validReference(profile, target.TargetID) && validTargetInstance(profile, target.InstanceRef) && validTargetStatus(target.Status) && target.Assets >= 0 && target.Observations >= 0 && validCoverageErrors(target.Errors)
}

func validTargetInstance(profile Profile, value string) bool {
	if value == "" {
		return true
	}
	if profile == ProfileRedacted {
		return exportToken(value)
	}
	return instanceToken(value)
}

func validEvidenceTarget(profile Profile, target model.EvidenceTargetResult, assetIDs, observationIDs, evidenceIDs map[string]struct{}) bool {
	return validReference(profile, target.TargetID) && validReference(profile, target.AssetID) && validReference(profile, target.ObservationID) && validReference(profile, target.EvidenceID) && contains(assetIDs, target.AssetID) && contains(observationIDs, target.ObservationID) && contains(evidenceIDs, target.EvidenceID) && validEvidenceStatus(target.Status) && validEvidenceErrors(target.Errors) && sortedEvidenceErrors(target.Errors)
}

func validChange(profile Profile, change model.Change, assets, observations, evidence map[string]struct{}) bool {
	if !validReference(profile, change.EntityID) || !validChangeKind(change.Kind) {
		return false
	}
	if change.Kind == model.ChangeRemoved {
		switch change.Entity {
		case model.ChangeEntityAsset, model.ChangeEntityObservation, model.ChangeEntityEvidence:
			return true
		default:
			return false
		}
	}
	switch change.Entity {
	case model.ChangeEntityAsset:
		return contains(assets, change.EntityID)
	case model.ChangeEntityObservation:
		return contains(observations, change.EntityID)
	case model.ChangeEntityEvidence:
		return contains(evidence, change.EntityID)
	default:
		return false
	}
}

func validRedactedDisplay(record Record) bool {
	for _, asset := range record.Inventory.Assets {
		if !redactedAsset(asset) {
			return false
		}
	}
	for _, result := range record.Coverage {
		for _, asset := range result.Assets {
			if !redactedAsset(asset) {
				return false
			}
		}
	}
	for _, observation := range append(append([]model.Observation(nil), record.Inventory.Observations...), coverageObservations(record.Coverage)...) {
		if observation.Host != "" || observation.LocationRef != "" || observation.Source != "" || len(observation.Consumers) != 0 || len(observation.Metadata) != 0 {
			return false
		}
	}
	for _, evidence := range record.Inventory.Evidence {
		if evidence.Digest != "" || len(evidence.Metadata) != 0 {
			return false
		}
	}
	for _, finding := range append(append([]model.Finding(nil), record.Inventory.Findings...), record.Findings...) {
		if finding.Version != "" || finding.SHA256 != "" {
			return false
		}
		for _, bundle := range finding.Bundles {
			if bundle.Digest != "" {
				return false
			}
		}
	}
	return true
}

func coverageObservations(results []model.CollectorResult) []model.Observation {
	var observations []model.Observation
	for _, result := range results {
		observations = append(observations, result.Observations...)
	}
	return observations
}

func redactedAsset(asset model.Asset) bool {
	return asset.Name == "" && asset.Version == "" && asset.Path == "" && asset.Source == "" && asset.SHA256 == "" && len(asset.Metadata) == 0 &&
		(asset.Signature == nil || asset.Signature.Identifier == "" && asset.Signature.TeamID == "") &&
		(asset.Provenance == nil || asset.Provenance.Source == "" && asset.Provenance.Integrity == "")
}

// Redact produces an export-local record that cannot correlate identities with another export.
func Redact(record Record, salt [32]byte) (Record, error) {
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	redacted, err := clone(record)
	if err != nil {
		return Record{}, err
	}
	identities := map[string]string{}
	token := func(value string) string {
		if value == "" {
			return ""
		}
		if existing, ok := identities[value]; ok {
			return existing
		}
		mac := hmac.New(sha256.New, salt[:])
		_, _ = mac.Write([]byte(value))
		result := "asset:export-sha256:" + hex.EncodeToString(mac.Sum(nil))
		identities[value] = result
		return result
	}
	for index := range redacted.Inventory.Assets {
		redactAsset(&redacted.Inventory.Assets[index], token)
	}
	for index := range redacted.Coverage {
		redactCollector(&redacted.Coverage[index], token)
	}
	for index := range redacted.Inventory.Relationships {
		redacted.Inventory.Relationships[index].From, redacted.Inventory.Relationships[index].To = token(redacted.Inventory.Relationships[index].From), token(redacted.Inventory.Relationships[index].To)
	}
	for index := range redacted.Inventory.Observations {
		redactObservation(&redacted.Inventory.Observations[index], token)
	}
	for index := range redacted.Inventory.Evidence {
		redactEvidence(&redacted.Inventory.Evidence[index], token)
	}
	for index := range redacted.Inventory.Findings {
		redactFinding(&redacted.Inventory.Findings[index], token)
	}
	for index := range redacted.Inventory.AnalyzerFacts {
		fact := &redacted.Inventory.AnalyzerFacts[index]
		fact.ID, fact.AssetID, fact.EvidenceID = token(fact.ID), token(fact.AssetID), token(fact.EvidenceID)
	}
	for index := range redacted.Findings {
		redactFinding(&redacted.Findings[index], token)
	}
	for index := range redacted.Changes.Changes {
		redacted.Changes.Changes[index].EntityID = token(redacted.Changes.Changes[index].EntityID)
	}
	if redacted.EvidenceCoverage != nil {
		for index := range redacted.EvidenceCoverage.Targets {
			target := &redacted.EvidenceCoverage.Targets[index]
			target.TargetID, target.AssetID, target.ObservationID, target.EvidenceID = token(target.TargetID), token(target.AssetID), token(target.ObservationID), token(target.EvidenceID)
		}
	}
	redacted.Profile = ProfileRedacted
	redacted.Run.ID, redacted.Run.DeviceID = exportIdentity("run", redacted.Run.ID, salt), exportIdentity("device", redacted.Run.DeviceID, salt)
	if redacted.Run.ScanID != "" {
		redacted.Run.ScanID = exportIdentity("scan", redacted.Run.ScanID, salt)
	}
	redacted.Run.Label, redacted.Run.Product, redacted.Run.Version = "redacted", "", ""
	normalizeRecord(&redacted)
	redacted.Summary = summarize(redacted)
	if err := Validate(redacted); err != nil {
		return Record{}, err
	}
	return redacted, nil
}

func exportIdentity(kind, value string, salt [32]byte) string {
	mac := hmac.New(sha256.New, salt[:])
	_, _ = mac.Write([]byte(value))
	return kind + ":export-sha256:" + hex.EncodeToString(mac.Sum(nil))
}
func redactAsset(asset *model.Asset, token func(string) string) {
	asset.ID = token(asset.ID)
	asset.Name, asset.Version, asset.Path, asset.Source, asset.SHA256, asset.Metadata = "", "", "", "", "", nil
	if asset.Signature != nil {
		asset.Signature.Identifier, asset.Signature.TeamID = "", ""
	}
	if asset.Provenance != nil {
		asset.Provenance.Source, asset.Provenance.Integrity = "", ""
	}
}
func redactCollector(result *model.CollectorResult, token func(string) string) {
	for index := range result.Assets {
		redactAsset(&result.Assets[index], token)
	}
	for index := range result.Relationships {
		result.Relationships[index].From, result.Relationships[index].To = token(result.Relationships[index].From), token(result.Relationships[index].To)
	}
	for index := range result.Observations {
		redactObservation(&result.Observations[index], token)
	}
	for index := range result.Targets {
		result.Targets[index].TargetID, result.Targets[index].InstanceRef = token(result.Targets[index].TargetID), token(result.Targets[index].InstanceRef)
	}
}
func redactObservation(observation *model.Observation, token func(string) string) {
	observation.ID, observation.AssetID, observation.ProjectID = token(observation.ID), token(observation.AssetID), token(observation.ProjectID)
	observation.Host, observation.LocationRef, observation.Source, observation.Consumers, observation.Metadata = "", "", "", nil, nil
}
func redactEvidence(evidence *model.ContentEvidence, token func(string) string) {
	evidence.ID, evidence.AssetID, evidence.ObservationID = token(evidence.ID), token(evidence.AssetID), token(evidence.ObservationID)
	evidence.Digest, evidence.Metadata = "", nil
}
func redactFinding(finding *model.Finding, token func(string) string) {
	finding.ID, finding.AssetID, finding.Version, finding.SHA256 = token(finding.ID), token(finding.AssetID), "", ""
	for index := range finding.EvidenceIDs {
		finding.EvidenceIDs[index] = token(finding.EvidenceIDs[index])
	}
	for index := range finding.Bundles {
		finding.Bundles[index].Digest = ""
	}
}

func clearCoverageErrors(errors []model.CoverageError) {
	for index := range errors {
		errors[index].Message, errors[index].Path = "", ""
	}
}
func clearEvidenceErrors(errors []model.EvidenceError) {
	for index := range errors {
		errors[index].Message = ""
	}
}

func validReference(profile Profile, value string) bool {
	if profile == ProfileRedacted {
		return exportToken(value)
	}
	return safeIdentifier(value)
}
func safeIdentifier(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || privacyboundary.ContainsSensitiveValue(value) || strings.Contains(value, `\`) || strings.ContainsRune(value, '\x00') {
		return false
	}
	if strings.HasPrefix(value, "pkg:") {
		return canonicalPURLPattern.MatchString(value)
	}
	return safeStructuredString(value) && !strings.ContainsAny(value, " /\\")
}
func safeRuleID(value string) bool {
	return value != "" && len(value) <= 256 && safeStructuredString(value) && (safeIdentifier(value) || ruleIDPattern.MatchString(value))
}
func safeText(value string) bool         { return value != "" && len(value) <= 256 && safeString(value) }
func safeOptionalText(value string) bool { return value == "" || safeText(value) }
func safeString(value string) bool       { return utf8.ValidString(value) && !unsafeAuditString(value) }
func safeStructuredString(value string) bool {
	return utf8.ValidString(value) && !privacyboundary.ContainsSensitiveValue(value) && !strings.Contains(value, `\`) && !hostnamePattern.MatchString(value) && !ipEndpointPattern.MatchString(value) && !envValuePattern.MatchString(value) && !privateIDPattern.MatchString(value) && !argumentPattern.MatchString(value) && !strings.ContainsRune(value, '\x00')
}
func unsafeAuditString(value string) bool {
	return !safeStructuredString(value) || uriPattern.MatchString(value) || unsafePathPattern.MatchString(value)
}
func addUnique(values map[string]struct{}, value string) bool {
	if _, found := values[value]; found {
		return false
	}
	values[value] = struct{}{}
	return true
}
func contains(values map[string]struct{}, value string) bool { _, found := values[value]; return found }
func utcOrZero(value time.Time) bool                         { return value.IsZero() || value.Location() == time.UTC }
func sortedBy[T any](values []T, key func(T) string) bool {
	for index := 1; index < len(values); index++ {
		if key(values[index-1]) >= key(values[index]) {
			return false
		}
	}
	return true
}
func sortedSafeStrings(values []string) bool {
	return sort.StringsAreSorted(values) && !hasDuplicateStrings(values) && func() bool {
		for _, value := range values {
			if !safeText(value) {
				return false
			}
		}
		return true
	}()
}
func sortedSafeRuleIDs(values []string) bool {
	return sort.StringsAreSorted(values) && !hasDuplicateStrings(values) && func() bool {
		for _, value := range values {
			if !safeRuleID(value) {
				return false
			}
		}
		return true
	}()
}
func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}
func duplicateRelationships(values []model.Relationship) bool {
	for index := 1; index < len(values); index++ {
		if relationshipKey(values[index-1]) == relationshipKey(values[index]) {
			return true
		}
	}
	return false
}
func sortedEvidenceErrors(values []model.EvidenceError) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].Code >= values[index].Code {
			return false
		}
	}
	return true
}
func validCoverageErrors(values []model.CoverageError) bool {
	for _, value := range values {
		if !validAuditErrorCode(value.Code) || value.Message != "" || value.Path != "" {
			return false
		}
	}
	return true
}
func validEvidenceErrors(values []model.EvidenceError) bool {
	for _, value := range values {
		if !validAuditErrorCode(value.Code) || value.Message != "" {
			return false
		}
	}
	return true
}
func sha256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
func bundleKey(value model.BundleReference) string {
	return value.Family + "\x00" + fmt.Sprintf("%020d", value.Sequence) + "\x00" + value.Digest
}

func validAssetType(value model.AssetType) bool {
	switch value {
	case model.AssetAgentPlugin, model.AssetSkill, model.AssetMCP, model.AssetIDEExtension, model.AssetPackage, model.AssetProject, model.AssetTool, model.AssetShellStartup, model.AssetGitHook, model.AssetCredentialHelper, model.AssetLaunchConfig, model.AssetProcess, model.AssetListeningEndpoint:
		return true
	}
	return false
}
func validCoverageStatus(value model.CoverageStatus) bool {
	switch value {
	case model.CoverageComplete, model.CoveragePartial, model.CoverageSkipped, model.CoverageUnavailable, model.CoverageFailed:
		return true
	}
	return false
}
func validTargetStatus(value model.TargetStatus) bool {
	switch value {
	case model.TargetComplete, model.TargetNotPresent, model.TargetPartial, model.TargetUnavailable, model.TargetUnsupported, model.TargetSkipped:
		return true
	}
	return false
}
func validEvidenceKind(value model.EvidenceKind) bool {
	switch value {
	case model.EvidenceFileSHA256, model.EvidenceTreeSHA256, model.EvidenceSemanticSHA256, model.EvidencePackageContent, model.EvidenceContainerIdentity:
		return true
	}
	return false
}
func validEvidenceStatus(value model.EvidenceStatus) bool {
	switch value {
	case model.EvidenceComplete, model.EvidencePartial, model.EvidenceOversize, model.EvidenceUnavailable, model.EvidenceUnsupported, model.EvidenceSkipped:
		return true
	}
	return false
}
func validEvidenceSubject(value string) bool {
	switch value {
	case model.EvidenceSubjectManifest, model.EvidenceSubjectSkillDocument, model.EvidenceSubjectEntrypointMain, model.EvidenceSubjectEntrypointBrowser, model.EvidenceSubjectPayloadTree, model.EvidenceSubjectMCPDeclaration, model.EvidenceSubjectPackageContent, model.EvidenceSubjectContainerImage, model.EvidenceSubjectShellStartup, model.EvidenceSubjectGitHook, model.EvidenceSubjectLaunchConfig, model.EvidenceSubjectCredentialConfig:
		return true
	}
	return model.ProjectEvidenceSubject(value)
}
func validScope(value model.ObservationScope) bool {
	switch value {
	case model.ScopeUser, model.ScopeProject, model.ScopeIDEProfile, model.ScopeToolEnvironment, model.ScopeSystem:
		return true
	}
	return false
}
func validCollector(value string) bool {
	switch value {
	case "agents", "ide", "mcp", "packages", "projects", "runtime", "surfaces":
		return true
	}
	return false
}
func validVerdict(value model.Verdict) bool {
	switch value {
	case model.VerdictKnownMalicious, model.VerdictBehaviorMalicious, model.VerdictSuspicious, model.VerdictNeedsReview, model.VerdictNoFinding:
		return true
	}
	return false
}
func validSeverity(value model.Severity) bool {
	switch value {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInformational:
		return true
	}
	return false
}
func validConfidence(value model.Confidence) bool {
	return value == model.ConfidenceHigh || value == model.ConfidenceMedium || value == model.ConfidenceLow
}
func validAction(value model.FindingAction) bool {
	switch value {
	case model.ActionAdvisory, model.ActionBlocked, model.ActionPaused, model.ActionExcepted, model.ActionAllowed:
		return true
	}
	return false
}
func validAnalyzerCategory(value model.AnalyzerCategory) bool {
	switch value {
	case model.AnalyzerVersionAdvisory, model.AnalyzerMutableReference, model.AnalyzerDynamicExecution, model.AnalyzerProcessLaunch, model.AnalyzerCredentialAccess, model.AnalyzerOutboundNetwork, model.AnalyzerObfuscation, model.AnalyzerCredentialEgress:
		return true
	}
	return false
}
func validChangeKind(value model.ChangeKind) bool {
	return value == model.ChangeAdded || value == model.ChangeRemoved || value == model.ChangeChanged
}
func validSignature(value *model.Signature) bool {
	return value == nil || value.Status.Valid() && safeOptionalText(value.Identifier) && safeOptionalText(value.TeamID)
}
func validProvenance(value *model.Provenance) bool {
	return value == nil || value.Status.Valid() && safeText(value.Ecosystem) && safeOptionalText(value.Source) && (value.Integrity == "" || sha256Integrity(value.Integrity))
}
func sha256Integrity(value string) bool {
	return strings.HasPrefix(value, "sha256:") && sha256Hex(strings.TrimPrefix(value, "sha256:"))
}

// auditCoverageErrorCodes is the closed union of the current collector error
// contracts. The producer-source parity test prevents an emitted code from
// becoming silently unavailable in the audit receipt.
var auditCoverageErrorCodes = map[string]struct{}{
	"byte_limit": {}, "collector_error": {}, "collector_failed": {}, "collector_panic": {}, "collector_timeout": {}, "config_invalid": {}, "config_limit": {}, "config_malformed": {}, "config_oversized": {}, "config_size_limit": {}, "config_unavailable": {}, "coverage_contract_violation": {}, "depth_limit": {}, "docker_unavailable": {}, "entry_limit": {}, "evidence_unavailable": {}, "executable_evidence_invalid": {}, "executable_replaced": {}, "executable_unavailable": {}, "file_limit": {}, "filesystem_unavailable": {}, "identity_changed": {}, "identity_rejected": {}, "inspector_unavailable": {}, "invalid_local_target": {}, "invalid_server": {}, "launch_malformed": {}, "launch_unavailable": {}, "legacy_manifest_partial": {}, "legacy_transport_unknown": {}, "manifest_changed": {}, "manifest_invalid": {}, "manifest_limit": {}, "manifest_oversized": {}, "manifest_size_limit": {}, "manifest_unavailable": {}, "metadata-conflict": {}, "metadata_malformed": {}, "metadata_oversize": {}, "metadata_unavailable": {}, "observation-conflict": {}, "orphan-observation": {}, "outside_home": {}, "output_malformed": {}, "output_truncated": {}, "path_invalid": {}, "path_unavailable": {}, "probe_failed": {}, "probe_output_invalid": {}, "probe_output_truncated": {}, "provenance_identity_changed": {}, "provenance_identity_rejected": {}, "provenance_malformed": {}, "provenance_unavailable": {}, "read_failed": {}, "read_unavailable": {}, "rejected_identity": {}, "rejected_metadata": {}, "remote_unsupported": {}, "root_limit": {}, "root_unavailable": {}, "rooted_access_unavailable": {}, "runner_unavailable": {}, "signature_unavailable": {}, "special_file_rejected": {}, "stale": {}, "symlink_rejected": {}, "target_not_reported": {}, "target_rejected": {}, "time_limit": {}, "unknown_server_field": {}, "unsupported": {}, "unsupported_target": {},
}

func validAuditErrorCode(value string) bool {
	_, ok := auditCoverageErrorCodes[value]
	return ok
}
