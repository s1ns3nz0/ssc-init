package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

// ErrSensitiveSnapshot is returned without field or value details when a
// snapshot contains a high-confidence credential shape.
var ErrSensitiveSnapshot = errors.New("snapshot contains sensitive data")

var errUnsafeSnapshotPath = errors.New("snapshot contains unsafe path reference")

var safeKeyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

const (
	maxPersistedPathValueBytes = 64 << 10
	maxStructuredPathDepth     = 64
	maxPercentDecodeRounds     = 3
)

func validateSnapshot(scan model.ScanResult, inventory model.Inventory) error {
	if scan.SchemaVersion == "ssc-init.scan.v7" {
		if scan.AnalyzerCoverage == nil || !scan.AnalyzerCoverage.Valid() {
			return errors.New("v7 snapshot requires valid analyzer coverage")
		}
	} else if scan.AnalyzerCoverage != nil || inventory.AnalyzerFacts != nil {
		return errors.New("analyzer persistence requires schema v7")
	}
	for field, value := range map[string]string{
		"scan schema version": scan.SchemaVersion,
		"scan id":             scan.ScanID,
		"scan status":         string(scan.Status),
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	if !scan.Status.Valid() {
		return errors.New("scan status is not a documented value")
	}
	if scan.StartedAt.IsZero() || scan.FinishedAt.IsZero() || scan.FinishedAt.Before(scan.StartedAt) {
		return errors.New("invalid scan timestamps")
	}
	for field, value := range map[string]string{
		"scan scope platform":        scan.Scope.Platform,
		"scan scope catalog version": scan.Scope.CatalogVersion,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	for _, projectRoot := range scan.Scope.ProjectRoots {
		if err := validatePersistenceSafePath("scan scope project root", projectRoot); err != nil {
			return err
		}
	}

	assetIDs := make(map[string]struct{}, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		if err := validateAsset(asset); err != nil {
			return err
		}
		if _, duplicate := assetIDs[asset.ID]; duplicate {
			return errors.New("duplicate inventory asset id")
		}
		assetIDs[asset.ID] = struct{}{}
	}
	relationships := make(map[model.Relationship]struct{}, len(inventory.Relationships))
	for _, relationship := range inventory.Relationships {
		if err := validateRelationship(relationship); err != nil {
			return err
		}
		if _, ok := assetIDs[relationship.From]; !ok {
			return errors.New("inventory relationship references missing source asset")
		}
		if _, ok := assetIDs[relationship.To]; !ok {
			return errors.New("inventory relationship references missing target asset")
		}
		if _, duplicate := relationships[relationship]; duplicate {
			return errors.New("duplicate inventory relationship")
		}
		relationships[relationship] = struct{}{}
	}
	for _, inventoryError := range inventory.Errors {
		if err := validateCoverageError(inventoryError); err != nil {
			return err
		}
	}
	observationAssets := make(map[string]string, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		if err := validateObservation(observation); err != nil {
			return err
		}
		if _, ok := assetIDs[observation.AssetID]; !ok {
			return errors.New("inventory observation references missing asset")
		}
		if _, duplicate := observationAssets[observation.ID]; duplicate {
			return errors.New("duplicate inventory observation id")
		}
		observationAssets[observation.ID] = observation.AssetID
	}
	// Content-evidence snapshots (v3 onward) always carry one non-zero
	// evidence coverage object and a non-nil evidence slice. Earlier schema
	// versions predate content evidence and stay valid without either.
	if scan.SchemaVersion == "ssc-init.scan.v3" || scan.SchemaVersion == "ssc-init.scan.v4" || scan.SchemaVersion == "ssc-init.scan.v5" || scan.SchemaVersion == "ssc-init.scan.v6" || scan.SchemaVersion == "ssc-init.scan.v7" {
		if evidenceCoverageIsZero(scan.EvidenceCoverage) {
			return errors.New("evidence snapshot requires evidence coverage")
		}
		if inventory.Evidence == nil {
			return errors.New("evidence snapshot requires an evidence inventory")
		}
	}
	evidenceByID := make(map[string]model.ContentEvidence, len(inventory.Evidence))
	for _, evidence := range inventory.Evidence {
		if err := validateContentEvidence(evidence, assetIDs, observationAssets); err != nil {
			return err
		}
		if _, duplicate := evidenceByID[evidence.ID]; duplicate {
			return errors.New("duplicate inventory evidence id")
		}
		evidenceByID[evidence.ID] = evidence
	}
	if err := validateEvidenceCoverageResult(scan.EvidenceCoverage, evidenceByID); err != nil {
		return err
	}
	analyzerIDs := make(map[string]struct{}, len(inventory.AnalyzerFacts))
	for _, fact := range inventory.AnalyzerFacts {
		if !fact.Valid() {
			return errors.New("invalid analyzer fact")
		}
		encoded, err := json.Marshal(fact)
		if err != nil || privacy.ContainsSensitiveValue(string(encoded)) {
			return ErrSensitiveSnapshot
		}
		if _, ok := assetIDs[fact.AssetID]; !ok {
			return errors.New("analyzer fact references missing asset")
		}
		if fact.EvidenceID != "" {
			if _, ok := evidenceByID[fact.EvidenceID]; !ok {
				return errors.New("analyzer fact references missing evidence")
			}
		}
		if _, duplicate := analyzerIDs[fact.ID]; duplicate {
			return errors.New("duplicate analyzer fact id")
		}
		analyzerIDs[fact.ID] = struct{}{}
	}
	findingIDs := make(map[string]struct{}, len(inventory.Findings))
	for _, finding := range inventory.Findings {
		if !finding.Valid() {
			return errors.New("invalid inventory finding")
		}
		if _, ok := assetIDs[finding.AssetID]; !ok {
			return errors.New("inventory finding references missing asset")
		}
		if _, duplicate := findingIDs[finding.ID]; duplicate {
			return errors.New("duplicate inventory finding id")
		}
		findingIDs[finding.ID] = struct{}{}
		encoded, err := json.Marshal(finding)
		if err != nil || privacy.ContainsSensitiveValue(string(encoded)) {
			return ErrSensitiveSnapshot
		}
	}

	collectors := make(map[string]struct{}, len(scan.Coverage))
	for _, result := range scan.Coverage {
		if err := validateRequiredString("coverage collector", result.Collector); err != nil {
			return err
		}
		if !validCoverageStatus(result.Status) {
			return errors.New("invalid coverage status")
		}
		if _, duplicate := collectors[result.Collector]; duplicate {
			return errors.New("duplicate coverage collector")
		}
		collectors[result.Collector] = struct{}{}
		resultAssets := make(map[string]model.Asset, len(result.Assets))
		for _, asset := range result.Assets {
			if err := validateAsset(asset); err != nil {
				return err
			}
			if existing, duplicate := resultAssets[asset.ID]; duplicate && !reflect.DeepEqual(existing, asset) {
				return errors.New("conflicting coverage asset id")
			}
			resultAssets[asset.ID] = asset
		}
		resultRelationships := make(map[model.Relationship]struct{}, len(result.Relationships))
		for _, relationship := range result.Relationships {
			if err := validateRelationship(relationship); err != nil {
				return err
			}
			if _, duplicate := resultRelationships[relationship]; duplicate {
				return errors.New("duplicate coverage relationship")
			}
			resultRelationships[relationship] = struct{}{}
		}
		for _, coverageError := range result.Errors {
			if err := validateCoverageError(coverageError); err != nil {
				return err
			}
		}
		resultObservationIDs := make(map[string]struct{}, len(result.Observations))
		for _, observation := range result.Observations {
			if err := validateObservation(observation); err != nil {
				return err
			}
			if _, ok := resultAssets[observation.AssetID]; !ok {
				return errors.New("coverage observation references missing asset")
			}
			if _, duplicate := resultObservationIDs[observation.ID]; duplicate {
				return errors.New("duplicate coverage observation id")
			}
			resultObservationIDs[observation.ID] = struct{}{}
		}
		for _, target := range result.Targets {
			if err := validateRequiredString("target id", target.TargetID); err != nil {
				return err
			}
			if err := validatePersistenceSafePath("target instance reference", target.InstanceRef); err != nil {
				return err
			}
			if !validTargetStatus(target.Status) {
				return errors.New("invalid target status")
			}
			if target.Assets < 0 || target.Observations < 0 {
				return errors.New("invalid target counts")
			}
			for _, targetError := range target.Errors {
				if err := validateCoverageError(targetError); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateAsset(asset model.Asset) error {
	if err := validateRequiredString("asset id", asset.ID); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"asset type": string(asset.Type), "asset name": asset.Name, "asset version": asset.Version,
		"asset source": asset.Source, "asset sha256": asset.SHA256,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	if err := validatePersistenceSafePath("asset path", asset.Path); err != nil {
		return err
	}
	if err := validateSignature(asset.Signature); err != nil {
		return err
	}
	if err := validateProvenance(asset.Provenance); err != nil {
		return err
	}
	return validateMetadata("asset", asset.Metadata)
}

func validateSignature(signature *model.Signature) error {
	if signature == nil {
		return nil
	}
	if !signature.Status.Valid() {
		return errors.New("invalid signature status")
	}
	if signature.Status != model.SignatureValid {
		if signature.Identifier != "" || signature.TeamID != "" {
			return errors.New("non-valid signature carries identity")
		}
		return nil
	}
	if !supplyChainToken(signature.Identifier, 255, false) || !supplyChainToken(signature.TeamID, 10, true) || len(signature.TeamID) != 10 {
		return errors.New("invalid signature identity")
	}
	return nil
}

func validateProvenance(provenance *model.Provenance) error {
	if provenance == nil {
		return nil
	}
	if !provenance.Status.Valid() || !validProvenanceEcosystem(provenance.Ecosystem) {
		return errors.New("invalid provenance fact")
	}
	if provenance.Source != "" && !validProvenanceSource(provenance.Source) {
		return errors.New("invalid provenance source")
	}
	if provenance.Status == model.ProvenanceImmutable {
		digest, ok := strings.CutPrefix(provenance.Integrity, "sha256:")
		if !ok || !lowercaseSHA256Hex(digest) {
			return errors.New("invalid provenance integrity")
		}
	} else if provenance.Integrity != "" {
		return errors.New("non-immutable provenance carries integrity")
	}
	return nil
}

func supplyChainToken(value string, maximum int, uppercaseOnly bool) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		allowed := character >= '0' && character <= '9' || character >= 'A' && character <= 'Z'
		if !uppercaseOnly {
			allowed = allowed || character >= 'a' && character <= 'z' || character == '.' || character == '_' || character == '-'
		}
		if !allowed {
			return false
		}
	}
	return true
}

func validProvenanceEcosystem(value string) bool {
	switch value {
	case "docker", "npm", "pnpm", "yarn", "bun", "pip", "pipx", "uv", "cargo", "go", "homebrew":
		return true
	default:
		return false
	}
}

func validProvenanceSource(value string) bool {
	switch value {
	case "local-daemon", "registry", "lockfile", "package-manager":
		return true
	default:
		return false
	}
}

func validateObservation(observation model.Observation) error {
	for field, value := range map[string]string{
		"observation id":           observation.ID,
		"observation asset id":     observation.AssetID,
		"observation collector":    observation.Collector,
		"observation scope":        string(observation.Scope),
		"observation location ref": observation.LocationRef,
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	if !validObservationScope(observation.Scope) {
		return errors.New("invalid observation scope")
	}
	if err := validatePersistenceSafePath("observation location ref", observation.LocationRef); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"observation host":       observation.Host,
		"observation project id": observation.ProjectID,
		"observation source":     observation.Source,
	} {
		if err := validateOptionalString(field, value); err != nil {
			return err
		}
	}
	for index, consumer := range observation.Consumers {
		if err := validateOptionalString("observation consumer", consumer); err != nil {
			return err
		}
		if index > 0 && observation.Consumers[index-1] >= consumer {
			return errors.New("observation consumers must be sorted and unique")
		}
	}
	return validateMetadata("observation", observation.Metadata)
}

func validateMetadata(owner string, metadata map[string]string) error {
	for key, value := range metadata {
		if err := validateOptionalString(owner+" metadata key", key); err != nil {
			return err
		}
		if safeListMetadataKey(key) {
			if err := validateSafeKeyList(value); err != nil {
				return ErrSensitiveSnapshot
			}
		} else if metadataKeyCarriesSecret(key) && value != "" && !privacy.IsRedactedPlaceholder(value) {
			return ErrSensitiveSnapshot
		}
		if err := validateOptionalString(owner+" metadata value", value); err != nil {
			return err
		}
		if metadataKeyCarriesPath(key) {
			if len(value) > maxPersistedPathValueBytes || containsRawPOSIXAbsolutePath(value) {
				return errUnsafeSnapshotPath
			}
		}
	}
	return nil
}

func validateRelationship(relationship model.Relationship) error {
	for field, value := range map[string]string{
		"relationship from": relationship.From,
		"relationship kind": relationship.Kind,
		"relationship to":   relationship.To,
	} {
		if err := validateRequiredString(field, value); err != nil {
			return err
		}
	}
	if !model.ValidRelationshipKind(relationship.Kind) {
		return errors.New("inventory relationship kind is unsupported")
	}
	if relationship.From == relationship.To {
		return errors.New("inventory relationship must connect distinct assets")
	}
	return nil
}

func validateCoverageError(coverageError model.CoverageError) error {
	if err := validateRequiredString("coverage error code", coverageError.Code); err != nil {
		return err
	}
	if err := validateRequiredString("coverage error message", coverageError.Message); err != nil {
		return err
	}
	return validatePersistenceSafePath("coverage error path", coverageError.Path)
}

func validatePersistenceSafePath(field, value string) error {
	if err := validateOptionalString(field, value); err != nil {
		return err
	}
	if len(value) > maxPersistedPathValueBytes || containsRawPOSIXAbsolutePath(value) {
		return errUnsafeSnapshotPath
	}
	return nil
}

func metadataKeyCarriesPath(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	switch normalized {
	case "args", "command", "command_basename", "cwd_ref", "entry_point", "manifest_path", "path", "probe_source", "ref", "root_ref", "symlink_chain":
		return true
	default:
		for _, suffix := range []string{"_id", "_target", "_type", "_kind", "_name", "_label"} {
			if strings.HasSuffix(normalized, suffix) {
				return false
			}
		}
		return metadataKeyHasSemanticAffix(normalized, "args") ||
			metadataKeyHasSemanticAffix(normalized, "command") ||
			metadataKeyHasSemanticAffix(normalized, "entry_point") ||
			metadataKeyHasSemanticAffix(normalized, "path") ||
			metadataKeyHasSemanticAffix(normalized, "paths") ||
			metadataKeyHasSemanticAffix(normalized, "ref") ||
			metadataKeyHasSemanticAffix(normalized, "refs") ||
			metadataKeyHasSemanticAffix(normalized, "symlink") ||
			metadataKeyHasSemanticAffix(normalized, "symlink_chain") ||
			metadataSourceKeyCarriesPath(normalized)
	}
}

func metadataKeyHasSemanticAffix(key, semantic string) bool {
	return strings.HasPrefix(key, semantic+"_") || strings.HasSuffix(key, "_"+semantic)
}

func metadataSourceKeyCarriesPath(key string) bool {
	switch key {
	case "probe_source", "runtime_source":
		return true
	default:
		return false
	}
}

func containsRawPOSIXAbsolutePath(value string) bool {
	if len(value) > maxPersistedPathValueBytes {
		return true
	}
	var structured any
	encoded := []byte(value)
	if json.Valid(encoded) {
		if !structuredJSONWithinDepth(encoded) {
			return true
		}
		if json.Unmarshal(encoded, &structured) != nil {
			return true
		}
		switch structured.(type) {
		case string, []any, map[string]any:
			return structuredValueCarriesRawPOSIXAbsolutePath(structured, 0)
		default:
			return false
		}
	}
	return textCarriesRawPOSIXAbsolutePath(value)
}

func structuredJSONWithinDepth(value []byte) bool {
	depth := 0
	inString := false
	escaped := false
	for _, character := range value {
		if inString {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == '"':
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxStructuredPathDepth {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}

func structuredValueCarriesRawPOSIXAbsolutePath(value any, depth int) bool {
	if depth > maxStructuredPathDepth {
		return true
	}
	switch typed := value.(type) {
	case string:
		return textCarriesRawPOSIXAbsolutePath(typed)
	case []any:
		for _, item := range typed {
			if structuredValueCarriesRawPOSIXAbsolutePath(item, depth+1) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if textCarriesRawPOSIXAbsolutePath(key) || structuredValueCarriesRawPOSIXAbsolutePath(item, depth+1) {
				return true
			}
		}
	}
	return false
}

func textCarriesRawPOSIXAbsolutePath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	decoded, unsafe := boundedPercentDecode(value)
	if unsafe {
		return true
	}
	if approvedRemoteOrPackageReference(value) {
		return false
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" || approvedRemoteOrPackageReference(decoded) {
		return false
	}
	return packageReferenceCarriesSubpathTraversal(decoded) || containsLocalFileReference(decoded) || containsAbsolutePathComponent(decoded)
}

func boundedPercentDecode(value string) (string, bool) {
	decoded := value
	progressed := false
	for range maxPercentDecodeRounds {
		next, changed := decodePercentTriplets(decoded)
		if !changed {
			return decoded, progressed && hasMalformedPercentEscape(decoded)
		}
		if hasMalformedPercentEscape(decoded) {
			return next, true
		}
		if !validDecodedPathText(next) {
			return next, true
		}
		decoded = next
		progressed = true
	}
	if hasMalformedPercentEscape(decoded) || hasDecodablePercentTriplet(decoded) {
		return decoded, true
	}
	return decoded, false
}

func decodePercentTriplets(value string) (string, bool) {
	if !hasDecodablePercentTriplet(value) {
		return value, false
	}
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); {
		if value[index] == '%' && index+2 < len(value) && isHexadecimal(value[index+1]) && isHexadecimal(value[index+2]) {
			decoded.WriteByte(hexadecimalValue(value[index+1])<<4 | hexadecimalValue(value[index+2]))
			index += 3
			continue
		}
		decoded.WriteByte(value[index])
		index++
	}
	return decoded.String(), true
}

func hasDecodablePercentTriplet(value string) bool {
	for index := 0; index+2 < len(value); index++ {
		if value[index] == '%' && isHexadecimal(value[index+1]) && isHexadecimal(value[index+2]) {
			return true
		}
	}
	return false
}

func hasMalformedPercentEscape(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+2 >= len(value) || !isHexadecimal(value[index+1]) || !isHexadecimal(value[index+2]) {
			return true
		}
		index += 2
	}
	return false
}

func validDecodedPathText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func approvedRemoteOrPackageReference(value string) bool {
	if approvedPackageReference(value) {
		return true
	}
	return approvedHTTPReference(value)
}

func approvedHTTPReference(value string) bool {
	if strings.ContainsAny(value, " \t\r\n\x1f\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func approvedPackageReference(value string) bool {
	if !strings.HasPrefix(value, "pkg:") || len(value) > maxPersistedPathValueBytes || strings.ContainsAny(value, " \t\r\n\x1f") {
		return false
	}
	body := value[len("pkg:"):]
	if strings.Count(body, "#") > 1 || strings.Count(body, "?") > 1 {
		return false
	}
	mainAndQualifiers, subpath, hasSubpath := strings.Cut(body, "#")
	if hasSubpath && !validPURLSubpath(subpath) || strings.ContainsRune(subpath, '?') {
		return false
	}
	main, qualifiers, hasQualifiers := strings.Cut(mainAndQualifiers, "?")
	if hasQualifiers && !validPURLQualifiers(qualifiers) {
		return false
	}
	packageType, packagePath, found := strings.Cut(main, "/")
	if !found || !validPURLType(packageType) {
		return false
	}
	versionSeparator := strings.LastIndexByte(packagePath, '@')
	if versionSeparator <= 0 || versionSeparator == len(packagePath)-1 {
		return false
	}
	pathPart := packagePath[:versionSeparator]
	version := packagePath[versionSeparator+1:]
	decodedVersion, ok := decodePURLPart(version, true)
	if !ok || decodedVersion == "." || decodedVersion == ".." || strings.ContainsRune(decodedVersion, '/') || purlDecodedPartCarriesLocalPath(decodedVersion) {
		return false
	}
	segments := strings.Split(pathPart, "/")
	if len(segments) == 0 {
		return false
	}
	for _, segment := range segments {
		if !validPURLPathSegment(segment) {
			return false
		}
	}
	return true
}

func packageReferenceCarriesSubpathTraversal(value string) bool {
	if !strings.HasPrefix(value, "pkg:") {
		return false
	}
	_, subpath, found := strings.Cut(value[len("pkg:"):], "#")
	if !found {
		return false
	}
	for _, segment := range strings.Split(subpath, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func containsLocalFileReference(value string) bool {
	for index := range value {
		if index+len("file:") <= len(value) && strings.EqualFold(value[index:index+len("file:")], "file:") && isComponentStart(value, index) {
			return true
		}
	}
	return false
}

func containsAbsolutePathComponent(value string) bool {
	for index := 0; index < len(value); {
		character, size := utf8.DecodeRuneInString(value[index:])
		if isComponentStart(value, index) {
			end := componentCandidateEnd(value, index)
			candidateEnd := trimReferenceWrappersRight(value, index, end)
			if candidateEnd > index && approvedRemoteOrPackageReference(value[index:candidateEnd]) {
				index = candidateEnd
				continue
			}
			if character == '/' {
				return true
			}
		}
		index += size
	}
	return false
}

func isComponentStart(value string, index int) bool {
	if index == 0 {
		return true
	}
	previous, _ := utf8.DecodeLastRuneInString(value[:index])
	return !isPathComponentRune(previous)
}

func isPathComponentRune(character rune) bool {
	return unicode.IsLetter(character) || unicode.IsNumber(character) || strings.ContainsRune("_-.$~+", character)
}

func componentCandidateEnd(value string, start int) int {
	for offset, character := range value[start:] {
		if unicode.IsSpace(character) || character == '\x1f' {
			return start + offset
		}
	}
	return len(value)
}

func trimReferenceWrappersRight(value string, start, end int) int {
	for end > start {
		character, size := utf8.DecodeLastRuneInString(value[start:end])
		if !strings.ContainsRune(`"'()[]{}<>`, character) {
			break
		}
		end -= size
	}
	return end
}

func validPURLType(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if !strings.ContainsRune(".+-", character) {
					return false
				}
			}
		}
	}
	return true
}

func validPURLPathSegment(value string) bool {
	decoded, ok := decodePURLPart(value, false)
	if !ok {
		return false
	}
	return decoded != "." && decoded != ".." && !strings.ContainsRune(decoded, '/') && !purlDecodedPartCarriesLocalPath(decoded)
}

func decodePURLPart(value string, allowAt bool) (string, bool) {
	if !validEncodedPURLPart(value, allowAt) {
		return "", false
	}
	decoded, unsafe := boundedPercentDecode(value)
	return decoded, !unsafe && decoded != ""
}

func validEncodedPURLPart(value string, allowAt bool) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); {
		character := value[index]
		if character == '%' {
			if index+2 >= len(value) || !isHexadecimal(value[index+1]) || !isHexadecimal(value[index+2]) {
				return false
			}
			index += 3
			continue
		}
		if character >= utf8.RuneSelf {
			return false
		}
		allowed := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~!$&'()*+,;=:", rune(character))
		if allowAt && character == '@' {
			allowed = true
		}
		if !allowed {
			return false
		}
		index++
	}
	return true
}

func validPURLQualifiers(value string) bool {
	if value == "" {
		return false
	}
	previousKey := ""
	for _, qualifier := range strings.Split(value, "&") {
		key, rawValue, found := strings.Cut(qualifier, "=")
		if !found || !validPURLQualifierKey(key) || key <= previousKey {
			return false
		}
		decoded, ok := decodePURLPart(rawValue, true)
		if !ok || decoded == "." || decoded == ".." || strings.ContainsRune(decoded, '/') || purlDecodedPartCarriesLocalPath(decoded) {
			return false
		}
		previousKey = key
	}
	return true
}

func validPURLQualifierKey(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if !strings.ContainsRune("._-", character) {
					return false
				}
			}
		}
	}
	return true
}

func validPURLSubpath(value string) bool {
	if value == "" {
		return false
	}
	decodedSegments := make([]string, 0, strings.Count(value, "/")+1)
	for _, segment := range strings.Split(value, "/") {
		decoded, ok := decodePURLPart(segment, false)
		if !ok || decoded == "." || decoded == ".." || strings.ContainsRune(decoded, '/') || purlDecodedPartCarriesLocalPath(decoded) {
			return false
		}
		decodedSegments = append(decodedSegments, decoded)
	}
	decodedSubpath := strings.Join(decodedSegments, "/")
	return !containsLocalFileReference(decodedSubpath) && !containsAbsolutePathComponent(decodedSubpath)
}

func purlDecodedPartCarriesLocalPath(value string) bool {
	decoded, exhausted := boundedPercentDecode(value)
	return exhausted || containsLocalFileReference(decoded) || containsAbsolutePathComponent(decoded)
}

func isHexadecimal(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func hexadecimalValue(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}

func validateRequiredString(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	return validateOptionalString(field, value)
}

func validateOptionalString(field, value string) error {
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s is not valid text", field)
	}
	if privacy.ContainsSensitiveValue(value) {
		return ErrSensitiveSnapshot
	}
	return nil
}

func metadataKeyCarriesSecret(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	for _, safe := range []string{"env_keys", "environment_keys", "token_keys", "secret_keys", "credential_keys"} {
		if normalized == safe {
			return false
		}
	}
	for _, marker := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "api_key", "access_key", "raw_env", "environment_value", "env_value"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	if normalized == "env" || normalized == "environment" || normalized == "env_vars" || normalized == "environment_variables" {
		return true
	}
	return false
}

func safeListMetadataKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	switch normalized {
	case "env_keys", "environment_keys", "token_keys", "secret_keys", "credential_keys":
		return true
	default:
		return false
	}
}

func validateSafeKeyList(value string) error {
	if privacy.IsRedactedPlaceholder(value) {
		return nil
	}
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\t =;:/?#&") || privacy.ContainsSensitiveValue(value) {
		return ErrSensitiveSnapshot
	}
	items := strings.Split(value, ",")
	if len(items) > 128 {
		return ErrSensitiveSnapshot
	}
	for _, item := range items {
		if !safeKeyName.MatchString(item) {
			return ErrSensitiveSnapshot
		}
	}
	return nil
}

func validCoverageStatus(status model.CoverageStatus) bool {
	switch status {
	case model.CoverageComplete, model.CoveragePartial, model.CoverageSkipped, model.CoverageUnavailable, model.CoverageFailed:
		return true
	default:
		return false
	}
}

func validObservationScope(scope model.ObservationScope) bool {
	switch scope {
	case model.ScopeUser, model.ScopeProject, model.ScopeIDEProfile, model.ScopeToolEnvironment, model.ScopeSystem:
		return true
	default:
		return false
	}
}

func validTargetStatus(status model.TargetStatus) bool {
	switch status {
	case model.TargetComplete, model.TargetNotPresent, model.TargetPartial, model.TargetUnavailable, model.TargetUnsupported, model.TargetSkipped:
		return true
	default:
		return false
	}
}
