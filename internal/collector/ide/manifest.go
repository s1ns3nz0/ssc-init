package ide

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	maxIdentityLength   = 512
	maxMetadataLength   = 4096
	maxMetadataItems    = 1024
	metadataListDivider = "\x1f"
	redactedMetadata    = "[redacted]"
)

var errInvalidManifest = errors.New("invalid IDE extension manifest")

var highConfidenceCredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(^|[^A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36}([^A-Za-z0-9]|$)`),
	regexp.MustCompile(`(^|[^A-Za-z0-9_])github_pat_[A-Za-z0-9_]{50,120}([^A-Za-z0-9_]|$)`),
	regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])xox[a-z]-[A-Za-z0-9-]{20,}([^A-Za-z0-9-]|$)`),
	regexp.MustCompile(`(^|[^A-Za-z0-9])sk-(?:[A-Za-z0-9]{32,64}|(?:proj|ant)-[A-Za-z0-9_-]{24,200})([^A-Za-z0-9_-]|$)`),
	regexp.MustCompile(`(^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)`),
	regexp.MustCompile(`(^|[^A-Za-z0-9])npm_[A-Za-z0-9]{36}([^A-Za-z0-9]|$)`),
	regexp.MustCompile(`(^|[^A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}([^A-Za-z0-9_-]|$)`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

type vscodeManifest struct {
	Name             string                     `json:"name"`
	Publisher        string                     `json:"publisher"`
	Version          string                     `json:"version"`
	Main             string                     `json:"main"`
	Browser          string                     `json:"browser"`
	ActivationEvents []string                   `json:"activationEvents"`
	Capabilities     map[string]json.RawMessage `json:"capabilities"`
	Contributes      map[string]json.RawMessage `json:"contributes"`
}

type jetBrainsManifest struct {
	ID      string `xml:"id"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

func parseVSCodeManifest(contents []byte, host, home, path string) (model.Asset, error) {
	var manifest vscodeManifest
	if err := decodeJSON(contents, &manifest); err != nil {
		return model.Asset{}, errInvalidManifest
	}
	name, ok := normalizeIdentity(manifest.Name)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	publisher, ok := normalizeIdentity(manifest.Publisher)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	version, ok := normalizeIdentity(manifest.Version)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	entryPoint := strings.TrimSpace(manifest.Main)
	if entryPoint == "" {
		entryPoint = strings.TrimSpace(manifest.Browser)
	}
	entryPoint, ok = sanitizeSelectedMetadata(home, entryPoint, false)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}

	activationEvents, ok := sanitizeMetadataList(home, manifest.ActivationEvents, false)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	capabilityNames := make([]string, 0, len(manifest.Capabilities)+len(manifest.Contributes))
	for capability := range manifest.Capabilities {
		capabilityNames = append(capabilityNames, capability)
	}
	for capability := range manifest.Contributes {
		capabilityNames = append(capabilityNames, capability)
	}
	capabilities, ok := sanitizeMetadataList(home, capabilityNames, true)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}

	return model.Asset{
		ID:      "ide-extension:" + host + ":" + publisher + "." + name + "@" + version,
		Type:    model.AssetIDEExtension,
		Name:    name,
		Version: version,
		Path:    redactPath(home, path),
		Source:  host,
		Metadata: map[string]string{
			"publisher":         publisher,
			"entry_point":       entryPoint,
			"activation_events": strings.Join(activationEvents, metadataListDivider),
			"capabilities":      strings.Join(capabilities, metadataListDivider),
		},
	}, nil
}

func parseJetBrainsManifest(contents []byte, home, path string) (model.Asset, error) {
	if err := validateJetBrainsIdentityElements(contents); err != nil {
		return model.Asset{}, errInvalidManifest
	}
	var manifest jetBrainsManifest
	if err := decodeXML(contents, &manifest); err != nil {
		return model.Asset{}, errInvalidManifest
	}
	id, ok := normalizeIdentity(manifest.ID)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	version, ok := normalizeIdentity(manifest.Version)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	name, ok := normalizeMetadata(manifest.Name)
	if !ok || name == "" {
		return model.Asset{}, errInvalidManifest
	}
	publisher := id
	if index := strings.LastIndexByte(id, '.'); index > 0 {
		publisher = id[:index]
	}

	return model.Asset{
		ID:      "ide-extension:jetbrains:" + id + "@" + version,
		Type:    model.AssetIDEExtension,
		Name:    name,
		Version: version,
		Path:    redactPath(home, path),
		Source:  "jetbrains",
		Metadata: map[string]string{
			"publisher":         publisher,
			"entry_point":       "",
			"activation_events": "",
			"capabilities":      "",
		},
	}, nil
}

func validateJetBrainsIdentityElements(contents []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	decoder.Strict = true
	depth := 0
	rootSeen := false
	rootClosed := false
	seenIdentity := make(map[string]struct{}, 3)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if !rootSeen || !rootClosed {
				return errInvalidManifest
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if !rootSeen {
				if rootClosed || value.Name.Local != "idea-plugin" {
					return errInvalidManifest
				}
				rootSeen = true
				depth = 1
				continue
			}
			if rootClosed {
				return errInvalidManifest
			}
			if depth == 1 && (value.Name.Local == "id" || value.Name.Local == "name" || value.Name.Local == "version") {
				if _, duplicate := seenIdentity[value.Name.Local]; duplicate {
					return errInvalidManifest
				}
				seenIdentity[value.Name.Local] = struct{}{}
			}
			depth++
		case xml.EndElement:
			if !rootSeen || depth == 0 {
				return errInvalidManifest
			}
			depth--
			if depth == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if (!rootSeen || rootClosed) && strings.TrimSpace(string(value)) != "" {
				return errInvalidManifest
			}
		}
	}
}

func decodeJSON(contents []byte, destination any) error {
	if err := validateUniqueJSONKeys(contents); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidManifest
	}
	return nil
}

func validateUniqueJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := readJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidManifest
	}
	return nil
}

func readJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidManifest
			}
			if _, exists := seen[key]; exists {
				return errInvalidManifest
			}
			seen[key] = struct{}{}
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidManifest
		}
	case '[':
		for decoder.More() {
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidManifest
		}
	default:
		return errInvalidManifest
	}
	return nil
}

func decodeXML(contents []byte, destination any) error {
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	decoder.Strict = true
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		characters, ok := token.(xml.CharData)
		if !ok || strings.TrimSpace(string(characters)) != "" {
			return errInvalidManifest
		}
	}
}

func normalizeIdentity(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxIdentityLength {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) || strings.ContainsRune(":@/\\", character) {
			return "", false
		}
	}
	return value, true
}

func normalizeMetadata(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) > maxMetadataLength {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

func sanitizeMetadataList(home string, values []string, redactSensitiveName bool) ([]string, bool) {
	if len(values) > maxMetadataItems {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized, ok := sanitizeSelectedMetadata(home, value, redactSensitiveName)
		if !ok {
			return nil, false
		}
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result, true
}

func sanitizeSelectedMetadata(home, value string, redactSensitiveName bool) (string, bool) {
	normalized, ok := normalizeMetadata(value)
	if !ok {
		return "", false
	}
	if normalized == "" {
		return "", true
	}
	normalized = redactHomeText(home, normalized)
	if containsHighConfidenceCredential(normalized) {
		return redactedMetadata, true
	}
	if sanitized, found := sanitizeEmbeddedMetadataURL(home, normalized); found {
		if len(sanitized) > maxMetadataLength {
			return redactedMetadata, true
		}
		return sanitized, true
	}
	if structuredSensitiveMetadata(normalized) || redactSensitiveName && hasSensitiveMetadataComponent(normalized) {
		return redactedMetadata, true
	}
	return normalized, true
}

func containsHighConfidenceCredential(value string) bool {
	for _, pattern := range highConfidenceCredentialPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func sanitizeEmbeddedMetadataURL(home, value string) (string, bool) {
	separator := strings.Index(value, "://")
	if separator < 1 {
		return "", false
	}
	start := separator - 1
	for start >= 0 && validSchemeCharacter(value[start]) {
		start--
	}
	start++
	parsed, err := url.Parse(value[start:])
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return redactedMetadata, true
	}
	parsed.User = nil
	query := parsed.Query()
	for key, values := range query {
		if hasSensitiveMetadataComponent(key) {
			query[key] = []string{redactedMetadata}
			continue
		}
		for index, queryValue := range values {
			queryValue = redactHomeText(home, queryValue)
			if containsHighConfidenceCredential(queryValue) || structuredSensitiveMetadata(queryValue) {
				queryValue = redactedMetadata
			}
			values[index] = queryValue
		}
		query[key] = values
	}
	parsed.RawQuery = query.Encode()
	if parsed.Fragment != "" {
		parsed.Fragment = redactedMetadata
	}
	return value[:start] + parsed.String(), true
}

func validSchemeCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' || character == '+' || character == '-' || character == '.'
}

func structuredSensitiveMetadata(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "bearer ") {
		return true
	}
	if key, _, found := strings.Cut(trimmed, "="); found && hasSensitiveMetadataComponent(key) {
		return true
	}
	if key, _, found := strings.Cut(trimmed, ":"); found && hasSensitiveMetadataComponent(key) {
		return true
	}
	fields := strings.Fields(trimmed)
	return len(fields) > 1 && hasSensitiveMetadataComponent(fields[0])
}

func hasSensitiveMetadataComponent(value string) bool {
	for _, component := range semanticMetadataComponents(strings.TrimLeft(value, "-")) {
		switch component {
		case "token", "secret", "password", "passwd", "credential", "credentials",
			"apikey", "accesskey", "privatekey", "clientsecret", "bearer", "signature",
			"authorization", "auth", "header", "headers", "env", "key":
			return true
		}
	}
	return false
}

func semanticMetadataComponents(value string) []string {
	runes := []rune(value)
	components := make([]string, 0, 4)
	for start := 0; start < len(runes); {
		for start < len(runes) && !unicode.IsLetter(runes[start]) && !unicode.IsDigit(runes[start]) {
			start++
		}
		if start == len(runes) {
			break
		}
		end := start
		for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end])) {
			end++
		}
		word := runes[start:end]
		wordStart := 0
		for index := 1; index < len(word); index++ {
			lowerToUpper := (unicode.IsLower(word[index-1]) || unicode.IsDigit(word[index-1])) && unicode.IsUpper(word[index])
			acronymToWord := unicode.IsUpper(word[index-1]) && unicode.IsUpper(word[index]) && index+1 < len(word) && unicode.IsLower(word[index+1])
			if lowerToUpper || acronymToWord {
				components = append(components, strings.ToLower(string(word[wordStart:index])))
				wordStart = index
			}
		}
		components = append(components, strings.ToLower(string(word[wordStart:])))
		start = end
	}
	return components
}

func redactHomeText(home, value string) string {
	if home == "" || value == "" {
		return value
	}
	return strings.ReplaceAll(value, filepath.Clean(home), "$HOME")
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}
