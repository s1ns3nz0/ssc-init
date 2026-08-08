package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const semanticMCPDomain = "ssc-init.semantic-mcp.v1"

const semanticMCPRedacted = "[redacted]"

const maxSemanticMCPFieldBytes = 4096

var semanticMCPKeys = []string{
	"transport", "command", "args", "url_shape", "cwd_ref", "enabled",
	"env_keys", "header_keys", "enabled_tools", "disabled_tools",
}

var errInvalidMCPObservation = errors.New("invalid MCP semantic observation")

// HashMCPObservation returns the immutable, secret-free semantic digest for
// one normalized MCP declaration. It deliberately excludes observation
// identity, locations, project identity, and metadata outside the closed v1
// field list.
func HashMCPObservation(observation model.Observation) (string, error) {
	if !validSemanticMCPIdentity(observation.Host) || !validSemanticMCPSource(observation.Source) || !strings.HasPrefix(observation.Source, "mcp."+observation.Host+".") || observation.Metadata == nil {
		return "", errInvalidMCPObservation
	}
	transport, ok := observation.Metadata["transport"]
	if !ok || transport == "" || !validSemanticMCPValue("transport", transport) {
		return "", errInvalidMCPObservation
	}
	if !validSemanticMCPStructure(transport, observation.Metadata) {
		return "", errInvalidMCPObservation
	}
	hash := sha256.New()
	writeTargetField(hash, []byte(semanticMCPDomain))
	writeTargetField(hash, []byte(observation.Host))
	writeTargetField(hash, []byte(observation.Source))
	for _, key := range semanticMCPKeys {
		value := observation.Metadata[key]
		if !validSemanticMCPValue(key, value) {
			return "", errInvalidMCPObservation
		}
		writeTargetField(hash, []byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSemanticMCPIdentity(value string) bool {
	return validSemanticMCPIdentifier(value)
}

func validSemanticMCPSource(value string) bool {
	parts := strings.Split(value, ".")
	return len(parts) == 3 && parts[0] == "mcp" && validSemanticMCPIdentifier(parts[1]) && validSemanticMCPIdentifier(parts[2])
}

func validSemanticMCPIdentifier(value string) bool {
	if value == "" || len(value) > 200 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func validSemanticMCPStructure(transport string, metadata map[string]string) bool {
	command, urlShape := metadata["command"], metadata["url_shape"]
	switch transport {
	case "stdio":
		return command != "" && urlShape == ""
	case "http", "sse", "streamable-http":
		return command == "" && urlShape != "" && metadata["args"] == "" && metadata["cwd_ref"] == ""
	default:
		return false
	}
}

func validSemanticMCPValue(key, value string) bool {
	if !validSemanticMCPText(value, key == "args", maxSemanticMCPFieldBytes) || !validSemanticMCPRedactionSpelling(key, value) || containsSemanticSensitiveValue(key, value) || ((key == "command" || key == "args") && semanticHasUnredactedCredential(value)) || containsSemanticRawAbsolutePath(value) {
		return false
	}
	switch key {
	case "transport":
		return validSemanticMCPToken(value)
	case "enabled":
		return value == "" || value == "true" || value == "false"
	case "url_shape":
		return value == "" || value == semanticMCPRedacted || validSanitizedURLShape(value)
	case "cwd_ref":
		return value == "" || value == semanticMCPRedacted || validSanitizedCWDRef(value)
	case "env_keys":
		return validSemanticMCPList(value, validSemanticMCPEnvKey)
	case "header_keys":
		return validSemanticMCPList(value, validSemanticMCPHeaderKey)
	case "enabled_tools", "disabled_tools":
		return validSemanticMCPList(value, validSemanticMCPToolName)
	case "args":
		return validSemanticMCPArgumentList(value)
	case "command":
		return value == "" || value == semanticMCPRedacted || validSemanticMCPFreeText(value)
	default:
		return false
	}
}

func validSemanticMCPRedactionSpelling(key, value string) bool {
	switch key {
	case "command", "url_shape", "cwd_ref":
		return !privacy.IsRedactedPlaceholder(value) || value == semanticMCPRedacted
	case "args":
		for _, item := range strings.Split(value, "\x1f") {
			if privacy.IsRedactedPlaceholder(item) && item != semanticMCPRedacted {
				return false
			}
		}
	}
	return true
}

func containsSemanticSensitiveValue(key, value string) bool {
	if key != "args" {
		return privacy.ContainsSensitiveValue(value)
	}
	for _, item := range strings.Split(value, "\x1f") {
		if privacy.ContainsSensitiveValue(item) {
			return true
		}
	}
	return false
}

func validSemanticMCPArgumentList(value string) bool {
	if value == "" {
		return true
	}
	for _, item := range strings.Split(value, "\x1f") {
		if item == "" || !validSemanticMCPFreeText(item) {
			return false
		}
	}
	return true
}

func validSemanticMCPText(value string, allowDelimiter bool, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && !(allowDelimiter && character == '\x1f') {
			return false
		}
	}
	return true
}

func validSemanticMCPToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func validSemanticMCPList(value string, validItem func(string) bool) bool {
	if value == "" {
		return true
	}
	previous := ""
	for _, item := range strings.Split(value, ",") {
		if !validItem(item) || (previous != "" && item <= previous) {
			return false
		}
		previous = item
	}
	return true
}

func validSemanticMCPEnvKey(value string) bool {
	if value == "" || !(value[0] == '_' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !(character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validSemanticMCPHeaderKey(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func validSemanticMCPToolName(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func validSemanticMCPFreeText(value string) bool {
	if value == "" {
		return false
	}
	return !strings.ContainsRune(value, '\x00')
}

func semanticHasUnredactedCredential(value string) bool {
	items := strings.FieldsFunc(value, func(character rune) bool { return unicode.IsSpace(character) || character == '\x1f' })
	for index, item := range items {
		if candidate, combined := semanticCombinedCredential(item); combined {
			if candidate == "" {
				if index+1 >= len(items) || items[index+1] != semanticMCPRedacted {
					return true
				}
				continue
			}
			if candidate != semanticMCPRedacted {
				return true
			}
			continue
		}
		if semanticCredentialFlag(item) {
			if index+1 >= len(items) || items[index+1] != semanticMCPRedacted {
				return true
			}
		}
	}
	return false
}

func semanticCombinedCredential(value string) (candidate string, combined bool) {
	if (strings.HasPrefix(value, "-H") || strings.HasPrefix(value, "-e")) && len(value) > 2 {
		remainder := value[2:]
		if remainder[0] == ':' || remainder[0] == '=' {
			remainder = remainder[1:]
			return remainder, true
		}
		if remainder == semanticMCPRedacted {
			return remainder, true
		}
		return value, true
	}
	separator := strings.IndexAny(value, "=:")
	if separator > 0 && semanticCredentialFlag(value[:separator]) {
		return value[separator+1:], true
	}
	if semanticAttachedSensitiveLongFlag(value) {
		return value, true
	}
	for _, prefix := range []string{"--api-key", "--apikey", "--token"} {
		if len(value) > len(prefix) && strings.EqualFold(value[:len(prefix)], prefix) {
			if prefix == "--token" && strings.HasPrefix(strings.ToLower(value[len(prefix):]), "izer") {
				return "", false
			}
			return value[len(prefix):], true
		}
	}
	return "", false
}

func semanticCredentialFlag(value string) bool {
	if value == "-H" || value == "-e" {
		return true
	}
	if strings.HasPrefix(value, "--") && validSemanticLongFlag(value) {
		return semanticCredentialKey(value)
	}
	return !strings.HasPrefix(value, "-") && validSemanticCredentialWord(value) && semanticCredentialKey(value)
}

func semanticAttachedSensitiveLongFlag(value string) bool {
	if !strings.HasPrefix(value, "--") {
		return false
	}
	end := 2
	for end < len(value) && semanticLongFlagCharacter(value[end]) {
		end++
	}
	if end == len(value) || end == 2 || !semanticCredentialKey(value[:end]) {
		return false
	}
	return true
}

func validSemanticLongFlag(value string) bool {
	if len(value) <= 2 || !strings.HasPrefix(value, "--") {
		return false
	}
	for index := 2; index < len(value); index++ {
		if !semanticLongFlagCharacter(value[index]) {
			return false
		}
	}
	return true
}

func semanticLongFlagCharacter(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_'
}

func validSemanticCredentialWord(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(semanticLongFlagCharacter(character) || character == '.') {
			return false
		}
	}
	return true
}

func semanticCredentialKey(value string) bool {
	return privacy.ContainsCredentialComponent(strings.TrimLeft(value, "-"))
}

func containsSemanticRawAbsolutePath(value string) bool {
	for index, character := range value {
		if character != '/' {
			continue
		}
		if semanticURLSchemeSlashes(value, index) {
			continue
		}
		if semanticHTTPAuthorityRootSlash(value, index) {
			continue
		}
		if index == 0 {
			return true
		}
		previous, _ := utf8.DecodeLastRuneInString(value[:index])
		if !(unicode.IsLetter(previous) || unicode.IsDigit(previous) || strings.ContainsRune("-._~", previous)) {
			return true
		}
	}
	return false
}

func semanticURLSchemeSlashes(value string, slash int) bool {
	for _, scheme := range []string{"http:", "https:"} {
		start := slash - len(scheme)
		if start >= 0 && value[start:slash] == scheme && (start == 0 || !semanticPathSafeByte(value[start-1])) && slash+1 < len(value) && value[slash+1] == '/' {
			return true
		}
		start = slash - len(scheme) - 1
		if start >= 0 && value[start:slash+1] == scheme+"//" && (start == 0 || !semanticPathSafeByte(value[start-1])) {
			return true
		}
	}
	return false
}

func semanticHTTPAuthorityRootSlash(value string, slash int) bool {
	prefix := value[:slash]
	for _, scheme := range []string{"http://", "https://"} {
		start := strings.LastIndex(prefix, scheme)
		if start < 0 || start > 0 && semanticPathSafeByte(value[start-1]) {
			continue
		}
		parsed, err := url.Parse(prefix[start:])
		if err == nil && parsed.Scheme+"://" == scheme && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
			return true
		}
	}
	return false
}

func semanticPathSafeByte(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", rune(character))
}

func validSanitizedURLShape(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if !validSemanticURLPath(parsed) {
		return false
	}
	if parsed.RawQuery == "" {
		return true
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 1 || len(query["query_keys"]) != 1 {
		return false
	}
	keys := query.Get("query_keys")
	return parsed.RawQuery == "query_keys="+keys && validSemanticURLQueryKeys(keys)
}

func validSemanticURLPath(parsed *url.URL) bool {
	escaped := parsed.EscapedPath()
	lowerEscaped := strings.ToLower(escaped)
	if strings.Contains(lowerEscaped, "%2f") || strings.Contains(lowerEscaped, "%5c") {
		return false
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil || containsValidPercentEscape(decoded) || !validSemanticMCPText(decoded, false, maxSemanticMCPFieldBytes) || strings.ContainsRune(decoded, '\\') || privacy.ContainsSensitiveValue(decoded) {
		return false
	}
	segments := strings.Split(decoded, "/")
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if separator := strings.IndexAny(segment, "=:"); separator > 0 && semanticCredentialKey(segment[:separator]) {
			return false
		}
	}
	return true
}

func containsValidPercentEscape(value string) bool {
	for index := 0; index+2 < len(value); index++ {
		if value[index] == '%' && isASCIIHex(value[index+1]) && isASCIIHex(value[index+2]) {
			return true
		}
	}
	return false
}

func isASCIIHex(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func validSemanticURLQueryKeys(value string) bool {
	if value == "" {
		return false
	}
	previous := ""
	for _, item := range strings.Split(value, ",") {
		if item == "" || item <= previous || privacy.ContainsSensitiveValue(item) {
			return false
		}
		for _, character := range item {
			if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' || character == '.') {
				return false
			}
		}
		previous = item
	}
	return true
}

func validSanitizedCWDRef(value string) bool {
	if value == "$HOME" {
		return true
	}
	if strings.HasPrefix(value, "$HOME/") {
		return validSemanticRelativePath(strings.TrimPrefix(value, "$HOME/"))
	}
	if strings.HasPrefix(value, "config-relative/") {
		return validSemanticRelativePath(strings.TrimPrefix(value, "config-relative/"))
	}
	label, digest, found := strings.Cut(value, "/path-sha256:")
	if !found || label != "external-cwd" || len(digest) != sha256.Size*2 {
		return false
	}
	for _, character := range digest {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validSemanticRelativePath(value string) bool {
	if value == "" || strings.ContainsRune(value, '\\') || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." {
		return false
	}
	return !strings.HasPrefix(value, ".."+string(filepath.Separator))
}
