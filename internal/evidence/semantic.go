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

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

const semanticMCPDomain = "ssc-init.semantic-mcp.v1"

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
	if !validSemanticMCPText(value, key == "args", maxSemanticMCPFieldBytes) || privacy.ContainsSensitiveValue(value) || ((key == "command" || key == "args") && semanticHasUnredactedCredential(value)) || containsSemanticRawAbsolutePath(value) {
		return false
	}
	switch key {
	case "transport":
		return validSemanticMCPToken(value)
	case "enabled":
		return value == "" || value == "true" || value == "false"
	case "url_shape":
		return value == "" || privacy.IsRedactedPlaceholder(value) || validSanitizedURLShape(value)
	case "cwd_ref":
		return value == "" || privacy.IsRedactedPlaceholder(value) || validSanitizedCWDRef(value)
	case "env_keys", "header_keys", "enabled_tools", "disabled_tools":
		return validSemanticMCPList(value, ',')
	case "args":
		return validSemanticMCPArgumentList(value)
	case "command":
		return value == "" || privacy.IsRedactedPlaceholder(value) || validSemanticMCPFreeText(value)
	default:
		return false
	}
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

func validSemanticMCPList(value string, delimiter rune) bool {
	if value == "" {
		return true
	}
	for _, item := range strings.Split(value, string(delimiter)) {
		if item == "" || !validSemanticMCPFreeText(item) || strings.ContainsAny(item, "=,\x1f") {
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
			if candidate == "" || !privacy.IsRedactedPlaceholder(candidate) {
				return true
			}
			continue
		}
		if semanticCredentialFlag(item) {
			if index+1 >= len(items) || !privacy.IsRedactedPlaceholder(items[index+1]) {
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
		}
		return remainder, true
	}
	separator := strings.IndexAny(value, "=:")
	if separator <= 0 || !semanticCredentialKey(value[:separator]) {
		return "", false
	}
	return value[separator+1:], true
}

func semanticCredentialFlag(value string) bool {
	if value == "-H" || value == "-e" {
		return true
	}
	return semanticCredentialKey(value)
}

func semanticCredentialKey(value string) bool {
	normalized := strings.ToLower(strings.TrimLeft(value, "-"))
	normalized = strings.NewReplacer("-", "_", ".", "_").Replace(normalized)
	components := strings.FieldsFunc(normalized, func(character rune) bool { return character == '_' })
	for _, component := range components {
		switch component {
		case "token", "secret", "password", "passwd", "credential", "credentials", "authorization", "auth",
			"bearer", "header", "headers", "env", "signature", "apikey", "accesskey", "privatekey", "clientsecret":
			return true
		}
	}
	return strings.Contains(normalized, "api_key") || strings.Contains(normalized, "access_key")
}

func containsSemanticRawAbsolutePath(value string) bool {
	items := strings.FieldsFunc(value, func(character rune) bool {
		return character == '\x1f' || character == ',' || character == '=' || character == ':' || character == ';' || unicode.IsSpace(character)
	})
	for index, item := range items {
		if filepath.IsAbs(item) {
			if strings.HasPrefix(item, "//") && index > 0 && (items[index-1] == "http" || items[index-1] == "https") {
				continue
			}
			return true
		}
	}
	return false
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
	if err != nil || !validSemanticMCPText(decoded, false, maxSemanticMCPFieldBytes) || strings.ContainsRune(decoded, '\\') || privacy.ContainsSensitiveValue(decoded) {
		return false
	}
	segments := strings.Split(decoded, "/")
	for index, segment := range segments {
		if segment == "" {
			continue
		}
		if separator := strings.IndexAny(segment, "=:"); separator > 0 && semanticCredentialKey(segment[:separator]) {
			return false
		}
		if semanticCredentialKey(segment) {
			for _, following := range segments[index+1:] {
				if following != "" {
					return false
				}
			}
		}
	}
	return true
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
