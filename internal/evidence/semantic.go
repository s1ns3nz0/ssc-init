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
	if !validSemanticMCPIdentity(observation.Host) || !validSemanticMCPSource(observation.Source) || observation.Metadata == nil {
		return "", errInvalidMCPObservation
	}
	transport, ok := observation.Metadata["transport"]
	if !ok || transport == "" || !validSemanticMCPValue("transport", transport) {
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
	if !validSemanticMCPText(value, false, 200) || strings.ContainsAny(value, "/\\:") {
		return false
	}
	return true
}

func validSemanticMCPSource(value string) bool {
	return strings.HasPrefix(value, "mcp.") && validSemanticMCPText(value, false, 200) && !strings.ContainsAny(value, "/\\:")
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
		key, candidate, found := strings.Cut(item, "=")
		if found && semanticCredentialKey(key) && candidate != "" && !privacy.IsRedactedPlaceholder(candidate) {
			return true
		}
		if !found && semanticCredentialFlag(item) {
			if index+1 >= len(items) || !privacy.IsRedactedPlaceholder(items[index+1]) {
				return true
			}
		}
	}
	return false
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
		case "token", "secret", "password", "passwd", "credential", "authorization", "bearer":
			return true
		}
	}
	return strings.Contains(normalized, "api_key") || strings.Contains(normalized, "access_key")
}

func containsSemanticRawAbsolutePath(value string) bool {
	for _, item := range strings.FieldsFunc(value, func(character rune) bool {
		return character == '\x1f' || character == ',' || character == '=' || unicode.IsSpace(character)
	}) {
		if filepath.IsAbs(item) {
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
	if parsed.RawQuery == "" {
		return true
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 1 || len(query["query_keys"]) != 1 {
		return false
	}
	return validSemanticMCPList(query.Get("query_keys"), ',')
}

func validSanitizedCWDRef(value string) bool {
	if value == "$HOME" || strings.HasPrefix(value, "$HOME/") {
		return true
	}
	if strings.HasPrefix(value, "config-relative/") {
		return validSemanticRelativePath(strings.TrimPrefix(value, "config-relative/"))
	}
	label, digest, found := strings.Cut(value, "/path-sha256:")
	if !found || !strings.HasPrefix(label, "external-") || len(digest) != sha256.Size*2 {
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
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." {
		return false
	}
	return !strings.HasPrefix(value, ".."+string(filepath.Separator))
}
