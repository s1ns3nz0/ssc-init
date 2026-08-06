package privacy

import (
	"net/url"
	"regexp"
	"strings"
)

var sensitiveValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

var embeddedURIPattern = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
var structuredSecretAssignment = regexp.MustCompile(`(?i)(?:^|[?&#;,\s])(?:access[_-]?token|refresh[_-]?token|authorization|bearer|token|password|passwd|secret|api[_-]?key|credential|env)\s*[:=]\s*([^?&#;,\s]+)`)
var sensitiveAssignments = []*regexp.Regexp{
	structuredSecretAssignment,
	regexp.MustCompile(`(?i)\bBearer\s+(\S+)`),
	regexp.MustCompile(`(?i)\b(?:authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie)\s*[:=]\s*(\S+)`),
	regexp.MustCompile(`(?i)\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY)[A-Z0-9_]*\s*=\s*(\S+)`),
	regexp.MustCompile(`(?:^|[\s,;])(?:env[._-])?[A-Z_][A-Z0-9_]{1,63}\s*=\s*(\S+)`),
}

// ContainsSensitiveValue reports whether value contains a high-confidence
// credential shape. Exact redaction placeholders are explicitly safe.
func ContainsSensitiveValue(value string) bool {
	if IsRedactedPlaceholder(value) {
		return false
	}
	for _, pattern := range sensitiveValuePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	plainValue := value
	for _, candidate := range embeddedURIPattern.FindAllString(value, -1) {
		if sensitiveURI(candidate) {
			return true
		}
		plainValue = strings.ReplaceAll(plainValue, candidate, "")
	}
	return containsSensitiveAssignment(plainValue)
}

// IsRedactedPlaceholder reports whether value is an exact, case-insensitive
// redaction marker accepted by snapshot validation.
func IsRedactedPlaceholder(value string) bool {
	return strings.EqualFold(value, "redacted") || strings.EqualFold(value, "[redacted]")
}

func sensitiveURI(value string) bool {
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" && (parsed.Host != "" || parsed.Opaque != "") {
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword || credentialLikeUser(parsed.User.Username()) {
				return true
			}
		}
		for key, values := range parsed.Query() {
			if sensitiveQueryKey(key) {
				for _, queryValue := range values {
					if queryValue != "" && !IsRedactedPlaceholder(queryValue) {
						return true
					}
				}
			}
		}
		fragment, fragmentErr := url.QueryUnescape(parsed.Fragment)
		if fragmentErr == nil && fragment != "" {
			for _, pattern := range sensitiveValuePatterns {
				if pattern.MatchString(fragment) {
					return true
				}
			}
			if containsSensitiveAssignment("&" + fragment) {
				return true
			}
		}
	}
	return false
}

func containsSensitiveAssignment(value string) bool {
	for _, pattern := range sensitiveAssignments {
		for _, match := range pattern.FindAllStringSubmatch(value, -1) {
			if len(match) == 2 && match[1] != "" && !IsRedactedPlaceholder(match[1]) {
				return true
			}
		}
	}
	return false
}

func credentialLikeUser(username string) bool {
	for _, pattern := range sensitiveValuePatterns[:7] {
		if pattern.MatchString(username) {
			return true
		}
	}
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(username))
	for _, marker := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "api_key", "access_key"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sensitiveQueryKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	for _, marker := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "api_key", "access_key"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
