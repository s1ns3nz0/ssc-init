package privacy

import "testing"

func TestContainsSensitiveValueRecognizesStoreSensitiveMarkers(t *testing.T) {
	for _, value := range []string{
		"ghp_123456789012345678901234567890123456",
		"xoxb-1234567890-abcdefghij",
		"sk-123456789012345678901234567890",
		"AKIA1234567890ABCDEF",
		"npm_123456789012345678901234567890",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
		"-----BEGIN PRIVATE KEY-----",
		"https://user:password@example.test/path",
		"https://example.test/path?access_token=raw-value",
		"Authorization: Bearer abcdefghijklmnop",
		"SERVICE_TOKEN=raw-value",
		"GITHUB_TOKEN=raw-secret",
		"https://example.test/callback#access_token=raw-value",
		"https://example.test/callback#authorization=Bearer%20abcdefghijklmnop",
	} {
		t.Run(value, func(t *testing.T) {
			if !ContainsSensitiveValue(value) {
				t.Fatalf("ContainsSensitiveValue(%q) = false", value)
			}
		})
	}
}

func TestContainsSensitiveValuePreservesSafeBoundaries(t *testing.T) {
	for _, value := range []string{
		"ssh://git@github.com/repo",
		"https://user@example.test/path",
		"GITHUB_TOKEN,HOME",
		"redacted",
		"[REDACTED]",
	} {
		t.Run(value, func(t *testing.T) {
			if ContainsSensitiveValue(value) {
				t.Fatalf("ContainsSensitiveValue(%q) = true", value)
			}
		})
	}
}

func TestContainsSensitiveValueRejectsRedactionNearMisses(t *testing.T) {
	for _, value := range []string{"REDACTED-secret", "[REDACTED]-secret", "prefix-redacted", "raw-secret"} {
		t.Run(value, func(t *testing.T) {
			if IsRedactedPlaceholder(value) {
				t.Fatalf("IsRedactedPlaceholder(%q) = true", value)
			}
		})
	}
}

func TestIsRedactedPlaceholderMatchesOnlyExactValues(t *testing.T) {
	for _, value := range []string{"[redacted]", "[REDACTED]", "redacted", "REDACTED"} {
		t.Run(value, func(t *testing.T) {
			if !IsRedactedPlaceholder(value) {
				t.Fatalf("IsRedactedPlaceholder(%q) = false", value)
			}
		})
	}
}
