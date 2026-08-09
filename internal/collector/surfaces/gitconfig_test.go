package surfaces

import (
	"strings"
	"testing"
)

func TestCredentialHelperParserKeepsOnlyNormalizedGlobalHelperNames(t *testing.T) {
	contents := `[credential]
    helper = osxkeychain
    helper = /usr/local/bin/git-credential-cache --timeout=3600 secret-token
[credential "https://user:password@example.invalid"]
    helper = store --file=/Users/private/.credentials
[user]
    email = private@example.invalid
`
	helpers, digest, err := parseCredentialHelpers([]byte(contents))
	if err != nil || strings.Join(helpers, ",") != "cache,osxkeychain" || len(digest) != 64 {
		t.Fatalf("helpers=%q digest=%q err=%v", helpers, digest, err)
	}
	if strings.Contains(strings.Join(helpers, "\x00")+digest, "secret-token") || strings.Contains(strings.Join(helpers, "\x00")+digest, "/Users/private") {
		t.Fatal("parser retained private helper arguments")
	}
}

func TestCredentialHelperParserSupportsResetAndDeterministicDuplicates(t *testing.T) {
	first, firstDigest, err := parseCredentialHelpers([]byte("[credential]\nhelper = store\nhelper = \nhelper = cache --timeout=1\nhelper = cache --timeout=2\n"))
	if err != nil || len(first) != 1 || first[0] != "cache" {
		t.Fatalf("helpers=%q err=%v", first, err)
	}
	second, secondDigest, err := parseCredentialHelpers([]byte("[credential]\nhelper=cache\n"))
	if err != nil || strings.Join(first, "\x00") != strings.Join(second, "\x00") || firstDigest != secondDigest {
		t.Fatalf("first=%q/%q second=%q/%q err=%v", first, firstDigest, second, secondDigest, err)
	}
}

func TestCredentialHelperParserRejectsMalformedAndHostileValuesWithoutEcho(t *testing.T) {
	for _, contents := range []string{
		"[credential\nhelper = cache\n",
		"[credential]\nhelper = ../../private/helper\n",
		"[credential]\nhelper = bad\x00name\n",
	} {
		_, _, err := parseCredentialHelpers([]byte(contents))
		if err != errGitConfigMalformed || strings.Contains(err.Error(), contents) {
			t.Fatalf("contents accepted or echoed: err=%v", err)
		}
	}
}
