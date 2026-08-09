package analyzer

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestObfuscationDetectsBoundedHighEntropyLiteral(t *testing.T) {
	raw := make([]byte, 256)
	for index := range raw {
		raw[index] = byte(index)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	clear(raw)
	if got := obfuscationOccurrences([]byte(`const payload = "` + encoded + `"`)); got != 1 {
		t.Fatalf("occurrences=%d", got)
	}
}

func TestObfuscationIgnoresLongLowEntropyAndBoundsDecode(t *testing.T) {
	if got := obfuscationOccurrences([]byte(`const text = "` + strings.Repeat("a", 256) + `"`)); got != 0 {
		t.Fatalf("low entropy occurrences=%d", got)
	}
	if got := obfuscationOccurrences([]byte(`const huge = "` + strings.Repeat("Q", maxDecodedLiteral+1) + `"`)); got != 0 {
		t.Fatalf("oversize occurrences=%d", got)
	}
}
