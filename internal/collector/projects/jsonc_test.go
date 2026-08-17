package projects

import "testing"

func TestValidLaunchJSONCAcceptsCommentsTrailingCommasAndStringMarkers(t *testing.T) {
	raw := []byte(`{
  // Vue-style launch file
  "version": "0.2.0",
  "url": "https://example.test/a//b",
  "marker": "/* literal */",
  "configurations": [
    {"type":"node", "request":"launch",},
  ],
  /* final comment */
}`)
	if !validLaunchJSONC(raw) {
		t.Fatal("valid launch JSONC rejected")
	}
}

func TestValidLaunchJSONCRejectsAmbiguousOrMalformedDocuments(t *testing.T) {
	tests := map[string]string{
		"duplicate key":        `{"version":"0.2.0","version":"0.3.0"}`,
		"unterminated comment": `{"version":"0.2.0" /* missing end}`,
		"multiple roots":       `{} {}`,
		"malformed escape":     `{"value":"\q"}`,
		"raw control":          "{\"value\":\"bad\x01\"}",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if validLaunchJSONC([]byte(raw)) {
				t.Fatalf("accepted %q", raw)
			}
		})
	}
}
