package ide

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVSCodeManifestKeepsIndependentMainAndBrowserForEvidence(t *testing.T) {
	got, err := parseVSCodeManifest([]byte(`{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/web.js"}`), "vscode", "/private/home")
	if err != nil {
		t.Fatal(err)
	}
	if got.main != "dist/main.js" || got.browser != "dist/web.js" {
		t.Fatalf("main=%q browser=%q", got.main, got.browser)
	}
	if got.metadata["entry_point"] != "dist/main.js" {
		t.Fatalf("entry_point=%q", got.metadata["entry_point"])
	}
}

func TestParseVSCodeManifestRejectsLegacyUnsafeSelectedEntrypoint(t *testing.T) {
	for _, entry := range []string{"dist/\x00bad.js", "dist/\x01bad.js", strings.Repeat("x", maxMetadataLength+1)} {
		t.Run(entry[:min(len(entry), 16)], func(t *testing.T) {
			contents := []byte(`{"name":"fixture","publisher":"acme","version":"1.0.0","main":` + jsonQuote(entry) + `}`)
			if _, err := parseVSCodeManifest(contents, "vscode", "/private/home"); !errors.Is(err, errInvalidManifest) {
				t.Fatalf("entry=%q err=%v", entry, err)
			}
		})
	}
}
