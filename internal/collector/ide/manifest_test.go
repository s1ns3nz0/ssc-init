package ide

import "testing"

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
