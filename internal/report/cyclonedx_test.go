package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestWriteCycloneDXUsesCanonicalIDsAndOmitsLocalLocations(t *testing.T) {
	inventory := model.Inventory{Assets: []model.Asset{{ID: "project:sha256:" + strings.Repeat("a", 64), Type: model.AssetProject, Name: "private-repository", Path: "/Users/alice/private", SHA256: strings.Repeat("b", 64)}, {ID: "pkg:npm/example@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0"}}, Relationships: []model.Relationship{{From: "project:sha256:" + strings.Repeat("a", 64), To: "pkg:npm/example@1.0.0", Kind: model.RelationshipContains}}}
	var output bytes.Buffer
	if err := WriteCycloneDX(&output, inventory); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, forbidden := range []string{"/Users/alice", "private-repository", `"path"`, `"source"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("contains %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"specVersion":"1.6"`) {
		t.Fatalf("output=%s", text)
	}
	if !strings.Contains(text, `"dependsOn":["pkg:npm/example@1.0.0"]`) {
		t.Fatalf("output=%s", text)
	}
}
