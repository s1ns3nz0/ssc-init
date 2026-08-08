package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteJSONUsesStableTopLevelShapeWithoutHTMLEscaping(t *testing.T) {
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v3",
		ScanID:        "00000000-0000-4000-8000-000000000001",
		Status:        "complete",
		StartedAt:     time.Unix(1_700_000_000, 0).UTC(),
		FinishedAt:    time.Unix(1_700_000_000, 0).UTC(),
		Scope: model.ScanScope{
			Platform: "darwin", CatalogVersion: "ssc-init.catalog.v1",
			ProjectRoots: []string{"$HOME/Projects"}, ExternalProbes: false,
		},
		Coverage: []model.CollectorResult{},
	}
	inventory := model.Inventory{Assets: []model.Asset{{ID: "tool:<ok>", Type: model.AssetTool, Name: "<ok>"}}, Relationships: []model.Relationship{}}
	delta := model.Delta{Changes: []model.Change{}}
	var out bytes.Buffer

	if err := WriteJSON(&out, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.HasSuffix(got, "\n") || !strings.Contains(got, `"schemaVersion":"ssc-init.scan.v3"`) {
		t.Fatalf("json=%q", got)
	}
	if strings.Index(got, `"coverage"`) > strings.Index(got, `"evidenceCoverage"`) {
		t.Fatalf("coverage must precede evidenceCoverage: %q", got)
	}
	if !strings.Contains(got, `"scope":{"platform":"darwin","catalogVersion":"ssc-init.catalog.v1","projectRoots":["$HOME/Projects"],"externalProbes":false}`) {
		t.Fatalf("json=%q", got)
	}
	if strings.Index(got, `"scope"`) > strings.Index(got, `"coverage"`) {
		t.Fatalf("scope must precede coverage: %q", got)
	}
	if strings.Contains(got, `\u003c`) || !strings.Contains(got, `"inventory":{"assets"`) || !strings.Contains(got, `"delta":{"changes"`) {
		t.Fatalf("json=%q", got)
	}
}

func TestWriteJSONMatchesV3BaselineGolden(t *testing.T) {
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v3",
		ScanID:        "00000000-0000-4000-8000-000000000001",
		Status:        "complete",
		StartedAt:     time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC),
		FinishedAt:    time.Date(2026, 8, 7, 0, 0, 1, 0, time.UTC),
		Scope: model.ScanScope{
			Platform: "darwin", CatalogVersion: "ssc-init.catalog.v1",
			ProjectRoots: []string{}, ExternalProbes: false,
		},
		Coverage:         []model.CollectorResult{},
		EvidenceCoverage: model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{}},
	}
	inventory := model.Inventory{
		Assets:        []model.Asset{},
		Observations:  []model.Observation{},
		Evidence:      []model.ContentEvidence{},
		Relationships: []model.Relationship{},
	}
	delta := model.Delta{Changes: []model.Change{}}
	want := `{"schemaVersion":"ssc-init.scan.v3",` +
		`"scanId":"00000000-0000-4000-8000-000000000001",` +
		`"status":"complete",` +
		`"startedAt":"2026-08-07T00:00:00Z",` +
		`"finishedAt":"2026-08-07T00:00:01Z",` +
		`"scope":{"platform":"darwin","catalogVersion":"ssc-init.catalog.v1","projectRoots":[],"externalProbes":false},` +
		`"coverage":[],` +
		`"evidenceCoverage":{"status":"complete","targets":[]},` +
		`"inventory":{"assets":[],"observations":[],"evidence":[],"relationships":[]},` +
		`"delta":{"changes":[]}}` + "\n"
	var out bytes.Buffer

	if err := WriteJSON(&out, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if out.String() != want {
		t.Fatalf("json=%q\nwant=%q", out.String(), want)
	}
}

func TestWriteJSONReturnsWriterError(t *testing.T) {
	if err := WriteJSON(failingWriter{}, model.ScanResult{}, model.Inventory{}, model.Delta{}); err == nil {
		t.Fatal("WriteJSON error=nil")
	}
}
