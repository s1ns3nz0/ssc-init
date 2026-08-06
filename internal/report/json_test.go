package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/model"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteJSONUsesStableTopLevelShapeWithoutHTMLEscaping(t *testing.T) {
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v2",
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
	if !strings.HasSuffix(got, "\n") || !strings.Contains(got, `"schemaVersion":"ssc-init.scan.v2"`) {
		t.Fatalf("json=%q", got)
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

func TestWriteJSONReturnsWriterError(t *testing.T) {
	if err := WriteJSON(failingWriter{}, model.ScanResult{}, model.Inventory{}, model.Delta{}); err == nil {
		t.Fatal("WriteJSON error=nil")
	}
}
