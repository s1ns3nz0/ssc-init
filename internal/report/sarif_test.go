package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestWriteSARIFOmitLocationsAndRawEvidence(t *testing.T) {
	finding := model.Finding{ID: "finding:one", AssetID: "tool:opaque", AssetType: model.AssetTool, Verdict: model.VerdictSuspicious, Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Level: 1, IntelligenceIDs: []string{"ti:one"}, DetectedAt: time.Unix(1, 0).UTC(), Action: model.ActionAdvisory, Bundles: []model.BundleReference{{Family: "ti", Sequence: 1, Digest: strings.Repeat("a", 64)}}}
	var output bytes.Buffer
	if err := WriteSARIF(&output, "1.0.0", []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, forbidden := range []string{`"locations"`, `"artifactLocation"`, `"region"`, "/Users/"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("contains %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"version":"2.1.0"`) || !strings.Contains(text, `"ruleId":"ti:one"`) {
		t.Fatalf("output=%s", text)
	}
}
