package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestWriteFindingsJSONIsDeterministicAndPrivacySafe(t *testing.T) {
	finding := model.Finding{ID: "finding:z", AssetID: "tool:opaque", AssetType: model.AssetTool, Verdict: model.VerdictNeedsReview, Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh, Level: 5, RuleIDs: []string{"rule"}, DetectedAt: time.Unix(1, 0).UTC(), Action: model.ActionAdvisory}
	var output bytes.Buffer
	err := WriteFindingsJSON(&output, FindingData{DeviceID: "device:sha256:" + strings.Repeat("a", 64), Intelligence: "fresh", Policy: "inactive", Findings: []model.Finding{finding}}, false)
	if err != nil || strings.Contains(output.String(), "/Users/") || !strings.Contains(output.String(), `"schemaVersion":"ssc-init.findings.v1"`) {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
}

func TestWriteFindingsJSONRejectsNonOpaqueDeviceAndInvalidFinding(t *testing.T) {
	for _, data := range []FindingData{{DeviceID: "/Users/alice"}, {DeviceID: "device:sha256:" + strings.Repeat("a", 64), Findings: []model.Finding{{ID: "invalid"}}}} {
		if err := WriteFindingsJSON(&bytes.Buffer{}, data, false); err == nil {
			t.Fatal("unsafe payload accepted")
		}
	}
}
