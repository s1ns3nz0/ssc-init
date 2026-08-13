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

func TestWriteFindingsPrettyRendersActionTableWhileJSONContractStaysJSON(t *testing.T) {
	assetID := "asset:sha256:" + strings.Repeat("b", 64)
	finding := model.Finding{ID: "finding:z", AssetID: assetID, AssetType: model.AssetPackage, Verdict: model.VerdictKnownMalicious, Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh, Level: 5, IntelligenceIDs: []string{"intel:one"}, DetectedAt: time.Unix(1, 0).UTC(), Action: model.ActionAdvisory}
	data := FindingData{
		DeviceID: "device:sha256:" + strings.Repeat("a", 64), Intelligence: "fresh", Policy: "inactive",
		Assets: []model.Asset{{ID: assetID, Type: model.AssetPackage, Name: "compromised-sdk", Version: "1.2.3"}}, Findings: []model.Finding{finding},
	}
	var pretty bytes.Buffer
	if err := WriteFindingsPretty(&pretty, data, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ACTION REQUIRED", "PRIORITY", "compromised-sdk", "KNOWN MALICIOUS", "HIGH", "VERIFIED INTELLIGENCE", "\x1b[31m"} {
		if !strings.Contains(pretty.String(), want) {
			t.Fatalf("human findings output missing %q:\n%q", want, pretty.String())
		}
	}
	if strings.HasPrefix(strings.TrimSpace(pretty.String()), "{") {
		t.Fatalf("pretty output is still JSON: %s", pretty.String())
	}

	var jsonOutput bytes.Buffer
	if err := WriteFindingsJSON(&jsonOutput, data, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(jsonOutput.String(), `{"schemaVersion":"ssc-init.findings.v1"`) || strings.Contains(jsonOutput.String(), "\x1b[") || strings.Contains(jsonOutput.String(), `"assets"`) {
		t.Fatalf("JSON contract changed: %q", jsonOutput.String())
	}
}
