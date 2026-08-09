package finding

import (
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestCorrelateAnalyzerProducesTruthfulAdvisoryFinding(t *testing.T) {
	asset := model.Asset{ID: "tool:fixture", Type: model.AssetTool, Name: "fixture"}
	facts := []model.AnalyzerFact{{ID: "fact:flow", AssetID: asset.ID, EvidenceID: "evidence:fixture", RuleID: "ssc-init/flow/credential-egress", Category: model.AnalyzerCredentialEgress, Confidence: model.ConfidenceHigh, Occurrences: 1}}
	got := CorrelateAnalyzer(model.Inventory{Assets: []model.Asset{asset}}, facts, time.Unix(1, 0).UTC())
	if len(got) != 1 || got[0].Verdict != model.VerdictSuspicious || got[0].Severity != model.SeverityHigh || got[0].Level != 5 || got[0].Action != model.ActionAdvisory || !got[0].Valid() {
		t.Fatalf("findings=%+v", got)
	}
}

func TestCorrelateAnalyzerNeverCallsCapabilityAloneMalicious(t *testing.T) {
	asset := model.Asset{ID: "tool:fixture", Type: model.AssetTool, Name: "fixture"}
	facts := []model.AnalyzerFact{{ID: "fact:credential", AssetID: asset.ID, RuleID: "ssc-init/api/credential-access", Category: model.AnalyzerCredentialAccess, Confidence: model.ConfidenceMedium, Occurrences: 1}}
	got := CorrelateAnalyzer(model.Inventory{Assets: []model.Asset{asset}}, facts, time.Unix(1, 0).UTC())
	if len(got) != 1 || got[0].Verdict != model.VerdictNeedsReview {
		t.Fatalf("findings=%+v", got)
	}
}
