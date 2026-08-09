package finding

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func CorrelateAnalyzer(inventory model.Inventory, facts []model.AnalyzerFact, now time.Time) []model.Finding {
	assets := make(map[string]model.Asset, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assets[asset.ID] = asset
	}
	byAsset := make(map[string][]model.AnalyzerFact)
	for _, fact := range facts {
		if fact.Valid() {
			if _, ok := assets[fact.AssetID]; ok {
				byAsset[fact.AssetID] = append(byAsset[fact.AssetID], fact)
			}
		}
	}
	var findings []model.Finding
	for assetID, matched := range byAsset {
		asset := assets[assetID]
		var rules, evidenceIDs []string
		verdict, severity, confidence := model.VerdictNeedsReview, model.SeverityMedium, model.ConfidenceLow
		for _, fact := range matched {
			rules = append(rules, fact.RuleID)
			if fact.EvidenceID != "" {
				evidenceIDs = append(evidenceIDs, fact.EvidenceID)
			}
			if confidenceRank(fact.Confidence) > confidenceRank(confidence) {
				confidence = fact.Confidence
			}
			if analyzerRiskRank(fact.Category) >= 2 {
				verdict, severity = model.VerdictSuspicious, model.SeverityHigh
			}
		}
		rules, evidenceIDs = sortedUnique(rules), sortedUnique(evidenceIDs)
		identity := strings.Join(append([]string{"ssc-init.finding.analyzer.v1", asset.ID}, rules...), "\x00")
		digest := sha256.Sum256([]byte(identity))
		finding := model.Finding{ID: fmt.Sprintf("finding:sha256:%x", digest), AssetID: asset.ID, AssetType: asset.Type, Version: asset.Version, SHA256: strings.ToLower(asset.SHA256), Verdict: verdict, Severity: severity, Confidence: confidence, Level: 5, RuleIDs: rules, EvidenceIDs: evidenceIDs, DetectedAt: now.UTC(), Action: model.ActionAdvisory}
		if finding.Valid() {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

func analyzerRiskRank(category model.AnalyzerCategory) int {
	switch category {
	case model.AnalyzerCredentialEgress, model.AnalyzerDynamicExecution, model.AnalyzerProcessLaunch, model.AnalyzerObfuscation, model.AnalyzerMutableReference, model.AnalyzerVersionAdvisory:
		return 2
	case model.AnalyzerCredentialAccess, model.AnalyzerOutboundNetwork:
		return 1
	default:
		return 0
	}
}
