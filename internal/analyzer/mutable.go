package analyzer

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// MutableFacts derives only from normalized persisted facts and performs no
// I/O. Absence is reported for packages because an unpinned package version is
// meaningful; other asset families may legitimately have no version.
func MutableFacts(inventory model.Inventory) []model.AnalyzerFact {
	var facts []model.AnalyzerFact
	for _, asset := range inventory.Assets {
		rules := make(map[string]model.Confidence)
		if asset.Provenance != nil && asset.Provenance.Status == model.ProvenanceMutable {
			rules["ssc-init/mutable/provenance"] = model.ConfidenceHigh
		}
		if strings.EqualFold(asset.Version, "latest") {
			rules["ssc-init/mutable/latest"] = model.ConfidenceHigh
		}
		if asset.Type == model.AssetPackage && asset.Version == "" {
			rules["ssc-init/mutable/unpinned-package"] = model.ConfidenceMedium
		}
		if asset.Metadata["git_ref_kind"] == "branch" {
			rules["ssc-init/mutable/git-branch"] = model.ConfidenceHigh
		}
		if asset.Metadata["execution_form"] == "remote-script" {
			rules["ssc-init/mutable/remote-script"] = model.ConfidenceHigh
		}
		for ruleID, confidence := range rules {
			digest := sha256.Sum256([]byte("ssc-init.analyzer.fact.v1\x00" + asset.ID + "\x00" + ruleID))
			facts = append(facts, model.AnalyzerFact{ID: fmt.Sprintf("analyzer:sha256:%x", digest), AssetID: asset.ID, RuleID: ruleID, Category: model.AnalyzerMutableReference, Confidence: confidence, Occurrences: 1})
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	return facts
}
