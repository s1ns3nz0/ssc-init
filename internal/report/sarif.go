package report

import (
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Properties sarifProperties `json:"properties"`
}
type sarifProperties struct {
	FindingID string `json:"findingId"`
	AssetID   string `json:"assetId"`
	AssetType string `json:"assetType"`
	Verdict   string `json:"verdict"`
	Action    string `json:"action"`
}

func WriteSARIF(writer io.Writer, version string, findings []model.Finding) error {
	findings = append([]model.Finding(nil), findings...)
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	ruleNames := map[string]string{}
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		if !finding.Valid() {
			return errors.New("invalid finding")
		}
		ruleID := findingRuleID(finding)
		ruleNames[ruleID] = string(finding.Verdict)
		results = append(results, sarifResult{RuleID: ruleID, Level: sarifLevel(finding.Severity), Message: sarifMessage{Text: finding.AssetID + ": " + string(finding.Verdict)}, Properties: sarifProperties{FindingID: finding.ID, AssetID: finding.AssetID, AssetType: string(finding.AssetType), Verdict: string(finding.Verdict), Action: string(finding.Action)}})
	}
	ids := make([]string, 0, len(ruleNames))
	for id := range ruleNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, sarifRule{ID: id, Name: ruleNames[id], ShortDescription: sarifMessage{Text: ruleNames[id]}})
	}
	document := sarifDocument{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "SSC Init", InformationURI: "https://github.com/s1ns3nz0/ssc-init", Version: version, Rules: rules}}, Results: results}}}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func findingRuleID(finding model.Finding) string {
	if len(finding.RuleIDs) > 0 {
		return finding.RuleIDs[0]
	}
	if len(finding.IntelligenceIDs) > 0 {
		return finding.IntelligenceIDs[0]
	}
	return "ssc-init/" + string(finding.Verdict)
}

func sarifLevel(severity model.Severity) string {
	if severity == model.SeverityCritical || severity == model.SeverityHigh {
		return "error"
	}
	if severity == model.SeverityMedium || severity == model.SeverityLow {
		return "warning"
	}
	return "note"
}
