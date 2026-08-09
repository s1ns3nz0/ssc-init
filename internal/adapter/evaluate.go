package adapter

import (
	"errors"
	"sort"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/quarantine"
)

const EvaluationSchemaV1 = "ssc-init.adapter-evaluation.v1"

type RemediationChoice string

const (
	ChoiceInspectReport RemediationChoice = "inspect-report"
	ChoiceQuarantine    RemediationChoice = "quarantine"
)

type FindingView struct {
	ID                string                 `json:"id"`
	AssetID           string                 `json:"assetId"`
	AssetType         model.AssetType        `json:"assetType"`
	Verdict           model.Verdict          `json:"verdict"`
	Severity          model.Severity         `json:"severity"`
	Confidence        model.Confidence       `json:"confidence"`
	Level             int                    `json:"level"`
	RuleIDs           []string               `json:"ruleIds,omitempty"`
	DetectedAt        time.Time              `json:"detectedAt"`
	Action            model.FindingAction    `json:"action"`
	Reason            string                 `json:"reason"`
	Choices           []RemediationChoice    `json:"choices"`
	QuarantineTargets []quarantine.Selection `json:"quarantineTargets,omitempty"`
}

type Evaluation struct {
	SchemaVersion string        `json:"schemaVersion"`
	Host          Host          `json:"host"`
	Event         Event         `json:"event"`
	Capability    Capability    `json:"capability"`
	Intelligence  string        `json:"intelligence"`
	Policy        string        `json:"policy"`
	Findings      []FindingView `json:"findings"`
}

func Evaluate(invocation Invocation, result finding.Result) (Evaluation, error) {
	return EvaluateInventory(invocation, result, model.Inventory{})
}

func EvaluateInventory(invocation Invocation, result finding.Result, inventory model.Inventory) (Evaluation, error) {
	if !invocation.Valid() {
		return Evaluation{}, errors.New("invalid adapter invocation")
	}
	if !validIntelligenceState(result.Intelligence) || !validPolicyState(result.Policy) {
		return Evaluation{}, errors.New("invalid adapter finding state")
	}
	selected := append([]model.Finding(nil), result.Findings...)
	for _, item := range selected {
		if !validAdapterFinding(item) {
			return Evaluation{}, errors.New("invalid adapter finding")
		}
	}
	if len(invocation.AssetIDs) > 0 {
		allowed := make(map[string]struct{}, len(invocation.AssetIDs))
		for _, id := range invocation.AssetIDs {
			allowed[id] = struct{}{}
		}
		filtered := selected[:0]
		for _, item := range selected {
			if _, ok := allowed[item.AssetID]; ok {
				filtered = append(filtered, item)
			}
		}
		selected = filtered
	}
	sort.Slice(selected, func(i, j int) bool {
		left, right := severityRank(selected[i].Severity), severityRank(selected[j].Severity)
		if left != right {
			return left < right
		}
		return selected[i].ID < selected[j].ID
	})
	if len(selected) > 5 {
		selected = selected[:5]
	}
	evaluation := Evaluation{
		SchemaVersion: EvaluationSchemaV1, Host: invocation.Host, Event: invocation.Event, Capability: invocation.Capability,
		Intelligence: result.Intelligence, Policy: result.Policy, Findings: make([]FindingView, 0, len(selected)),
	}
	for _, item := range selected {
		choices := []RemediationChoice{ChoiceInspectReport}
		targets := quarantine.EligibleSelections(inventory, item.AssetID)
		if len(targets) > 0 && (item.Verdict == model.VerdictKnownMalicious || item.Verdict == model.VerdictBehaviorMalicious) {
			choices = append(choices, ChoiceQuarantine)
		} else {
			targets = nil
		}
		evaluation.Findings = append(evaluation.Findings, FindingView{
			ID: item.ID, AssetID: item.AssetID, AssetType: item.AssetType, Verdict: item.Verdict, Severity: item.Severity,
			Confidence: item.Confidence, Level: item.Level, RuleIDs: append([]string(nil), item.RuleIDs...), DetectedAt: item.DetectedAt,
			Action: item.Action, Reason: verdictReason(item.Verdict), Choices: choices, QuarantineTargets: targets,
		})
	}
	return evaluation, nil
}

func (e Evaluation) Valid() bool {
	if e.SchemaVersion != EvaluationSchemaV1 || !validHost(e.Host) || !validEventCapability(e.Event, e.Capability) ||
		!validIntelligenceState(e.Intelligence) || !validPolicyState(e.Policy) || e.Findings == nil || len(e.Findings) > 5 {
		return false
	}
	for index, view := range e.Findings {
		if !validFindingView(view) || index > 0 && !findingViewBefore(e.Findings[index-1], view) {
			return false
		}
	}
	return true
}

func validAdapterFinding(value model.Finding) bool {
	if !value.Valid() || !validCanonicalID(value.ID) || !validCanonicalID(value.AssetID) {
		return false
	}
	for _, ruleID := range value.RuleIDs {
		if !validCanonicalID(ruleID) {
			return false
		}
	}
	return true
}

func validFindingView(value FindingView) bool {
	if !validCanonicalID(value.ID) || !validCanonicalID(value.AssetID) || value.DetectedAt.IsZero() || value.Level < 1 || value.Level > 5 || value.Reason != verdictReason(value.Verdict) || len(value.Choices) == 0 || len(value.Choices) > 2 {
		return false
	}
	probe := model.Finding{ID: value.ID, AssetID: value.AssetID, AssetType: value.AssetType, Verdict: value.Verdict, Severity: value.Severity, Confidence: value.Confidence, Level: value.Level, RuleIDs: value.RuleIDs, DetectedAt: value.DetectedAt, Action: value.Action}
	if !validAdapterFinding(probe) || value.Choices[0] != ChoiceInspectReport {
		return false
	}
	wantQuarantine := len(value.QuarantineTargets) > 0 && (value.Verdict == model.VerdictKnownMalicious || value.Verdict == model.VerdictBehaviorMalicious)
	if len(value.QuarantineTargets) > 64 || (len(value.Choices) == 2) != wantQuarantine || len(value.Choices) == 2 && value.Choices[1] != ChoiceQuarantine {
		return false
	}
	for index, target := range value.QuarantineTargets {
		if target.AssetID != value.AssetID || !validCanonicalID(target.ObservationID) || !validCanonicalID(target.EvidenceID) {
			return false
		}
		if index > 0 {
			previous := value.QuarantineTargets[index-1]
			if previous.ObservationID > target.ObservationID || previous.ObservationID == target.ObservationID && previous.EvidenceID >= target.EvidenceID {
				return false
			}
		}
	}
	return true
}

func findingViewBefore(left, right FindingView) bool {
	l, r := severityRank(left.Severity), severityRank(right.Severity)
	return l < r || l == r && left.ID < right.ID
}

func severityRank(value model.Severity) int {
	switch value {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	default:
		return 4
	}
}

func verdictReason(value model.Verdict) string {
	switch value {
	case model.VerdictKnownMalicious:
		return "Verified intelligence identified this exact asset."
	case model.VerdictBehaviorMalicious:
		return "High-confidence behavior evidence requires intervention."
	case model.VerdictSuspicious:
		return "Bounded evidence identified suspicious behavior."
	case model.VerdictNeedsReview:
		return "Recorded evidence requires human review."
	case model.VerdictNoFinding:
		return "No finding was produced for the recorded evidence."
	default:
		return ""
	}
}

func validIntelligenceState(value string) bool {
	return value == "unavailable" || value == "fresh" || value == "stale" || value == "expired"
}

func validPolicyState(value string) bool {
	return value == "inactive" || value == "fresh" || value == "stale" || value == "expired"
}
