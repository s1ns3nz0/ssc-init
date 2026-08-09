package model

import (
	"encoding/hex"
	"sort"
	"time"
)

type Verdict string

const (
	VerdictKnownMalicious    Verdict = "known-malicious"
	VerdictBehaviorMalicious Verdict = "behaviorally-malicious"
	VerdictSuspicious        Verdict = "suspicious"
	VerdictNeedsReview       Verdict = "needs-review"
	VerdictNoFinding         Verdict = "no-finding"
)

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type FindingAction string

const (
	ActionAdvisory FindingAction = "advisory"
	ActionBlocked  FindingAction = "blocked"
	ActionPaused   FindingAction = "paused"
	ActionExcepted FindingAction = "excepted"
	ActionAllowed  FindingAction = "allowed"
)

type BundleReference struct {
	Family   string `json:"family"`
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
}

type Finding struct {
	ID               string            `json:"id"`
	AssetID          string            `json:"assetId"`
	AssetType        AssetType         `json:"assetType"`
	Version          string            `json:"version,omitempty"`
	SHA256           string            `json:"sha256,omitempty"`
	Verdict          Verdict           `json:"verdict"`
	Severity         Severity          `json:"severity"`
	Confidence       Confidence        `json:"confidence"`
	Level            int               `json:"level"`
	RuleIDs          []string          `json:"ruleIds,omitempty"`
	IntelligenceIDs  []string          `json:"intelligenceIds,omitempty"`
	EvidenceIDs      []string          `json:"evidenceIds,omitempty"`
	DetectedAt       time.Time         `json:"detectedAt"`
	Action           FindingAction     `json:"action"`
	Bundles          []BundleReference `json:"bundles,omitempty"`
	CampaignIDs      []string          `json:"campaignIds,omitempty"`
	AttackTechniques []string          `json:"attackTechniques,omitempty"`
}

func (f Finding) Valid() bool {
	if f.ID == "" || f.AssetID == "" || !validFindingAssetType(f.AssetType) || f.DetectedAt.IsZero() || f.Level < 1 || f.Level > 5 ||
		!validVerdict(f.Verdict) || !validSeverity(f.Severity) || !validConfidence(f.Confidence) || !validFindingAction(f.Action) ||
		f.SHA256 != "" && !findingSHA256(f.SHA256) || !sortedUniqueFindingValues(f.RuleIDs) || !sortedUniqueFindingValues(f.IntelligenceIDs) ||
		!sortedUniqueFindingValues(f.EvidenceIDs) || !sortedUniqueFindingValues(f.CampaignIDs) || !sortedUniqueFindingValues(f.AttackTechniques) {
		return false
	}
	for _, reference := range f.Bundles {
		if reference.Family != "ti" && reference.Family != "policy" || reference.Sequence == 0 || !findingSHA256(reference.Digest) {
			return false
		}
	}
	return true
}

func validFindingAssetType(value AssetType) bool {
	switch value {
	case AssetAgentPlugin, AssetSkill, AssetMCP, AssetIDEExtension, AssetPackage, AssetProject, AssetTool, AssetShellStartup,
		AssetGitHook, AssetCredentialHelper, AssetLaunchConfig, AssetProcess, AssetListeningEndpoint:
		return true
	default:
		return false
	}
}

func validVerdict(value Verdict) bool {
	switch value {
	case VerdictKnownMalicious, VerdictBehaviorMalicious, VerdictSuspicious, VerdictNeedsReview, VerdictNoFinding:
		return true
	default:
		return false
	}
}

func validSeverity(value Severity) bool {
	switch value {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		return true
	default:
		return false
	}
}

func validConfidence(value Confidence) bool {
	return value == ConfidenceHigh || value == ConfidenceMedium || value == ConfidenceLow
}

func validFindingAction(value FindingAction) bool {
	switch value {
	case ActionAdvisory, ActionBlocked, ActionPaused, ActionExcepted, ActionAllowed:
		return true
	default:
		return false
	}
}

func findingSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func sortedUniqueFindingValues(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return sort.StringsAreSorted(values)
}
