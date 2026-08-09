package model

import "sort"

type AnalyzerCategory string

const (
	AnalyzerVersionAdvisory  AnalyzerCategory = "version-advisory"
	AnalyzerMutableReference AnalyzerCategory = "mutable-reference"
	AnalyzerDynamicExecution AnalyzerCategory = "dynamic-execution"
	AnalyzerProcessLaunch    AnalyzerCategory = "process-launch"
	AnalyzerCredentialAccess AnalyzerCategory = "credential-access"
	AnalyzerOutboundNetwork  AnalyzerCategory = "outbound-network"
	AnalyzerObfuscation      AnalyzerCategory = "obfuscation"
	AnalyzerCredentialEgress AnalyzerCategory = "credential-egress"
)

type AnalyzerFact struct {
	ID          string           `json:"id"`
	AssetID     string           `json:"assetId"`
	EvidenceID  string           `json:"evidenceId,omitempty"`
	RuleID      string           `json:"ruleId"`
	Category    AnalyzerCategory `json:"category"`
	Confidence  Confidence       `json:"confidence"`
	Occurrences int              `json:"occurrences"`
}

func (f AnalyzerFact) Valid() bool {
	return f.ID != "" && f.AssetID != "" && f.RuleID != "" && validAnalyzerCategory(f.Category) && validConfidence(f.Confidence) && f.Occurrences > 0 && f.Occurrences <= 10_000
}

func validAnalyzerCategory(value AnalyzerCategory) bool {
	switch value {
	case AnalyzerVersionAdvisory, AnalyzerMutableReference, AnalyzerDynamicExecution, AnalyzerProcessLaunch, AnalyzerCredentialAccess, AnalyzerOutboundNetwork, AnalyzerObfuscation, AnalyzerCredentialEgress:
		return true
	default:
		return false
	}
}

type AnalyzerCoverage struct {
	Status       CoverageStatus `json:"status"`
	FilesRead    int            `json:"filesRead"`
	BytesRead    int64          `json:"bytesRead"`
	SkippedRules []string       `json:"skippedRules,omitempty"`
}

func (c AnalyzerCoverage) Valid() bool {
	if !validAnalyzerCoverageStatus(c.Status) || c.FilesRead < 0 || c.BytesRead < 0 || c.BytesRead > 1<<30 {
		return false
	}
	for index, value := range c.SkippedRules {
		if value == "" || index > 0 && c.SkippedRules[index-1] >= value {
			return false
		}
	}
	return sort.StringsAreSorted(c.SkippedRules)
}

func validAnalyzerCoverageStatus(value CoverageStatus) bool {
	switch value {
	case CoverageComplete, CoveragePartial, CoverageSkipped, CoverageUnavailable, CoverageFailed:
		return true
	default:
		return false
	}
}
