package policy

import (
	"sort"
	"time"

	inventorypkg "github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// Pin is an approved digest for one asset evidence subject. Task 6 adds pin
// evaluation; the value lives at this boundary now so callers do not change.
type Pin struct {
	AssetID string
	Kind    string
	Subject string
	Digest  string
}

// Applied identifies an exception that matched or expired without carrying
// its reason, digest, or other author-controlled values.
type Applied struct {
	RuleID  string `json:"ruleId"`
	AssetID string `json:"assetId"`
}

// Input is everything Evaluate reads. Evaluation is pure: it opens no file,
// starts no process, opens no socket, and consults no clock beyond Now.
type Input struct {
	Sources    Sources
	Inventory  model.Inventory
	Delta      model.Delta
	Pins       []Pin
	Exceptions []Exception
	Now        time.Time
}

// Violation names the rule and asset but never the matched value, digest,
// path, metadata, or exception reason.
type Violation struct {
	RuleID    string `json:"ruleId"`
	Level     int    `json:"level"`
	AssetID   string `json:"assetId"`
	AssetType string `json:"assetType"`
	AssetName string `json:"assetName"`
	Host      string `json:"host,omitempty"`
	Standing  bool   `json:"standing"`
}

// Result is the deterministic policy evaluation result.
type Result struct {
	Levels     []Level     `json:"levels"`
	Violations []Violation `json:"violations"`
	Applied    []Applied   `json:"exceptionsApplied,omitempty"`
	Expired    []Applied   `json:"exceptionsExpired,omitempty"`
}

// Evaluate applies active local rules to already-recorded inventory facts.
func Evaluate(input Input) Result {
	result := Result{Levels: Levels(input.Sources), Violations: []Violation{}}
	observations := make(map[string][]model.Observation)
	evidence := make(map[string][]model.ContentEvidence)
	for _, observation := range input.Inventory.Observations {
		observations[observation.AssetID] = append(observations[observation.AssetID], observation)
	}
	for _, item := range input.Inventory.Evidence {
		evidence[item.AssetID] = append(evidence[item.AssetID], item)
	}

	for _, rule := range input.Sources.Document.Rules {
		if !rule.Enabled || rule.Family != FamilyShape || rule.Match == nil {
			continue
		}
		for _, asset := range input.Inventory.Assets {
			candidates := observations[asset.ID]
			if len(candidates) == 0 {
				candidates = []model.Observation{{}}
			}
			for _, observation := range candidates {
				if matchesShape(*rule.Match, asset, observation, evidence[asset.ID]) {
					result.Violations = append(result.Violations, Violation{
						RuleID: rule.ID, Level: 5, AssetID: asset.ID,
						AssetType: string(asset.Type), AssetName: asset.Name, Host: observation.Host,
					})
					break
				}
			}
		}
	}

	assets := make(map[string]model.Asset, len(input.Inventory.Assets))
	for _, asset := range input.Inventory.Assets {
		assets[asset.ID] = asset
	}
	for _, rule := range input.Sources.Document.Rules {
		if !rule.Enabled || rule.Family != FamilyChange || rule.Match == nil {
			continue
		}
		for _, row := range inventorypkg.Ladder(input.Inventory, input.Delta) {
			if !matchesSet(rule.Match.Rungs, row.Rung.Label()) {
				continue
			}
			asset, present := assets[row.AssetID()]
			if !present {
				asset = model.Asset{ID: row.AssetID(), Type: model.AssetType(row.Type), Name: row.Name, Source: row.Host}
			}
			candidates := observations[asset.ID]
			if len(candidates) == 0 {
				candidates = []model.Observation{{Host: row.Host}}
			}
			for _, observation := range candidates {
				if matchesShape(*rule.Match, asset, observation, evidence[asset.ID]) {
					result.Violations = append(result.Violations, Violation{
						RuleID: rule.ID, Level: 5, AssetID: row.AssetID(), AssetType: row.Type, AssetName: row.Name, Host: row.Host,
					})
					break
				}
			}
		}
	}
	result.Violations = append(result.Violations, evaluatePins(input.Sources.Document, input.Inventory, input.Pins)...)
	sort.Slice(result.Violations, func(i, j int) bool {
		left, right := result.Violations[i], result.Violations[j]
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.AssetID < right.AssetID
	})
	return result
}
