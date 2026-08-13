package finding

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	versionanalyzer "github.com/s1ns3nz0/ssc-init/internal/analyzer/version"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/packageid"
)

// Correlate produces level-one findings from exact, verified intelligence
// matches. Version-range interpretation is deliberately left to the advisory
// engine; this boundary never guesses about package versions.
func Correlate(inventory model.Inventory, active bundle.ActiveBundle, now time.Time) []model.Finding {
	if active.Verified.Envelope.Family != bundle.FamilyTI || active.Verified.Envelope.TI == nil {
		return nil
	}
	records := make(map[string][]bundle.TIRecord)
	for _, record := range active.Verified.Envelope.TI.Records {
		if record.Withdrawn || record.AssetID == "" {
			continue
		}
		records[record.AssetID] = append(records[record.AssetID], record)
	}
	evidence := make(map[string][]string)
	for _, item := range inventory.Evidence {
		if item.AssetID != "" && item.ID != "" && item.Status == model.EvidenceComplete {
			evidence[item.AssetID] = append(evidence[item.AssetID], item.ID)
		}
	}

	var findings []model.Finding
	for _, asset := range inventory.Assets {
		lookupID := asset.ID
		if asset.Type == model.AssetPackage {
			coordinate, ok := packageid.Coordinate(asset)
			if !ok {
				continue
			}
			lookupID = coordinate
		}
		var matches []bundle.TIRecord
		for _, record := range records[lookupID] {
			if exactSelectorMatch(asset, record) {
				matches = append(matches, record)
			}
		}
		if len(matches) == 0 {
			continue
		}
		finding := mergedFinding(asset, matches, evidence[asset.ID], active, now.UTC())
		if finding.Valid() {
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings
}

func exactSelectorMatch(asset model.Asset, record bundle.TIRecord) bool {
	if record.SHA256 != "" {
		return asset.SHA256 != "" && strings.EqualFold(record.SHA256, asset.SHA256)
	}
	if record.VersionRange == "" {
		return asset.Type != model.AssetPackage
	}
	if asset.Version == "" || record.VersionRange == "" {
		return false
	}
	matched, supported := versionanalyzer.Match(asset.ID, asset.Version, record.VersionRange)
	return supported && matched
}

func mergedFinding(asset model.Asset, records []bundle.TIRecord, evidenceIDs []string, active bundle.ActiveBundle, detectedAt time.Time) model.Finding {
	intelligenceIDs := make([]string, 0, len(records))
	var campaigns, techniques []string
	verdict := model.VerdictNoFinding
	confidence := model.ConfidenceLow
	for _, record := range records {
		intelligenceIDs = append(intelligenceIDs, record.ID)
		campaigns = append(campaigns, record.CampaignIDs...)
		techniques = append(techniques, record.AttackTechniques...)
		candidate := model.Verdict(record.Verdict)
		if verdictRank(candidate) > verdictRank(verdict) {
			verdict = candidate
		}
		candidateConfidence := model.Confidence(record.Confidence)
		if confidenceRank(candidateConfidence) > confidenceRank(confidence) {
			confidence = candidateConfidence
		}
	}
	intelligenceIDs = sortedUnique(intelligenceIDs)
	evidenceIDs = sortedUnique(evidenceIDs)
	identity := strings.Join(append([]string{"ssc-init.finding.v1", asset.ID}, intelligenceIDs...), "\x00")
	digest := sha256.Sum256([]byte(identity))
	return model.Finding{
		ID:               fmt.Sprintf("finding:sha256:%x", digest),
		AssetID:          asset.ID,
		AssetType:        asset.Type,
		Version:          asset.Version,
		SHA256:           strings.ToLower(asset.SHA256),
		Verdict:          verdict,
		Severity:         severityFor(verdict),
		Confidence:       confidence,
		Level:            1,
		IntelligenceIDs:  intelligenceIDs,
		EvidenceIDs:      evidenceIDs,
		DetectedAt:       detectedAt,
		Action:           model.ActionAdvisory,
		Bundles:          []model.BundleReference{{Family: string(bundle.FamilyTI), Sequence: active.Verified.Envelope.Sequence, Digest: fmt.Sprintf("%x", active.Verified.Digest)}},
		CampaignIDs:      sortedUnique(campaigns),
		AttackTechniques: sortedUnique(techniques),
	}
}

func verdictRank(value model.Verdict) int {
	switch value {
	case model.VerdictKnownMalicious:
		return 5
	case model.VerdictBehaviorMalicious:
		return 4
	case model.VerdictSuspicious:
		return 3
	case model.VerdictNeedsReview:
		return 2
	case model.VerdictNoFinding:
		return 1
	default:
		return 0
	}
}

func confidenceRank(value model.Confidence) int {
	switch value {
	case model.ConfidenceHigh:
		return 3
	case model.ConfidenceMedium:
		return 2
	case model.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func severityFor(verdict model.Verdict) model.Severity {
	switch verdict {
	case model.VerdictKnownMalicious, model.VerdictBehaviorMalicious:
		return model.SeverityCritical
	case model.VerdictSuspicious:
		return model.SeverityHigh
	case model.VerdictNeedsReview:
		return model.SeverityMedium
	default:
		return model.SeverityInformational
	}
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	values = values[:0]
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
