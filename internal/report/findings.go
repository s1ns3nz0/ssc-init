package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/findingdisplay"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

type FindingData struct {
	DeviceID     string
	Intelligence string
	Policy       string
	Findings     []model.Finding
	Assets       []model.Asset
}

type findingPayload struct {
	SchemaVersion string          `json:"schemaVersion"`
	DeviceID      string          `json:"deviceId"`
	Intelligence  string          `json:"intelligence"`
	Policy        string          `json:"policy"`
	Findings      []model.Finding `json:"findings"`
}

func WriteFindingsJSON(writer io.Writer, data FindingData, pretty bool) error {
	if !strings.HasPrefix(data.DeviceID, "device:sha256:") || len(strings.TrimPrefix(data.DeviceID, "device:sha256:")) != 64 || privacy.ContainsSensitiveValue(data.DeviceID) {
		return errors.New("invalid opaque device identity")
	}
	findings := append([]model.Finding(nil), data.Findings...)
	for _, item := range findings {
		if !item.Valid() {
			return errors.New("invalid finding")
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(findingPayload{SchemaVersion: "ssc-init.findings.v1", DeviceID: data.DeviceID, Intelligence: data.Intelligence, Policy: data.Policy, Findings: findings})
}

func WriteFindingsPretty(writer io.Writer, data FindingData, color bool) error {
	if writer == nil {
		return errors.New("invalid findings output")
	}
	var validation strings.Builder
	if err := WriteFindingsJSON(&validation, data, false); err != nil {
		return err
	}
	assets := make(map[string]string, len(data.Assets))
	projectAliases := findingdisplay.ProjectAliases(data.Assets)
	for _, asset := range data.Assets {
		if asset.ID == "" || asset.Name == "" || privacy.ContainsSensitiveValue(asset.Name) {
			return errors.New("invalid finding asset")
		}
		assets[asset.ID] = asset.Name
		if alias := projectAliases[asset.ID]; alias != "" {
			assets[asset.ID] = alias
		}
	}
	rows := append([]model.Finding(nil), data.Findings...)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Level != rows[j].Level {
			return rows[i].Level > rows[j].Level
		}
		return rows[i].ID < rows[j].ID
	})
	status := "NO ACTION IDENTIFIED"
	statusColor := ""
	for _, finding := range rows {
		if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
			status, statusColor = "ACTION REQUIRED", "\x1b[31m"
			break
		}
		if finding.Verdict == model.VerdictSuspicious {
			status, statusColor = "INVESTIGATION RECOMMENDED", "\x1b[33m"
		} else if finding.Verdict == model.VerdictNeedsReview && status == "NO ACTION IDENTIFIED" {
			status, statusColor = "REVIEW RECOMMENDED", "\x1b[33m"
		}
	}
	paint := func(value, code string) string {
		if !color || code == "" {
			return value
		}
		return code + value + "\x1b[0m"
	}
	if _, err := fmt.Fprintln(writer, "SSC Init findings\n\nASSESSMENT\n  status      "+paint(status, statusColor)+"\n\nPRIORITY FINDINGS\n  PRIORITY    ASSET                CLASSIFICATION          CONFIDENCE  BASIS"); err != nil {
		return err
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(writer, "  (none)")
		return err
	}
	for _, finding := range rows {
		priority := "REVIEW"
		code := "\x1b[33m"
		if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
			priority, code = "IMMEDIATE", "\x1b[31m"
		}
		name := assets[finding.AssetID]
		if name == "" {
			name = "(redacted)"
		}
		classification := strings.ToUpper(strings.ReplaceAll(string(finding.Verdict), "-", " "))
		basis := "LOCAL ANALYSIS"
		if len(finding.IntelligenceIDs) > 0 {
			basis = "VERIFIED INTELLIGENCE"
		} else if len(finding.RuleIDs) > 0 {
			basis = "POLICY / LOCAL RULE"
		}
		if _, err := fmt.Fprintf(writer, "  %-11s %-20s %-23s %-11s %s\n", priority, name, paint(classification, code), strings.ToUpper(string(finding.Confidence)), basis); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "              why: "+findingdisplay.Reason(finding)); err != nil {
			return err
		}
		if advisories := findingdisplay.PublicAdvisories(finding); advisories != "" {
			if _, err := fmt.Fprintln(writer, "              advisory: "+advisories); err != nil {
				return err
			}
		}
		if sequence := findingTISequence(finding); sequence > 0 {
			if _, err := fmt.Fprintf(writer, "              sequence: %d\n", sequence); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer, "              evidence: "+findingdisplay.Evidence(finding)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "              action: "+findingdisplay.Action(finding)); err != nil {
			return err
		}
	}
	return nil
}

func findingTISequence(finding model.Finding) uint64 {
	for _, reference := range finding.Bundles {
		if reference.Family == "ti" {
			return reference.Sequence
		}
	}
	return 0
}
