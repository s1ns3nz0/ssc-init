package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/findingdisplay"
	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type Section string

type Style struct {
	Color bool
}

const (
	SectionFindings Section = "findings"
	SectionChanges  Section = "changes"
	SectionCoverage Section = "coverage"
	SectionAssets   Section = "assets"
	SectionEvidence Section = "evidence"
)

var severityOrder = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInformational}
var changeOrder = []inventory.Rung{inventory.RungNew, inventory.RungChanged, inventory.RungUnverified, inventory.RungUpgraded, inventory.RungRemoved}
var coverageOrder = []model.CoverageStatus{model.CoverageComplete, model.CoveragePartial, model.CoverageUnavailable, model.CoverageSkipped, model.CoverageFailed}
var assetTypeOrder = []model.AssetType{
	model.AssetAgentPlugin, model.AssetSkill, model.AssetMCP, model.AssetIDEExtension, model.AssetPackage, model.AssetProject, model.AssetTool,
	model.AssetShellStartup, model.AssetGitHook, model.AssetCredentialHelper, model.AssetLaunchConfig, model.AssetProcess, model.AssetListeningEndpoint,
}

func WritePretty(writer io.Writer, record Record, stored *Stored) error {
	return WritePrettyStyled(writer, record, stored, Style{})
}

func WritePrettyStyled(writer io.Writer, record Record, stored *Stored, style Style) error {
	if writer == nil || Validate(record) != nil || stored != nil && !validStoredDisplay(*stored) {
		return errors.New("invalid audit report")
	}
	printer := auditPrinter{writer: writer, color: style.Color}
	printer.line("SSC Init security review")
	printer.field("run", printer.styled(record.Run.ID, ansiDim))
	printer.field("state", strings.ToUpper(string(record.State)))
	printer.field("started", printer.styled(record.Run.StartedAt.UTC().Format(time.RFC3339), ansiDim))
	printer.field("device", printer.styled(record.Run.DeviceID, ansiDim))
	if record.Run.Label != "" {
		printer.field("label", record.Run.Label)
	}
	if record.State == StateFailed {
		printer.assessment(record)
		printer.intelligence(record)
		printer.line(fmt.Sprintf("FAILED stage=%s code=%s", record.Failure.Stage, record.Failure.Code))
		printer.auditEvidence(stored)
		return printer.err
	}
	printer.assessment(record)
	printer.intelligence(record)
	printer.priorityFindings(record)
	printer.nextSteps(record)
	printer.summary(record.Summary)
	printer.findingSummary(record)
	printer.changeSummary(record)
	printer.coverageSummary(record)
	printer.assetSummary(record)
	printer.auditEvidence(stored)
	return printer.err
}

func WriteSection(writer io.Writer, record Record, section Section) error {
	return WriteSectionStyled(writer, record, section, Style{})
}

func WriteSectionStyled(writer io.Writer, record Record, section Section, style Style) error {
	if writer == nil || Validate(record) != nil || record.State == StateFailed {
		return errors.New("invalid audit section")
	}
	printer := auditPrinter{writer: writer, color: style.Color}
	switch section {
	case SectionFindings:
		printer.findingDetails(record)
	case SectionChanges:
		printer.changeDetails(record)
	case SectionCoverage:
		printer.coverageDetails(record)
	case SectionAssets:
		printer.assetDetails(record)
	case SectionEvidence:
		printer.evidenceDetails(record)
	default:
		return errors.New("invalid audit section")
	}
	return printer.err
}

func WriteList(writer io.Writer, records []Stored) error {
	if writer == nil {
		return errors.New("invalid audit list")
	}
	ordered := append([]Stored(nil), records...)
	for _, stored := range ordered {
		if !validStoredList(stored) {
			return errors.New("invalid audit list")
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].RunID < ordered[j].RunID
		}
		return ordered[i].CreatedAt.After(ordered[j].CreatedAt)
	})
	printer := auditPrinter{writer: writer}
	printer.line("SSC Init audit archives")
	for _, stored := range ordered {
		state := "invalid"
		if stored.Valid {
			state = string(stored.State)
		}
		line := fmt.Sprintf("  %s  %-8s  %s", stored.CreatedAt.UTC().Format(time.RFC3339), strings.ToUpper(state), stored.RunID)
		if stored.Label != "" {
			line += "  " + stored.Label
		}
		printer.line(line)
	}
	if len(ordered) == 0 {
		printer.line("  (none)")
	}
	return printer.err
}

func WriteVerify(writer io.Writer, verified Verified, safePath string) error {
	if writer == nil || Validate(verified.Record) != nil || verified.Manifest.Authentication != "unsigned" || !sha256Hex(verified.ZIPSHA256) || !validSafeDisplayPath(safePath) {
		return errors.New("invalid audit verification output")
	}
	printer := auditPrinter{writer: writer}
	printer.line("SSC Init audit verification")
	printer.field("state", "valid")
	printer.field("file", safePath)
	printer.field("run", verified.Record.Run.ID)
	printer.field("profile", string(verified.Record.Profile))
	printer.field("archive", strings.ToUpper(string(verified.Record.State)))
	printer.field("sha256", verified.ZIPSHA256)
	printer.field("authentication", verified.Manifest.Authentication)
	return printer.err
}

func ReportText(record Record) ([]byte, error) {
	var buffer bytes.Buffer
	if err := WritePretty(&buffer, record, nil); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type auditPrinter struct {
	writer io.Writer
	err    error
	color  bool
}

const (
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiDim    = "\x1b[2m"
	ansiReset  = "\x1b[0m"
)

func (p *auditPrinter) line(value string) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.writer, value)
	}
}

func (p *auditPrinter) field(name, value string) { p.line(fmt.Sprintf("  %-10s %s", name, value)) }

func (p *auditPrinter) styled(value, code string) string {
	if !p.color || code == "" {
		return value
	}
	return code + value + ansiReset
}

func (p *auditPrinter) heading(value string) {
	p.line("")
	p.line(value)
}

func (p *auditPrinter) summary(summary Summary) {
	p.heading("SUMMARY")
	for _, row := range []struct {
		name  string
		value int
	}{{"assets", summary.Assets}, {"observations", summary.Observations}, {"evidence", summary.Evidence}, {"findings", summary.Findings}, {"changes", summary.Changes}} {
		p.field(row.name, fmt.Sprintf("%d", row.value))
	}
}

func (p *auditPrinter) assessment(record Record) {
	status, reason, confidence := assessment(record)
	p.heading("ASSESSMENT")
	color := ansiYellow
	if status == "ACTION REQUIRED" {
		color = ansiRed
	} else if status == "NO ACTION IDENTIFIED" {
		color = ""
	}
	p.field("status", p.styled(status, color))
	p.field("reason", reason)
	p.field("confidence", confidence)
	coverage := coverageAssessment(record)
	coverageColor := ansiYellow
	if record.State == StateComplete {
		coverageColor = ""
	}
	p.field("coverage", p.styled(coverage, coverageColor))
	p.field("mode", "advisory — nothing was blocked automatically")
}

func (p *auditPrinter) intelligence(record Record) {
	p.heading("INTELLIGENCE")
	if record.Intelligence == nil {
		p.field("update", "not requested")
		p.field("freshness", p.styled("unavailable", ansiYellow))
		return
	}
	update := record.Intelligence
	statusColor, freshnessColor := ansiYellow, ansiYellow
	if (update.Status == "updated" || update.Status == "current") && update.Freshness == "fresh" {
		statusColor, freshnessColor = ansiGreen, ansiGreen
	}
	p.field("update", p.styled(update.Status, statusColor))
	p.field("freshness", p.styled(update.Freshness, freshnessColor))
	if update.Sequence > 0 {
		p.field("sequence", fmt.Sprintf("%d", update.Sequence))
		p.field("records", fmt.Sprintf("%d", update.Records))
		p.field("malicious", fmt.Sprintf("%d", update.Malicious))
		p.field("vulnerable", fmt.Sprintf("%d", update.Vulnerable))
	}
	if update.ErrorCode != "" {
		p.field("error", update.ErrorCode)
	}
}

func assessment(record Record) (string, string, string) {
	if record.State == StateFailed {
		return "INCOMPLETE", "scan did not complete", "LOW"
	}
	malicious, suspicious, review := 0, 0, 0
	confidence := model.ConfidenceLow
	for _, finding := range record.Findings {
		if finding.Confidence == model.ConfidenceHigh || finding.Confidence == model.ConfidenceMedium && confidence == model.ConfidenceLow {
			confidence = finding.Confidence
		}
		switch finding.Verdict {
		case model.VerdictKnownMalicious, model.VerdictBehaviorMalicious:
			malicious++
		case model.VerdictSuspicious:
			suspicious++
		case model.VerdictNeedsReview:
			review++
		}
	}
	if malicious > 0 {
		return "ACTION REQUIRED", fmt.Sprintf("%d known-malicious finding(s)", malicious), strings.ToUpper(string(confidence))
	}
	if suspicious > 0 {
		return "INVESTIGATION RECOMMENDED", fmt.Sprintf("%d suspicious finding(s)", suspicious), strings.ToUpper(string(confidence))
	}
	if review > 0 {
		return "REVIEW RECOMMENDED", fmt.Sprintf("%d finding(s) need review", review), strings.ToUpper(string(confidence))
	}
	return "NO ACTION IDENTIFIED", "no actionable findings were identified", "LOW"
}

func coverageAssessment(record Record) string {
	if record.State == StateComplete {
		return "COMPLETE"
	}
	if record.State == StateFailed {
		return "INCOMPLETE — scan failed"
	}
	return "PARTIAL — some targets were not checked"
}

func (p *auditPrinter) priorityFindings(record Record) {
	p.heading("PRIORITY FINDINGS")
	rows := orderedFindings(record.Findings)
	assets := assetDisplays(record)
	p.line("  PRIORITY    ASSET                CLASSIFICATION          CONFIDENCE  ACTION")
	if len(rows) == 0 {
		p.line("  (none)")
		return
	}
	if len(rows) > 5 {
		rows = rows[:5]
	}
	for _, finding := range rows {
		priority := "REVIEW"
		if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
			priority = "IMMEDIATE"
		}
		classification := strings.ToUpper(strings.ReplaceAll(string(finding.Verdict), "-", " "))
		if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
			classification = p.styled(classification, ansiRed)
		} else {
			classification = p.styled(classification, ansiYellow)
		}
		action := "INSPECT"
		if priority == "IMMEDIATE" {
			action = "REVIEW NOW"
		}
		p.line(fmt.Sprintf("  %-11s %-20s %-23s %-11s %s", priority, assets[finding.AssetID], classification, strings.ToUpper(string(finding.Confidence)), action))
		p.line("              why: " + findingdisplay.Reason(finding))
	}
}

func (p *auditPrinter) nextSteps(record Record) {
	p.heading("NEXT STEPS")
	p.line("  1. Inspect: " + p.styled("ssc-init audit show "+record.Run.ID+" --section findings", ansiDim))
	p.line("  2. Review evidence: " + p.styled("ssc-init audit show "+record.Run.ID+" --section evidence", ansiDim))
	p.line("  3. Verify archive: " + p.styled("ssc-init audit verify <absolute-zip> --pretty", ansiDim))
}

func (p *auditPrinter) findingSummary(record Record) {
	p.heading("FINDINGS")
	counts := map[model.Severity]int{}
	for _, finding := range record.Findings {
		counts[finding.Severity]++
	}
	for _, severity := range severityOrder {
		if counts[severity] > 0 {
			p.field(strings.ToUpper(string(severity)), fmt.Sprintf("%d", counts[severity]))
		}
	}
	p.line("  next: ssc-init findings --pretty")
}

func (p *auditPrinter) changeSummary(record Record) {
	p.heading("CHANGES")
	counts := map[inventory.Rung]int{}
	for _, row := range inventory.Ladder(record.Inventory, record.Changes) {
		counts[row.Rung]++
	}
	for _, rung := range changeOrder {
		if counts[rung] > 0 {
			p.field(rung.Label(), fmt.Sprintf("%d", counts[rung]))
		}
	}
	p.line("  next: ssc-init audit show " + record.Run.ID + " --section changes")
}

func (p *auditPrinter) coverageSummary(record Record) {
	p.heading("COVERAGE")
	counts := map[model.CoverageStatus]int{}
	for _, result := range record.Coverage {
		counts[result.Status]++
	}
	for _, status := range coverageOrder {
		if counts[status] > 0 {
			p.field(string(status), fmt.Sprintf("%d", counts[status]))
		}
	}
	p.line("  next: ssc-init audit show " + record.Run.ID + " --section coverage")
}

func (p *auditPrinter) assetSummary(record Record) {
	p.heading("ASSETS")
	counts := map[model.AssetType]int{}
	for _, asset := range record.Inventory.Assets {
		counts[asset.Type]++
	}
	for _, assetType := range assetTypeOrder {
		if counts[assetType] > 0 {
			p.field(string(assetType), fmt.Sprintf("%d", counts[assetType]))
		}
	}
	p.line("  next: ssc-init audit show " + record.Run.ID + " --section assets")
}

func (p *auditPrinter) auditEvidence(stored *Stored) {
	p.heading("AUDIT EVIDENCE")
	if stored == nil || !stored.Valid {
		p.field("state", "unavailable")
		return
	}
	p.field("state", "saved")
	p.field("file", stored.SafePath)
	p.field("sha256", stored.SHA256)
	p.line("  verify: ssc-init audit verify <absolute-zip> --pretty")
}

func (p *auditPrinter) findingDetails(record Record) {
	p.line("FINDINGS")
	assets := assetDisplays(record)
	rows := orderedFindings(record.Findings)
	p.line("  SEVERITY      ASSET                CLASSIFICATION           CONFIDENCE  BASIS                  ACTION")
	for _, finding := range rows {
		classification := strings.ToUpper(strings.ReplaceAll(string(finding.Verdict), "-", " "))
		if finding.Verdict == model.VerdictKnownMalicious || finding.Verdict == model.VerdictBehaviorMalicious {
			classification = p.styled(classification, ansiRed)
		} else if finding.Verdict == model.VerdictSuspicious || finding.Verdict == model.VerdictNeedsReview {
			classification = p.styled(classification, ansiYellow)
		}
		p.line(fmt.Sprintf("  %-13s %-20s %-24s %-11s %-22s %s", strings.ToUpper(string(finding.Severity)), assets[finding.AssetID], classification, strings.ToUpper(string(finding.Confidence)), findingBasis(finding), finding.Action))
		p.line("    why       " + findingdisplay.Reason(finding))
		if advisories := findingdisplay.PublicAdvisories(finding); advisories != "" {
			p.line("    advisory  " + advisories)
		}
		if sequence := tiSequence(finding); sequence > 0 {
			p.line(fmt.Sprintf("    sequence  %d", sequence))
		}
		p.line("    rules     " + findingdisplay.Rules(finding))
		p.line("    evidence  " + findingdisplay.Evidence(finding))
		p.line("    action    " + findingdisplay.Action(finding))
	}
	if len(rows) == 0 {
		p.line("  (none)")
	}
}

func tiSequence(finding model.Finding) uint64 {
	for _, reference := range finding.Bundles {
		if reference.Family == "ti" {
			return reference.Sequence
		}
	}
	return 0
}

func orderedFindings(findings []model.Finding) []model.Finding {
	rows := append([]model.Finding(nil), findings...)
	sort.Slice(rows, func(i, j int) bool {
		left, right := severityRank(rows[i].Severity), severityRank(rows[j].Severity)
		if left != right {
			return left < right
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

func findingBasis(finding model.Finding) string {
	if len(finding.IntelligenceIDs) > 0 {
		return "VERIFIED INTELLIGENCE"
	}
	if len(finding.RuleIDs) > 0 {
		return "POLICY / LOCAL RULE"
	}
	return "LOCAL ANALYSIS"
}

func (p *auditPrinter) changeDetails(record Record) {
	p.line("CHANGES")
	rows := inventory.Ladder(record.Inventory, record.Changes)
	for _, row := range rows {
		line := fmt.Sprintf("  %-10s %-20s %s", row.Rung.Label(), row.Type, row.Name)
		if row.Rung == inventory.RungUpgraded {
			line += fmt.Sprintf("  %s → %s", row.From, row.To)
		}
		p.line(line)
	}
	if len(rows) == 0 {
		p.line("  (none)")
	}
}

func (p *auditPrinter) coverageDetails(record Record) {
	p.line("COVERAGE")
	for _, result := range record.Coverage {
		p.line(fmt.Sprintf("  %-20s %-12s targets=%d errors=%d", result.Collector, result.Status, len(result.Targets), len(result.Errors)))
		for _, issue := range result.Errors {
			p.line("    error " + issue.Code)
		}
	}
	if len(record.Coverage) == 0 {
		p.line("  (none)")
	}
}

func (p *auditPrinter) assetDetails(record Record) {
	p.line("ASSETS")
	rows := append([]model.Asset(nil), record.Inventory.Assets...)
	sort.Slice(rows, func(i, j int) bool {
		left, right := assetTypeRank(rows[i].Type), assetTypeRank(rows[j].Type)
		if left != right {
			return left < right
		}
		return rows[i].ID < rows[j].ID
	})
	aliases := findingdisplay.ProjectAliases(record.Inventory.Assets)
	for _, asset := range rows {
		p.line(fmt.Sprintf("  %-20s %-28s %s", asset.Type, displayName(asset, aliases), asset.Version))
	}
	if len(rows) == 0 {
		p.line("  (none)")
	}
}

func (p *auditPrinter) evidenceDetails(record Record) {
	p.line("EVIDENCE")
	assets := assetDisplays(record)
	for _, evidence := range record.Inventory.Evidence {
		code := "-"
		if len(evidence.Errors) > 0 {
			code = evidence.Errors[0].Code
		}
		p.line(fmt.Sprintf("  %-20s %-20s %-12s %s", assets[evidence.AssetID], evidence.Subject, evidence.Status, code))
	}
	if len(record.Inventory.Evidence) == 0 {
		p.line("  (none)")
	}
}

func assetDisplays(record Record) map[string]string {
	result := make(map[string]string, len(record.Inventory.Assets))
	aliases := findingdisplay.ProjectAliases(record.Inventory.Assets)
	for _, asset := range record.Inventory.Assets {
		result[asset.ID] = displayName(asset, aliases)
	}
	return result
}

func displayName(asset model.Asset, projectAliases map[string]string) string {
	if alias := projectAliases[asset.ID]; asset.Type == model.AssetProject && alias != "" {
		return alias
	}
	if asset.Name == "" {
		return "(redacted)"
	}
	return asset.Name
}

func severityRank(value model.Severity) int {
	for index, candidate := range severityOrder {
		if value == candidate {
			return index
		}
	}
	return len(severityOrder)
}

func assetTypeRank(value model.AssetType) int {
	for index, candidate := range assetTypeOrder {
		if value == candidate {
			return index
		}
	}
	return len(assetTypeOrder)
}

func validStoredDisplay(stored Stored) bool {
	return stored.Valid && validSafeDisplayPath(stored.SafePath) && sha256Hex(stored.SHA256)
}

func validStoredList(stored Stored) bool {
	if !runIDPattern.MatchString(stored.RunID) || stored.Label != "" && !ValidLabel(stored.Label) || !validSafeDisplayPath(stored.SafePath) {
		return false
	}
	if !stored.Valid {
		return stored.SHA256 == ""
	}
	return sha256Hex(stored.SHA256) && (stored.State == StateComplete || stored.State == StatePartial || stored.State == StateFailed) && (stored.Profile == ProfileInternal || stored.Profile == ProfileRedacted)
}

func validSafeDisplayPath(value string) bool {
	prefix := safeAuditPrefix
	if strings.HasPrefix(value, "$INPUT/") {
		prefix = "$INPUT/"
	} else if !strings.HasPrefix(value, prefix) {
		return false
	}
	name := strings.TrimPrefix(value, prefix)
	return name != "" && !strings.ContainsAny(name, `/\\`) && strings.HasSuffix(name, ".zip")
}
