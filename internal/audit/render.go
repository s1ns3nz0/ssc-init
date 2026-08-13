package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type Section string

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
	if writer == nil || Validate(record) != nil || stored != nil && !validStoredDisplay(*stored) {
		return errors.New("invalid audit report")
	}
	printer := auditPrinter{writer: writer}
	printer.line("SSC Init audit")
	printer.field("run", record.Run.ID)
	printer.field("state", strings.ToUpper(string(record.State)))
	printer.field("started", record.Run.StartedAt.UTC().Format(time.RFC3339))
	printer.field("device", record.Run.DeviceID)
	if record.Run.Label != "" {
		printer.field("label", record.Run.Label)
	}
	if record.State == StateFailed {
		printer.line("")
		printer.line(fmt.Sprintf("FAILED stage=%s code=%s", record.Failure.Stage, record.Failure.Code))
		printer.auditEvidence(stored)
		return printer.err
	}
	printer.summary(record.Summary)
	printer.findingSummary(record)
	printer.changeSummary(record)
	printer.coverageSummary(record)
	printer.assetSummary(record)
	printer.auditEvidence(stored)
	return printer.err
}

func WriteSection(writer io.Writer, record Record, section Section) error {
	if writer == nil || Validate(record) != nil || record.State == StateFailed {
		return errors.New("invalid audit section")
	}
	printer := auditPrinter{writer: writer}
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
}

func (p *auditPrinter) line(value string) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.writer, value)
	}
}

func (p *auditPrinter) field(name, value string) { p.line(fmt.Sprintf("  %-10s %s", name, value)) }

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
	rows := append([]model.Finding(nil), record.Findings...)
	sort.Slice(rows, func(i, j int) bool {
		left, right := severityRank(rows[i].Severity), severityRank(rows[j].Severity)
		if left != right {
			return left < right
		}
		return rows[i].ID < rows[j].ID
	})
	for _, finding := range rows {
		p.line(fmt.Sprintf("  %-13s %-20s %-24s %s", strings.ToUpper(string(finding.Severity)), assets[finding.AssetID], finding.Verdict, finding.Action))
	}
	if len(rows) == 0 {
		p.line("  (none)")
	}
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
	for _, asset := range rows {
		p.line(fmt.Sprintf("  %-20s %-28s %s", asset.Type, displayName(asset), asset.Version))
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
	for _, asset := range record.Inventory.Assets {
		result[asset.ID] = displayName(asset)
	}
	return result
}

func displayName(asset model.Asset) string {
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
