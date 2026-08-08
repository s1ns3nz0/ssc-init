package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// StatusData carries the status payload fields the human renderer may show.
// Legacy snapshots keep coverage fields nil so no evidence claim is rendered.
type StatusData struct {
	Initialized            bool
	LegacyInventory        bool
	InventorySchemaVersion string
	Scope                  *model.ScanScope
	Coverage               []model.CollectorResult
	EvidenceCoverage       *model.EvidenceCoverage
	Inventory              *model.Inventory
}

// evidenceStatusOrder fixes the rendering order of the closed status vocabulary.
var evidenceStatusOrder = []model.EvidenceStatus{
	model.EvidenceComplete,
	model.EvidencePartial,
	model.EvidenceOversize,
	model.EvidenceUnavailable,
	model.EvidenceUnsupported,
	model.EvidenceSkipped,
}

// WritePretty renders a baseline scan as deterministic human-readable tables.
// It shows names, statuses, counts, and error codes only — never digests,
// paths, or file contents.
func WritePretty(writer io.Writer, scan model.ScanResult, inventory model.Inventory, delta model.Delta) error {
	printer := &prettyPrinter{writer: writer}
	printer.line("SSC Init baseline scan")
	printer.field("schema", scan.SchemaVersion)
	printer.field("scan", scan.ScanID)
	printer.field("status", scan.Status)
	printer.field("started", scan.StartedAt.UTC().Format(time.RFC3339))
	printer.field("finished", scan.FinishedAt.UTC().Format(time.RFC3339))
	if scan.Scope.Platform != "" {
		probes := "off"
		if scan.Scope.ExternalProbes {
			probes = "on"
		}
		printer.field("scope", fmt.Sprintf("%s catalog=%s probes=%s roots=%d",
			scan.Scope.Platform, scan.Scope.CatalogVersion, probes, len(scan.Scope.ProjectRoots)))
	}
	printer.collectorTable(scan.Coverage)
	printer.evidenceSections(&scan.EvidenceCoverage, inventory)
	printer.deltaSummary(delta)
	return printer.err
}

// WriteStatusPretty renders the status payload as human-readable tables.
func WriteStatusPretty(writer io.Writer, status StatusData) error {
	printer := &prettyPrinter{writer: writer}
	printer.line("SSC Init status")
	if !status.Initialized {
		printer.field("state", "not initialized (no baseline scan recorded)")
		return printer.err
	}
	printer.field("state", "initialized")
	printer.field("inventory", status.InventorySchemaVersion)
	if status.Inventory != nil {
		printer.field("counts", fmt.Sprintf("assets=%d observations=%d evidence=%d",
			len(status.Inventory.Assets), len(status.Inventory.Observations), len(status.Inventory.Evidence)))
	}
	if status.LegacyInventory {
		printer.field("note", "legacy inventory (pre-v3): content evidence was not collected")
		return printer.err
	}
	if status.Scope != nil {
		probes := "off"
		if status.Scope.ExternalProbes {
			probes = "on"
		}
		printer.field("scope", fmt.Sprintf("%s catalog=%s probes=%s roots=%d",
			status.Scope.Platform, status.Scope.CatalogVersion, probes, len(status.Scope.ProjectRoots)))
	}
	printer.collectorTable(status.Coverage)
	inventory := model.Inventory{}
	if status.Inventory != nil {
		inventory = *status.Inventory
	}
	printer.evidenceSections(status.EvidenceCoverage, inventory)
	return printer.err
}

type prettyPrinter struct {
	writer io.Writer
	err    error
}

func (p *prettyPrinter) line(text string) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintln(p.writer, text)
}

func (p *prettyPrinter) field(name, value string) {
	p.line(fmt.Sprintf("  %-9s %s", name, value))
}

func (p *prettyPrinter) table(title string, header []string, rows [][]string) {
	p.line("")
	p.line(title)
	if len(rows) == 0 {
		p.line("  (none)")
		return
	}
	if p.err != nil {
		return
	}
	tab := tabwriter.NewWriter(p.writer, 0, 0, 2, ' ', 0)
	write := func(cells []string) {
		if p.err != nil {
			return
		}
		line := "  "
		for index, cell := range cells {
			if index > 0 {
				line += "\t"
			}
			line += cell
		}
		_, p.err = fmt.Fprintln(tab, line)
	}
	write(header)
	for _, row := range rows {
		write(row)
	}
	if p.err == nil {
		p.err = tab.Flush()
	}
}

func (p *prettyPrinter) collectorTable(coverage []model.CollectorResult) {
	rows := make([][]string, 0, len(coverage))
	for _, result := range coverage {
		rows = append(rows, []string{
			result.Collector,
			string(result.Status),
			fmt.Sprintf("%d", len(result.Targets)),
			fmt.Sprintf("%d", len(result.Assets)),
		})
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a][0] < rows[b][0] })
	p.table("COLLECTOR COVERAGE", []string{"COLLECTOR", "STATUS", "TARGETS", "ASSETS"}, rows)
}

func (p *prettyPrinter) evidenceSections(coverage *model.EvidenceCoverage, inventory model.Inventory) {
	if coverage == nil {
		return
	}
	statusCounts := make(map[model.EvidenceStatus]int)
	for _, target := range coverage.Targets {
		statusCounts[target.Status]++
	}
	statusRows := make([][]string, 0, len(evidenceStatusOrder))
	for _, status := range evidenceStatusOrder {
		if statusCounts[status] > 0 {
			statusRows = append(statusRows, []string{string(status), fmt.Sprintf("%d", statusCounts[status])})
		}
	}
	p.table(fmt.Sprintf("EVIDENCE COVERAGE  %s (%d targets)", coverage.Status, len(coverage.Targets)),
		[]string{"STATUS", "COUNT"}, statusRows)

	observationSource := make(map[string]string, len(inventory.Observations))
	observationAsset := make(map[string]string, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		observationSource[observation.ID] = observation.Source
		observationAsset[observation.ID] = observation.AssetID
	}
	assetName := make(map[string]string, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assetName[asset.ID] = asset.Name
	}

	type sourceCount struct {
		total    int
		complete int
	}
	sources := make(map[string]*sourceCount)
	issueRows := make([][]string, 0)
	for _, evidence := range inventory.Evidence {
		source := observationSource[evidence.ObservationID]
		if source == "" {
			source = "(unknown)"
		}
		count, ok := sources[source]
		if !ok {
			count = &sourceCount{}
			sources[source] = count
		}
		count.total++
		if evidence.Status == model.EvidenceComplete {
			count.complete++
			continue
		}
		// Unsupported is a deliberate non-claim (for example package payloads
		// and Docker identities), not an anomaly: it stays visible in the
		// coverage counts and source totals without flooding ISSUES.
		if evidence.Status == model.EvidenceUnsupported {
			continue
		}
		name := assetName[observationAsset[evidence.ObservationID]]
		if name == "" {
			name = evidence.AssetID
		}
		errorCode := "-"
		if len(evidence.Errors) > 0 {
			errorCode = evidence.Errors[0].Code
		}
		issueRows = append(issueRows, []string{name, string(evidence.Subject), string(evidence.Status), errorCode})
	}
	sourceRows := make([][]string, 0, len(sources))
	for source, count := range sources {
		sourceRows = append(sourceRows, []string{source, fmt.Sprintf("%d", count.total), fmt.Sprintf("%d", count.complete)})
	}
	sort.Slice(sourceRows, func(a, b int) bool { return sourceRows[a][0] < sourceRows[b][0] })
	p.table("EVIDENCE BY SOURCE", []string{"SOURCE", "TOTAL", "COMPLETE"}, sourceRows)

	sort.Slice(issueRows, func(a, b int) bool {
		if issueRows[a][0] != issueRows[b][0] {
			return issueRows[a][0] < issueRows[b][0]
		}
		return issueRows[a][1] < issueRows[b][1]
	})
	p.table("ISSUES", []string{"ASSET", "SUBJECT", "STATUS", "ERROR"}, issueRows)
}

func (p *prettyPrinter) deltaSummary(delta model.Delta) {
	counts := map[model.ChangeKind]int{}
	for _, change := range delta.Changes {
		counts[change.Kind]++
	}
	p.line("")
	p.line(fmt.Sprintf("DELTA  added=%d changed=%d removed=%d",
		counts[model.ChangeAdded], counts[model.ChangeChanged], counts[model.ChangeRemoved]))
}
