package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const maxHookDetailRows = 20

var hookKindOrder = map[model.ChangeKind]int{
	model.ChangeAdded:   0,
	model.ChangeChanged: 1,
	model.ChangeRemoved: 2,
}

// WriteHookSummary renders an advisory toolchain-drift summary for hook
// consumers. An empty delta writes nothing. Output carries asset types,
// names, hosts, statuses, and counts only — never digests, paths, or
// contents.
func WriteHookSummary(writer io.Writer, inventory model.Inventory, delta model.Delta) error {
	if len(delta.Changes) == 0 {
		return nil
	}
	observationAsset := make(map[string]string, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		observationAsset[observation.ID] = observation.AssetID
	}
	evidenceAsset := make(map[string]string, len(inventory.Evidence))
	for _, evidence := range inventory.Evidence {
		evidenceAsset[evidence.ID] = evidence.AssetID
	}
	assetName := make(map[string]string, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assetName[asset.ID] = asset.Name
	}

	type groupKey struct {
		kind   model.ChangeKind
		entity model.ChangeEntity
		label  string
	}
	rows := make([]struct {
		kind  model.ChangeKind
		label string
	}, 0, len(delta.Changes))
	groups := make(map[groupKey]int)
	unresolved := make(map[groupKey]int)
	for _, change := range delta.Changes {
		switch change.Entity {
		case model.ChangeEntityAsset:
			rows = append(rows, struct {
				kind  model.ChangeKind
				label string
			}{change.Kind, describeHookAssetID(change.EntityID)})
		case model.ChangeEntityObservation, model.ChangeEntityEvidence:
			assetID := observationAsset[change.EntityID]
			if change.Entity == model.ChangeEntityEvidence {
				assetID = evidenceAsset[change.EntityID]
			}
			if name := assetName[assetID]; name != "" {
				groups[groupKey{change.Kind, change.Entity, name}]++
			} else {
				unresolved[groupKey{kind: change.Kind, entity: change.Entity}]++
			}
		default:
			unresolved[groupKey{kind: change.Kind, entity: change.Entity}]++
		}
	}
	for key, count := range groups {
		rows = append(rows, struct {
			kind  model.ChangeKind
			label string
		}{key.kind, fmt.Sprintf("%d %s records (%s)", count, key.entity, key.label)})
	}
	for key, count := range unresolved {
		rows = append(rows, struct {
			kind  model.ChangeKind
			label string
		}{key.kind, fmt.Sprintf("%d %s records", count, key.entity)})
	}
	sort.Slice(rows, func(a, b int) bool {
		if hookKindOrder[rows[a].kind] != hookKindOrder[rows[b].kind] {
			return hookKindOrder[rows[a].kind] < hookKindOrder[rows[b].kind]
		}
		return rows[a].label < rows[b].label
	})

	printer := &prettyPrinter{writer: writer}
	printer.line("ssc-init: toolchain drift since last snapshot")
	detail := rows
	overflow := 0
	if len(detail) > maxHookDetailRows {
		overflow = len(detail) - maxHookDetailRows
		detail = detail[:maxHookDetailRows]
	}
	for _, row := range detail {
		printer.line(fmt.Sprintf("  %-8s %s", row.kind, row.label))
	}
	if overflow > 0 {
		printer.line(fmt.Sprintf("  …and %d more changes", overflow))
	}
	printer.hookIssuesLine(inventory)
	return printer.err
}

// hookIssuesLine appends the non-complete evidence counts, excluding the
// deliberate unsupported non-claims (same rule as the pretty ISSUES table).
func (p *prettyPrinter) hookIssuesLine(inventory model.Inventory) {
	counts := make(map[model.EvidenceStatus]int)
	total := 0
	for _, evidence := range inventory.Evidence {
		if evidence.Status == model.EvidenceComplete || evidence.Status == model.EvidenceUnsupported {
			continue
		}
		counts[evidence.Status]++
		total++
	}
	if total == 0 {
		return
	}
	parts := make([]string, 0, len(counts))
	for _, status := range evidenceStatusOrder {
		if counts[status] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", status, counts[status]))
		}
	}
	p.line(fmt.Sprintf("  issues: %d non-complete evidence records (%s)", total, strings.Join(parts, ", ")))
}

// describeHookAssetID renders "<type> <name>[@version] (<host>)" from the
// structured asset ID "<type>:<host>:<name>[@version]"; two-segment IDs
// render "<type> <rest>", anything else renders verbatim.
func describeHookAssetID(id string) string {
	parts := strings.SplitN(id, ":", 3)
	switch len(parts) {
	case 3:
		return parts[0] + " " + parts[2] + " (" + parts[1] + ")"
	case 2:
		return parts[0] + " " + parts[1]
	default:
		return id
	}
}
