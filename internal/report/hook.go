package report

import (
	"fmt"
	"io"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const maxHookDetailRows = 20

// WriteHookSummary renders an advisory severity ladder. An empty delta writes
// nothing. Output carries asset types, names, hosts, versions, rungs, and
// counts only — never digests, paths, or contents, and never a safety verdict.
func WriteHookSummary(writer io.Writer, inventory model.Inventory, delta model.Delta) error {
	if len(delta.Changes) == 0 {
		return nil
	}
	printer := &prettyPrinter{writer: writer}
	unverified := standingUnverified(inventory)

	if isInitialBaseline(inventory, delta) {
		printer.line(fmt.Sprintf("ssc-init: initial baseline recorded — %d assets, %d evidence records, %d unverified",
			len(inventory.Assets), len(inventory.Evidence), unverified))
		return printer.err
	}

	rows := classify(inventory, delta)
	if len(rows) == 0 {
		return nil
	}
	printer.line(fmt.Sprintf("ssc-init: %d changes since last snapshot", len(rows)))
	shown := rows
	if len(shown) > maxHookDetailRows {
		shown = shown[:maxHookDetailRows]
	}
	for _, row := range shown {
		printer.line("  " + row.render())
	}
	if overflow := len(rows) - len(shown); overflow > 0 {
		printer.line(fmt.Sprintf("  …and %d more changes", overflow))
	}
	if unverified > 0 {
		printer.line(fmt.Sprintf("  %d targets unverified (standing — run: ssc-init status --pretty)", unverified))
	}
	return printer.err
}

// standingUnverified counts records with no trusted digest. Unsupported is a
// deliberate non-claim (package payloads, container identity), not a gap.
func standingUnverified(inventory model.Inventory) int {
	count := 0
	for _, evidence := range inventory.Evidence {
		if evidence.Status != model.EvidenceComplete && evidence.Status != model.EvidenceUnsupported {
			count++
		}
	}
	return count
}

// isInitialBaseline reports whether this delta is the first snapshot: every
// change is an addition and every asset in the inventory is among them. On a
// first run "NEW" would describe the absence of history, not the machine.
func isInitialBaseline(inventory model.Inventory, delta model.Delta) bool {
	addedAssets := 0
	for _, change := range delta.Changes {
		if change.Kind != model.ChangeAdded {
			return false
		}
		if change.Entity == model.ChangeEntityAsset {
			addedAssets++
		}
	}
	return addedAssets == len(inventory.Assets)
}
