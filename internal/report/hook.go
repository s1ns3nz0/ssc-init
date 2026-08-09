package report

import (
	"fmt"
	"io"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

const maxHookDetailRows = 20

// WriteHookSummary renders an advisory severity ladder. An empty delta writes
// nothing. Output carries asset types, names, hosts, versions, rungs, and
// counts only — never digests, paths, or contents, and never a safety verdict.
// This build performs no content analysis, so it has no basis for one.
//
// firstRun says whether the scan found no previous snapshot at all. On a first
// run "NEW" would describe the absence of history, not the machine, so the run
// reports counts instead. The delta cannot answer this — a first snapshot that
// recorded zero assets makes the next run look identical — so the caller must
// pass the fact.
func WriteHookSummary(writer io.Writer, inventory model.Inventory, delta model.Delta, firstRun bool, policyResults ...policy.Result) error {
	return writeHookSummary(writer, inventory, delta, firstRun, nil, policyResults...)
}

func WriteHookSummaryFindings(writer io.Writer, inventory model.Inventory, delta model.Delta, firstRun bool, findings []model.Finding, policyResults ...policy.Result) error {
	return writeHookSummary(writer, inventory, delta, firstRun, findings, policyResults...)
}

func writeHookSummary(writer io.Writer, inventory model.Inventory, delta model.Delta, firstRun bool, findings []model.Finding, policyResults ...policy.Result) error {
	var policyResult policy.Result
	if len(policyResults) > 0 {
		policyResult = policyResults[0]
	}
	newViolations := make([]policy.Violation, 0, len(policyResult.Violations))
	standing := 0
	for _, violation := range policyResult.Violations {
		if violation.Standing {
			standing++
		} else {
			newViolations = append(newViolations, violation)
		}
	}
	if len(delta.Changes) == 0 && len(policyResult.Violations) == 0 && len(findings) == 0 {
		return nil
	}
	printer := &prettyPrinter{writer: writer}
	unverified := standingUnverified(inventory)
	wroteLadder := false

	if firstRun && len(delta.Changes) > 0 {
		printer.line(fmt.Sprintf("ssc-init: initial baseline recorded — %d assets, %d evidence records, %d unverified",
			len(inventory.Assets), len(inventory.Evidence), unverified))
		wroteLadder = true
	}

	rows := classify(inventory, delta)
	if !firstRun && len(rows) > 0 {
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
		wroteLadder = true
	}
	if len(newViolations) > 0 {
		if wroteLadder {
			printer.line("")
		}
		if printer.err == nil {
			summary := fmt.Sprintf("%d violations", len(newViolations))
			printer.err = writePolicy(writer, newViolations, summary)
		}
	}
	if standing > 0 {
		label := "violations"
		if standing == 1 {
			label = "violation"
		}
		printer.line(fmt.Sprintf("ssc-init: %d policy %s standing (run: ssc-init policy check)", standing, label))
	}
	if len(findings) > 0 {
		printer.line("")
		printer.line(fmt.Sprintf("ssc-init: %d new verified findings (advisory — run: ssc-init findings --pretty)", len(findings)))
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
