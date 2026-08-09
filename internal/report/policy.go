package report

import (
	"fmt"
	"io"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

// WritePolicy renders policy claims in their own section, separate from the
// factual change ladder.
func WritePolicy(writer io.Writer, result policy.Result) error {
	return writePolicy(writer, result.Violations, fmt.Sprintf("%d violations", len(result.Violations)))
}

func writePolicy(writer io.Writer, violations []policy.Violation, summary string) error {
	if _, err := fmt.Fprintf(writer, "POLICY (%s)\n", summary); err != nil {
		return err
	}
	for _, violation := range violations {
		row := inventory.Row{Type: violation.AssetType, Name: violation.AssetName, Host: violation.Host}
		if _, err := fmt.Fprintf(writer, "  %s\n", render(violation.RuleID, 19, row)); err != nil {
			return err
		}
	}
	return nil
}
