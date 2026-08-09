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
	if _, err := fmt.Fprintf(writer, "POLICY (%d violations)\n", len(result.Violations)); err != nil {
		return err
	}
	for _, violation := range result.Violations {
		row := inventory.Row{Type: violation.AssetType, Name: violation.AssetName, Host: violation.Host}
		if _, err := fmt.Fprintf(writer, "  %s\n", render(violation.RuleID, 19, row)); err != nil {
			return err
		}
	}
	return nil
}
