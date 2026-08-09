package report

import (
	"fmt"

	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// Compatibility aliases keep the report tests focused on rendering while the
// classifier itself has one owner beside inventory.Diff.
type rung = inventory.Rung

const (
	rungNew        = inventory.RungNew
	rungChanged    = inventory.RungChanged
	rungUnverified = inventory.RungUnverified
	rungUpgraded   = inventory.RungUpgraded
	rungRemoved    = inventory.RungRemoved
)

var rungLabels = map[rung]string{
	rungNew:        rungNew.Label(),
	rungChanged:    rungChanged.Label(),
	rungUnverified: rungUnverified.Label(),
	rungUpgraded:   rungUpgraded.Label(),
	rungRemoved:    rungRemoved.Label(),
}

var parseAssetID = inventory.ParseAssetID

type digestMatcher struct{}

func (digestMatcher) MatchString(value string) bool { return inventory.IsDigestSegment(value) }

var digestSegment digestMatcher

const unnamedAsset = inventory.UnnamedAsset

type rungRow struct {
	key      string
	Rung     rung
	Type     string
	Name     string
	Host     string
	From, To string
}

// render is shared by the ladder and the later POLICY section; callers choose
// the left-column label and width while all asset columns remain identical.
func render(label string, labelWidth int, row inventory.Row) string {
	line := fmt.Sprintf("%-*s %-13s %s", labelWidth, label, row.Type, row.Name)
	if row.Host != "" {
		line += fmt.Sprintf(" (%s)", row.Host)
	}
	if row.Rung == inventory.RungUpgraded && label == row.Rung.Label() {
		line += fmt.Sprintf("  %s → %s", row.From, row.To)
	}
	return line
}

func rungLine(row inventory.Row) string { return render(row.Rung.Label(), 10, row) }

func (row rungRow) render() string {
	return render(row.Rung.Label(), 10, inventory.Row{Rung: row.Rung, Type: row.Type, Name: row.Name, Host: row.Host, From: row.From, To: row.To})
}

func classify(current model.Inventory, delta model.Delta) []rungRow {
	classified := inventory.Ladder(current, delta)
	rows := make([]rungRow, 0, len(classified))
	for _, row := range classified {
		rows = append(rows, rungRow{key: row.AssetID(), Rung: row.Rung, Type: row.Type, Name: row.Name, Host: row.Host, From: row.From, To: row.To})
	}
	return rows
}
