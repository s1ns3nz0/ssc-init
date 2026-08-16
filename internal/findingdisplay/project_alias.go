package findingdisplay

import (
	"fmt"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// ProjectAliases returns presentation-only names for project assets. The
// canonical IDs remain the graph identity and are never rendered by aliases.
func ProjectAliases(assets []model.Asset) map[string]string {
	ids := make([]string, 0, len(assets))
	seen := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		if asset.Type != model.AssetProject || asset.ID == "" {
			continue
		}
		if _, duplicate := seen[asset.ID]; duplicate {
			continue
		}
		seen[asset.ID] = struct{}{}
		ids = append(ids, asset.ID)
	}
	sort.Strings(ids)
	aliases := make(map[string]string, len(ids))
	for index, id := range ids {
		aliases[id] = fmt.Sprintf("project-%d", index+1)
	}
	return aliases
}
