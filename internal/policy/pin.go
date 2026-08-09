package policy

import "github.com/s1ns3nz0/ssc-init/internal/model"

type pinKey struct {
	assetID string
	kind    string
	subject string
}

func evaluatePins(document Document, inventory model.Inventory, pins []Pin) []Violation {
	enabled := map[string]bool{}
	for _, rule := range document.Rules {
		if rule.Enabled && rule.Family == FamilyPin {
			enabled[rule.ID] = true
		}
	}
	if !enabled["pin-mismatch"] && !enabled["unpinned"] {
		return nil
	}
	approved := make(map[pinKey]string, len(pins))
	for _, pin := range pins {
		approved[pinKey{pin.AssetID, pin.Kind, pin.Subject}] = pin.Digest
	}
	assets := make(map[string]model.Asset, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assets[asset.ID] = asset
	}
	emitted := map[string]bool{}
	violations := []Violation{}
	for _, evidence := range inventory.Evidence {
		if evidence.Status != model.EvidenceComplete || evidence.Digest == "" {
			continue
		}
		key := pinKey{evidence.AssetID, string(evidence.Kind), evidence.Subject}
		want, pinned := approved[key]
		ruleID := ""
		switch {
		case pinned && want != evidence.Digest && enabled["pin-mismatch"]:
			ruleID = "pin-mismatch"
		case !pinned && enabled["unpinned"]:
			ruleID = "unpinned"
		}
		if ruleID == "" || emitted[ruleID+"\x00"+evidence.AssetID] {
			continue
		}
		asset, present := assets[evidence.AssetID]
		if !present {
			continue
		}
		emitted[ruleID+"\x00"+evidence.AssetID] = true
		violations = append(violations, Violation{RuleID: ruleID, Level: 5, AssetID: asset.ID, AssetType: string(asset.Type), AssetName: asset.Name, Host: asset.Source})
	}
	return violations
}
