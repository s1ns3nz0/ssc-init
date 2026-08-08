package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// rung ranks a change by what the tool established about it. No rung expresses
// a safety verdict: SSC Init hashes bytes and analyses nothing.
type rung int

const (
	rungNew rung = iota
	rungChanged
	rungUnverified
	rungUpgraded
	rungRemoved
)

var rungLabels = map[rung]string{
	rungNew:        "NEW",
	rungChanged:    "CHANGED",
	rungUnverified: "UNVERIFIED",
	rungUpgraded:   "UPGRADED",
	rungRemoved:    "REMOVED",
}

// rungRow is one rendered line: one asset, its highest rung.
type rungRow struct {
	Rung     rung
	Type     string
	Name     string
	Host     string
	From, To string
}

// render returns the display line for one row, without the leading indent. It
// is the single format both the hook and the pretty ladder print; only the
// hook caps how many rows reach it.
func (row rungRow) render() string {
	line := fmt.Sprintf("%-10s %-13s %s", rungLabels[row.Rung], row.Type, row.Name)
	if row.Host != "" {
		line += fmt.Sprintf(" (%s)", row.Host)
	}
	if row.Rung == rungUpgraded {
		line += fmt.Sprintf("  %s → %s", row.From, row.To)
	}
	return line
}

// versionedAssetTypes is the closed set of asset-ID prefixes that append
// "@<version>": agents (when a version is known), IDE extensions and packages.
// The mcp, project and project-config prefixes never do, and their names may
// contain "@" ("ctx@prod"), so splitting a version out of those IDs would
// invent a version transition between two unrelated assets.
var versionedAssetTypes = map[string]struct{}{
	"agent-plugin":  {},
	"agent-skill":   {},
	"ide-extension": {},
	"pkg":           {},
}

// digestSegment matches the digest of an anchored ID ("project:sha256:<hex>").
// Such an ID carries no readable name, and a digest is never printed.
var digestSegment = regexp.MustCompile(`^[0-9a-f]{64}$`)

// unnamedAsset stands in for an asset whose name cannot be recovered: a
// digest-anchored ID that is gone from the current inventory.
const unnamedAsset = "(unnamed)"

// parseAssetID splits "<type>:<host>:<name>[@<version>]" into the parts that
// identify an asset across snapshots. Package IDs carry no host
// ("pkg:pypi/moto@5.1.22"); names may contain "@" (npm scopes), so the version
// splits on the last "@" — and only for prefixes that carry one at all.
func parseAssetID(id string) (assetType, host, name, version string) {
	parts := strings.SplitN(id, ":", 3)
	switch len(parts) {
	case 3:
		assetType, host, name = parts[0], parts[1], parts[2]
	case 2:
		assetType, name = parts[0], parts[1]
	default:
		name = id
	}
	if _, versioned := versionedAssetTypes[assetType]; versioned {
		if at := strings.LastIndex(name, "@"); at > 0 {
			name, version = name[:at], name[at+1:]
		}
	}
	return assetType, host, name, version
}

// displayFor resolves the columns a row prints. The inventory is the only
// place a digest-anchored asset has a readable name, so a present asset is
// described by its record. A removed asset is absent from the current
// inventory by definition and falls back to its ID, which for a digest-
// anchored form yields no name rather than a digest.
func displayFor(assets map[string]model.Asset, id string) (assetType, name, host string) {
	if asset, present := assets[id]; present {
		return string(asset.Type), asset.Name, asset.Source
	}
	assetType, host, name, _ = parseAssetID(id)
	if digestSegment.MatchString(name) {
		return assetType, unnamedAsset, ""
	}
	return assetType, name, host
}

// assetIdentity pairs an added asset with its removed predecessor. It stays
// derived from the full asset ID: substituting display names would collapse
// every digest-anchored project into a single identity.
type assetIdentity struct{ assetType, host, name string }

// assetChange records what an added or removed asset contributes to its row.
type assetChange struct{ id, version string }

// classify turns a delta into at most one row per asset, highest rung winning.
// It is a pure function of the current inventory and the delta: no previous
// inventory is consulted, so UNVERIFIED is approximate by design (see the
// severity ladder design document).
func classify(inventory model.Inventory, delta model.Delta) []rungRow {
	observationAsset := make(map[string]string, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		observationAsset[observation.ID] = observation.AssetID
	}
	evidenceAsset := make(map[string]string, len(inventory.Evidence))
	evidenceStatus := make(map[string]model.EvidenceStatus, len(inventory.Evidence))
	for _, evidence := range inventory.Evidence {
		assetID := evidence.AssetID
		if assetID == "" {
			assetID = observationAsset[evidence.ObservationID]
		}
		evidenceAsset[evidence.ID] = assetID
		evidenceStatus[evidence.ID] = evidence.Status
	}

	assets := make(map[string]model.Asset, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assets[asset.ID] = asset
	}

	added := make(map[assetIdentity]assetChange)
	removed := make(map[assetIdentity]assetChange)
	best := make(map[assetIdentity]rungRow)

	note := func(identity assetIdentity, row rungRow) {
		if existing, ok := best[identity]; !ok || row.Rung < existing.Rung {
			best[identity] = row
		}
	}

	for _, change := range delta.Changes {
		switch change.Entity {
		case model.ChangeEntityAsset:
			assetType, host, name, version := parseAssetID(change.EntityID)
			identity := assetIdentity{assetType, host, name}
			switch change.Kind {
			case model.ChangeAdded:
				added[identity] = assetChange{id: change.EntityID, version: version}
			case model.ChangeRemoved:
				removed[identity] = assetChange{id: change.EntityID, version: version}
			case model.ChangeChanged:
				displayType, displayName, displayHost := displayFor(assets, change.EntityID)
				note(identity, rungRow{Rung: rungChanged, Type: displayType, Name: displayName, Host: displayHost})
			}
		case model.ChangeEntityEvidence, model.ChangeEntityObservation:
			if change.Kind == model.ChangeRemoved {
				continue // rolls into its asset's UPGRADED/REMOVED row, or is an orphan
			}
			assetID := observationAsset[change.EntityID]
			status := model.EvidenceComplete
			if change.Entity == model.ChangeEntityEvidence {
				assetID = evidenceAsset[change.EntityID]
				status = evidenceStatus[change.EntityID]
			}
			if assetID == "" {
				continue // unattributable: no actionable line (see design doc)
			}
			assetType, host, name, _ := parseAssetID(assetID)
			identity := assetIdentity{assetType, host, name}
			level := rungChanged
			if status != model.EvidenceComplete {
				level = rungUnverified
			}
			displayType, displayName, displayHost := displayFor(assets, assetID)
			note(identity, rungRow{Rung: level, Type: displayType, Name: displayName, Host: displayHost})
		}
	}

	for identity, addition := range added {
		displayType, displayName, displayHost := displayFor(assets, addition.id)
		row := rungRow{Rung: rungNew, Type: displayType, Name: displayName, Host: displayHost}
		if removal, paired := removed[identity]; paired {
			row.Rung, row.From, row.To = rungUpgraded, removal.version, addition.version
			delete(removed, identity)
		}
		best[identity] = row // an asset-level event outranks any of its records
	}
	for identity, removal := range removed {
		displayType, displayName, displayHost := displayFor(assets, removal.id)
		best[identity] = rungRow{Rung: rungRemoved, Type: displayType, Name: displayName, Host: displayHost, From: removal.version}
	}

	rows := make([]rungRow, 0, len(best))
	for _, row := range best {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(a, b int) bool {
		if rows[a].Rung != rows[b].Rung {
			return rows[a].Rung < rows[b].Rung
		}
		if rows[a].Type != rows[b].Type {
			return rows[a].Type < rows[b].Type
		}
		if rows[a].Name != rows[b].Name {
			return rows[a].Name < rows[b].Name
		}
		return rows[a].Host < rows[b].Host
	})
	return rows
}
