package report

import (
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

// parseAssetID splits "<type>:<host>:<name>[@<version>]". Package IDs carry no
// host ("pkg:pypi/moto@5.1.22"); names may contain "@" (npm scopes), so the
// version splits on the last "@".
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
	if at := strings.LastIndex(name, "@"); at > 0 {
		name, version = name[:at], name[at+1:]
	}
	return assetType, host, name, version
}

type assetIdentity struct{ assetType, host, name string }

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

	added := make(map[assetIdentity]string)
	removed := make(map[assetIdentity]string)
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
				added[identity] = version
			case model.ChangeRemoved:
				removed[identity] = version
			case model.ChangeChanged:
				note(identity, rungRow{Rung: rungChanged, Type: assetType, Name: name, Host: host})
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
			note(identity, rungRow{Rung: level, Type: assetType, Name: name, Host: host})
		}
	}

	for identity, toVersion := range added {
		row := rungRow{Rung: rungNew, Type: identity.assetType, Name: identity.name, Host: identity.host}
		if fromVersion, paired := removed[identity]; paired {
			row = rungRow{Rung: rungUpgraded, Type: identity.assetType, Name: identity.name, Host: identity.host, From: fromVersion, To: toVersion}
			delete(removed, identity)
		}
		best[identity] = row // an asset-level event outranks any of its records
	}
	for identity, fromVersion := range removed {
		best[identity] = rungRow{Rung: rungRemoved, Type: identity.assetType, Name: identity.name, Host: identity.host, From: fromVersion}
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
