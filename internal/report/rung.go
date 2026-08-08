package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// rung ranks a change by what the tool established about it. A rung states what
// changed and how well it could be verified, never whether anything is safe.
// This build performs no content analysis and has no threat intelligence, so it
// has no basis for a risk claim.
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

// rungRow is one rendered line: one asset, its highest rung. key is the asset
// ID the row describes; it is never rendered and exists only to make the row
// order total (see the comparator in classify).
type rungRow struct {
	key      string
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

// assetTypeByIDPrefix maps an asset-ID prefix to the model.AssetType its
// collector records. Several prefixes are finer-grained than the type
// ("project-config" and "project" are both model.AssetProject), and two spell
// it differently ("mcp"/"pkg"). A removed asset is gone from the inventory, so
// its row is built from the ID alone: without this map the TYPE column would
// print one vocabulary for removals and another for every other rung. An
// unrecognised prefix is printed verbatim rather than guessed at.
var assetTypeByIDPrefix = map[string]string{
	"agent-plugin":    string(model.AssetAgentPlugin),
	"agent-skill":     string(model.AssetSkill),
	"ide-extension":   string(model.AssetIDEExtension),
	"mcp":             string(model.AssetMCP),
	"pkg":             string(model.AssetPackage),
	"project":         string(model.AssetProject),
	"project-config":  string(model.AssetProject),
	"tool":            string(model.AssetTool),
	"tool-executable": string(model.AssetTool),
}

// parseAssetID splits "<type>:<host>:<name>[@<version>]" into the parts that
// identify an asset across snapshots. Package IDs carry no host
// ("pkg:pypi/moto@5.1.22"). Every versioned prefix escapes "@" out of the name
// (percent-encoding for pkg, outright rejection for the rest), so a versioned
// ID holds exactly one literal "@" and splitting on the last one is the same
// as splitting on the first.
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
// anchored form yields no name rather than a digest. Its ID prefix is mapped
// back to the asset type so both branches print one vocabulary.
func displayFor(assets map[string]model.Asset, id string) (assetType, name, host string) {
	if asset, present := assets[id]; present {
		return string(asset.Type), asset.Name, asset.Source
	}
	assetType, host, name, _ = parseAssetID(id)
	if mapped, known := assetTypeByIDPrefix[assetType]; known {
		assetType = mapped
	}
	if digestSegment.MatchString(name) {
		return assetType, unnamedAsset, ""
	}
	return assetType, name, host
}

// assetIdentity pairs an added asset with its removed predecessor. It stays
// derived from the full asset ID: substituting display names would collapse
// every digest-anchored project into a single identity.
//
// An identity is not an asset. Every family that appends "@<version>" keeps the
// version in the ID and out of the identity, so one identity legitimately
// covers several live assets — ~/.vscode/extensions holds a directory per
// installed version and stale ones are routinely left behind. Identity is used
// for the pairing decision only; rows are always keyed by asset ID.
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

	added := make(map[assetIdentity][]assetChange)
	removed := make(map[assetIdentity][]assetChange)
	addedAssets := make(map[string]struct{})
	best := make(map[string]rungRow)

	// note keeps the highest rung per asset ID. Keying it by identity instead
	// would let one live version of an extension silence another's row.
	note := func(assetID string, row rungRow) {
		if existing, ok := best[assetID]; !ok || row.Rung < existing.Rung {
			best[assetID] = row
		}
	}

	// Asset-level changes are collected first: whether a record belongs to an
	// asset that is itself new decides what that record is allowed to claim.
	for _, change := range delta.Changes {
		if change.Entity != model.ChangeEntityAsset {
			continue
		}
		assetType, host, name, version := parseAssetID(change.EntityID)
		identity := assetIdentity{assetType, host, name}
		switch change.Kind {
		case model.ChangeAdded:
			added[identity] = append(added[identity], assetChange{id: change.EntityID, version: version})
			addedAssets[change.EntityID] = struct{}{}
		case model.ChangeRemoved:
			removed[identity] = append(removed[identity], assetChange{id: change.EntityID, version: version})
		case model.ChangeChanged:
			displayType, displayName, displayHost := displayFor(assets, change.EntityID)
			note(change.EntityID, rungRow{key: change.EntityID, Rung: rungChanged, Type: displayType, Name: displayName, Host: displayHost})
		}
	}

	for _, change := range delta.Changes {
		switch change.Entity {
		case model.ChangeEntityEvidence, model.ChangeEntityObservation:
		default:
			continue
		}
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
		level := rungChanged
		// Unsupported is a deliberate non-claim (package payloads, container
		// identities), not a coverage gap — the same exclusion standingUnverified
		// and the pretty ISSUES table already make.
		if status != model.EvidenceComplete && status != model.EvidenceUnsupported {
			level = rungUnverified
		}
		// An upgrade mints a new asset ID and therefore new observation and
		// evidence IDs, so every record of an added asset arrives as added.
		// Such a record is part of that asset-level event, not a separate
		// CHANGED claim — CHANGED means "same version, different bytes", which
		// a new asset ID contradicts. A record that could not be fully hashed
		// still speaks: UNVERIFIED reports a gap the asset-level rung cannot.
		// The test is the record's own asset, not its identity: a sibling
		// version being installed says nothing about this asset's bytes.
		if _, isAddedAsset := addedAssets[assetID]; isAddedAsset && level == rungChanged {
			continue
		}
		displayType, displayName, displayHost := displayFor(assets, assetID)
		note(assetID, rungRow{key: assetID, Rung: level, Type: displayType, Name: displayName, Host: displayHost})
	}

	for identity, additions := range added {
		// A transition is only reported when the tool established it, which
		// takes exactly one addition against exactly one removal, both carrying
		// a version.
		//
		// Both endpoints must be known: the agents collector appends
		// "@<version>" only when a version is known, so a plugin that gains or
		// loses its manifest version field yields two genuine assets under one
		// identity with one version between them, and an arrow with nothing on
		// one side asserts a move that was never established.
		//
		// The multiplicity must be one to one for the same reason: with two
		// removals and one addition there is no single established transition,
		// and choosing a predecessor by string order would be an unearned
		// claim. Every candidate is then reported as the event it is.
		removals := removed[identity]
		if len(additions) == 1 && len(removals) == 1 && additions[0].version != "" && removals[0].version != "" {
			displayType, displayName, displayHost := displayFor(assets, additions[0].id)
			note(additions[0].id, rungRow{key: additions[0].id, Rung: rungUpgraded, Type: displayType,
				Name: displayName, Host: displayHost, From: removals[0].version, To: additions[0].version})
			delete(removed, identity)
			continue
		}
		for _, addition := range additions {
			displayType, displayName, displayHost := displayFor(assets, addition.id)
			// Highest rung wins, including over the asset's own records.
			note(addition.id, rungRow{key: addition.id, Rung: rungNew, Type: displayType, Name: displayName, Host: displayHost})
		}
	}

	rows := make([]rungRow, 0, len(best)+len(removed))
	for _, row := range best {
		rows = append(rows, row)
	}
	// A removed asset is absent from the current inventory by definition, so no
	// current record can belong to it and it never shares a row with one: when
	// its identity collides with a current asset's, the two are distinct assets
	// and each gets its own line. Two removals under one identity are likewise
	// two deleted surfaces and get two lines — dropping either would hide a
	// deletion, which is the one thing this report exists to show.
	for _, removals := range removed {
		for _, removal := range removals {
			displayType, displayName, displayHost := displayFor(assets, removal.id)
			rows = append(rows, rungRow{key: removal.id, Rung: rungRemoved, Type: displayType, Name: displayName, Host: displayHost, From: removal.version})
		}
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
		if rows[a].Host != rows[b].Host {
			return rows[a].Host < rows[b].Host
		}
		// Display columns are not unique: an IDE extension's Name drops the
		// publisher its ID keeps, and package rows carry no host. Two such rows
		// differ only in their versions, so without this the order came out of
		// map iteration and the report was not byte-identical run to run. The
		// key is the asset ID, unique per row, which makes the order total.
		return rows[a].key < rows[b].key
	})
	return rows
}
