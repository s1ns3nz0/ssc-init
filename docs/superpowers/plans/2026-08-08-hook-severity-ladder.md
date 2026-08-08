# Hook Severity Ladder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hook's undifferentiated grouped rows with a five-rung severity ladder, and stop cache provenance from generating fictional change signals.

**Architecture:** Task 1 removes cache metadata from evidence diffing in `internal/inventory` (one point, fixes every consumer). Tasks 2–3 rewrite `internal/report/hook.go` as a rung classifier that stays a pure function of `(inventory, delta)`. Task 4 reuses the same renderer for `scan --baseline --pretty`. Task 5 updates acceptance fixtures, README, and the two now-false spec sentences.

**Tech Stack:** Go stdlib only. Design: `docs/superpowers/specs/2026-08-08-hook-severity-ladder-design.md`.

Conventions (every task): strict TDD; after GREEN run `go vet ./...`, `gofmt -l` on touched dirs, `git diff --check`; commit messages end with the trailer `Claude-Session: https://claude.ai/code/session_01YCnH78bwuqahh8qmL5wpu6`. Do not run `go test ./scripts` before committing (clean-tree gate).

---

### Task 1: Cache provenance stops being a change signal

**Files:**
- Modify: `internal/inventory/graph.go` (`canonicalEvidence`, around line 245)
- Modify: `internal/inventory/graph_test.go`
- Modify: `internal/acceptance/usecase_matrix_test.go` (`TestV3BaselineReopenStatusCacheWarmRescanAndObservedLocationDelta`, around line 760)

**Why:** `canonicalEvidence` marshals the whole record including `Metadata{cache: hit|miss}`. Because the cache key embeds size/mtime/ctime, any changed file misses on the run that first sees it and hits on the next, so every content change emits a second, contentless `changed` entry — forever, not once.

- [ ] **Step 1: Write the failing test**

Add to `internal/inventory/graph_test.go`:

```go
func TestDiffIgnoresEvidenceCacheProvenance(t *testing.T) {
	base := model.ContentEvidence{
		ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0",
		ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256,
		Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidenceComplete,
		Algorithm: "sha256", Digest: "abc", Size: 10,
		Metadata: map[string]string{"cache": "miss", "completeness": "complete"},
	}
	warmed := base
	warmed.Metadata = map[string]string{"cache": "hit", "completeness": "complete"}

	previous := model.Inventory{Evidence: []model.ContentEvidence{base}}
	current := model.Inventory{Evidence: []model.ContentEvidence{warmed}}
	if delta := Diff(previous, current); len(delta.Changes) != 0 {
		t.Fatalf("cache provenance produced drift: %+v", delta.Changes)
	}

	// A real content change must still be reported, even while cache flips.
	mutated := warmed
	mutated.Digest = "def"
	if delta := Diff(previous, model.Inventory{Evidence: []model.ContentEvidence{mutated}}); len(delta.Changes) != 1 ||
		delta.Changes[0].Kind != model.ChangeChanged || delta.Changes[0].Entity != model.ChangeEntityEvidence {
		t.Fatalf("digest change not reported: %+v", delta.Changes)
	}

	// Every other metadata key must remain a change signal.
	relabelled := warmed
	relabelled.Metadata = map[string]string{"cache": "hit", "completeness": "observed-subset"}
	if delta := Diff(previous, model.Inventory{Evidence: []model.ContentEvidence{relabelled}}); len(delta.Changes) != 1 {
		t.Fatalf("completeness change not reported: %+v", delta.Changes)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/inventory -run TestDiffIgnoresEvidenceCacheProvenance -count=1`

Expected: FAIL on the first assertion — `cache provenance produced drift: [{Kind:changed Entity:evidence ...}]`.

- [ ] **Step 3: Implement**

Replace `canonicalEvidence` in `internal/inventory/graph.go`:

```go
// canonicalEvidence excludes cache provenance the same way canonicalAssetForDiff
// excludes observation timestamps: the cache outcome describes how this run
// obtained the digest, not what the content is. Including it made every content
// change echo on the following run, when the newly-written cache entry hits.
func canonicalEvidence(evidence model.ContentEvidence) []byte {
	if len(evidence.Metadata) > 0 {
		metadata := make(map[string]string, len(evidence.Metadata))
		for key, value := range evidence.Metadata {
			if key != model.MetadataCache {
				metadata[key] = value
			}
		}
		evidence.Metadata = metadata
		if len(metadata) == 0 {
			evidence.Metadata = nil
		}
	}
	canonical, _ := json.Marshal(evidence)
	return canonical
}
```

If `model.MetadataCache` does not exist, first locate the literal used by
`internal/evidence/session.go` (grep for `metadataCache`) and export a constant
in `internal/model` beside the other metadata key constants, then use it in both
places. Do not duplicate a bare `"cache"` string literal across packages.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/inventory -count=1`

Expected: PASS.

- [ ] **Step 5: Update the acceptance test this intentionally changes**

`TestV3BaselineReopenStatusCacheWarmRescanAndObservedLocationDelta`
(`internal/acceptance/usecase_matrix_test.go:760`) asserts an exact cache-warm
delta that no longer occurs. Rewrite that assertion: the second, unmodified
rescan must now produce **zero** changes. Rename the test to
`TestV3BaselineReopenStatusQuiescentRescanAndObservedLocationDelta`. Keep the
observed-location half of the test unchanged.

Run: `go test ./internal/acceptance -count=1` and fix any other fixture that
asserted the echo. Do not weaken assertions that check real content changes.

- [ ] **Step 6: Full regression**

Run: `go test ./... -count=1` (the `scripts` clean-tree failure is expected pre-commit)

Run: `go test -race ./internal/inventory ./internal/acceptance ./internal/scan -count=1`

Expected: PASS apart from the noted `scripts` gate.

- [ ] **Step 7: Commit**

```bash
git add internal/inventory internal/acceptance
git commit -m "fix: exclude cache provenance from evidence diffing"
```

---

### Task 2: Rung classification

**Files:**
- Create: `internal/report/rung.go`
- Create: `internal/report/rung_test.go`

Pure classification, no rendering — rendering is Task 3. Keeping them apart
keeps each file small and lets the classifier be tested exhaustively.

- [ ] **Step 1: Write the failing test**

Create `internal/report/rung_test.go`:

```go
package report

import (
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestClassifyPairsUpgradesAndRanksRungs(t *testing.T) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"},
			{ID: "ide-extension:vscode:big@1.0.0", Type: model.AssetIDEExtension, Name: "big", Version: "1.0.0", Source: "vscode"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-skill:claude:docx"},
			{ID: "observation:sha256:2222", AssetID: "ide-extension:vscode:big@1.0.0"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete},
			{ID: "evidence:sha256:bbbb", ObservationID: "observation:sha256:2222", Status: model.EvidenceOversize},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:cursor:stale"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:orphan"},
	}}

	got := classify(inventory, delta)
	want := []rungRow{
		{Rung: rungNew, Type: "mcp-server", Name: "github", Host: "claude-code"},
		{Rung: rungChanged, Type: "agent-skill", Name: "docx", Host: "claude"},
		{Rung: rungUnverified, Type: "ide-extension", Name: "big", Host: "vscode"},
		{Rung: rungUpgraded, Type: "agent-plugin", Name: "superpowers", Host: "claude", From: "6.1.1", To: "6.2.0"},
		{Rung: rungRemoved, Type: "mcp-server", Name: "stale", Host: "cursor"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v\nwant=%+v", got, want)
	}
}

func TestClassifyKeepsHighestRungPerAsset(t *testing.T) {
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0"}},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete},
			{ID: "evidence:sha256:bbbb", ObservationID: "observation:sha256:1111", Status: model.EvidencePartial},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
	}}
	got := classify(inventory, delta)
	if len(got) != 1 || got[0].Rung != rungChanged {
		t.Fatalf("expected one CHANGED row, got=%+v", got)
	}
}

func TestParseAssetIDHandlesRealWorldForms(t *testing.T) {
	for _, test := range []struct{ id, wantType, wantHost, wantName, wantVersion string }{
		{"agent-plugin:claude:superpowers@6.2.0", "agent-plugin", "claude", "superpowers", "6.2.0"},
		{"agent-skill:claude:docx", "agent-skill", "claude", "docx", ""},
		{"ide-extension:vscode:usernamehw.errorlens@3.16.0", "ide-extension", "vscode", "usernamehw.errorlens", "3.16.0"},
		{"pkg:pypi/moto@5.1.22", "pkg", "", "pypi/moto", "5.1.22"},
		{"mcp:claude-code:@scope/server@1.0.0", "mcp", "claude-code", "@scope/server", "1.0.0"},
		{"opaque", "", "", "opaque", ""},
	} {
		gotType, gotHost, gotName, gotVersion := parseAssetID(test.id)
		if gotType != test.wantType || gotHost != test.wantHost || gotName != test.wantName || gotVersion != test.wantVersion {
			t.Fatalf("id=%q got=(%q,%q,%q,%q) want=(%q,%q,%q,%q)", test.id,
				gotType, gotHost, gotName, gotVersion, test.wantType, test.wantHost, test.wantName, test.wantVersion)
		}
	}
}

func TestClassifyIsEmptyForEmptyDelta(t *testing.T) {
	if rows := classify(model.Inventory{}, model.Delta{}); len(rows) != 0 {
		t.Fatalf("rows=%+v", rows)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/report -run 'TestClassify|TestParseAssetID' -count=1`

Expected: FAIL — `undefined: classify`, `undefined: rungRow`, `undefined: parseAssetID`.

- [ ] **Step 3: Implement**

Create `internal/report/rung.go`:

```go
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/report -count=1 && go test ./internal/report -run 'TestClassify|TestParseAssetID' -count=50`

Expected: PASS both (the 50x run proves map iteration cannot reorder rows).

- [ ] **Step 5: Commit**

```bash
git add internal/report/rung.go internal/report/rung_test.go
git commit -m "feat: classify delta changes into severity rungs"
```

---

### Task 3: Render the ladder in the hook

**Files:**
- Modify: `internal/report/hook.go` (replace the grouping body of `WriteHookSummary`)
- Modify: `internal/report/hook_test.go`

- [ ] **Step 1: Write the failing test**

Replace the body assertions in `internal/report/hook_test.go` — keep
`TestWriteHookSummaryIsSilentOnEmptyDelta` exactly as it is, and replace the
other two tests with:

```go
func TestWriteHookSummaryRendersLadder(t *testing.T) {
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"}},
		Observations: []model.Observation{{ID: "observation:sha256:1111", AssetID: "agent-skill:claude:docx"}},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", ObservationID: "observation:sha256:1111", Status: model.EvidenceComplete, Digest: strings.Repeat("a", 64)},
			{ID: "evidence:sha256:cccc", ObservationID: "observation:sha256:1111", Status: model.EvidenceOversize},
			{ID: "evidence:sha256:dddd", ObservationID: "observation:sha256:1111", Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "mcp-server:claude-code:github"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.2.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:superpowers@6.1.1"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}}

	var first, second bytes.Buffer
	if err := report.WriteHookSummary(&first, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteHookSummary(&second, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("not deterministic:\n%q\n%q", first.String(), second.String())
	}
	output := first.String()
	for _, pattern := range []string{
		`^ssc-init: 3 changes since last snapshot\n`,
		`(?m)^  NEW\s+mcp-server\s+github \(claude-code\)$`,
		`(?m)^  CHANGED\s+agent-skill\s+docx \(claude\)$`,
		`(?m)^  UPGRADED\s+agent-plugin\s+superpowers \(claude\)\s+6\.1\.1 → 6\.2\.0$`,
		`(?m)^  1 targets unverified \(standing — run: ssc-init status --pretty\)$`,
	} {
		if !regexp.MustCompile(pattern).MatchString(output) {
			t.Fatalf("missing %q in:\n%s", pattern, output)
		}
	}
	if strings.Contains(output, strings.Repeat("a", 64)) || strings.Contains(output, "evidence records") {
		t.Fatalf("leaked digest or legacy grouping:\n%s", output)
	}
}

func TestWriteHookSummaryReportsInitialBaselineWithoutRungs(t *testing.T) {
	inventory := model.Inventory{
		Assets:   []model.Asset{{ID: "agent-skill:claude:docx", Type: model.AssetSkill, Name: "docx", Source: "claude"}},
		Evidence: []model.ContentEvidence{{ID: "evidence:sha256:aaaa", Status: model.EvidenceComplete}},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-skill:claude:docx"},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
	}}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !strings.Contains(output, "initial baseline recorded — 1 assets, 1 evidence records, 0 unverified") {
		t.Fatalf("initial baseline line missing:\n%s", output)
	}
	if strings.Contains(output, "NEW") {
		t.Fatalf("initial baseline must not print rungs:\n%s", output)
	}
}

func TestWriteHookSummaryCapsDetailRows(t *testing.T) {
	var delta model.Delta
	for index := 0; index < 25; index++ {
		delta.Changes = append(delta.Changes,
			model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset,
				EntityID: "agent-skill:claude:" + string(rune('a'+index))},
			model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset,
				EntityID: "mcp-server:cursor:" + string(rune('a'+index))})
	}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, model.Inventory{Assets: []model.Asset{{ID: "x"}}}, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if got := strings.Count(output, "\n  NEW"); got != 20 {
		t.Fatalf("NEW rows=%d want 20 (cap must favour the highest rung):\n%s", got, output)
	}
	if strings.Contains(output, "REMOVED") || !strings.Contains(output, "…and 30 more changes") {
		t.Fatalf("cap did not prefer high rungs:\n%s", output)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/report -run TestWriteHookSummary -count=1`

Expected: FAIL — the current renderer emits `changed N evidence records (…)` and no rung labels.

- [ ] **Step 3: Implement**

Rewrite `WriteHookSummary` in `internal/report/hook.go` to use `classify`.
Delete the old grouping helpers that become unused (`groupKey` and its loops);
keep `hookIssuesLine`'s counting logic but re-word it per the design.

```go
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
		line := fmt.Sprintf("  %-10s %-13s %s", rungLabels[row.Rung], row.Type, row.Name)
		if row.Host != "" {
			line += fmt.Sprintf(" (%s)", row.Host)
		}
		if row.Rung == rungUpgraded {
			line += fmt.Sprintf("  %s → %s", row.From, row.To)
		}
		printer.line(line)
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/report -count=1 && go test -race ./internal/report -count=1 && go test ./internal/report -run TestWriteHookSummary -count=50`

Expected: PASS all three.

- [ ] **Step 5: Commit**

```bash
git add internal/report/hook.go internal/report/hook_test.go
git commit -m "feat: render hook drift as a severity ladder"
```

---

### Task 4: Same ladder in `scan --baseline --pretty`

**Files:**
- Modify: `internal/report/pretty.go` (`deltaSummary`)
- Modify: `internal/report/pretty_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/report/pretty_test.go`:

```go
func TestWritePrettyRendersDeltaAsLadderAndAlwaysPrintsIt(t *testing.T) {
	scan, inventory, delta := prettyFixture()
	var buffer bytes.Buffer
	if err := report.WritePretty(&buffer, scan, inventory, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if !regexp.MustCompile(`(?m)^DELTA$`).MatchString(output) ||
		!regexp.MustCompile(`(?m)^  NEW\s+ide-extension\s+bravo \(vscode\)$`).MatchString(output) {
		t.Fatalf("delta ladder missing:\n%s", output)
	}
	if regexp.MustCompile(`added=\d+`).MatchString(output) {
		t.Fatalf("bare delta counts still rendered:\n%s", output)
	}

	// Unlike the hook, an interactive scan states "no changes" explicitly.
	var quiet bytes.Buffer
	if err := report.WritePretty(&quiet, scan, inventory, model.Delta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quiet.String(), "DELTA\n  (no changes)") {
		t.Fatalf("quiet delta must say so:\n%s", quiet.String())
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/report -run TestWritePrettyRendersDeltaAsLadder -count=1`

Expected: FAIL — output still contains `DELTA  added=1 changed=1 removed=0`.

- [ ] **Step 3: Implement**

Replace `deltaSummary` in `internal/report/pretty.go`:

```go
func (p *prettyPrinter) deltaSummary(inventory model.Inventory, delta model.Delta) {
	p.line("")
	p.line("DELTA")
	rows := classify(inventory, delta)
	if len(rows) == 0 {
		p.line("  (no changes)")
		return
	}
	for _, row := range rows {
		line := fmt.Sprintf("  %-10s %-13s %s", rungLabels[row.Rung], row.Type, row.Name)
		if row.Host != "" {
			line += fmt.Sprintf(" (%s)", row.Host)
		}
		if row.Rung == rungUpgraded {
			line += fmt.Sprintf("  %s → %s", row.From, row.To)
		}
		p.line(line)
	}
}
```

Update its single call site in `WritePretty` to pass `inventory`. Note the
scan view is **not** capped: it is an interactive command, not a session
interrupt.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/report ./internal/cli -count=1`

Expected: PASS. Fix any pretty golden assertions that pinned the old
`DELTA  added=…` line.

- [ ] **Step 5: Commit**

```bash
git add internal/report/pretty.go internal/report/pretty_test.go
git commit -m "feat: render scan delta as a severity ladder"
```

---

### Task 5: Acceptance, README, and spec corrections

**Files:**
- Modify: `internal/acceptance/hook_test.go`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-08-hook-command-design.md`
- Modify: `docs/superpowers/specs/2026-08-07-local-content-evidence-core-design.md`

- [ ] **Step 1: Update the acceptance lifecycle test**

`TestHookLifecycleFirstDriftThenCacheWarmThenSilent` encodes behaviour that
Task 1 deletes. Rename it to `TestHookLifecycleInitialBaselineThenSilent` and
change its three runs to assert:

- run 1: exit 0, stdout contains `initial baseline recorded` and **no** rung labels;
- run 2: exit 0, stdout **exactly empty** (the cache echo is gone as of Task 1);
- run 3: exit 0, stdout exactly empty.

Then add a fourth phase to the same test: mutate the plugin payload file, run
again, and assert exit 0 with stdout matching `^  CHANGED\s+agent-plugin` and
containing no 64-hex digest and no home path; then run once more and assert
stdout is exactly empty (proving the echo is gone).

Delete the now-unused `hookCacheWarmLine` regexp.

- [ ] **Step 2: Run it to verify it fails, then passes**

Run: `go test ./internal/acceptance -run TestHookLifecycle -count=1`

Expected before Tasks 1–3 are in the branch: FAIL. With them: PASS. Then run
`-count=20` for stability.

- [ ] **Step 3: Correct README**

In `README.md`, replace the hook paragraph's silence claim. It currently says
the hook stays "completely silent when nothing changed", which was false under
the echo and is now true — but the paragraph must also describe the ladder.
State: the hook prints one line per changed asset, tagged `NEW`, `CHANGED`,
`UNVERIFIED`, `UPGRADED`, or `REMOVED`; that these describe what changed and
how well it could be verified, **not** whether anything is safe; that it stays
silent when nothing changed; and that it always exits zero except for invalid
arguments.

- [ ] **Step 4: Correct the two false spec sentences**

In `docs/superpowers/specs/2026-08-08-hook-command-design.md`, replace the
"collapsing the one-time cache-warm flood" phrasing and the §Testing item 4
three-run expectation, pointing both at the severity ladder design document.

In `docs/superpowers/specs/2026-08-07-local-content-evidence-core-design.md`
§6.1, correct "excludes only explicit observation timestamps" to also name
cache provenance.

- [ ] **Step 5: Full verification**

Run: `go clean -testcache && go test -race -count=1 ./...`

Run: `go vet ./...` and `git diff --check`

Expected: all pass except the `scripts` clean-tree gate, which must pass after
the commit in Step 6.

- [ ] **Step 6: Commit**

```bash
git add internal/acceptance/hook_test.go README.md docs/superpowers/specs
git commit -m "test: lock severity ladder lifecycle and correct docs"
```

Then run `go test ./scripts -count=1` and confirm it passes on the clean tree.
