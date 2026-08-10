# SSC Init Inventory Trust Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a truthful, lossless macOS inventory foundation with target-level coverage, scope-aware observations, current local MCP/plugin catalogs, opt-in external probes, and explicit non-Darwin rejection.

**Architecture:** Evolve the existing collector → inventory → SQLite → JSON pipeline in place. Collectors emit canonical assets plus per-location observations and target coverage; an ephemeral `json:"-"` handoff carries raw project config paths only within one scan. SQLite migration 4 stores v2 scope and observations while preserving v1 snapshots, and the standalone CLI remains a single static Go binary.

**Tech Stack:** Go 1.26.5, `os.Root`, `golang.org/x/sys/unix`, `modernc.org/sqlite`, pinned pure-Go `github.com/pelletier/go-toml/v2`, JSON/TOML fixtures, shell release checks.

## Global Constraints

- Supported operational platform: macOS only; Darwin `arm64` and `amd64` release artifacts are required.
- Distribution remains one dependency-free executable per architecture with `CGO_ENABLED=0`; no runtime, daemon, interpreter, or service installation is added.
- Scan schema becomes `ssc-init.scan.v2`; status schema becomes `ssc-init.status.v2`; migration-3 databases and v1 snapshots remain readable and are marked legacy.
- Default scan is passive: npm, pip, pipx, uv, Cargo, Go, Homebrew, and Docker commands execute only with `--external-probes`.
- No scan, fixture, or test may contact a real registry, marketplace, Docker daemon, SaaS endpoint, or the real user home.
- No raw credential, authorization header, environment value, secret-shaped identity, command stderr, or outside-home absolute path may be persisted.
- All filesystem reads, hashes, directory walks, command output, timeouts, symlink chains, target expansions, and concurrency remain bounded.
- A collector reports `complete` only when each applicable catalog target is `complete` or `not_present`; unsupported, unavailable, and partial targets force partial coverage.
- Implementation is TDD: observe RED before production code, run focused GREEN, run the full package regression, then commit each task.
- Do not merge, push, add release-distribution work, add TI, add policy, or add blocking behavior in this plan.

## File Structure

### New focused files

- `internal/model/observation.go` — observation, scope, target, catalog, and v2 delta contracts.
- `internal/privacy/sensitive.go` — shared high-confidence credential detection and redaction-placeholder semantics.
- `internal/privacy/sensitive_test.go` — parity vectors moved from store plus collector-facing cases.
- `internal/identity/observation.go` — safe location references, identity validation, canonical observation IDs.
- `internal/identity/observation_test.go` — deterministic ID, consumer ordering, outside-home reference, and quarantine tests.
- `internal/collector/coverage.go` — targeted-collector interface, catalog/result validation, target aggregation.
- `internal/collector/coverage_test.go` — missing, duplicate, unsupported, partial, and deterministic target cases.
- `internal/collector/projects/walk.go` — bounded fd-rooted project traversal and ephemeral MCP local-target emission.
- `internal/collector/projects/walk_test.go` — root/subtree symlink, identity-swap, depth, and entry-bound tests.
- `internal/collector/mcp/catalog.go` — immutable user/project/dynamic MCP target specifications.
- `internal/collector/mcp/parser_json.go` — strict JSON normalization and unknown server-field reporting.
- `internal/collector/mcp/parser_toml.go` — Codex TOML normalization using the pinned pure-Go parser.
- `internal/collector/mcp/parser_toml_test.go` — stdio, HTTP, secret omission, malformed, and unknown-field cases.
- `internal/collector/agents/catalog.go` and `manifest.go` — fixed agent targets and bounded recognized-marker parsing.
- `internal/collector/ide/catalog.go` — fixed IDE targets plus unsupported custom/dynamic surfaces.
- `internal/platform/executable.go` — bounded executable resolution, symlink-chain inspection, hash, and identity recheck.
- `internal/platform/executable_test.go` — regular file, symlink chain, loop, replacement, oversize, and secret-free evidence tests.
- `internal/platform/support.go` and `support_test.go` — explicit operational OS predicate and contract tests.
- `internal/cli/options.go` — exact command/flag parser for project roots and external probe opt-in.
- `internal/cli/options_test.go` — accepted permutations and rejected near-miss argument forms.
- `internal/acceptance/usecase_matrix_test.go` — isolated official-catalog, persistence, collision, and no-execution matrix.

### Existing files with changed responsibilities

- `internal/model/asset.go` and `internal/model/scan.go` — embed observations, target coverage, scope, local targets, and entity-aware changes.
- `internal/inventory/graph.go` — normalize observations without loss and diff both assets and observations.
- `internal/store/migrations.go` — apply and verify migration 4 including `scope_json`, observation tables/state/counts/FKs.
- `internal/store/snapshots.go` — atomic observation save/load and latest full-snapshot reads.
- `internal/store/validation.go` — validate observations/targets through shared privacy logic; retain store backstop.
- `internal/scan/service.go` — create v2 scope, consume ephemeral local targets, strip raw paths, and compare latest snapshot.
- `internal/report/json.go` — stable scan.v2 shape containing scope and observations.
- `internal/cli/run.go` — parsed scan options and status.v2 legacy provenance/coverage output.
- `cmd/ssc-init/main.go` — option-aware wiring, configured roots/probe mode, and early Darwin boundary.
- `internal/collector/projects/collector.go` — resolved roots, observations, target coverage, and rooted walker use.
- `internal/collector/mcp/collector.go` — catalog targets, JSON/TOML dispatch, observations, collision preservation, identity quarantine.
- `internal/collector/agents/collector.go` — bounded manifest-backed nested plugin/skill discovery; no container-as-plugin classification.
- `internal/collector/ide/collector.go` and `manifest.go` — per-root targets and per-install observations without local ID overwrite.
- `internal/collector/packages/collector.go` — default skip, inspected absolute executables, per-probe observations, collision preservation.
- `internal/platform/runner.go` — continue direct execution but receive already resolved absolute command paths.
- `README.md`, `docs/testing/2026-08-06-use-case-validation.md`, `testdata/home/**`, and acceptance tests — truthful scope, official fixtures, and executable-level evidence.

## Design Traceability

| Approved design requirement | Implemented by | Final proof |
|---|---|---|
| v2 observations, collision preservation, entity-aware delta | Tasks 1–3 | graph and delta tests |
| privacy extraction and identity quarantine | Task 2, then every collector task | privacy vectors plus hostile sibling acceptance |
| migration 4, v1 legacy reads, latest full snapshot | Task 4 | migration/corruption/reopen/status tests |
| immutable target catalog and truthful aggregation | Task 5 | target-contract table plus full catalog matrix |
| declared project roots and non-persisted raw handoff | Task 6–7 | hostile rooted-walk and leak assertions |
| official MCP JSON/TOML targets | Tasks 7–8 | every section-8 fixture and parser matrix |
| manifest-backed agent and fixed IDE catalogs | Tasks 9–10 | container-negative and duplicate-occurrence tests |
| default-disabled package/Docker execution and executable evidence | Task 11 | fail-on-call default plus inspected opt-in tests |
| explicit macOS operational boundary | Task 12 | non-Darwin no-state tests and Linux compile guard |
| truthful public claims, builds, and independent review | Task 13 | full race/vet/module/build/checksum/review gates |

Content-tree hashing, immutable Docker digest proof, TI, Git-managed policy, organization integrations, host adapters, warning UX, and blocking are deliberately absent; the design assigns them to later programs after this inventory foundation is verified.

---

### Task 1: Add the v2 model contracts without changing collection behavior

**Files:**
- Create: `internal/model/observation.go`
- Modify: `internal/model/scan.go`
- Modify: `internal/inventory/graph.go`
- Test: `internal/inventory/graph_test.go`

**Interfaces:**
- Produces: `model.Observation`, `model.ObservationScope`, `model.TargetSpec`, `model.TargetCoverage`, `model.TargetStatus`, `model.TargetMethod`, `model.ScanScope`, `model.LocalTarget`, `model.ChangeEntity`.
- Produces: optional `Targets`, `Observations`, `LocalTargets`, and `Scope` fields used by every later task.
- Preserves: current asset-only diff semantics until Task 3 adds observation comparison.

- [ ] **Step 1: Write the failing v2 model and asset-delta tests**

Add JSON shape and asset entity assertions:

```go
func TestV2ModelJSONNamesAndAssetChangeEntity(t *testing.T) {
    result := model.CollectorResult{
        Collector: "mcp",
        Status: model.CoveragePartial,
        Targets: []model.TargetCoverage{{
            TargetID: "mcp.codex.user",
            Status: model.TargetUnsupported,
        }},
    }
    encoded, err := json.Marshal(result)
    if err != nil { t.Fatal(err) }
    for _, marker := range []string{`"targets"`, `"targetId"`, `"unsupported"`} {
        if !bytes.Contains(encoded, []byte(marker)) { t.Fatalf("missing %s in %s", marker, encoded) }
    }

    delta := Diff(model.Inventory{}, model.Inventory{Assets: []model.Asset{{ID: "asset", Type: model.AssetTool, Name: "tool"}}})
    want := []model.Change{{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "asset"}}
    if !reflect.DeepEqual(delta.Changes, want) { t.Fatalf("changes=%+v want=%+v", delta.Changes, want) }
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `go test ./internal/inventory -run TestV2ModelJSONNamesAndAssetChangeEntity -count=1`

Expected: compile failure for undefined `model.TargetCoverage`, `model.TargetUnsupported`, `model.ChangeEntity`, and `EntityID`.

- [ ] **Step 3: Define the exact v2 types and compatibility fields**

Create `internal/model/observation.go` with these public contracts:

```go
package model

type ObservationScope string
const (
    ScopeUser ObservationScope = "user"
    ScopeProject ObservationScope = "project"
    ScopeIDEProfile ObservationScope = "ide-profile"
    ScopeToolEnvironment ObservationScope = "tool-environment"
    ScopeSystem ObservationScope = "system"
)

type Observation struct {
    ID string `json:"id"`
    AssetID string `json:"assetId"`
    Collector string `json:"collector"`
    Host string `json:"host,omitempty"`
    Consumers []string `json:"consumers,omitempty"`
    Scope ObservationScope `json:"scope"`
    LocationRef string `json:"locationRef"`
    ProjectID string `json:"projectId,omitempty"`
    Source string `json:"source,omitempty"`
    Metadata map[string]string `json:"metadata,omitempty"`
}

type TargetMethod string
const (
    TargetFile TargetMethod = "file"
    TargetDirectory TargetMethod = "directory"
    TargetCommand TargetMethod = "command"
    TargetDynamicAPI TargetMethod = "dynamic-api"
    TargetServiceAPI TargetMethod = "service-api"
)

type TargetStatus string
const (
    TargetComplete TargetStatus = "complete"
    TargetNotPresent TargetStatus = "not_present"
    TargetPartial TargetStatus = "partial"
    TargetUnavailable TargetStatus = "unavailable"
    TargetUnsupported TargetStatus = "unsupported"
    TargetSkipped TargetStatus = "skipped"
)

type TargetSpec struct {
    ID string `json:"id"`
    Collector string `json:"collector"`
    Host string `json:"host,omitempty"`
    Scope ObservationScope `json:"scope"`
    Platform string `json:"platform"`
    Format string `json:"format,omitempty"`
    Method TargetMethod `json:"method"`
}

type TargetCoverage struct {
    TargetID string `json:"targetId"`
    InstanceRef string `json:"instanceRef,omitempty"`
    Status TargetStatus `json:"status"`
    Assets int `json:"assets"`
    Observations int `json:"observations"`
    Errors []CoverageError `json:"errors,omitempty"`
}

type ScanScope struct {
    Platform string `json:"platform"`
    CatalogVersion string `json:"catalogVersion"`
    ProjectRoots []string `json:"projectRoots"`
    ExternalProbes bool `json:"externalProbes"`
}

type LocalTarget struct {
    TargetID string `json:"-"`
    InstanceRef string `json:"-"`
    Path string `json:"-"`
    Format string `json:"-"`
    Host string `json:"-"`
    Consumers []string `json:"-"`
}

type ChangeEntity string
const (
    ChangeEntityAsset ChangeEntity = "asset"
    ChangeEntityObservation ChangeEntity = "observation"
)
```

Modify `CollectorResult`, `Inventory`, `ScanResult`, and `Change`:

```go
Targets []TargetCoverage `json:"targets,omitempty"`
Observations []Observation `json:"observations,omitempty"`
LocalTargets []LocalTarget `json:"-"`
Scope ScanScope `json:"scope,omitempty,omitzero"`

type Change struct {
    Kind ChangeKind `json:"kind"`
    Entity ChangeEntity `json:"entity"`
    EntityID string `json:"entityId"`
}
```

Update current asset-only `Diff` constructors to set `Entity: model.ChangeEntityAsset` and `EntityID: id`.

- [ ] **Step 4: Run focused and model-adjacent tests**

Run: `go test ./internal/inventory ./internal/model ./internal/report ./internal/scan -count=1`

Expected: PASS; no collector emits observations or targets yet, and existing scan output remains v1 because new fields are omitted when empty.

- [ ] **Step 5: Commit the model contracts**

```bash
git add internal/model/observation.go internal/model/scan.go internal/inventory/graph.go internal/inventory/graph_test.go
git commit -m "feat: define inventory v2 model contracts"
```

---

### Task 2: Centralize privacy checks and deterministic observation identity

**Files:**
- Create: `internal/privacy/sensitive.go`
- Create: `internal/privacy/sensitive_test.go`
- Create: `internal/identity/observation.go`
- Create: `internal/identity/observation_test.go`
- Modify: `internal/store/validation.go`
- Test: `internal/store/snapshots_test.go`

**Interfaces:**
- Consumes: `model.Observation` and `model.ObservationScope` from Task 1.
- Produces: `privacy.ContainsSensitiveValue(string) bool`, `privacy.IsRedactedPlaceholder(string) bool`.
- Produces: `identity.SafeLocationRef(home, path, externalLabel string) string` and `identity.FinalizeObservation(model.Observation) (model.Observation, error)`.
- Produces: `identity.ErrRejectedIdentity` for generic collector quarantine.

- [ ] **Step 1: Write privacy parity and deterministic identity tests**

Use fixed vectors rather than generated expectations:

```go
func TestFinalizeObservationCanonicalizesConsumersAndID(t *testing.T) {
    input := model.Observation{
        AssetID: "mcp:shared:workspace", Collector: "mcp",
        Consumers: []string{"vscode", "claude", "vscode"},
        Scope: model.ScopeProject, LocationRef: "$HOME/Projects/a/.mcp.json",
        ProjectID: "project:sha256:abc", Source: "mcp",
    }
    got, err := FinalizeObservation(input)
    if err != nil { t.Fatal(err) }
    if !reflect.DeepEqual(got.Consumers, []string{"claude", "vscode"}) { t.Fatalf("consumers=%q", got.Consumers) }
    if got.ID != "observation:sha256:02b164e37c428313b30c9f1231f3ba9fc44c01dbbef8f6ae4d1cb8ca25d459c2" {
        t.Fatalf("id=%q", got.ID)
    }
}

func TestFinalizeObservationRejectsSensitiveIdentityWithoutEcho(t *testing.T) {
    candidate := model.Observation{AssetID: "agent:ghp_123456789012345678901234567890123456", Collector: "agents", Scope: model.ScopeUser, LocationRef: "$HOME/.claude/plugins/rejected"}
    _, err := FinalizeObservation(candidate)
    if !errors.Is(err, ErrRejectedIdentity) || strings.Contains(err.Error(), "ghp_") { t.Fatalf("err=%v", err) }
}

func TestSafeLocationRefHidesOutsideHome(t *testing.T) {
    got := SafeLocationRef("/Users/test", "/Volumes/work/client/project", "external-root-1")
    if !strings.HasPrefix(got, "external-root-1/path-sha256:") || strings.Contains(got, "/Volumes/") { t.Fatalf("ref=%q", got) }
}
```

Include every existing store sensitive marker and safe-list near miss in `privacy/sensitive_test.go` so extraction cannot weaken the backstop.

- [ ] **Step 2: Run the new packages and verify RED**

Run: `go test ./internal/privacy ./internal/identity -count=1`

Expected: package/build failure because both packages and functions are absent.

- [ ] **Step 3: Extract privacy logic and implement canonical observation IDs**

Move the existing sensitive regexes and URI/assignment logic from store into `privacy` without changing patterns. Keep store wrappers only where tests require package-private helpers.

Implement identity finalization with length-prefixed fields so delimiter characters cannot collide:

```go
var ErrRejectedIdentity = errors.New("observation identity rejected")

func FinalizeObservation(value model.Observation) (model.Observation, error) {
    value.Consumers = uniqueSorted(value.Consumers)
    required := []string{value.AssetID, value.Collector, string(value.Scope), value.LocationRef}
    for _, field := range required {
        if field == "" || privacy.ContainsSensitiveValue(field) { return model.Observation{}, ErrRejectedIdentity }
    }
    for _, field := range append([]string{value.Host, value.ProjectID, value.Source}, value.Consumers...) {
        if privacy.ContainsSensitiveValue(field) { return model.Observation{}, ErrRejectedIdentity }
    }
    digest := sha256.Sum256(canonicalTuple(value))
    value.ID = fmt.Sprintf("observation:sha256:%x", digest)
    return value, nil
}

func SafeLocationRef(home, path, externalLabel string) string {
    cleanHome, cleanPath := filepath.Clean(home), filepath.Clean(path)
    if redacted := platform.RedactHome(cleanHome, cleanPath); strings.HasPrefix(redacted, "$HOME") {
        return filepath.ToSlash(redacted)
    }
    digest := sha256.Sum256([]byte(filepath.ToSlash(cleanPath)))
    return fmt.Sprintf("%s/path-sha256:%x", externalLabel, digest)
}
```

`canonicalTuple` writes big-endian uint32 byte lengths followed by UTF-8 bytes in this exact order: literal `ssc-init.observation.v1`, asset ID, collector, host, scope, location ref, project ID, source; then a uint32 consumer count and each sorted consumer; then a uint32 metadata-key count and each sorted key/value pair using the same length prefix. It excludes `Observation.ID`. The fixed digest above was calculated from this format and must not be changed to accommodate an implementation mismatch.

- [ ] **Step 4: Switch store validation to the shared privacy package**

Replace store-local calls without weakening error behavior:

```go
if privacy.ContainsSensitiveValue(value) {
    return ErrSensitiveSnapshot
}

if privacy.IsRedactedPlaceholder(value) {
    return nil
}
```

Delete only regex/functions now owned by `privacy`; retain store metadata-key and safe-key-list validation.

- [ ] **Step 5: Run privacy, identity, and store regressions**

Run: `go test ./internal/privacy ./internal/identity ./internal/store -count=1`

Expected: PASS, including all prior sensitive snapshot rejection vectors.

- [ ] **Step 6: Commit the shared privacy and identity boundary**

```bash
git add internal/privacy internal/identity internal/store/validation.go internal/store/snapshots_test.go
git commit -m "feat: add safe observation identity"
```

---

### Task 3: Normalize and diff observations without collector-local loss

**Files:**
- Modify: `internal/inventory/graph.go`
- Modify: `internal/inventory/graph_test.go`

**Interfaces:**
- Consumes: finalized `model.Observation` values from Task 2.
- Produces: deterministic `Inventory.Observations` and asset/observation `Delta.Changes` sorted by entity then ID.
- Preserves: asset metadata conflict fingerprints and asset-only relationships.

- [ ] **Step 1: Write failing observation merge, orphan, conflict, and delta tests**

```go
func TestBuildPreservesMultipleObservationsForOneAsset(t *testing.T) {
    asset := model.Asset{ID: "mcp:vscode:workspace", Type: model.AssetMCP, Name: "workspace"}
    first := model.Observation{ID: "observation:sha256:1", AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/Projects/a/.vscode/mcp.json"}
    second := model.Observation{ID: "observation:sha256:2", AssetID: asset.ID, Collector: "mcp", Scope: model.ScopeProject, LocationRef: "$HOME/Projects/b/.vscode/mcp.json"}
    got := Build([]model.CollectorResult{{Collector: "mcp", Assets: []model.Asset{asset, asset}, Observations: []model.Observation{second, first}}})
    if !reflect.DeepEqual(got.Observations, []model.Observation{first, second}) { t.Fatalf("observations=%+v", got.Observations) }
}

func TestBuildDropsOrphanObservationWithGenericError(t *testing.T) {
    got := Build([]model.CollectorResult{{Collector: "mcp", Observations: []model.Observation{{ID: "observation:sha256:1", AssetID: "missing"}}}})
    if len(got.Observations) != 0 || len(got.Errors) != 1 || got.Errors[0].Code != "orphan-observation" { t.Fatalf("inventory=%+v", got) }
}

func TestDiffReportsObservationOnlyChange(t *testing.T) {
    before := model.Inventory{Observations: []model.Observation{{ID: "observation:sha256:1", AssetID: "a", Collector: "mcp", Scope: model.ScopeUser, LocationRef: "$HOME/a"}}}
    after := model.Inventory{Observations: []model.Observation{{ID: "observation:sha256:2", AssetID: "a", Collector: "mcp", Scope: model.ScopeUser, LocationRef: "$HOME/b"}}}
    got := Diff(before, after)
    want := []model.Change{
        {Kind: model.ChangeRemoved, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:1"},
        {Kind: model.ChangeAdded, Entity: model.ChangeEntityObservation, EntityID: "observation:sha256:2"},
    }
    if !reflect.DeepEqual(got.Changes, want) { t.Fatalf("changes=%+v", got.Changes) }
}
```

- [ ] **Step 2: Run observation graph tests and verify RED**

Run: `go test ./internal/inventory -run 'TestBuildPreservesMultipleObservations|TestBuildDropsOrphan|TestDiffReportsObservation' -count=1`

Expected: failures because `Build` ignores observations and `Diff` compares only assets.

- [ ] **Step 3: Implement deterministic observation normalization**

Add a second accumulator keyed by observation ID. Select the lexicographically smallest canonical JSON on duplicate-ID conflict, emit one generic fingerprinted `observation-conflict`, and filter observations whose `AssetID` is absent after asset normalization:

```go
observationsByID := map[string]model.Observation{}
canonicalByID := map[string][]byte{}
for _, result := range results {
    for _, candidate := range result.Observations {
        canonical, _ := json.Marshal(candidate)
        existing, ok := canonicalByID[candidate.ID]
        if ok && !bytes.Equal(existing, canonical) {
            inventory.Errors = append(inventory.Errors, observationConflict(candidate.ID))
        }
        if !ok || bytes.Compare(canonical, existing) < 0 {
            observationsByID[candidate.ID], canonicalByID[candidate.ID] = candidate, canonical
        }
    }
}
```

Sort by `Observation.ID`; do not mutate collector slices.

- [ ] **Step 4: Extend diff to assets and observations**

Use one helper per entity and sort changes by `Entity`, `EntityID`, then `Kind`:

```go
appendEntityChanges(&changes, model.ChangeEntityAsset, assetBefore, assetAfter)
appendEntityChanges(&changes, model.ChangeEntityObservation, observationBefore, observationAfter)
sort.Slice(changes, func(i, j int) bool {
    if changes[i].Entity != changes[j].Entity { return changes[i].Entity < changes[j].Entity }
    if changes[i].EntityID != changes[j].EntityID { return changes[i].EntityID < changes[j].EntityID }
    return changes[i].Kind < changes[j].Kind
})
```

Observation canonical diff ignores no fields in this slice; observations do not contain timestamps.

- [ ] **Step 5: Run inventory and scan regressions**

Run: `go test ./internal/inventory ./internal/scan ./internal/acceptance -count=1`

Expected: PASS with existing collectors still producing empty observation lists.

- [ ] **Step 6: Commit lossless graph behavior**

```bash
git add internal/inventory/graph.go internal/inventory/graph_test.go
git commit -m "feat: preserve inventory observations"
```

---

### Task 4: Persist migration-4 observations and latest full snapshots

**Files:**
- Modify: `internal/store/migrations.go`
- Modify: `internal/store/snapshots.go`
- Modify: `internal/store/validation.go`
- Modify: `internal/store/snapshots_test.go`
- Modify: `internal/model/scan.go`

**Interfaces:**
- Consumes: `Inventory.Observations`, `ScanResult.Scope`, and target-bearing coverage.
- Produces: `model.Snapshot{Scan model.ScanResult, Inventory model.Inventory}`.
- Produces: `Store.LatestSnapshot(context.Context) (model.Snapshot, bool, error)`.
- Preserves: `LatestInventory` as a compatibility wrapper until all in-repo callers move in Task 5.

- [ ] **Step 1: Write failing migration and v2 round-trip tests**

Add tests that open a migration-3 database, reopen with migration 4, and persist all nil/non-nil states:

```go
func TestMigrationFourAddsScopeAndObservationSchema(t *testing.T) {
    path := createDatabaseAtMigration(t, 3)
    s, err := Open(path)
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = s.Close() })
    for _, table := range []string{"observations", "observation_state"} {
        assertTableExists(t, s.db, table)
    }
    assertColumnExists(t, s.db, "scans", "scope_json")
    assertColumnExists(t, s.db, "inventory_state", "observations_nil")
    assertColumnExists(t, s.db, "inventory_state", "observation_count")
}

func TestObservationAndScopeRoundTrip(t *testing.T) {
    s := openTestStore(t)
    scan := testScan("v2", time.Unix(2, 0).UTC())
    scan.SchemaVersion = "ssc-init.scan.v2"
    scan.Scope = model.ScanScope{Platform: "darwin", CatalogVersion: "ssc-init.catalog.v1", ProjectRoots: []string{"$HOME/Projects"}}
    observation, err := identity.FinalizeObservation(model.Observation{AssetID: "a", Collector: "packages", Scope: model.ScopeToolEnvironment, LocationRef: "$HOME/bin/a", Consumers: []string{}})
    if err != nil { t.Fatal(err) }
    inventory := model.Inventory{
        Assets: []model.Asset{{ID: "a", Type: model.AssetTool, Name: "a"}},
        Observations: []model.Observation{observation},
        Relationships: []model.Relationship{}, Errors: []model.CoverageError{},
    }
    if err := s.SaveScan(context.Background(), scan, inventory); err != nil { t.Fatal(err) }
    snapshot, ok, err := s.LatestSnapshot(context.Background())
    if err != nil || !ok { t.Fatalf("ok=%v err=%v", ok, err) }
    if !reflect.DeepEqual(snapshot, model.Snapshot{Scan: scan, Inventory: inventory}) { t.Fatalf("snapshot=%+v", snapshot) }
}
```

Define `createDatabaseAtMigration`, `assertTableExists`, and `assertColumnExists` as local test helpers in `snapshots_test.go`: create the database at an explicit path, apply exactly the first three production migration strings in order, close it, then reopen through `store.Open` so migration 4 is exercised. Do not mutate the global `migrations` slice or depend on a helper not present in the repository.

Add corruption cases for missing observation state, mismatched JSON ID, orphan `asset_id`, invalid indexes, and row-count mismatch.

- [ ] **Step 2: Run store tests and verify RED**

Run: `go test ./internal/store -run 'TestMigrationFour|TestObservationAndScopeRoundTrip|Observation' -count=1`

Expected: compile/schema failures for migration 4, `model.Snapshot`, and `LatestSnapshot`.

- [ ] **Step 3: Add migration 4 and schema verification**

Append this migration shape and update `requiredColumns`, check clauses, foreign keys, and index expectations:

```sql
ALTER TABLE scans ADD COLUMN scope_json BLOB NOT NULL DEFAULT '{}';
ALTER TABLE inventory_state ADD COLUMN observations_nil INTEGER NOT NULL DEFAULT 1 CHECK (observations_nil IN (0, 1));
ALTER TABLE inventory_state ADD COLUMN observation_count INTEGER NOT NULL DEFAULT 0 CHECK (observation_count >= 0);
CREATE TABLE observations (
    scan_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    observation_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, observation_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)
);
CREATE TABLE observation_state (
    scan_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    observation_index INTEGER NOT NULL CHECK (observation_index >= 0),
    metadata_nil INTEGER NOT NULL CHECK (metadata_nil IN (0, 1)),
    consumers_nil INTEGER NOT NULL CHECK (consumers_nil IN (0, 1)),
    PRIMARY KEY (scan_id, observation_id),
    UNIQUE (scan_id, observation_index),
    FOREIGN KEY (scan_id, observation_id) REFERENCES observations(scan_id, observation_id)
);
```

Define in `internal/model/scan.go`:

```go
type Snapshot struct {
    Scan ScanResult `json:"scan"`
    Inventory Inventory `json:"inventory"`
}
```

- [ ] **Step 4: Save scope and observations atomically**

Marshal `scan.Scope` into `scans.scope_json`; insert each observation and state before relationships/coverage, and extend `inventory_state` values:

```go
INSERT INTO observations(scan_id, observation_id, asset_id, observation_json) VALUES (?, ?, ?, ?)
INSERT INTO observation_state(scan_id, observation_id, observation_index, metadata_nil, consumers_nil) VALUES (?, ?, ?, ?, ?)
```

Validate unique IDs, referenced assets, scopes, sorted/unique consumers, target status/counts, and every observation string through the shared privacy package before opening the transaction.

- [ ] **Step 5: Load the latest complete snapshot and preserve legacy state**

Implement `LatestSnapshot` by selecting all scan columns, decoding `scope_json` strictly, loading coverage in collector order, and loading observations in state order. For a v1 row with `{}` scope, retain the original `SchemaVersion`; do not synthesize target coverage.

Keep the wrapper:

```go
func (s *Store) LatestInventory(ctx context.Context) (model.Inventory, bool, error) {
    snapshot, ok, err := s.LatestSnapshot(ctx)
    return snapshot.Inventory, ok, err
}
```

- [ ] **Step 6: Run store race and full persistence tests**

Run: `go test -race ./internal/store -count=1`

Expected: PASS for fresh, migration-3, rollback, corruption, cancellation, concurrency, permission, and secret-rejection suites.

- [ ] **Step 7: Commit migration 4**

```bash
git add internal/model/scan.go internal/store/migrations.go internal/store/snapshots.go internal/store/validation.go internal/store/snapshots_test.go
git commit -m "feat: persist observation snapshots"
```

---

### Task 5: Enforce target-level coverage and expose scan/status v2

**Files:**
- Create: `internal/collector/coverage.go`
- Create: `internal/collector/coverage_test.go`
- Modify: `internal/collector/collector.go`
- Modify: `internal/collector/orchestrator.go`
- Test: `internal/collector/orchestrator_test.go`
- Modify: `internal/scan/service.go`
- Test: `internal/scan/service_test.go`
- Modify: `internal/report/json.go`
- Test: `internal/report/json_test.go`
- Modify: `internal/cli/run.go`
- Test: `internal/cli/run_test.go`
- Modify: `internal/acceptance/memory_test.go`
- Modify: `internal/acceptance/baseline_test.go`
- Modify: `internal/acceptance/real_store_test.go`
- Modify: `internal/report/testdata/scan.golden.json`

**Interfaces:**
- Consumes: the v2 target/scope contracts from Task 1 and `LatestSnapshot` from Task 4.
- Produces: optional `collector.TargetedCollector`, target contract validation, and deterministic collector aggregation.
- Produces: `ssc-init.scan.v2` and `ssc-init.status.v2`; preserves status reads for v1 snapshots as explicitly legacy.

- [ ] **Step 1: Write the failing target-contract table tests**

Cover every aggregate rule and contract error:

```go
func TestApplyTargetContractSynthesizesMissingTarget(t *testing.T) {
    specs := []model.TargetSpec{{
        ID: "mcp.codex.user", Collector: "mcp", Platform: "darwin",
        Scope: model.ScopeUser, Method: model.TargetFile,
    }}
    got := ApplyTargetContract("mcp", specs, model.CollectorResult{Collector: "mcp"})
    if got.Status != model.CoveragePartial { t.Fatalf("status=%q", got.Status) }
    if got.Targets[0].Status != model.TargetUnsupported { t.Fatalf("target=%+v", got.Targets[0]) }
    if got.Targets[0].Errors[0].Code != "target_not_reported" { t.Fatalf("errors=%+v", got.Targets[0].Errors) }
}

func TestApplyTargetContractRejectsUnknownAndDuplicateInstances(t *testing.T) {
    // Unknown target IDs and duplicate (targetId, instanceRef) pairs become
    // failed collector results with coverage_contract_violation.
}

func TestAggregateTargetStatus(t *testing.T) {
    tests := []struct {
        targets []model.TargetCoverage
        want model.CoverageStatus
    }{
        {[]model.TargetCoverage{{Status: model.TargetComplete}, {Status: model.TargetNotPresent}}, model.CoverageComplete},
        {[]model.TargetCoverage{{Status: model.TargetSkipped}}, model.CoverageSkipped},
        {[]model.TargetCoverage{{Status: model.TargetComplete}, {Status: model.TargetUnsupported}}, model.CoveragePartial},
        {[]model.TargetCoverage{{Status: model.TargetUnavailable}}, model.CoverageUnavailable},
        {[]model.TargetCoverage{{Status: model.TargetNotPresent}, {Status: model.TargetUnavailable}}, model.CoveragePartial},
        {[]model.TargetCoverage{{Status: model.TargetPartial}}, model.CoveragePartial},
    }
    // Assert each table row.
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `go test ./internal/collector -run 'TestApplyTargetContract|TestAggregateTargetStatus' -count=1`

Expected: compile failure for `TargetedCollector`, `ApplyTargetContract`, and `AggregateTargetStatus`.

- [ ] **Step 3: Add the optional target catalog interface and validator**

Add to the collector package:

```go
const CatalogVersion = "ssc-init.catalog.v1"

type TargetedCollector interface {
    Collector
    Targets() []model.TargetSpec
}

func ApplyTargetContract(collectorName string, specs []model.TargetSpec, result model.CollectorResult) model.CollectorResult
func AggregateTargetStatus(targets []model.TargetCoverage) model.CoverageStatus
```

Validate immutable spec ownership, platform, scope, method, unique target IDs, unique `(targetId, instanceRef)` result keys, non-negative counts, and known statuses. Sort specs and results by target ID then instance reference. A targeted collector may be `complete` only when every applicable target instance is `complete` or `not_present`; all skipped is `skipped`; all applicable supported targets unavailable is `unavailable`; any skipped target mixed with performed targets, any unsupported/partial target, or unavailable mixed with any other status is `partial`.

Extend `collector.Environment`:

```go
type Environment struct {
    Home string
    Platform string
    Scope model.ScanScope
    FS platform.FileSystem
    Runner platform.Runner
    Now func() time.Time
}
```

Have the orchestrator apply the contract only to collectors implementing `TargetedCollector`, so intermediate tasks remain buildable. Retain panic recovery and deterministic collector order.

- [ ] **Step 4: Write failing v2 scan/status tests**

Assert a scan stores and prints this scope:

```go
model.ScanScope{
    Platform: "darwin",
    CatalogVersion: collector.CatalogVersion,
    ProjectRoots: []string{"$HOME/Projects"},
    ExternalProbes: false,
}
```

Assert `ScanResult.SchemaVersion == "ssc-init.scan.v2"`, ephemeral `LocalTargets` do not survive orchestration or persistence, and status uses this exact top-level contract:

```go
type statusPayload struct {
    SchemaVersion string `json:"schemaVersion"`
    Initialized bool `json:"initialized"`
    InventorySchemaVersion string `json:"inventorySchemaVersion,omitempty"`
    LegacyInventory bool `json:"legacyInventory,omitempty"`
    Scope *model.ScanScope `json:"scope,omitempty"`
    Coverage []model.CollectorResult `json:"coverage,omitempty"`
    Inventory *model.Inventory `json:"inventory,omitempty"`
}
```

For a v1 latest snapshot assert `legacyInventory: true`, no synthesized scope/coverage, and the original inventory remains readable.

- [ ] **Step 5: Switch the scan and status surfaces to v2**

Build scope once in `scan.Service`, pass it through `collector.Environment`, set `ssc-init.scan.v2`, compare with `LatestSnapshot.Inventory`, clear every collector result's `LocalTargets` before assigning the final inventory, and save the full snapshot.

Make `status` call `LatestSnapshot`. Emit `ssc-init.status.v2`, inventory provenance, v2 scope/coverage when present, and the legacy marker only for pre-v2 data. Keep field order stable through structs, never map-based marshaling.

- [ ] **Step 6: Update scan/status golden and acceptance expectations**

Regenerate the checked-in golden only from deterministic fake collectors; include v2 schema, scope, target coverage, asset entity fields, and no raw local target path. Update memory and real-store fakes to implement the new snapshot interface without bypassing persistence behavior.

- [ ] **Step 7: Run the focused and regression suites**

Run:

```bash
go test ./internal/collector ./internal/scan ./internal/report ./internal/cli -count=1
go test -race ./internal/acceptance ./internal/store -count=1
```

Expected: PASS; targeted fake collectors cannot overclaim complete coverage, while untargeted production collectors remain temporarily compatible.

- [ ] **Step 8: Commit truthful coverage and v2 output**

```bash
git add internal/collector internal/scan internal/report internal/cli internal/acceptance
git commit -m "feat: enforce truthful target coverage"
```

---

### Task 6: Add strict scan options and fd-rooted project discovery

**Files:**
- Create: `internal/cli/options.go`
- Create: `internal/cli/options_test.go`
- Create: `internal/collector/projects/walk.go`
- Create: `internal/collector/projects/walk_test.go`
- Modify: `internal/cli/run.go`
- Test: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Test: `cmd/ssc-init/main_test.go`
- Modify: `internal/collector/projects/collector.go`
- Test: `internal/collector/projects/collector_test.go`
- Modify: `internal/scan/service_test.go`
- Modify: `internal/testutil/files.go`

**Interfaces:**
- Produces: exact CLI parsing for repeatable absolute `--project-root` and boolean `--external-probes`.
- Produces: `App.RunOptions` so main parses once before constructing host dependencies.
- Produces: `projects.Root`, deterministic safe root references, and bounded descriptor-rooted traversal.
- Produces: `projects.root` target instances plus ephemeral downstream MCP `LocalTarget` values; raw paths remain `json:"-"` and memory-only.

- [ ] **Step 1: Write the failing strict option-parser tests**

```go
func TestParseOptions(t *testing.T) {
    got, err := ParseOptions([]string{"scan", "--baseline", "--json", "--project-root", "/Volumes/work", "--project-root=$HOME/Developer", "--external-probes"})
    if err != nil { t.Fatal(err) }
    want := Options{
        Command: "scan", Baseline: true, JSON: true, ExternalProbes: true,
        ProjectRoots: []string{"/Volumes/work", "$HOME/Developer"},
    }
    if !reflect.DeepEqual(got, want) { t.Fatalf("got=%+v want=%+v", got, want) }
}

func TestParseOptionsRejectsAmbiguousForms(t *testing.T) {
    for _, args := range [][]string{
        {"scan", "--project-root", "relative"},
        {"scan", "--project-root", "$HOMEevil/work"},
        {"scan", "--project-root"},
        {"scan", "--json"},
        {"status", "--external-probes"},
        {"scan", "--external-probes=true"},
        {"scan", "--project-root", "/tmp/a", "--project-root", "/tmp/a"},
        {"scan", "--unknown"},
    } {
        if _, err := ParseOptions(args); err == nil { t.Fatalf("accepted %q", args) }
    }
}
```

- [ ] **Step 2: Run option tests and verify RED**

Run: `go test ./internal/cli -run 'TestParseOptions' -count=1`

Expected: compile failure because `Options` and `ParseOptions` do not exist.

- [ ] **Step 3: Implement exact, command-aware parsing**

```go
type Options struct {
    Command string
    JSON bool
    Baseline bool
    ExternalProbes bool
    ProjectRoots []string
}
```

Accept only documented flags, reject positional leftovers and near-miss booleans, require both `--baseline` and `--json` for scan, and allow both `--project-root VALUE` and `--project-root=VALUE`. A root must be absolute or exactly `$HOME`/start with the literal `$HOME/` boundary; expand the literal only in `ResolveRoots`, clean the result, and reject duplicates after canonicalization. Default scan roots are resolved later to `$HOME/Projects`; status, doctor, and version require `--json` and reject scan-only flags.

- [ ] **Step 4: Write failing root resolution and hostile traversal tests**

Test these exact invariants:

```go
func TestResolveRootsUsesSafeStableReferences(t *testing.T) {
    home := t.TempDir()
    roots, err := ResolveRoots(home, []string{filepath.Join(home, "Projects"), "/Volumes/team"})
    if err != nil { t.Fatal(err) }
    if roots[0].Ref != "$HOME/Projects" { t.Fatalf("home ref=%q", roots[0].Ref) }
    if roots[1].Ref != "external-root-1" { t.Fatalf("external ref=%q", roots[1].Ref) }
}
```

Also prove the walker:

- rejects a symlinked configured root;
- never follows a symlinked project subtree or config file;
- detects a directory identity swap between enumeration and open;
- returns bounded partial coverage at configured depth/entry/file-size limits;
- emits deterministic order independent of directory enumeration order;
- never embeds an outside-home absolute path in a `LocationRef`.

- [ ] **Step 5: Implement resolved roots and descriptor-rooted traversal**

Add:

```go
type Root struct {
    Path string
    Ref string
}

func ResolveRoots(home string, values []string) ([]Root, error)
func RootRefs(roots []Root) []string
func New(roots []Root) collector.TargetedCollector
```

Canonicalize and sort roots first; label outside-home roots `external-root-1`, `external-root-2`, and so on in canonical order. Use `os.OpenRoot`, `Root.Open`/`OpenFile`, `unix.Fstatat` with no-follow semantics, and post-open `Fstat` identity comparison. Keep explicit maximum root count, depth, directory entries, configs, and config bytes. Record limit/symlink/swap errors on the affected target instance and continue safe siblings.

- [ ] **Step 6: Recognize only the fixed project config catalog**

The project collector owns one `projects.root` directory target expanded by safe root `InstanceRef`. Within a completely walked root, it may emit downstream MCP `LocalTarget` entries only for recognized files in this table; the IDs below belong to the MCP collector and must not appear as project collector target coverage:

| Relative path | Downstream MCP target ID | Host/consumers | Format |
|---|---|---|---|
| `.mcp.json` | `mcp.shared.project` | host `shared`; Claude Code + VS Code agent host | JSON |
| `.cursor/mcp.json` | `mcp.cursor.project` | Cursor | JSON |
| `.codex/config.toml` | `mcp.codex.project` | Codex | TOML |
| `.vscode/mcp.json` | `mcp.vscode.project` | VS Code | JSON |

For every recognized project config, emit a path-digest-identified project/config asset without location fields, a safe project observation carrying root/location facts, and a memory-only `LocalTarget{Path: rawAbsolutePath}` for Task 7. Unknown `.json`/`.toml` files are not MCP evidence. A missing configured root instance is `not_present`; an unreadable root is `unavailable`, not absent. A safely walked existing root is complete even when it contains no recognized file; the downstream MCP collector is responsible for base `not_present` results for its four project target IDs.

- [ ] **Step 7: Wire options, scope, and project roots through main**

Parse once in `main`, resolve roots against the already resolved home, construct `projects.New(roots)`, and set:

```go
model.ScanScope{
    Platform: runtime.GOOS,
    CatalogVersion: collector.CatalogVersion,
    ProjectRoots: projects.RootRefs(roots),
    ExternalProbes: options.ExternalProbes,
}
```

Add `func (a App) RunOptions(ctx context.Context, options Options, stdout, stderr io.Writer) int`; retain `App.Run` as a compatibility wrapper that parses and delegates. Main calls `ParseOptions` once, converts any parse failure to exit 2 plus generic `invalid command arguments` without echoing a supplied path/value, constructs only dependencies required by the recognized command, and then calls `RunOptions`—it must not reparse. Ensure CLI validation fails before home/state resolution. Define all test-only fakes and helper file writers locally in the named test files rather than relying on undeclared shared helpers.

- [ ] **Step 8: Run focused, race, and command tests**

Run:

```bash
go test ./internal/cli ./internal/collector/projects ./internal/scan ./cmd/ssc-init -count=1
go test -race ./internal/collector/projects -count=1
```

Expected: PASS with hostile-root cases returning partial coverage and safe siblings still inventoried.

- [ ] **Step 9: Commit bounded project scope**

```bash
git add internal/cli internal/collector/projects internal/scan cmd/ssc-init internal/testutil
git commit -m "feat: add bounded project scope"
```

---

### Task 7: Inventory the official JSON MCP catalog without losing collisions

**Files:**
- Create: `internal/collector/mcp/catalog.go`
- Create: `internal/collector/mcp/parser_json.go`
- Modify: `internal/collector/mcp/parser.go`
- Test: `internal/collector/mcp/parser_test.go`
- Modify: `internal/collector/mcp/collector.go`
- Test: `internal/collector/mcp/collector_test.go`
- Modify: `internal/scan/service.go`
- Test: `internal/scan/service_test.go`
- Create: `internal/collector/mcp/testdata/json/*.json`

**Interfaces:**
- Consumes: project `LocalTarget` values produced by Task 6.
- Produces: immutable user/project/dynamic target specs and strict JSON server normalization.
- Produces: canonical MCP assets plus one observation per source location; duplicate canonical IDs remain visible as multiple candidates until graph normalization.

- [ ] **Step 1: Write the failing catalog contract test**

Assert the catalog contains these fixed user targets with exact IDs, relative paths, hosts, formats, and consumers:

| Target ID | Relative path | Host |
|---|---|---|
| `mcp.claude-code.user` | `.claude.json` | `claude-code` |
| `mcp.claude-code.legacy-user` | `.claude/settings.json` | `claude-code` |
| `mcp.claude-desktop.user` | `Library/Application Support/Claude/claude_desktop_config.json` | `claude-desktop` |
| `mcp.cursor.user` | `.cursor/mcp.json` | `cursor` |
| `mcp.windsurf.user` | `.codeium/windsurf/mcp_config.json` | `windsurf` |
| `mcp.windsurf.legacy-user` | `.windsurf/mcp.json` | `windsurf` |
| `mcp.vscode.user` | `Library/Application Support/Code/User/mcp.json` | `vscode` |
| `mcp.vscode-insiders.user` | `Library/Application Support/Code - Insiders/User/mcp.json` | `vscode-insiders` |
| `mcp.github-copilot.user` | `.copilot/mcp-config.json` | `github-copilot` |

Also assert the catalog declares the four Task 6 project target IDs and explicit unsupported targets for generic dynamic/profile/remote/dev-container/relocated/service-managed state. Codex user TOML is present but reports unsupported until Task 8.

- [ ] **Step 2: Write failing JSON normalization tests**

Use fixtures for stdio, HTTP, disabled servers, malformed entries, secret-bearing env/header maps, and unknown fields:

```go
func TestParseJSONOmitsSecretValues(t *testing.T) {
    got, err := ParseJSON([]byte(`{
      "mcpServers": {"demo": {
        "command": "node", "args": ["server.js"],
        "env": {"API_TOKEN": "super-secret"},
        "headers": {"Authorization": "Bearer secret"}
      }}
    }`))
    if err != nil { t.Fatal(err) }
    server := got.Servers[0]
    if !reflect.DeepEqual(server.EnvKeys, []string{"API_TOKEN"}) { t.Fatalf("env=%v", server.EnvKeys) }
    if !reflect.DeepEqual(server.HeaderKeys, []string{"Authorization"}) { t.Fatalf("headers=%v", server.HeaderKeys) }
    encoded, _ := json.Marshal(got)
    if bytes.Contains(encoded, []byte("super-secret")) || bytes.Contains(encoded, []byte("Bearer secret")) {
        t.Fatalf("secret leaked: %s", encoded)
    }
}
```

Define and assert the normalized shape:

```go
type ServerConfig struct {
    Name string
    Command string
    Args []string
    URL string
    Transport string
    CWD string
    Enabled *bool
    EnvKeys []string
    HeaderKeys []string
    EnabledTools []string
    DisabledTools []string
    UnknownFields []string
}
```

- [ ] **Step 3: Run catalog/parser tests and verify RED**

Run: `go test ./internal/collector/mcp -run 'TestCatalog|TestParseJSON' -count=1`

Expected: missing catalog and parser contracts or failing secret/collision assertions.

- [ ] **Step 4: Implement strict JSON parsing and normalization**

Decode with a bounded input reader and `json.RawMessage`; accept only top-level `mcpServers` or the host's catalog-declared equivalent. Parse each server object into allowed fields, preserve unknown field names but never values, retain env/header key names only, canonicalize set-like fields, and reject a server having both or neither command/URL. A malformed server makes the target partial but does not discard valid siblings.

Unknown semantic fields make the target partial with `unknown_server_field`; syntactically valid and fully understood empty maps remain complete. Never persist an entire raw config or command environment.

- [ ] **Step 5: Write failing collector collision and identity-quarantine tests**

Cover:

- two project configs defining the same host/name produce two candidate assets and two observations before graph normalization;
- graph normalization yields one canonical asset and both observations;
- same server name on different hosts remains distinct;
- a secret-shaped server name is rejected as `rejected_identity`, marks only that target partial, and leaves safe sibling servers;
- every `LocationRef` is home-relative, project-relative, or an external root label—never a raw outside-home path;
- target asset/observation counts match emitted values.

- [ ] **Step 6: Implement catalog-driven MCP collection**

Change construction to:

```go
func New(projectTargets ...model.LocalTarget) collector.TargetedCollector
func (c *mcpCollector) Targets() []model.TargetSpec
```

Collect each fixed user target with no-follow bounded reads, then the supplied project target instances. When a project target ID has no supplied instance, emit one base `not_present` result with empty `InstanceRef`; when instances exist, emit exactly one result per unique safe instance and no base result. The canonical asset contains only stable semantic identity (`type`, host/source, name, and version if independently known). Put transport, command, args, URL shape, CWD reference, enabled state, key names, tool lists, source target, and unknown field names into the observation metadata after privacy validation.

Do not use `map[assetID]Asset` inside the collector: append every valid candidate and observation. Let the graph merge identical assets and flag conflicting canonical candidates as partial. Implement local test helpers for fixtures, observation lookup, and asset counting in the MCP test package.

- [ ] **Step 7: Pass ephemeral project targets from projects to MCP**

Keep MCP out of the primary concurrent orchestrator. In `scan.Service`, collect the primary set (including projects), copy only validated project `LocalTargets`, run exactly one MCP follow-up containing fixed user targets plus those local instances, replace any stale MCP result defensively, and sort the published results by collector name. Clear every raw target immediately after the copy/follow-up. Do not add raw target paths to errors, logs, JSON, SQLite, or test golden files. Add a test proving an externally rooted project config is opened through a fresh verified root rather than the home root.

- [ ] **Step 8: Run focused, privacy, and race tests**

Run:

```bash
go test ./internal/collector/mcp ./internal/scan ./internal/inventory -count=1
go test -race ./internal/collector/mcp ./internal/scan -count=1
```

Expected: PASS; same-name multi-location definitions preserve observations and no fixture secret appears in marshaled output.

- [ ] **Step 9: Commit the JSON MCP catalog**

```bash
git add internal/collector/mcp internal/scan internal/inventory
git commit -m "feat: inventory official JSON MCP targets"
```

---

### Task 8: Parse official Codex MCP TOML with a pinned pure-Go dependency

**Files:**
- Create: `internal/collector/mcp/parser_toml.go`
- Create: `internal/collector/mcp/parser_toml_test.go`
- Modify: `internal/collector/mcp/collector.go`
- Test: `internal/collector/mcp/collector_test.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/collector/mcp/testdata/toml/*.toml`

**Interfaces:**
- Consumes: `ServerConfig` and catalog dispatch from Task 7.
- Produces: strict normalization of the official `[mcp_servers.<name>]` Codex TOML table.
- Adds: pinned `github.com/pelletier/go-toml/v2` while preserving `CGO_ENABLED=0` static builds.

Dependency review note (2026-08-06): the public Go package record identifies v2.4.3 and documents TOML v1.1.0 support; implementation must still review its module graph and license before committing the pin: <https://pkg.go.dev/github.com/pelletier/go-toml/v2>.

- [ ] **Step 1: Write failing stdio, HTTP, and secret-omission tests**

```go
func TestParseTOMLNormalizesCodexServers(t *testing.T) {
    raw := []byte(`
[mcp_servers.local]
command = "uvx"
args = ["demo"]
cwd = "/tmp/work"
env = { API_TOKEN = "must-not-persist" }
enabled_tools = ["read"]

[mcp_servers.remote]
url = "https://example.invalid/mcp"
http_headers = { Authorization = "Bearer must-not-persist" }
bearer_token_env_var = "MCP_TOKEN"
`)
    got, err := ParseTOML(raw)
    if err != nil { t.Fatal(err) }
    if got.Servers[0].Command != "uvx" || got.Servers[1].URL == "" { t.Fatalf("servers=%+v", got.Servers) }
    encoded, _ := json.Marshal(got)
    for _, forbidden := range []string{"must-not-persist", "Bearer"} {
        if bytes.Contains(encoded, []byte(forbidden)) { t.Fatalf("leaked %q: %s", forbidden, encoded) }
    }
}
```

Also assert `env_vars`, `env_http_headers`, disabled servers, enabled/disabled tool lists, malformed TOML, both/neither command and URL, an unknown server field, and unrelated top-level tables. Only unknown fields inside a server table affect coverage.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `go test ./internal/collector/mcp -run 'TestParseTOML' -count=1`

Expected: compile failure because `ParseTOML` does not exist.

- [ ] **Step 3: Pin the parser and implement typed TOML dispatch**

Run:

```bash
go get github.com/pelletier/go-toml/v2@v2.4.3
go mod tidy
go mod verify
go mod why -m github.com/pelletier/go-toml/v2
go list -deps ./cmd/ssc-init
```

Review the `go.mod`/`go.sum` diff and module metadata before continuing: the dependency must remain direct, pinned, pure Go, and MIT-licensed, and the executable dependency list must not gain an unexpected runtime module. Decode only `mcp_servers`. Recognize these server fields exactly:

```text
command, args, url, cwd, enabled, env, env_vars,
http_headers, env_http_headers, bearer_token_env_var,
enabled_tools, disabled_tools
```

Convert direct env/header maps to sorted key names, preserve environment-variable references by name, and never retain direct values. Reject ambiguous transport (both command and URL) and missing transport. Return valid sibling servers plus structured issues exactly like the JSON parser.

Dispatch by the catalog target format, make `mcp.codex.user` and `mcp.codex.project` implemented, and remove their temporary unsupported status. Define fixture readers and assertion helpers inside `parser_toml_test.go`.

- [ ] **Step 4: Run parser, collector, module, and static-build checks**

Run:

```bash
go test ./internal/collector/mcp -count=1
go mod verify
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o /tmp/ssc-init-plan-check-arm64 ./cmd/ssc-init
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o /tmp/ssc-init-plan-check-amd64 ./cmd/ssc-init
```

Expected: PASS; both binaries build without a C toolchain and TOML secret fixture values are absent from all output.

- [ ] **Step 5: Commit Codex TOML support**

```bash
git add go.mod go.sum internal/collector/mcp
git commit -m "feat: inventory Codex MCP configuration"
```

---

### Task 9: Replace directory-name guesses with manifest-backed agent inventory

**Files:**
- Create: `internal/collector/agents/catalog.go`
- Create: `internal/collector/agents/manifest.go`
- Modify: `internal/collector/agents/collector.go`
- Test: `internal/collector/agents/collector_test.go`
- Create: `internal/collector/agents/testdata/plugin/*.json`
- Create: `internal/collector/agents/testdata/skill/*.md`
- Modify: `testdata/home/.codex/plugins/example/.codex-plugin/plugin.json`

**Interfaces:**
- Produces: fixed agent target specs for Claude, Codex, Cursor, and Windsurf roots, including visible unsupported host surfaces.
- Produces: bounded recursive marker discovery for recognized plugin manifests and `SKILL.md` files.
- Removes: the unsafe assumption that every immediate child directory is an installed plugin.

- [ ] **Step 1: Write failing catalog and container-misclassification tests**

```go
func TestCatalogContainersAreNotAssets(t *testing.T) {
    home := t.TempDir()
    writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "cache", "vendor", "demo", "1.2.3", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.2.3"}`)
    got, err := agents.New().Collect(context.Background(), testutil.Environment(t, home))
    if err != nil { t.Fatal(err) }
    assertNoAssetNamed(t, got.Assets, "cache")
    asset := testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:demo@1.2.3")
    if asset.Version != "1.2.3" { t.Fatalf("asset=%+v", asset) }
}
```

Add cases where top-level `cache`, `extensions`, `marketplaces`, a README-only directory, and an arbitrary nested directory are not assets. Assert the catalog declares all known fixed roots and reports undocumented/custom, remote, and relocated roots as `unsupported` rather than absent.

- [ ] **Step 2: Write failing recognized-marker and hostile-walk tests**

Cover these marker rules:

| Kind | Recognized marker | Required identity |
|---|---|---|
| Claude plugin | `.claude-plugin/plugin.json` | manifest `name`; optional `version` |
| Codex plugin | `.codex-plugin/plugin.json` | manifest `name`; optional `version` |
| Skill | `SKILL.md` | bounded YAML frontmatter `name`, otherwise safe containing-directory name |

Test nested cache versions, multiple installed versions of one plugin, skills directly under skill roots, skills bundled below a recognized plugin's `skills/` directory, malformed/duplicate-key manifests, secret-shaped names, symlinked entries, identity swaps, depth/entry/file-size limits, and cancellation. A bad sibling makes only that target instance partial and never suppresses a safe sibling.

- [ ] **Step 3: Run the focused tests and verify RED**

Run: `go test ./internal/collector/agents -run 'TestCatalogContainers|TestAgentManifest|TestAgentWalk' -count=1`

Expected: the current collector incorrectly emits directory names as plugins and lacks target/observation output.

- [ ] **Step 4: Implement the immutable agent catalog**

Define target specs for the current fixed roots:

```text
agents.claude.plugins   $HOME/.claude/plugins
agents.claude.skills    $HOME/.claude/skills
agents.codex.plugins    $HOME/.codex/plugins
agents.codex.skills     $HOME/.codex/skills
agents.cursor.plugins   $HOME/.cursor/plugins
agents.cursor.skills    $HOME/.cursor/skills
agents.windsurf.plugins $HOME/.windsurf
```

Claude/Codex plugin roots and all explicit skill roots are implemented directory targets on Darwin. Cursor and Windsurf plugin roots remain cataloged but return `unsupported` until a recognized local plugin manifest is documented; do not invent a marker format from a directory name. Add catalog-only unsupported specs for custom roots, remote host state, environment-relocated state, and host-side/dynamic plugin APIs. `Targets()` returns a defensive copy in deterministic target-ID order.

- [ ] **Step 5: Implement bounded rooted marker discovery**

Reuse the descriptor-rooted helpers and identity checks from Task 6. Enforce constants for root count, recursion depth, total entries, total manifests, and manifest bytes. Never follow a symlink or derive identity from a container directory. Parse recognized Claude/Codex JSON markers with duplicate-key rejection and only retain `name`/`version`; parse only bounded `SKILL.md` frontmatter keys and never retain body content in this slice. Do not traverse unsupported Cursor/Windsurf plugin targets as if they were implemented.

Create canonical assets:

```text
agent-plugin:<host>:<manifest-name>@<version>  (when version is present)
agent-plugin:<host>:<manifest-name>            (when version is absent)
agent-skill:<host>:<skill-name>
```

Keep version on the canonical candidate but keep location/path and bundle/container facts out of the asset. Emit one observation per discovered location/version with target ID, marker kind, manifest-relative safe path, and version metadata. Multiple candidates with the same canonical ID must be appended, not overwritten; the graph retains all observations and reports incompatible canonical fields generically.

Run every identity through `identity.FinalizeObservation`. Quarantine invalid or credential-shaped identities with `identity_rejected`, no raw name/path, and partial target coverage.

- [ ] **Step 6: Replace old direct-directory fixtures and assertions**

Convert the repository's positive Codex fixture to a real `.codex-plugin/plugin.json`. Delete test expectations that a README-only Windsurf directory is a plugin and replace them with a negative regression. Add observation and target count assertions to all positive tests. Define test helpers (`assertNoAssetNamed`, fixture writer, observation matcher) inside `collector_test.go`.

- [ ] **Step 7: Run focused and race suites**

Run:

```bash
go test ./internal/collector/agents ./internal/inventory -count=1
go test -race ./internal/collector/agents -count=1
```

Expected: PASS; no container asset exists, nested real manifests are found, and every known root has one target result.

- [ ] **Step 8: Commit manifest-backed agent discovery**

```bash
git add internal/collector/agents testdata/home/.codex/plugins/example
git commit -m "feat: inventory manifest-backed agent assets"
```

---

### Task 10: Add IDE target coverage and preserve every installation observation

**Files:**
- Modify: `internal/collector/ide/collector.go`
- Modify: `internal/collector/ide/manifest.go`
- Test: `internal/collector/ide/collector_test.go`
- Create: `internal/collector/ide/catalog.go`
- Create: `internal/collector/ide/catalog_test.go`

**Interfaces:**
- Produces: target specs/results for each fixed VS Code-family root and bounded JetBrains product instances.
- Produces: one observation for every installed extension/plugin location.
- Removes: local map overwrite by canonical asset ID.

- [ ] **Step 1: Write failing fixed-catalog and unsupported-root tests**

Assert these directory targets and their home-relative roots:

```text
ide.vscode.extensions          $HOME/.vscode/extensions
ide.vscode-insiders.extensions $HOME/.vscode-insiders/extensions
ide.cursor.extensions          $HOME/.cursor/extensions
ide.windsurf.extensions        $HOME/.windsurf/extensions
ide.vscode-oss.extensions      $HOME/.vscode-oss/extensions
ide.jetbrains.plugins          $HOME/Library/Application Support/JetBrains/<product>/plugins
```

The JetBrains spec expands to one safe `InstanceRef` per bounded product directory. Catalog custom extension directories, Remote SSH/WSL/container extension state, environment-relocated roots, and IDE service APIs as `unsupported`. A missing fixed root is `not_present`; an unreadable or truncated root is partial/unavailable according to whether any content was safely evaluated.

- [ ] **Step 2: Write failing duplicate-install observation tests**

```go
func TestSameVSCodeExtensionAtTwoLocationsPreservesBothObservations(t *testing.T) {
    home := t.TempDir()
    writeVSCodeManifest(t, home, ".vscode/extensions/demo-a/package.json", "pub", "demo", "1.0.0")
    writeVSCodeManifest(t, home, ".vscode/extensions/demo-b/package.json", "pub", "demo", "1.0.0")
    got, err := ide.New().Collect(context.Background(), testutil.Environment(t, home))
    if err != nil { t.Fatal(err) }
    if countAssets(got.Assets, "ide-extension:vscode:pub.demo@1.0.0") != 2 { t.Fatalf("assets=%+v", got.Assets) }
    if countObservations(got.Observations, "ide-extension:vscode:pub.demo@1.0.0") != 2 { t.Fatalf("observations=%+v", got.Observations) }
}
```

Add graph assertion for one normalized asset plus two observations. Add cross-root, multiple-version, JetBrains product-instance, symlink, identity-swap, oversized manifest, duplicate manifest key, and credential-shaped publisher/name fixtures. Ensure a rejected identity never leaks through the error or path.

- [ ] **Step 3: Run the focused tests and verify RED**

Run: `go test ./internal/collector/ide -run 'TestIDECatalog|TestSameVSCodeExtension|TestIDEIdentity' -count=1`

Expected: duplicate install count is one because the current `assetsByID` map overwrites the first location; no target or observation contracts exist.

- [ ] **Step 4: Separate canonical fields from observed fields**

Refactor manifest normalization to return canonical identity plus observed metadata. Canonical VS Code assets retain host, publisher, name, and version; canonical JetBrains assets retain plugin ID, name, publisher, and version. Move path, manifest path, entry point, activation events, capabilities, product instance, and selected source details into the observation.

Do not retain arbitrary manifest keys or source file contents. Continue strict duplicate-key JSON, strict XML structure, bounded lists/strings, shared privacy validation, and identity quarantine.

- [ ] **Step 5: Emit target results and lossless candidates**

Implement `Targets() []model.TargetSpec`. Change traversal functions to append `[]model.Asset` and `[]model.Observation` instead of assigning a map. Each successful manifest increments its target counts; each malformed, symlinked, swapped, oversized, or identity-rejected occurrence marks only its root/product target partial. A root that exists and is safely empty is complete, not absent.

Finalize every observation deterministically using its target ID and safe root-relative location. For JetBrains, derive `InstanceRef` from the sanitized product directory identity, never an absolute path.

- [ ] **Step 6: Run focused, graph, and race suites**

Run:

```bash
go test ./internal/collector/ide ./internal/inventory -count=1
go test -race ./internal/collector/ide -count=1
```

Expected: PASS; duplicate occurrences survive collection and graph normalization, target counts agree, and the existing hostile-manifest suite stays green.

- [ ] **Step 7: Commit IDE occurrence preservation**

```bash
git add internal/collector/ide
git commit -m "feat: preserve IDE extension observations"
```

---

### Task 11: Make external package probes explicit and record the executable used

**Files:**
- Create: `internal/platform/executable.go`
- Create: `internal/platform/executable_test.go`
- Modify: `internal/collector/collector.go`
- Modify: `internal/collector/packages/collector.go`
- Test: `internal/collector/packages/collector_test.go`
- Modify: `internal/platform/runner_test.go`
- Modify: `cmd/ssc-init/main.go`
- Test: `cmd/ssc-init/main_test.go`
- Modify: `internal/doctor/doctor_test.go`

**Interfaces:**
- Produces: bounded executable inspection and post-run identity verification.
- Produces: eight package target specs whose default result is explicitly `skipped`.
- Produces: executable assets/observations and package observations linked by safe IDs.

- [ ] **Step 1: Write failing executable-inspection tests**

Define the intended contract in tests:

```go
type FileIdentity struct {
    Device uint64
    Inode uint64
    Size int64
    ModTimeUnixNano int64
}

type ExecutableEvidence struct {
    Command string
    Path string
    LocationRef string
    SymlinkRefs []string
    SHA256 string
    Mode uint32
    Identity FileIdentity
}

type ExecutableInspector interface {
    Inspect(context.Context, string, string) (ExecutableEvidence, error)
    Verify(ExecutableEvidence) error
}
```

Test a direct regular executable, a two-link chain, relative symlink targets, a loop, chain limit, non-regular target, non-executable mode, oversized file, outside-home safe reference, pre/post replacement, and context cancellation. Assert serialized model output never receives `Path`, `Identity`, or a raw outside-home symlink target.

- [ ] **Step 2: Run executable tests and verify RED**

Run: `go test ./internal/platform -run 'TestExecutable' -count=1`

Expected: compile failure because the inspector contracts do not exist.

- [ ] **Step 3: Implement bounded PATH resolution and evidence**

Use `exec.LookPath` only to select the candidate, then make it absolute and inspect it. Resolve at most 16 symlinks with `Lstat`/`Readlink`, reject loops and escapes to non-absolute final identity, require a regular file with at least one execute bit, hash through an already opened file with a 64 MiB limit, and compare pre-open/post-open `os.SameFile` plus size/mode.

Derive `LocationRef` and every retained chain reference through `identity.SafeLocationRef`; outside-home values use a generic `external-executable:<ordinal>` reference, not the absolute path. Capture Darwin device/inode plus size/mtime in `FileIdentity`. `Verify` re-stats the final path and rejects any identity change.

`ExecutableEvidence.Path` and `Identity` are execution-only values: add `json:"-"` tags and never embed the struct into `model.Inventory`. Hash, safe location, mode, and command basename are the only persisted facts.

- [ ] **Step 4: Write failing default-skip and opt-in package tests**

Cover:

```go
func TestPackageProbesAreSkippedByDefault(t *testing.T) {
    inspector := &fakeInspector{failOnCall: true}
    runner := &fakeRunner{failOnCall: true}
    env := testEnvironment(t)
    env.Scope.ExternalProbes = false
    env.Inspector, env.Runner = inspector, runner
    got, err := packages.New().Collect(context.Background(), env)
    if err != nil { t.Fatal(err) }
    for _, target := range got.Targets {
        if target.Status != model.TargetSkipped { t.Fatalf("target=%+v", target) }
    }
}
```

Opt-in tests assert inspector-before-run order, the runner receives the inspected absolute path and exact fixed argv, verification runs after every attempted execution, replacement makes the target partial, missing executable is `not_present`, timeout/nonzero/truncation/parser loss is partial, Docker daemon failure is unavailable, and Docker locality metadata is `unknown` unless proven.

Add a real temporary `PATH` spoof fixture: the selected fake executable is identified by its actual hash and safe location rather than silently treated as the expected vendor binary. Opt-in means “executed with evidence,” never “trusted.”

- [ ] **Step 5: Extend the environment and package target catalog**

Preserve existing environment fields and add:

```go
type Environment struct {
    Home string
    Platform string
    Scope model.ScanScope
    FS platform.FileSystem
    Runner platform.Runner
    Inspector platform.ExecutableInspector
    Now func() time.Time
}
```

Implement `Targets()` for `packages.npm`, `packages.pip`, `packages.pipx`, `packages.uv`, `packages.cargo`, `packages.go`, `packages.homebrew`, and `packages.docker`, all `TargetCommand`. When probes are disabled, do not call inspector or runner and return one skipped result per target.

- [ ] **Step 6: Execute only inspected absolute paths and preserve manager collisions**

For each enabled probe:

1. inspect the fixed command name;
2. create a location-free `tool-executable:sha256:<digest>` asset with its SHA-256 identity and an executable observation carrying safe location, chain, mode, and command-basename facts;
3. run `evidence.Path` with the existing fixed argument vector;
4. parse bounded stdout without retaining stderr;
5. append location-free package candidates and one observation per manager occurrence, moving manager/path/probe-source facts out of the canonical asset;
6. store safe `probe_target_id` and `executable_observation_id` metadata;
7. verify executable identity after the attempt;
8. mark truncation, parser loss, or replacement partial.

Remove `assetsByID`. A package found by two managers yields duplicate canonical candidates and two observations before graph normalization. Docker image identity remains its reported reference with `locality=unknown`; do not fabricate immutable digest or local provenance in this slice.

- [ ] **Step 7: Wire the real inspector and keep doctor passive**

Construct the inspector in `main` with explicit chain/hash bounds. `doctor` may continue availability checks such as `LookPath`, but add a regression fake proving it never invokes a package probe or the inspected executable. Never create an inspector when external probes are false if doing so would touch the filesystem.

- [ ] **Step 8: Run focused, race, and full package tests**

Run:

```bash
go test ./internal/platform ./internal/collector/packages ./internal/doctor ./cmd/ssc-init -count=1
go test -race ./internal/platform ./internal/collector/packages -count=1
```

Expected: PASS; default scans execute zero package commands and enabled probes always report which executable was used.

- [ ] **Step 9: Commit explicit external probes**

```bash
git add internal/platform internal/collector/collector.go internal/collector/packages internal/doctor cmd/ssc-init
git commit -m "feat: make external probes explicit"
```

---

### Task 12: Reject non-Darwin operational commands before touching host state

**Files:**
- Create: `internal/platform/support.go`
- Create: `internal/platform/support_test.go`
- Modify: `cmd/ssc-init/main.go`
- Test: `cmd/ssc-init/main_test.go`

**Interfaces:**
- Produces: one explicit operational-platform predicate.
- Enforces: `doctor`, `scan`, and `status` exit 2 on non-Darwin before home or state resolution.
- Preserves: `version --json` on every OS that compiles.

- [ ] **Step 1: Write failing command-boundary tests**

Inject the runtime platform through a package variable or a small function seam, then test every operational command:

```go
func TestNonDarwinOperationalCommandsCreateNoState(t *testing.T) {
    old := runtimeGOOS
    runtimeGOOS = "linux"
    t.Cleanup(func() { runtimeGOOS = old })

    home := t.TempDir()
    t.Setenv("HOME", home)
    for _, args := range [][]string{
        {"doctor", "--json"},
        {"scan", "--baseline", "--json"},
        {"status", "--json"},
    } {
        stdout, stderr := captureRun(t, args)
        if stdout != "" || stderr != "unsupported operating system\n" { t.Fatalf("args=%v stdout=%q stderr=%q", args, stdout, stderr) }
        if stateExists(home) { t.Fatalf("state created for %v", args) }
    }
}
```

Assert each return code is 2. Also assert `version --json` still succeeds with the injected Linux platform and invalid/unknown commands remain CLI usage errors without host initialization.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `go test ./cmd/ssc-init -run 'TestNonDarwin|TestVersionOnNonDarwin' -count=1`

Expected: current main resolves home/opens SQLite and does not emit the unsupported contract.

- [ ] **Step 3: Implement one early platform gate**

Add:

```go
func OperationallySupported(goos string) bool { return goos == "darwin" }
```

In `main.run`, parse/recognize the command first. For recognized `doctor`, `scan`, and `status`, check `runtimeGOOS` before `hostPaths`, collector construction, path creation, or `store.Open`:

```go
if operationalCommand(options.Command) && !platform.OperationallySupported(runtimeGOOS) {
    fmt.Fprintln(os.Stderr, "unsupported operating system")
    return 2
}
```

Do not describe Linux as supported merely because the code cross-builds. Keep Windows out of the build matrix until its POSIX-specific packages are separated.

- [ ] **Step 4: Run tests and Linux compile guard**

Run:

```bash
go test ./cmd/ssc-init ./internal/platform -count=1
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/ssc-init-linux-compile-guard ./cmd/ssc-init
```

Expected: PASS; the Linux artifact is only a compile guard, while operational tests prove no state access.

- [ ] **Step 5: Commit the platform boundary**

```bash
git add internal/platform/support.go internal/platform/support_test.go cmd/ssc-init
git commit -m "feat: reject unsupported operating systems"
```

---

### Task 13: Prove the official matrix end to end and correct public claims

**Files:**
- Create: `internal/acceptance/usecase_matrix_test.go`
- Modify: `internal/acceptance/baseline_test.go`
- Modify: `internal/acceptance/real_store_test.go`
- Modify: `internal/acceptance/memory_store_test.go`
- Create: `testdata/home/.claude.json`
- Create: `testdata/home/Library/Application Support/Claude/claude_desktop_config.json`
- Create: `testdata/home/.codex/config.toml`
- Create: `testdata/home/.codeium/windsurf/mcp_config.json`
- Create: `testdata/home/.windsurf/mcp.json`
- Create: `testdata/home/Library/Application Support/Code/User/mcp.json`
- Create: `testdata/home/Library/Application Support/Code - Insiders/User/mcp.json`
- Create: `testdata/home/.copilot/mcp-config.json`
- Create: `testdata/home/Projects/sample/.mcp.json`
- Create: `testdata/home/Projects/sample/.cursor/mcp.json`
- Create: `testdata/home/Projects/sample/.codex/config.toml`
- Modify: `testdata/home/Projects/sample/.vscode/mcp.json`
- Modify: `README.md`
- Modify: `docs/testing/2026-08-06-use-case-validation.md`

**Interfaces:**
- Proves: the implemented catalog has no silent misses in an isolated home and every unimplemented catalog surface is visible.
- Proves: baseline → SQLite reopen → status → second scan preserves v2 scope, observations, coverage, and delta.
- Documents: the tested boundary as catalog-scoped macOS inventory, not EDR or laptop-wide protection.

- [ ] **Step 1: Write the failing isolated-home use-case matrix**

Build the application through production constructors but inject only isolated filesystem roots, a temporary SQLite database, fake time, a fail-on-call runner/inspector for the default scan, and buffered output. Assert:

```go
func TestOfficialCatalogMatrixIsTruthful(t *testing.T) {
    result := runIsolatedBaseline(t, baselineOptions{ExternalProbes: false})
    assertEveryApplicableTargetInstanceReportedOnce(t, result)
    assertImplementedFixtureTargetsComplete(t, result)
    assertUnsupportedDynamicTargetsVisible(t, result)
    assertNoContainerAsset(t, result.Inventory, "cache")
    assertNoRawFixtureRoot(t, result)
    assertNoSecretFixtureValue(t, result)
    assertRunnerAndInspectorUnused(t, result)
}
```

Add separate cases for:

- every user and project MCP path in the approved design, both JSON container spellings, and Codex TOML stdio/HTTP;
- two projects with the same MCP server name retaining two observations;
- nested plugin cache with no `cache` asset;
- same IDE extension in two locations retaining two observations;
- same package through two enabled fake managers retaining two observations;
- a hostile identity/malformed/symlink sibling making the affected target partial while safe siblings persist;
- v1 migration-3 snapshot read as legacy through status.v2;
- v2 baseline, process-style SQLite close/reopen, status, unchanged second scan, then one observed-location change;
- absence of any real-home sentinel, network client, registry, marketplace, Docker daemon, or unconfigured root access.

For fixed targets, “reported once” means one result for the target ID. For expanded project and JetBrains targets, it means one result for each unique `(targetId, instanceRef)` pair plus an explicit base result when the expansion root is missing. All helper constructors, fakes, target assertions, and fixture-secret sentinels are defined in `usecase_matrix_test.go`; no undeclared helper names remain.

- [ ] **Step 2: Run the acceptance test and verify RED**

Run: `go test ./internal/acceptance -run 'TestOfficialCatalogMatrix|TestV2BaselineReopenStatus' -count=1`

Expected: missing fixtures and/or unimplemented final wiring make at least one matrix assertion fail.

- [ ] **Step 3: Add only synthetic official-path fixtures**

Populate each fixture with clearly fake `.invalid` URLs, non-secret placeholder values, deterministic names/versions, and no executable content. Include collision and malformed sibling cases in per-test temporary homes rather than the shared happy-path fixture. Never copy real user configuration, tokens, marketplace caches, or absolute machine paths into the repository.

- [ ] **Step 4: Finish production wiring exposed by the matrix**

Register agents, IDE, projects, and packages in the primary orchestrator; retain MCP as the explicit single follow-up after projects so raw local targets never require a general dependency scheduler. Ensure every production collector now implements `TargetedCollector`, every fixed catalog spec or expanded `(targetId, instanceRef)` has exactly one result, raw `LocalTargets` are cleared, package probes inherit the parsed opt-in, and status uses the latest persisted full snapshot.

Fix only defects exposed by the acceptance matrix; do not add content hashing, TI, policy, blocking, adapters, signing, network updates, or broader filesystem discovery.

- [ ] **Step 5: Rewrite README claims to the tested boundary**

Use these exact claims:

- “macOS local inventory within versioned developer-tool catalogs and configured project roots”;
- default project scope is `$HOME/Projects`, with repeatable `--project-root` for additional roots;
- package/Docker command probes are disabled unless `--external-probes` is supplied;
- target status distinguishes not present, skipped, unsupported, unavailable, and partial;
- no daemon, kernel sensor, arbitrary personal-file scan, malware verdict, or safety guarantee;
- plugin/project content hashing, TI, Git-managed policy, organization integrations, host adapters, warnings, and blocking remain later programs.

Remove “across the laptop,” “all plugins,” and any implication that an optional command's mere availability enriches the default baseline. Show both default and opt-in command examples and retain the single-static-binary distribution statement.

- [ ] **Step 6: Append a dated revalidation section to the gap report**

In `docs/testing/2026-08-06-use-case-validation.md`, preserve the original evidence and append the implementation commit range plus the exact acceptance commands. Mark only these gaps closed: truthful target coverage, occurrence preservation, official local catalog parsing, external-probe opt-in/evidence, and non-Darwin rejection. Keep content hashing/provenance, TI, policy, organizational integrations, host adapters, warnings, and blocking explicitly open.

- [ ] **Step 7: Run formatting and the complete verification suite**

Run:

```bash
gofmt -w cmd internal
go test -race -count=1 ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/ssc-init-linux-compile-guard ./cmd/ssc-init
git diff --check
```

Expected: every command passes with no real-home/network/daemon dependency. Review the resulting diff against all twelve acceptance criteria in the design and search for forbidden claims and leaked values:

```bash
rg -n 'across the laptop|laptop-wide|all plugins|must-not-persist|super-secret|Bearer secret' README.md docs internal testdata
```

Expected: only negative test fixtures/assertions may contain secret sentinels; public claims contain none of the overbroad phrases.

- [ ] **Step 8: Commit acceptance evidence and documentation before release build**

```bash
git add internal/acceptance testdata README.md docs/testing/2026-08-06-use-case-validation.md
git commit -m "test: validate trustworthy inventory scope"
git status --short
```

Expected: clean worktree. If the matrix required production fixes, include each fix in the owning task's commit or a focused additional commit before this documentation/test commit; never hide unrelated production changes here.

- [ ] **Step 9: Run clean reproducible Darwin release gates**

Run only after the commit leaves a clean worktree:

```bash
go test ./scripts -count=1
sh scripts/build-darwin.sh
file dist/ssc-init-darwin-arm64 dist/ssc-init-darwin-amd64
shasum -a 256 -c dist/checksums.txt
./dist/ssc-init-darwin-$(go env GOARCH) version --json
git status --short
```

Expected: reproducible CGO-free arm64/amd64 Mach-O artifacts, valid checksums, the native binary reports `dev+git.<HEAD>`, and ignored `dist/` leaves the worktree clean.

- [ ] **Step 10: Request independent implementation review**

Use `superpowers:requesting-code-review` against the complete implementation range. Require the reviewer to check spec coverage, privacy boundaries, target aggregation, migration compatibility, hostile filesystem/identity behavior, default-zero external execution, and claims-versus-tests. Address findings with focused RED/GREEN commits, rerun Steps 7 and 9, and finish only with a clean worktree.
