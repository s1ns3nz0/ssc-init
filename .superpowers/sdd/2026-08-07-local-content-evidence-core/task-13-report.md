# Task 13 — Baseline pipeline, report JSON, status v3, and cache handoff

Base: `703736d` (docs: report Task 12 implementation)
Product commit: `a68f952`

## Delivered

- `internal/scan/service.go` moves the baseline contract to
  `ssc-init.scan.v3` and integrates the evidence engine in the exact design
  §6.3 order: collect → sealed project-MCP follow-up → graph build/normalize
  (`inventory.Build`) → engine issuance/graph validation → local evidence
  collection → runtime-target clearing (inside `Engine.Collect`, before any
  report or persistence use) → evidence-aware delta → atomic `SaveScan` →
  best-effort content-cache write. Evidence records are appended to the
  normalized inventory and sorted by ID; the engine's target results already
  arrive ordered by TargetID/ObservationID/EvidenceID.
- Cache wiring is automatic and interface-driven: when the snapshot store's
  dynamic type implements `evidence.LeafCache` the engine uses it, otherwise
  the explicit `evidence.DisabledLeafCache{}`. After a successful `SaveScan`,
  a store implementing `evidence.CacheWriter` receives the collection's cache
  writes; the error is deliberately dropped (best-effort, spec §9), and no
  write is attempted when the snapshot commit failed or there is nothing to
  write.
- `overallStatus` now requires evidence coverage `complete` in addition to
  complete discovery and an error-free graph. Zero accepted targets with
  complete discovery yield `evidenceCoverage: {status: "complete",
  targets: []}` (the engine's empty-candidate status, with `Targets`
  normalized to a non-nil empty slice by the service), so an all-discovery
  scan stays `complete` rather than reporting unknown coverage.
- `collectProjectMCP` now clears the replaced initial `mcp` result's runtime
  evidence state (`collector.ClearLocalEvidenceTargets`) when it is dropped
  from the merged results, so no sealed target or issuer nonce survives the
  follow-up merge outside the engine's own clearing path. The follow-up MCP
  result's and the projects collector's own evidence targets flow through to
  the engine unchanged (locked by test).
- The service also normalizes `Inventory.Observations` to a non-nil slice so
  the v3 inventory contract serializes every graph slice as an array.
- `internal/report/json.go`: `baselinePayload` gains `EvidenceCoverage`
  immediately after collector coverage; a report-private `inventoryPayload`
  keeps `assets`, `observations`, `evidence`, `relationships` always present
  (matching the plan's exact golden), `errors` still omitted when empty. No
  `version`/`doctor` contract change; no "full scan" phrasing exists.
- `internal/cli/run.go`: status is `ssc-init.status.v3`. Only
  `ssc-init.scan.v3` snapshots surface `scope`, `coverage`, and a new
  `evidenceCoverage` object. v1 **and now v2** snapshots return
  `legacyInventory: true` with their persisted inventory (nil evidence
  serializes as `"evidence":null`) and never echo scope, coverage, or any
  evidence coverage — locked by a test whose v2 snapshot deliberately carries
  a complete `EvidenceCoverage` that must not appear. Error messages are
  unchanged and path-free.
- **Store edit (authorized narrow exception, flagged):**
  `internal/store/validation.go` implements the deferred Task 12 gating
  decision now that the version string exists: a `ssc-init.scan.v3` snapshot
  must carry one non-zero (valid) evidence coverage object and a non-nil
  evidence slice; earlier schema versions keep their lenient legacy behavior.
  The gate runs in `validateSnapshot`, so it applies to both `SaveScan` and
  `LatestSnapshot` (a manually deleted v3 `evidence_coverage` row now fails
  the load). Content validity of a non-zero coverage object was already
  enforced by Task 12's `validateEvidenceCoverageResult` and is not
  duplicated. Full evidence↔coverage bijection remains unenforced at the
  store: rejected targets legitimately produce coverage errors without
  records, and the referential/uniqueness checks from Task 12 plus this
  presence gate cover the v3 shape without guessing engine semantics.
- `cmd/ssc-init/main.go` needed no code change — the CLI already hands the
  concrete `*store.Store` to `scan.NewService`, and the service's type
  assertions see the dynamic type through the `applicationStore` interface.
  `main_test.go` locks this with
  `TestDefaultStoreSupportsAutomaticEvidenceCacheWiring`, which opens the
  real default store and asserts it implements `evidence.LeafCache` and
  `evidence.CacheWriter`.

## TDD evidence (RED → GREEN)

- Scan (Step 1/2 RED): `go test ./internal/scan -run
  'Evidence|Cache|GraphNormalization|Baseline' -count=1` failed with 9
  failures — e.g. `TestBaselineCollectsEvidenceAfterGraphNormalization:
  scan={SchemaVersion:ssc-init.scan.v2 … EvidenceCoverage:{Status: …}}` with
  `LocalEvidenceTargets` (raw temp paths) visibly surviving in
  `scan.Coverage`, `TestBaselineCacheHandoff… saved=1` with no cache calls,
  and `TestBaselineZeroAcceptedTargets…` showing empty coverage status.
  GREEN after the service change: `ok github.com/ssc-init/ssc-init/internal/scan`.
- Report (Step 4 RED): `TestWriteJSONMatchesV3BaselineGolden` failed —
  output lacked `"evidenceCoverage"` and `"observations"`; the shape test
  also failed on coverage/evidenceCoverage ordering. GREEN after
  `json.go` rewrite.
- CLI (Step 4 RED): all four status subtests failed
  (`schemaVersion":"ssc-init.status.v2"`, v2 wrongly surfacing
  scope/coverage, v3 wrongly marked legacy). GREEN after `run.go` change.
  The rewritten baseline golden test (inline v3 golden, no dependency on the
  Task 14-owned `testdata/golden/baseline.json`) passed once scan/report were
  in place.
- Store (RED): `TestSnapshotV3RequiresEvidenceCoverageAndEvidenceInventory`
  failed on all three gate subtests (`SaveScan error=nil`,
  `LatestSnapshot error=nil` after coverage-row deletion). GREEN after the
  11-line `validation.go` gate.

## New pipeline tests (internal/scan/service_test.go)

- `TestBaselineCollectsEvidenceAfterGraphNormalization` — plan sketch adapted
  (renamed locals to avoid shadowing the `collector`/`evidence` packages;
  uses a sealed file-evidence collector plus `testEnvironment(t)`): v3
  version, one complete evidence record with the expected SHA-256, complete
  evidence coverage referencing the record, cleared targets and issuers in
  returned and persisted coverage, evidence `added` delta entry, and no raw
  root path in the serialized scan+inventory.
- `TestBaselineRejectsEvidenceForObservationRemovedByGraphNormalizationWithoutPathAccess`
  — an orphan observation dropped by graph normalization: its sealed target
  becomes a `target_rejected` coverage error, produces no evidence, never
  opens the fixture root (recording FS), and degrades both evidence coverage
  and overall scan to `partial`. This also locks the Task 11 review's
  pip/pipx `target_rejected` degradation at pipeline level.
- `TestBaselineProjectMCPFollowUpPreservesProjectsAndMCPEvidenceTargets` —
  real `projects` collector + sealed MCP follow-up over a project with
  `package.json` and `.mcp.json`: complete `project-manifest:package.json`
  file evidence and complete `mcp-declaration` semantic evidence coexist,
  coverage targets match evidence count, no runtime state or raw path
  survives.
- `TestBaselineEvidenceChangeContributesToDelta` — evidence digest change in
  the previous snapshot produces a `changed`/`evidence` delta entry.
- `TestBaselinePartialEvidenceMakesCompleteDiscoveryPartial` — unsupported
  preset evidence flips a fully complete discovery scan to `partial` while
  discovery coverage itself stays `complete`.
- `TestBaselineZeroAcceptedTargetsYieldsCompleteEmptyEvidenceCoverage` —
  complete empty (non-nil) coverage, overall `complete`, non-nil evidence and
  observations slices.
- `TestBaselineCacheHandoffIsBestEffortAfterSave` — three subtests: a
  failing `StoreContentCache` still returns a successfully persisted scan
  (store-backed cache wired: leaf lookups observed, `cache:miss` metadata,
  one non-empty write batch); a failing `SaveScan` prevents any cache write;
  a plain memory store gets the disabled cache (`cache:disabled`).

## Verification (exact commands)

- PASS `go test ./internal/scan ./internal/report ./internal/cli ./cmd/ssc-init ./internal/store -count=1`
- PASS `go test -race ./internal/scan ./internal/report ./internal/cli ./cmd/ssc-init ./internal/store -count=1`
- PASS `go vet ./...`
- PASS `git diff --check` (no output); `gofmt -l` on all touched packages (no output)
- PASS focused `-count=20`:
  `go test ./internal/scan -run 'TestBaselineCollectsEvidenceAfterGraphNormalization|TestBaselineRejectsEvidenceForObservationRemoved|TestBaselineProjectMCPFollowUpPreserves|TestBaselineEvidenceChangeContributesToDelta|TestBaselinePartialEvidenceMakes|TestBaselineZeroAcceptedTargets|TestBaselineCacheHandoff' -count=20`,
  `go test ./internal/store -run 'TestSnapshotV3RequiresEvidenceCoverage' -count=20`,
  `go test ./internal/cli -run 'TestBaselineJSON|TestStatusJSON' -count=20`,
  `go test ./internal/report -run 'TestWriteJSON' -count=20`
- `go test ./... -count=1` post-commit: only `internal/acceptance` fails
  (3 tests, Task 14 owns); `scripts` passes on the clean worktree.

## Full-suite failure audit (expected shape change)

The acceptance failure *set* changed with the v3 contract, verified by
running `./internal/acceptance` in a temporary worktree at base `703736d`:

- Base (pre-Task 13): `TestBaselineFixturePersistsWithRealStore`,
  `TestBaselinePersistsSameMCPServerFromTwoProjectsWithRealStore`,
  `TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta`.
- Now (post-Task 13): the two real-store baseline tests **pass** (they were
  staged for the v3 pipeline), and the failing three are:
  - `TestBaselineFixtureNeverReadsRealHome` —
    `baseline_test.go:75: schemaVersion=ssc-init.scan.v3` (golden still
    expects v2 output);
  - `TestMigrationThreeLegacySnapshotSurfacesThroughStatusV2` —
    `usecase_matrix_test.go:732: legacy status={SchemaVersion:ssc-init.status.v3 …}`
    (expects `ssc-init.status.v2`);
  - `TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta` —
    `usecase_matrix_test.go:768: v2 status provenance={SchemaVersion:ssc-init.status.v3
    … InventorySchemaVersion:ssc-init.scan.v3 …}` (expects v2 shapes).

All three are golden/contract updates owned by Task 14; `internal/acceptance`
and `testdata/` were not touched.

## Files changed (commit `a68f952`)

- `internal/scan/service.go`, `internal/scan/service_test.go`
- `internal/report/json.go`, `internal/report/json_test.go`
- `internal/cli/run.go`, `internal/cli/run_test.go`
- `cmd/ssc-init/main_test.go` (`main.go` unchanged — wiring is automatic;
  the new test locks it)
- **Store (flagged narrow exception):** `internal/store/validation.go`
  (11-line v3 presence gate), `internal/store/evidence_test.go` (gate tests)

## Self-review

- Pipeline order matches §6.3 one-to-one; evidence cannot resurrect
  normalization-rejected entities (locked by the orphan test), and runtime
  targets/issuers are cleared before any report or persistence use, including
  the previously uncleared replaced initial MCP result.
- §6.2 held: one target result per sealed target, ordering deterministic,
  non-complete required evidence forces partial coverage and partial scan,
  discovery coverage is never rewritten by evidence outcomes.
- §13 invariants: no raw path or secret enters JSON (byte-level assertions in
  the new tests), all CLI/service error strings unchanged and path-free,
  output deterministic (fixed clock/UUID goldens byte-exact).
- Legacy truthfulness: v1/v2 status is `legacyInventory: true` with nil
  evidence and no evidence-coverage claim even if a coverage object is
  somehow present in the snapshot.

## Concerns

- Overall-status strictness: per the task instruction, only evidence coverage
  `complete` yields a `complete` scan, so an all-`skipped` evidence coverage
  (engine status `skipped`) reports the scan as `partial`. Spec §6.2 lists
  partial/oversize/unavailable/unsupported as the coverage blockers and is
  silent on all-skipped at scan level; if product direction wants deliberate
  skips to keep a scan `complete`, it is a one-line change in
  `overallStatus` plus a test.
- Baseline JSON serializes a nil observations slice as `"observations":null`
  when a caller bypasses the scan service (the service itself always
  normalizes to `[]`). The report layer deliberately does not invent non-nil
  slices for data it did not receive.
- The status payload for a hypothetical v3 snapshot with a zero
  `EvidenceCoverage` would render an empty object; the new store gate makes
  such a snapshot unloadable from the real store, so this is unreachable
  through shipped wiring.
- The v2-legacy status change (v2 no longer surfaces scope/coverage) is a
  deliberate contract decision from the plan ("A v1/v2 snapshot returns
  legacyInventory=true"): a v2 snapshot cannot substantiate v3 coverage
  claims. Task 14's acceptance goldens must encode this.
