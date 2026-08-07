# Task 12 — Snapshot v3 persistence, migration 5, and SQLite cache

Base: `4b3a5edb` (docs: report Task 11 implementation)
Product commit: `991e789`

## Delivered

- Migration 5 in `internal/store/migrations.go` creates `evidence`,
  `evidence_state`, `evidence_coverage`, and `content_cache` exactly as
  specified in the plan, and adds `evidence_nil` (default 1) and
  `evidence_count` (default 0) to `inventory_state`. The migration runs as one
  transaction; a conflicting pre-existing table rolls the whole step back and
  leaves the database at version 4.
- All closed schema-verification contracts were extended: `requiredColumns`
  (exact name/type/nullability/default/pk position for the four new tables and
  the two new `inventory_state` columns), `requiredChecks` (index/nil-flag
  checks on `evidence_state`, key-length and size checks on `content_cache`,
  the two new `inventory_state` checks), `requiredForeignKeys` (the three
  evidence foreign keys including both compound keys binding `scan_id` to the
  same scan column, the `evidence_state`→`evidence` compound key, and
  `evidence_coverage`→`scans`; `content_cache` is verified to have none), and
  `requiredIndexFingerprints` (primary keys plus the
  `(scan_id, evidence_index)` unique index). Future, missing, gapped,
  reordered, or shape-conflicting histories still fail open through the
  untouched `applyMigrations` ordering check.
- `internal/store/evidence.go` adds save/load/validation for evidence:
  - `saveEvidence` writes `evidence` + `evidence_state` rows preserving order
    (`evidence_index`) and nil shapes (`metadata_nil`, `errors_nil`);
  - `saveEvidenceCoverage` writes exactly one `evidence_coverage` row for a
    non-zero `scan.EvidenceCoverage`, via `persistedEvidenceCoverage` /
    `persistedEvidenceTargetResult` structs that keep nil-versus-empty target
    and error slices distinguishable and contain no runtime target fields;
  - `loadEvidence` establishes asset and observation maps before decoding,
    checks state presence, contiguous indexes, row-level asset/observation
    references (including observation-owner equality), JSON/row ID agreement
    for evidence ID, asset ID, and observation ID, and nil-flag consistency;
  - `loadEvidenceCoverage` returns the zero value when no row exists (legacy
    scans) and rejects an empty stored coverage object;
  - `validateContentEvidence` enforces the design's persistence rules:
    required identifiers, closed kind/subject pairs, closed status vocabulary,
    kind/status pairing (package-content and container-identity are
    terminal-only), references to present assets/observations with matching
    owner asset, recomputed `identity.FinalizeEvidence` ID equality (subsumes
    malformed-ID detection), non-negative and kind-consistent counts,
    lowercase SHA-256 + `sha256` algorithm for complete evidence, tree subset
    digests for partial/oversize, digest-free terminal payloads, the closed
    `completeness`/`cache` metadata vocabulary, and error entries passed
    through the existing secret and path-masking validators (max 64);
  - `validateEvidenceCoverageResult` requires a valid coverage status,
    resolvable unique evidence references with matching asset, observation,
    and status, and validated error entries; the all-zero coverage value is
    the explicit "not run / legacy" shape.
- `SaveScan` persists in the required order — assets, observations, evidence,
  relationships, collector coverage, evidence coverage, inventory errors,
  inventory state — inside the existing single snapshot transaction, so any
  evidence write failure rolls back everything. `LatestSnapshot` loads and
  revalidates evidence and evidence coverage; `inventory_state` row counts now
  include the evidence count and nil flag.
- `internal/store/content_cache.go` implements `evidence.LeafCache` and
  `evidence.CacheWriter` on `*Store` with compile-time assertions. `Lookup`
  accepts only rows carrying the exact `ssc-init.content-cache.v1` format,
  `sha256` algorithm, lowercase 64-hex digest, and non-negative size; anything
  else is a miss, never trusted content and never a scan failure.
  `StoreContentCache` runs its own transaction, upserts valid complete
  entries (touching `last_used_at` for reused keys), prunes rows unused for
  90 days, then prunes the oldest rows above the cap (250,000 in production;
  `contentCacheRowLimit` on `Store` is the injected test seam, zero means
  production default and it is not CLI-configurable). Failure rolls back only
  the cache transaction.
- v1/v2 compatibility: legacy rows load with a nil evidence slice, the two new
  `inventory_state` columns default to nil/zero, and a scan without an
  `evidence_coverage` row loads the zero `EvidenceCoverage` value — legacy
  snapshots can never imply evidence coverage. The scan schema-version string
  change to `ssc-init.scan.v3` remains Task 13's; the store is
  version-agnostic and persists whatever shape validation accepts.

## TDD record

- RED (Step 2): `go test ./internal/store -run 'Migration5|EvidenceSchema|ContentCacheSchema' -count=1` →
  `--- FAIL: TestMigration5AddsEvidenceAndContentCacheSchema` with
  `applied migration=4 want=5`;
  `--- FAIL: TestMigration5RollsBackAsOneTransaction` with
  `conflicting migration unexpectedly opened`; every
  `TestEvidenceSchemaRejectsIncompatibleShapes` /
  `TestContentCacheSchemaRejectsIncompatibleShapes` subtest failed with
  `affected=0` (tables absent) or `incompatible schema unexpectedly opened`.
- GREEN: after adding migration 5 and the four verification-contract
  extensions, the same filter passed, and the full store suite stayed green.
- RED (Step 5): `go test ./internal/store -run 'Evidence|SnapshotV3|Corrupt' -count=1` →
  `--- FAIL: TestSnapshotV3EvidenceRoundTrip` (loaded snapshot had
  `Evidence:[]model.ContentEvidence(nil)` and zero `EvidenceCoverage`), both
  shape round-trip tests failed on lost nil/empty distinctions, and all 29
  `TestSnapshotV3EvidenceValidationHappensBeforeTransaction` subtests failed
  with `error=<nil>` — evidence was neither saved nor validated.
- GREEN: after `evidence.go`, the `validateSnapshot` hook, and the
  `SaveScan`/`LatestSnapshot` wiring, the same filter passed.
- RED (Step 7): `go test ./internal/store -run 'Cache' -count=1` → build
  failure: `store.StoreContentCache undefined (type *Store has no field or
  method StoreContentCache)` and `s.Lookup undefined` across
  `content_cache_test.go` — the plan's
  `TestCacheWriteFailureDoesNotRollbackCommittedSnapshot` was included
  verbatim (adapted only for the fixture helpers it names).
- GREEN: after `content_cache.go` and the `contentCacheRowLimit` seam on
  `Store`, the cache filter passed.
- Regression guards added alongside (GREEN-by-construction, verified against
  the corruption suites): `TestMigration5PreservesLegacyV2Snapshot`,
  `TestSnapshotV3EvidenceRowFailureRollsBackEveryTable` (trigger-forced
  failure on the last evidence table shows full-snapshot rollback), and
  `TestSnapshotV3EvidenceRuntimeTargetsNeverPersist` (byte-level SQLite scan
  for the runtime root path).

## Security and integration decisions

- Evidence identity is recomputed on every save and load via
  `identity.FinalizeEvidence` and compared to the stored ID, so a snapshot
  cannot bind evidence content to a different observation/kind/subject tuple
  than the one that produced its ID, and malformed IDs are rejected without
  a bespoke parser.
- Evidence free-text surfaces are minimal by construction: subjects, statuses,
  kinds, algorithms, and metadata are closed vocabularies; error codes and
  messages run through the existing `validateRequiredString` +
  `validatePersistenceSafePath` pipeline, so credential shapes
  (`ErrSensitiveSnapshot`, fixed string) and raw or percent-encoded absolute
  paths (`errUnsafeSnapshotPath`, fixed string) are rejected before any row is
  written, and rejection messages never echo the offending value
  (asserted in the validation test against the raw-path sentinel).
- The two compound evidence foreign keys are verified column-by-column through
  `foreignKeyFingerprint`, including the `scan_id → scan_id` mapping in each,
  so both must bind to the same scan; the split-key, reordered-column, and
  cross-column rewrites in `TestEvidenceSchemaRejectsIncompatibleShapes` all
  fail open.
- Evidence coverage persists through dedicated persisted structs, mirroring
  the collector-coverage pattern: runtime `LocalEvidenceTargets` /
  `LocalEvidenceIssuer` fields have no persistence representation. Consistent
  with the established store behavior for `LocalTargets` (see
  `TestLatestSnapshotPreservesCoverageNilAndEmptyShapes`), surviving runtime
  targets are excluded rather than causing rejection;
  `TestSnapshotV3EvidenceRuntimeTargetsNeverPersist` asserts none of their
  bytes reach the database or WAL files.
- The cache is fully subordinate to snapshots: `StoreContentCache` begins its
  own transaction only when called (after the caller's snapshot commit),
  invalid writes are skipped rather than failing the batch, corrupt rows
  produce misses, and the dropped-table test proves a cache failure reports an
  error while the committed snapshot stays readable. Cache rows contain only
  the opaque 32-byte key, algorithm, format, digest, size, and use time —
  no path, observation ID, subject, or fingerprint columns exist to populate.
- Retention pruning uses only `last_used_at` (fixed-width UTC timestamps whose
  lexicographic order is chronological) and the opaque key as the
  deterministic tie-breaker.
- No new dependency; `internal/store` now imports `internal/evidence` and
  `internal/identity` (both already store-adjacent, no import cycle).

## Verification

- PASS: `go test ./internal/store -count=1`
- PASS: `go test -race ./internal/store -count=1`
- PASS: `go vet ./internal/store/...`
- PASS: `git diff --check` (no output), `gofmt -l internal/store/` (no output)
- PASS: `go test ./internal/store -run
  'Migration5|EvidenceSchema|ContentCacheSchema|SnapshotV3|Cache|Corrupt'
  -count=20` (project convention for adversarial suites)
- `go test ./... -count=1` retains the known staged Task 13–14 failures
  unchanged: `internal/acceptance`
  (`TestBaselineFixturePersistsWithRealStore`,
  `TestBaselinePersistsSameMCPServerFromTwoProjectsWithRealStore`,
  `TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta`) and
  `internal/cli` (`TestBaselineJSONReportsPartialCoverageAndPersists`,
  `TestStatusJSONHasStableEmptyV1AndV2Shapes`). The acceptance failure site
  (`real_store_test.go:65`) was compared against the stashed base commit and
  is identical, so the store change did not flip any staged failure text.
  `scripts` (`TestBuildScriptWorksOutsideRepositoryAndIsReproducible`) fails
  only on a dirty worktree, as documented in the Task 11 report.
- One full-suite run showed
  `internal/collector/packages/TestRealPATHSpoofIsRecordedByActualHashAndSafeLocation`
  failing at its 5-second deadline under whole-repo parallel load; it passes
  in isolation (`-count=1`, 0.46s) and does not touch the store. Recorded as a
  load-sensitive flake, not a regression.

## Concerns

- The store validates evidence records against the engine's structural
  contract (digest/status/count/metadata rules) but deliberately does not pin
  the engine's closed error code/message list. Pinning it would make old
  snapshots unreadable the moment the engine adds an error string; instead
  errors are held to the non-empty/secret-free/path-free rules. If reviewers
  want the closed list enforced at the store boundary too, it is a small
  addition to `validateEvidenceErrors`.
- Evidence coverage is validated for referential integrity (every target must
  resolve to a present evidence record with matching asset, observation, and
  status; duplicates rejected) but the store does not require a bijection
  between evidence records and coverage targets, nor does it require coverage
  to be present whenever evidence is. That version/shape gating belongs to
  the Task 13 `ssc-init.scan.v3` contract change; enforcing it in the store
  now would have to guess Task 13's legacy-versus-v3 signal.
- `Lookup` intentionally leaves corrupt cache rows in place (read path stays
  read-only); they are unusable (always a miss) and are removed by the next
  cache transaction's retention/cap pruning or overwritten by an upsert.
- Metadata `completeness` values are pinned to the status (`complete` for
  complete evidence, `observed-subset` for partial/oversize), matching
  exactly what `finalizeRecord` emits today. A future engine metadata key
  would need a coordinated store change — which is the intended fail-closed
  direction.
