# Task 11 — Explicit unsupported package and container identities

Base: `6e93c916529c37a0579fbbbe873bda875e1c021d`
Product commit: `43971ed`

## Delivered

- Added `internal/collector/packages/evidence.go` with
  `issuePackageArtifactEvidence`, which seals exactly one path-free terminal
  `unsupported` evidence target per package observation through the sealed
  `evidence.Issuer` bound to the collector result.
- Non-Docker package observations use target ID `packages.<ecosystem>.content`,
  kind `package-content`, subject `package-content`. Docker package
  observations use target ID `packages.docker.container-identity`, kind
  `container-identity`, subject `container-image`.
- Targets carry no path, anchor, algorithm, digest, size, count, or metadata.
  The issued `Anchor` is the zero value, `RootPath`/`RelativePath` are empty,
  and `PresetStatus` is `unsupported`.
- `model.AssetTool` observations — the per-probe `tool-executable:sha256:…`
  identities and the `tool:go:<name>` GOPATH binaries — receive no target. Only
  observations whose surviving appended asset has type `model.AssetPackage` are
  issued.
- Added `abortPackageCollection`, mirroring the projects collector: every
  context-cancellation exit from `Collect` now clears issued runtime targets,
  proofs, and the issuer, and returns an empty result rather than partially
  issued state.
- Replaced the two remaining `"packages.docker"` string literals in
  `collector.go` with the new `dockerProbeTargetID` constant so probe-identity
  branching cannot drift from evidence issuance.

## TDD record

- RED: `go test ./internal/collector/packages -run UnsupportedEvidence -count=1`
  →
  `--- FAIL: TestPackageObservationsIssueVisibleUnsupportedEvidence`
  `observation={… AssetID:pkg:pypi/ruff@0.5.0 …} target={TargetID: AssetID: … PresetStatus: …} present=false`
  (no targets emitted at all).
- RED (same round, full new file):
  `--- FAIL: TestPackageEvidenceTargetsUseDockerAndPackageIdentitiesOnly` →
  `containers=0 contents=0 targets=[]`;
  `--- FAIL: TestPackageEvidenceCollectsAsTerminalUnsupportedWithoutHostAccess`
  → `fixture issued no evidence targets`.
- GREEN: after adding `issuePackageArtifactEvidence` and the `AssetPackage`-only
  call from `appendPackageEvidence`, all four new evidence tests passed.
- Intermediate RED→GREEN inside the kind/subject test: the first version derived
  the expected non-Docker target ID from `asset.Source`, which failed with
  `asset={… Source: …}` because `appendPackageEvidence` clears
  `candidate.Source` before appending. The assertion was corrected to derive the
  ecosystem from the finalizing probe (`observation.Source + ".content"`, cross
  checked against `observation.Metadata["manager"]`) and now also asserts the
  appended asset's `Source` is empty, locking that invariant down.
- RED for cancellation: with `abortPackageCollection` stubbed to
  `return *result, err`,
  `go test ./internal/collector/packages -run TestCanceledPackageCollectionReturnsNoPartiallyIssuedEvidence -count=1`
  failed with
  `canceled collection returned issued evidence: {… LocalEvidenceIssuer:0x… LocalEvidenceTargets:[{TargetID:packages.npm.content … PresetStatus:unsupported …}]}`.
- GREEN: restoring the real `abortPackageCollection` and routing every
  ctx-error exit through it made the test pass.
- `TestPackageToolObservationsReceiveNoEvidenceTarget` and the skipped-scope
  assertion added to `TestPackageProbesAreSkippedByDefault` are invariant
  guards; they cannot be observed RED against a correct implementation and are
  present to fail any future over-issuance.

## Security and integration decisions

- Package and container artifacts are not local content. Rather than silently
  omitting them from the evidence graph, they are now visibly terminal
  `unsupported`, so a report cannot read as "fully covered" while whole
  ecosystems were never examined.
- Every target is issued through `evidence.BindCollectorResult` /
  `Issuer.Issue`, so a mutated target tuple fails the engine's seal check. When
  binding fails closed (inactive or foreign lifecycle) issuance is skipped
  silently, matching the established `mcp` and `projects` behavior.
- Target IDs are derived from the fixed probe catalog, never from parsed probe
  output, so no external string can reach a target ID. They satisfy
  `validTargetID`: lowercase identifier components and the mandatory
  `packages.` collector prefix.
- The evidence path performs no filesystem, network, or process access.
  `TestPackageEvidenceCollectsAsTerminalUnsupportedWithoutHostAccess` runs the
  real engine over the real collector output with a counting
  `platform.FileSystem` (including `OpenRoot`/`Lstat`/`WalkDir`) and a counting
  runner, and asserts both counters are exactly zero. Counting rather than
  panicking fakes were used deliberately, because the engine recovers panics
  into `unavailable` records and would have masked a violation.
- The same test asserts zero `Coverage.Errors` (no `target_rejected`), one
  terminal `unsupported` record per target with empty algorithm/digest/size/
  counts/metadata/errors, coverage status `partial`, and zero cache writes.
- Probe behavior is unchanged: coverage statuses, `docker_unavailable`
  classification, executable inspection/verification order, parser-loss
  accounting, and issue accumulation all still pass their existing suites.
- No dependency was added; no path, digest, or secret is persisted by the new
  code.

## Verification

- PASS: `go test ./internal/collector/packages ./internal/evidence -count=1`
- PASS: `go test -race ./internal/collector/packages ./internal/evidence -count=1`
- PASS: `go vet ./internal/collector/packages/... ./internal/evidence/...`
- PASS: `git diff --check` (no output)
- PASS from the clean product commit:
  `go test ./scripts -run TestBuildScriptWorksOutsideRepositoryAndIsReproducible -count=1`
- `go test ./... -count=1` retains only the known staged Task 13–14 failures:
  `internal/acceptance` (`TestBaselineFixturePersistsWithRealStore`,
  `TestBaselinePersistsSameMCPServerFromTwoProjectsWithRealStore`,
  `TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta`) and
  `internal/cli` (`TestBaselineJSONReportsPartialCoverageAndPersists`,
  `TestStatusJSONHasStableEmptyV1AndV2Shapes`). Confirmed pre-existing: the
  `scripts` release-build test only fails on a dirty worktree and passes at the
  committed state.

## Concerns

- Package-manager collisions produce duplicate asset IDs by design (see
  `TestPackageManagerCollisionsRemainCandidatesAndDistinctObservations`, where
  `pkg:pypi/black@24.4.2` is discovered by both pip and pipx). The evidence
  engine's `uniqueAssets` drops any asset ID that appears more than once in the
  normalized inventory, so both colliding targets will be rejected with
  `target_rejected` coverage errors instead of producing `unsupported` records.
  Coverage still degrades to `partial`, so nothing is silently reported as
  complete, but the resulting diagnostic is a rejection rather than the intended
  explicit unsupported statement. This is an interaction with pre-existing graph
  normalization, not something Task 11 introduced or is scoped to change; it
  likely warrants a decision during Task 12–13 reporting work.
- `abortPackageCollection` now clears partial assets/observations on every
  cancellation exit from `Collect`, not just the new issuance path. That is a
  deliberate widening required by the "do not return partial issued state"
  invariant; the orchestrator already discards a collector result whenever
  `Collect` returns an error, so no caller loses data, and no existing test
  asserted the old partial-return shape.
- No persistence, CLI, or report-schema work was added ahead of Tasks 12–14.
