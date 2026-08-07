# Task 10 — Project manifest and lockfile evidence catalog

Base: `6b1d7fc4b61d3c00cd9025b8c62ada011c002b99`
Product commit: `2bf7acaf17ff7edc8e239e3a66bc7a6389854c0f`
Review fix commit: `1993e58a46525da76301cb0b9ca41502077d42cc`

## Delivered

- Added the exact closed 18-file project manifest/lockfile catalog. Every
  target uses the normative `projects.manifest.<basename>` or
  `projects.lockfile.<basename>` ID and a 32 MiB file bound.
- Extended the descriptor-rooted, no-follow project walker to discover exact
  basenames without reading file bytes. Discovery retains the configured-root,
  project-directory, and file fingerprints while preserving exclusions,
  deterministic order, root/depth/entry/discovery limits, and existing MCP
  configuration discovery.
- Added one finalized project observation for every project found through an
  MCP configuration or catalog file. All catalog files in that directory bind
  to and reuse the same project asset and observation.
- Added verified bounded post-walk hashing and sealed runtime evidence targets.
  The engine independently reopens and verifies the configured root, project
  root, anchor file, and target file before accepting evidence.
- Preserved existing project MCP `LocalTarget` provenance, config assets,
  observations, `contains` relationships, and downstream MCP handoff.
- Added isolated terminal results for hostile files: oversized files become
  `oversize`, while unavailable or identity-changing files become
  `unavailable`, without suppressing safe siblings.
- Added catalog, exact-match, exclusion, symlink, root/file identity swap,
  configured-root project, external-root privacy, shared-basename multi-project,
  walker-limit, full mutation-matrix, oversize-isolation, post-collection
  mutation, MCP-regression, and runtime serialization tests.

## TDD record

- RED: `go test ./internal/collector/projects -run EvidenceCatalog -count=1`
  failed with `undefined: evidenceCatalog`.
- GREEN: the catalog suite passed after adding only the exact closed table and
  target-ID derivation.
- RED: `go test ./internal/collector/projects -run DiscoversManifestEvidenceAtConfiguredRoot -count=1`
  returned no project assets or observations.
- GREEN: the E2E tracer passed after descriptor discovery, project observation
  finalization, verified anchor hashing, sealed issuance, and engine collection.
- RED: `go test ./internal/evidence -run 'ProjectsOnlyTerminal|ProjectTerminalPresets' -count=1`
  rejected both project `oversize` and `unavailable` terminal targets.
- GREEN: the same suite passed after the narrow projects-only closed-subject
  preset validation and fixed diagnostic record construction were added.
- Each subsequent hostile-sibling, privacy, mutation, exclusion, and limit case
  was added as a focused vertical regression and kept green before proceeding.

## Security and integration decisions

- The directory walk opens and identity-checks catalog files but never reads
  their bytes. Content hashing occurs only after the bounded walk completes.
- Complete evidence seals a full content anchor: configured-root fingerprint,
  project-root fingerprint, asset-relative path, root-relative file path,
  discovery digest/size/mode/file fingerprint, and exact 32 MiB bound.
- Enumeration and post-walk hash fingerprints must match. The evidence engine
  then verifies the same anchor and fresh root/project binding again, catching
  mutations between collector return and evidence collection.
- Oversize/unavailable files cannot safely carry a complete content anchor.
  They therefore use path-free presets. Validation permits these statuses only
  for collector `projects`, kind `file-sha256`, and the closed
  `ProjectEvidenceSubject` vocabulary; tests prove other collectors, generic
  subjects, other statuses, paths, and anchors are rejected before filesystem
  access. Fixed public diagnostics are created inside the engine.
- Catalog basenames and subjects are intentionally public. Raw absolute paths,
  external project directory names, file contents, fingerprints, anchors, and
  issuer provenance remain runtime-only and were checked across collector,
  inventory, evidence collection, and JSON serialization.
- `.git` joins the existing excluded dependency/generated directory set. No
  discovered content is parsed or executed, and no dependency was added.
- `internal/model/evidence.go` already contained the exact Task 10 closed
  subject vocabulary from Task 1, so production model code did not require a
  duplicate edit; `internal/model/scan_test.go` now locks that catalog down.

## Verification

- PASS: `go test ./internal/collector/projects ./internal/model ./internal/evidence -count=1`
- PASS: `go test ./internal/collector/mcp ./internal/collector/projects ./internal/evidence ./internal/model ./internal/inventory -count=1`
- PASS: `go test ./internal/collector/projects -run 'Identity|Symlink|Oversize|Mutation|RuntimePaths|External|Bounded|ExactCatalog' -count=20`
- PASS: `go test -race ./internal/collector/projects ./internal/evidence -count=1`
- PASS: `go vet ./internal/collector/projects/... ./internal/evidence/... ./internal/model/...`
- PASS: `git diff --check`
- `go test ./... -count=1` has only the staged known failures: Task 13–14
  acceptance/CLI schema-fixture expectations and the release-build test's
  intentional dirty-worktree guard. All project, evidence, model, MCP,
  inventory, collector, privacy, report, scan, store, and platform packages
  passed.

## Concerns

No persistence or CLI schema work was added ahead of Tasks 12–14. Project
evidence collection remains intentionally Darwin-bound with the existing
strong filesystem fingerprint contract.

## Review fix round 1

The Task 10 review found three important gaps and one test-strength issue. All
were reproduced with focused regressions before the product changes.

### Cancellation propagation

- RED: cancellation from the walker open callback was returned as `err=nil`
  with complete project-root coverage and an `unavailable` evidence target.
  The new phase matrix also showed that cancellation immediately before hashing
  returned already-finalized project assets and observations as partial
  false-success output.
- GREEN: the walker now checks context immediately after every callback.
  `Collect`, `buildEvidence`, and target issuance check context after walking,
  before and within every bounded loop, around test-only phase seams, before
  and after hashing, and before returning. Cancellation and deadline errors are
  propagated without conversion to evidence status.
- Cancellation abort now clears any issued runtime target/proof and returns an
  empty collector result, rather than exposing partial graph or target state.
  A counting reader proves cancellation during the first hash stops before the
  next project file is read.

### Stat-known oversize files

- RED contract: the original post-walk path called `HashVerifiedFile` for a
  file already known by verified stat to be 32 MiB + 1, causing a bounded but
  unnecessary content read.
- GREEN: the walker records `oversize` only after no-follow verified open and
  matching discovery/open fingerprints. Issuance converts that marker directly
  to a sealed path-free preset. A counting filesystem proves zero content read
  calls and zero content bytes for the pre-existing oversize case.
- A separate regression grows a within-bound enumerated file immediately before
  hashing. That path still performs exactly `maxBytes + 1` bytes of bounded
  reading, emits `oversize`, and preserves its safe sibling target.

### Project graph semantics

- RED: both preset and complete filesystem project subjects were accepted when
  bound to an agent-plugin asset, non-project scope, mismatched `ProjectID`, or
  a project-config source; complete targets reached the filesystem.
- GREEN: every closed `ProjectEvidenceSubject` now requires collector
  `projects`, kind `file-sha256`, asset type `project`, scope `project`,
  `ProjectID == AssetID`, and source `projects.root`. The shared check executes
  before preset/filesystem branching and before all filesystem access.

### Mutation delta strength

- Every catalog mutation case now includes a second safe catalog sibling.
  Tests require stable evidence IDs, one changed digest only for the mutated
  subject, byte-for-byte stable sibling evidence, and exactly one
  `inventory.Diff` change for the mutated evidence ID.

### Review-fix verification

- PASS: `go test ./internal/collector/projects ./internal/evidence ./internal/model ./internal/inventory ./internal/collector/mcp -count=1`
- PASS (50x): project cancellation, hash cancellation, stat-known oversize,
  post-enumeration growth, identity swap, and post-collection mutation suite.
- PASS (50x): project graph-binding negatives, preset-contract negatives, and
  legitimate project preset positives.
- PASS: `go test -race ./internal/collector/projects ./internal/evidence -count=1`
- PASS: `go vet ./internal/collector/projects/... ./internal/evidence/... ./internal/model/... ./internal/inventory/...`
- PASS: `git diff --check`
- PASS from clean product commit: `go test ./scripts -count=1`
- `go test ./... -count=1` retained only the known staged Task 13–14
  acceptance/CLI fixture failures and the dirty-worktree release guard during
  the pre-commit run; all Task 10 and related packages passed.
