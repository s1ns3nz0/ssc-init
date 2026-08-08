# Task 14 — Isolated-home acceptance matrix, truthful docs, and release gates

Base: `7efb2bb` (docs: report Task 13 fix round 1)
Task commit: `81148b1` (`81148b127748b1bf81afa9e1620549273f630bd2`,
`test: validate local content evidence scope`)

Status: **DONE** (product code untouched; internal/acceptance, testdata,
scripts test, README, and the validation report only).

## Delivered

### Step 1 — content mutation matrix (`internal/acceptance/content_evidence_test.go`)

`TestContentEvidenceMutationMatrix` drives 51 table cases through the plan's
`contentMutationCase` shape (name/assetType/subject/mutate/wantStatus, plus
fixture, expected-delta, and probe fields). Per case: isolated `t.TempDir()`
home, baseline into a real SQLite store, one content-only mutation, rescan
with a second scan ID, fresh `store.Open` reopen, and an exact
`reflect.DeepEqual` delta assertion. Cases:

- Claude/Codex plugin manifest and payload mutations (4): manifest change →
  exactly `changed` for the manifest file evidence and payload-tree evidence
  (the manifest lives inside the tree); payload change → exactly the tree.
- Claude/Codex/Cursor `SKILL.md` body-only changes (3): `skill-document` +
  `payload-tree` changed with stable evidence IDs and unchanged frontmatter
  identity.
- VS Code, Insiders, OSS, Cursor, Windsurf × {manifest, `main` entry point,
  `browser` entry point, payload} (20): entry-point mutations change the
  entry-point file evidence + tree; manifest mutations preserve
  publisher/name/version identity.
- JetBrains `plugin.xml` (manifest + tree) and JAR-byte (tree only) (2).
- Supported-semantic MCP field change, user (`.claude.json`) and project
  (`.mcp.json` through the sealed project-MCP follow-up) (2): a semantic
  field lives in the observation metadata, so the observation identity is
  replaced — asserted as exactly removed+added observation and evidence
  entries (evidence IDs and observation IDs both change; secret-only changes
  are covered by the adversarial/semantic layers as producing no change).
- Every project catalog filename (18): exactly one `changed` evidence entry
  per mutation, complete status, lowercase 64-hex digest.
- Unsupported package content (pip probe fakes) and Docker container
  identity (docker probe fakes) (2): terminal `unsupported` evidence with no
  digest/algorithm/size/count and exactly one coverage target result.

Shared assertions per scan: `assertEvidenceCoverageTerminal` (bijection
between evidence records and coverage target results, one terminal result
per target, matching status/asset/observation), initial complete evidence
must carry a trusted lowercase SHA-256, stable evidence IDs across content
change, digest inequality after mutation, reopened SQLite equality with the
second scan (evidence non-nil), and the existing `assertPrivacyBoundary`
(report + snapshot + SQLite/WAL/SHM, denied-path recording FS).

### Step 2 — adversarial coverage (`internal/acceptance/evidence_adversarial_test.go`)

Bespoke `runAdversarialBaseline` (error-tolerant, injectable FS/context/
store) plus `triggerFileSystem`, which fires a one-shot mutation on the
first `OpenRoot` of the exact catalog root — the boundary between discovery
(descends from the home root) and the evidence stage (reopens the sealed
root). Tests:

- `SymlinkCatalogRootIsRejected` — symlinked `.codex/plugins` → no asset, no
  evidence, non-complete target, zero denied out-of-home paths, outside
  marker absent from all surfaces.
- `SymlinkEntriesAreRepresentedNeverFollowed` — final-file and intermediate
  directory symlinks → tree `partial`, `Symlinks:2`; referent content change
  leaves the digest identical (link-target bytes only); link retarget
  changes it.
- `LinkSwapAfterDiscoveryIsNeverFollowed` — payload swapped to an outside
  symlink at the evidence boundary → the sealed asset-directory fingerprint
  changed, so manifest and tree both become `unavailable/identity_changed`
  with no digest (stronger than following or hashing the swap; recorded as
  product truth).
- `ManifestAnchorSwapYieldsIdentityChanged` — manifest rewritten at the
  evidence boundary → both targets `unavailable/identity_changed`, coverage
  and scan `partial`, swapped identity never surfaces.
- `EntryPointEscapes` — parent traversal and absolute → `path_invalid`;
  missing → `read_unavailable`; symlinked → `symlink_rejected`; manifest
  stays complete; zero denied out-of-home paths; outside secret absent.
- `SpecialFilesAreNeverOpened` — FIFO (+ unix socket when bindable) in a
  payload tree → `partial` without blocking (30s watchdog).
- `ProjectFileByteBounds` — exact 32 MiB `complete` with size; 32 MiB+1 →
  `oversize/byte_limit`, no digest, partial coverage.
- `TreeLimits` — 33-deep chain → `oversize/depth_limit`; 4100 entries →
  `oversize/file_limit`; 8×32 MiB + 1 byte → `oversize/byte_limit`.
- `CancellationPreservesPreviousSnapshot` — context canceled at the
  evidence boundary → `Baseline` returns the error, previous snapshot
  intact after reopen, later clean scan complete (covers the folded Task 13
  item (a) at acceptance level; `internal/scan` untouched).
- `PermissionDenialIsIsolated` — chmod 000 payload → tree
  `partial/read_unavailable`; manifest and unrelated project evidence stay
  complete (euid-0 guarded skip).
- `HostileSiblingIsolation` — unreadable+symlinked hostile plugin sibling →
  safe plugin complete, hostile tree partial, snapshot persisted.
- `UnicodeAndHostileNames` — decomposed-NFD and shell-hostile names →
  complete tree with a digest stable across rescans. Invalid UTF-8 file
  names are rejected by APFS at fixture-creation time (`EILSEQ`); the
  attempt is made and its rejection logged — on this platform such names
  cannot exist to be scanned (unit layers cover synthetic FS cases).
- `CacheLifecycle` — miss→hit with identical digests; size-mismatched row →
  engine-side `rejected` + correct rehash; corrupt digest row → store-side
  safe miss + correct rehash; size/mtime-preserving replacement detected via
  ctime/inode fingerprint (no stale digest); cache-less memory store →
  `disabled`.
- `ExternalProjectRootPrivacy` — external configured root (allow-listed
  recording FS) → complete evidence, external absolute path absent from all
  surfaces.
- `NoReadsOutsideIsolatedHome` — decoy `$HOME` with sentinel + recording FS
  → zero denied paths, sentinel absent everywhere.

### Golden, CLI end-to-end, legacy status, real store

- `TestContentEvidenceGoldenBaselineReport` regenerates and locks
  `testdata/golden/baseline.json` as the byte-exact v3 report of the
  official fixture home (modes normalized 0700/0600 for umask-independent
  tree digests; fixed clock/UUID). Also guards report-field drift (folded
  item (b)): schemaVersion, `evidenceCoverage`, and non-empty
  `assets`/`observations`/`evidence`/`relationships` must all be present.
  Golden: 25 evidence records, evidence coverage `complete`, scan status
  `partial` (packages targets are `skipped` by default — truthful).
- `TestContentEvidenceCLIBaselineAndStatusEndToEnd` (folded item (c)) runs
  `scan --baseline --json` and `status --json` through the real `cli.App`
  argument path over the real store and full collector set, asserts the v3
  contract, complete evidence coverage, survival of project-MCP semantic
  evidence through the CLI, status/baseline equality, and no home/secret
  leak. The release-binary smoke (below) covers the env-driven `cmd` path.
- `TestMigrationThreeLegacySnapshotSurfacesThroughStatusV3AsLegacyInventory`
  (renamed): status schema is v3, payload is `legacyInventory:true`, raw
  JSON contains `"evidence":null` and none of `"scope"`, `"coverage"`,
  `"evidenceCoverage"` — the deliberate v1/v2 contract.
- `TestV3BaselineReopenStatusCacheWarmRescanAndObservedLocationDelta`
  (rewritten from the v2 test): v3 status echoes scope/coverage/evidence
  coverage; the cache-warm rescan's delta is exactly the payload-tree
  records whose recorded `cache` provenance flipped miss→hit (digests
  identical — see Concerns); the extension move produces exactly 8 entries:
  observation removed+added plus its manifest/entrypoint-main/payload-tree
  evidence removed+added with identical digests at the new identity.
- `real_store_test.go` gains v3 schema, non-nil round-tripped evidence,
  terminal coverage bijection, project-MCP semantic evidence, and
  two-project semantic evidence assertions.
- `baseline_test.go` expects v3 + evidenceCoverage.
- `matrixStatus` gains the `evidenceCoverage` field; `readMatrixStatusRaw`
  added.

### Fixtures added

`testdata/home/.vscode/extensions/acme.safe-1.2.3/dist/extension.js` — the
fixture manifest has always declared `main: dist/extension.js`; without the
file the official home's `entrypoint-main` evidence is `unavailable` and
evidence coverage `partial`. Discovery counts are unchanged, so the
52-target approved oracles hold.

### Step 4 — docs

- `README.md`: coverage section now states exactly what default scans hash
  (plugin/skill manifests + `SKILL.md` + bounded payload trees; IDE
  manifests/entry points/trees incl. JetBrains JAR bytes without archive
  enumeration; secret-free `ssc-init.semantic-mcp.v1` semantics with raw MCP
  files never hashed; exact closed project filename catalog) and that
  package payloads, immutable Docker identity, code signatures, TI, behavior
  analysis, policy, warnings, blocking, and host adapters remain
  unimplemented. "Not an EDR", "malware verdict", "safety guarantee"
  disclaimers preserved; terminal evidence statuses and the
  only-complete-is-trusted rule stated; legacy status truthfulness stated.
- `docs/testing/2026-08-06-use-case-validation.md`: appended
  "Revalidation — 2026-08-08 (local content evidence core, scan v3)" with
  the exact command list and results, fixture scope, false-negative
  boundaries (semantic MCP raw/secret-only invisibility, unsupported
  package/Docker, JAR members, wildcard filenames, non-complete digests,
  the deterministic first-cache-warm-rescan delta), and the no-contact
  proof. Historical sections untouched.
- `scripts/build-darwin_test.go`: `assertNativeIsolatedStatusV3` — the
  built native binary runs `status --json` under an isolated
  symlink-resolved `HOME`, must report `ssc-init.status.v3`,
  `initialized:false`, and create state only inside that home.

## TDD evidence (RED → GREEN)

- Step 3 RED (required): with the matrix written and before fixture/golden
  wiring, `go test ./internal/acceptance -run 'ContentEvidence' -count=1`
  failed with
  `TestContentEvidenceGoldenBaselineReport ... baseline report drifted from
  golden: got {"schemaVersion":"ssc-init.scan.v3",...} want
  {"schemaVersion":"ssc-init.scan.v2",...}` (stale v2 golden) and
  `TestContentEvidenceCLIBaselineAndStatusEndToEnd ... fixture home produced
  no complete evidence: coverage={Status:partial ...
  ide.vscode.extensions.entrypoint-main Status:unavailable
  [{read_unavailable ...}]}` (missing `dist/extension.js`). Three skill
  cases also failed on the `agent-skill` asset-type constant. GREEN after
  adding the fixture file, regenerating the golden
  (`SSC_INIT_UPDATE_GOLDEN=1`, then a clean verifying run), and the constant
  fix.
- Adversarial RED: first run failed
  `LinkSwapAfterDiscovery` (product returns `unavailable/identity_changed`
  because the sealed asset-directory fingerprint changed — stronger than the
  expected `partial` symlink representation) and
  `corrupt cache row` (store-side validation surfaces malformed digests as a
  safe `miss`, not `rejected`). Expectations were corrected to product truth
  and an engine-side `rejected` case (size-mismatched row) was added; both
  paths prove correct rehash with no stale digest. GREEN afterward.
- Pre-existing staged failures resolved: the 3 Task 13 acceptance failures
  (`baseline_test.go:75` v2 schema; `usecase_matrix_test.go:732` status.v2;
  `usecase_matrix_test.go:768` v2 shapes) now encode the v3 contract and
  pass.
- Behavior probed before assertion via a temporary (deleted, never
  committed) probe test: unchanged cache-warm rescans flip tree `cache`
  metadata miss→hit and the evidence diff includes metadata, producing a
  deterministic 3-entry `changed` delta on the official fixture home; a
  directory containing only catalog files (e.g. `go.mod`/`go.sum`) is
  discovered as a project with file evidence.

## Verification (exact commands and results)

- PASS `go test ./internal/acceptance -count=1` (full package, 2.3s)
- PASS `go test ./internal/acceptance -run 'EvidenceAdversarial' -count=50`
  — ok 31.9s
- PASS `go test ./internal/acceptance -run 'ContentEvidence' -count=50`
  — ok 43.3s
- PASS `go test -race ./internal/acceptance -run
  'ContentEvidence|EvidenceAdversarial' -count=5` — ok 87.1s
  (count=5 for the race variant: the race detector multiplies the
  50-iteration wall time past 10 minutes; the non-race count=50 runs above
  cover flake detection)
- Step 5 (all exit 0, run at the committed clean tree `81148b1`):
  `go clean -testcache`; `go test -race -count=1 ./...` (all packages ok,
  including `./scripts`; 30.9s + scripts build time); `go vet ./...`;
  `go mod verify` ("all modules verified"); `git diff --check` (empty).
- One iteration required a fix: the new release smoke initially failed
  (`failed to initialize SSC Init`) because macOS `t.TempDir()` lives under
  the `/var -> /private/var` symlink and the store enforces a no-symlink
  database parent; fixed with `filepath.EvalSymlinks` and amended into the
  task commit before any further gating.

## Step 6 — release build outputs (at `81148b1`, clean tree)

```
$ sh scripts/build-darwin.sh        # exit 0
$ file dist/ssc-init-darwin-arm64 dist/ssc-init-darwin-amd64
dist/ssc-init-darwin-arm64: Mach-O 64-bit executable arm64
dist/ssc-init-darwin-amd64: Mach-O 64-bit executable x86_64
$ shasum -a 256 -c dist/checksums.txt
dist/ssc-init-darwin-amd64: OK
dist/ssc-init-darwin-arm64: OK
$ ./dist/ssc-init-darwin-arm64 version --json
{"command":"ssc-init","product":"SSC Init","version":"dev+git.81148b127748b1bf81afa9e1620549273f630bd2"}
$ arch -x86_64 ./dist/ssc-init-darwin-amd64 version --json
{"command":"ssc-init","product":"SSC Init","version":"dev+git.81148b127748b1bf81afa9e1620549273f630bd2"}
$ git status --short                # empty (dist/ is gitignored)
```

Both payloads report the committed HEAD. `dist/` is covered by the tracked
`.gitignore` (`/dist/`) and does not pollute the worktree; the binaries were
left in place as the current release artifacts.

## Step 7 — static audit output and dispositions

`rg -n 'EvalSymlinks|filepath\.Walk|os\.ReadFile|os\.Open\(' internal/evidence internal/collector internal/scan`
— 10 hits, every one in `*_test.go`:
`packages/collector_test.go:561`, `ide/collector_test.go:747`,
`agents/collector_test.go:322` (`filepath.EvalSymlinks(t.TempDir())` for
symlink-free test databases); `ide/evidence_test.go:411`,
`mcp/parser_test.go:235`, `mcp/parser_toml_test.go:205`,
`agents/collector_test.go:194,202,223` (`os.ReadFile` of repo-local test
fixtures); `ide/collector_test.go:1384` (`os.Open` inside a test fake that
simulates a replacement race). Zero hits in production code: no evidence
target uses a forbidden path-reopen pattern. Disposition: all benign.

`rg -n 'RootPath|RelativePath|Provenance|LocalEvidenceTargets' internal/store internal/report`
— 3 hits, all in `internal/store/evidence_test.go:419-425`: a test that
builds a scan carrying a runtime `LocalEvidenceTarget` and proves the store
rejects/never persists it (`wantScan.Coverage[0].LocalEvidenceTargets =
nil`). Zero production hits. Disposition: exactly the permitted
"validators/tests proving rejection" category.

`rg -n 'malware|safe|full scan|block|signature|Docker' README.md docs/testing/2026-08-06-use-case-validation.md`
— "full scan": zero hits anywhere. README hits: the not-an-EDR/no-malware-
verdict/no-safety-guarantee disclaimer, explicit `unsupported`
package/Docker evidence, and the unimplemented-programs list (code-signature
validation, blocking) — all disclaimers, no capability claims. Validation
doc hits: historical foundation sections (preserved verbatim) plus the new
revalidation's explicit open-programs and no-verdict statements. Disposition:
public claims match implemented scope.

## Files changed (commit `81148b1`)

- `internal/acceptance/content_evidence_test.go` (new, mutation matrix +
  golden + CLI e2e)
- `internal/acceptance/evidence_adversarial_test.go` (new)
- `internal/acceptance/baseline_test.go`,
  `internal/acceptance/real_store_test.go`,
  `internal/acceptance/usecase_matrix_test.go` (v3 contract updates)
- `testdata/golden/baseline.json` (v3 golden, 25 evidence records)
- `testdata/home/.vscode/extensions/acme.safe-1.2.3/dist/extension.js` (new
  fixture)
- `scripts/build-darwin_test.go` (isolated-home v3 status release smoke)
- `README.md`, `docs/testing/2026-08-06-use-case-validation.md`

## Self-review

- Product code (`cmd/`, `internal/*` outside acceptance) untouched; the
  matrix exposed no product bug requiring escalation (two initial
  expectation mismatches were my test expectations being weaker/stronger
  than correct product behavior, verified against the design's identity and
  cache contracts).
- All 13 design acceptance criteria are exercised at acceptance level:
  (1) mutation matrix; (2) terminal-result bijection in every scan;
  (3) trusted-digest checks on complete-only; (4) symlink/no-follow suite;
  (5) anchor-swap suite; (6) hostile isolation + cancellation snapshot
  preservation; (7) cache lifecycle incl. identity-contract rejection;
  (8) privacy boundaries on report/SQLite/WAL/SHM everywhere; (9) exact
  18-name catalog + external-root privacy; (10) fail-on-call runner and
  inspector in every default acceptance scan; (11) byte-exact golden +
  legacy v1 status truthfulness; (12) README truth pass + claim audit;
  (13) clean-cache race/vet/mod/diff, migration fixture, isolated-home,
  build, checksum, native + Rosetta smoke on a clean worktree.
- Isolation: no real `$HOME` (decoy-sentinel test), no network, no package
  manager/Docker/codesign contact; probes use in-memory fakes.

## Concerns

1. **Cache-provenance delta on the first cache-warm rescan.** Tree evidence
   metadata `cache` flips miss→hit on the first unchanged rescan and the
   evidence diff (per design §6.1: "excludes only explicit observation
   timestamps") therefore reports those records as `changed` although every
   digest is identical. This is deterministic, spec-conformant as written,
   and now explicitly locked and documented (usecase test + validation doc),
   but it is a false-positive "change" signal on the first rescan after a
   baseline. If product direction wants delta to ignore cache provenance, it
   is a small change in `internal/inventory` canonical evidence plus test
   updates — flagged for the Step 9 reviewer/product owner, not fixed here
   (product code frozen).
2. Default scans always report overall status `partial` because the eight
   package targets are `skipped` without `--external-probes`; the golden
   encodes this truthfully. All-`skipped` evidence keeping a scan partial
   was already flagged in the Task 13 report.
3. Invalid UTF-8 file names cannot be created on APFS (`EILSEQ`), so that
   adversarial case can only attempt-and-log at acceptance level; synthetic
   filesystems cover it at unit level.
4. The race-detector stability run used `-count=5` (87s) instead of
   `-count=50` for runtime reasons; non-race `-count=50` passed for both new
   suites (31.9s / 43.3s).
5. The task commit was amended once (pre-report, unpushed) to fold in the
   `EvalSymlinks` fix for the release smoke; final SHA `81148b1` is the only
   Task 14 code commit.
