# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SSC Init (`ssc-init`) is a standalone, dependency-minimized, CGO-free, Darwin-only Go binary for developer supply-chain inventory, bounded local analysis, verified local TI/organization bundles, advisory host feedback, reversible quarantine, and opt-in daily scheduling. It is snapshot-based and local-first, and explicitly not an EDR: no daemon, no kernel sensor, no continuous monitoring, no automatic blocking, and no scan result is a guarantee that an asset is safe. Missing, stale, or failed coverage stays visible instead of being treated as success. State lives at `$HOME/Library/Application Support/SSC Init/state.db`.

## Commands

```sh
go test ./... -count=1                                 # full suite
go test ./internal/evidence -count=1                   # one package
go test ./internal/evidence -run TestName -count=1     # one test
go test -race ./internal/... -count=1                  # race detector
go vet ./...
git diff --check
go test ./scripts -count=1                             # build-script tests (needs clean committed tree)
go mod download && sh scripts/build-darwin.sh          # release build → dist/ (arm64 + amd64 + checksums.txt)
```

The release build script disables network/toolchain downloads and requires a clean tracked worktree; binaries report the exact `v*` tag when HEAD is tagged, else `dev+git.<full-commit>` from committed HEAD.

The reproducible unsigned release set is the Universal Binary, three native
adapter ZIPs, `checksums.txt`, CycloneDX SBOM, and provenance statement. The
thin architecture binaries are build intermediates. See
`docs/release-runbook.md` for the release contract.

## Architecture

Baseline scan pipeline: `cmd/ssc-init` → `internal/cli` → `internal/scan` orchestration → collectors → graph normalization (`internal/inventory`) → local evidence engine (`internal/evidence`) → delta/report (`internal/report`) → atomic SQLite snapshot (`internal/store`).

- `internal/collector/{agents,ide,mcp,packages,projects,surfaces,runtime}` — closed-catalog discovery: Claude/Codex/Cursor plugins and skills, VS Code-family and JetBrains extensions, MCP configurations, project manifests/lockfiles, shell startup files, Git credential-helper declarations, project hooks/launch configuration, and (only with `--external-probes`) package/Docker plus point-in-time process/listener command probes. Collectors additionally issue sealed runtime-only `LocalEvidenceTarget` values (`json:"-"`, never persisted).
- `internal/evidence` — validates sealed targets against the normalized graph (issuer seal, graph binding, path validation), then performs descriptor-anchored file/tree hashing and secret-free semantic MCP hashing. Discovery-time identity anchors are re-verified before and after every read; mismatch yields `unavailable/identity_changed`.
- `internal/platform` — descriptor-rooted, no-follow filesystem primitives (`os.Root`-based), file identity fingerprints, and bounded macOS `codesign` inspection.
- `internal/model` — public v5 data model: assets with closed signature/provenance and developer-surface facts, observations, relationships, and `ContentEvidence` with closed kind/subject/status/error/metadata vocabularies.
- `internal/provenance` — bounded, network-free npm/Cargo/Go lockfile parsing plus Python `requirements.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`; Go `h1` remains a source-specific integrity fact and is never mislabeled SHA-256.
- `internal/identity` — canonical ID finalization for observations and evidence (IDs are stable across content changes).
- `internal/privacy` — sensitive-value detection used by validation across collectors, evidence, and persistence.
- `internal/store` — migrations, atomic snapshot persistence, and validation that rejects raw paths, secrets, and runtime state. Rebuildable `bundle_index` and bounded `bundle_audit` tables have no `scan_id`; verified files remain the bundle activation source of truth.
- `internal/install` — the only default product path that executes a supplied binary, solely for a bounded doctor health check; it is never reachable from scanning. The current-version pointer is a regular file, never a symlink, and every read re-validates it.
- `internal/policy` — pure evaluation over already-recorded inventory facts. It must not read the host, run processes, open sockets, or import `internal/report`.
- `internal/bundle` — closed TI/organization schemas, family-scoped Ed25519 verification, monotonic sequence protection, atomic stage/activate/rollback, and freshness state. It never fetches a bundle; production trust roots are an explicit reviewed input.
- `internal/analyzer`, `internal/finding` — bounded facts and deterministic shared verdicts; adapters never invent or alter severity/action/rule identity.
- `internal/adapter` and `adapters/{claude,codex,cursor}` — closed host contracts and native advisory packages over the one GitHub-installed core.
- `internal/quarantine` — preview-bound, descriptor-rooted reversible file quarantine with identity-drift and collision refusal.
- `internal/schedule` — one explicit, atomic, idempotent launchd job shared by every adapter.
- `internal/inventory` — owns both inventory diffing and the shared change-ladder classifier; report code only renders its result.
- `internal/acceptance` — isolated-home end-to-end fixtures.

## Security invariants (release-blocking)

- Evidence filesystem access is descriptor-rooted and never follows symlinks; a target cannot escape its verified collector root, and no absolute path is reconstructed after root verification.
- Target catalogs are exact and closed; every accepted evidence target receives exactly one terminal result; only `complete` evidence is a trusted content digest.
- Never persist raw content, secrets, absolute paths, tree leaf names/lists, link targets, fingerprints, anchors, or runtime provenance.
- Default scans execute no process and perform no network access; discovered content is never executed.
- Cancellation/deadline errors propagate and clear partial runtime state; hostile targets are isolated from safe siblings.
- No new runtime dependency without revising the plan first. Deterministic input produces byte-identical report JSON and snapshot state.
- Policy precedence always exposes five levels; verified TI and organization evidence fail closed when missing, stale, invalid, or inapplicable.
- `policy_pins`, `policy_exceptions`, and `policy_decisions` are independent local state and carry no `scan_id`. No policy field may enter inventory snapshot contracts.

## Completed work

The current public contracts are `ssc-init.scan.v7` / `ssc-init.status.v7`; earlier snapshots load as legacy inventory without upgrading historical claims. The local content evidence core remains documented at:

- design: `docs/superpowers/specs/2026-08-07-local-content-evidence-core-design.md`
- plan: `docs/superpowers/plans/2026-08-07-local-content-evidence-core.md`
- ledger + per-task reports: `.superpowers/sdd/2026-08-07-local-content-evidence-core/`
- validation report: `docs/testing/2026-08-06-use-case-validation.md` (dated v3 revalidation appended)

Program B (scan status vocabulary, retention, budgets) is also merged to `master`:

- `model.ScanStatus` is a closed vocabulary (`complete|partial|stale|blocked`) checked by `Valid()` inside `validateSnapshot`, which gates both the save and the load path in `internal/store`. `stale` and `blocked` are defined but unreachable today: `overallStatus` (`internal/scan/service.go`) returns only `complete` or `partial`, and `stale` needs the TI manager (foundation design §7.2). An out-of-vocabulary persisted status is a hard read failure with no fallback.
- Every `SaveScan` prunes: snapshots at 30 days, asset change history at 90 days. The snapshot window is inclusive of its edge (a snapshot finished exactly at the cutoff is kept, so daily scanning plateaus at 31 snapshots), and the newest snapshot is never pruned at any age. `asset_history` has no `scan_id` and no foreign key, so it survives snapshot pruning and is O(distinct assets) rather than O(snapshots × assets).
- `store.Options` is an in-process seam only (no flag, env var, or config file). A zero — or negative — window selects the documented default, never zero; `Open(path)` is `OpenWithOptions(path, Options{})` and is what the binary uses.
- Space reclamation (post-commit gated `VACUUM` + `wal_checkpoint(TRUNCATE)`) fires only when the freelist is at least 256 pages **and** at least a quarter of the file. Under daily-cadence scanning the gate never opens, so this recovers space after an idle gap or a batch aging out, not routinely. Reclamation errors are swallowed deliberately: the snapshot is already durable, and failing the save would discard a report for persisted data.
- `scan.DefaultBudget` (10 minutes, design §12 baseline) bounds one baseline scan and degrades to `partial` with the unfinished collectors named in coverage; a caller cancellation or caller deadline is different — it still errors and persists nothing.
- The performance harness `internal/acceptance/perf_budget_test.go` is behind `//go:build perfbudget` and is excluded from `go test ./...`. Run it with `go test ./internal/acceptance -tags perfbudget -run TestPerformanceBudgets -v -count=1`.

Program C adds the local advisory policy engine: an inert starter document, five-level precedence with levels 1–3 truthfully inactive, shape/change/pin rules, expiring scoped exceptions, TOFU pins, `policy check` exit code 3 for violations, and hook reporting. It does not add enforcement, threat intelligence, or verified organization bundles.

The doctor JSON contract is `ssc-init.doctor.v2`; its `install` object reports
managed-install integrity and rollback availability without paths.

Program D adds full local Docker SHA-256 identity evidence, bounded macOS signature facts for verified external-probe executables, npm/Cargo/Go lockfile provenance, Python `requirements.txt`/`Pipfile.lock`/`poetry.lock`/`uv.lock` provenance, and a closed deterministic relationship vocabulary. Remaining provenance gaps are other ecosystems and conditional dependency-edge extraction. It adds no verdict, safety claim, network lookup, or enforcement. Release signing is not a product roadmap item; local signature inspection must not be conflated with artifact publication.

Program I adds bounded shell startup, Git credential-helper, project Git-hook and VS Code launch-config inventory. With explicit `--external-probes`, it also records a point-in-time process/listener snapshot containing only PID, executable basename, protocol, and local port. It is not continuous monitoring, and default scans still execute no process.

Program E adds the network-free verified-bundle core: closed TI and organization-policy payloads, family-scoped Ed25519 signatures, hardened local staging, last-known-good activation/rollback, high-water rollback protection, freshness reporting, CLI commands, rebuildable store indexes, publisher tooling, schemas, and CI gates. The production key registry is deliberately empty pending reviewed public keys; actual publication and scheduled retrieval remain external evidence. Program E does not yet correlate TI into findings or activate organization precedence in policy decisions—Program F owns that decision/reporting layer.

Programs F/G/H add shared finding verdicts, bounded analyzers, advisory host packages, reversible quarantine, and explicit launchd scheduling. Native adapters use the installed core and never bundle an unsigned executable or maintain separate state. Known accepted behaviors: the first cache-warm rescan emits a one-time benign `changed` delta for payload-tree evidence (cache metadata miss→hit; digests identical); default scans are overall `partial` because the packages collector is skipped without `--external-probes`. Remaining boundaries include provenance for other ecosystems, conditional dependency-edge extraction, broader language analysis, production bundle publication, and automatic host blocking.

Development follows strict TDD: observe the named test fail, add the minimum implementation, run the focused package, then the stated regression set. For multi-task plans, SDD conventions apply: controller never edits product code; fresh implementer + separate read-only reviewer per task; ledger lines follow `Task N: dispatched (base <sha>)` / `Task N complete: commits …; task review clean`; review fixes need a reproducing failing test first; adversarial/race-prone suites re-verified with `-count=50`.

## Gotchas

- Package assets have `Source` cleared before append (`internal/collector/packages/collector.go` `appendPackageEvidence`); the ecosystem lives in `observation.Source` (= probe target ID, e.g. `packages.npm`). Don't derive anything from `asset.Source` for packages.
- Release gates and `go test ./scripts` require a clean tracked worktree — keep scratch files outside the repo.
- Never run `go test ./...` inside a `git archive` export: `scripts/build-darwin_test.go` checks a newer tree out over the working directory (adding `.git/` and `dist/`, overwriting tracked files), so the export silently stops representing the commit under test. Verify a pinned commit in a real `git clone`, or exclude `./scripts`.
