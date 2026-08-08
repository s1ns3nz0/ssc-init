# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SSC Init (`ssc-init`) is a standalone, dependency-minimized, CGO-free, Darwin-only Go binary for developer supply-chain inventory and bounded local content evidence. It is snapshot-based and local-first, and explicitly not an EDR: no daemon, no kernel sensor, no malware verdicts, no safety guarantees. Missing or failed coverage stays visible instead of being treated as success. All commands emit JSON. State lives at `$HOME/Library/Application Support/SSC Init/state.db`.

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

## Architecture

Baseline scan pipeline: `cmd/ssc-init` → `internal/cli` → `internal/scan` orchestration → collectors → graph normalization (`internal/inventory`) → local evidence engine (`internal/evidence`) → delta/report (`internal/report`) → atomic SQLite snapshot (`internal/store`).

- `internal/collector/{agents,ide,mcp,packages,projects}` — closed-catalog discovery: Claude/Codex/Cursor plugins and skills, VS Code-family and JetBrains extensions, MCP configurations, project manifests/lockfiles, and (only with `--external-probes`) package/Docker command probes. Collectors additionally issue sealed runtime-only `LocalEvidenceTarget` values (`json:"-"`, never persisted).
- `internal/evidence` — validates sealed targets against the normalized graph (issuer seal, graph binding, path validation), then performs descriptor-anchored file/tree hashing and secret-free semantic MCP hashing. Discovery-time identity anchors are re-verified before and after every read; mismatch yields `unavailable/identity_changed`.
- `internal/platform` — descriptor-rooted, no-follow filesystem primitives (`os.Root`-based) and file identity fingerprints.
- `internal/model` — public data model: assets, observations, `ContentEvidence` with closed kind/subject/status/error/metadata vocabularies.
- `internal/identity` — canonical ID finalization for observations and evidence (IDs are stable across content changes).
- `internal/privacy` — sensitive-value detection used by validation across collectors, evidence, and persistence.
- `internal/store` — migrations, atomic snapshot persistence, and validation that rejects raw paths, secrets, and runtime state.
- `internal/acceptance` — isolated-home end-to-end fixtures.

## Security invariants (release-blocking)

- Evidence filesystem access is descriptor-rooted and never follows symlinks; a target cannot escape its verified collector root, and no absolute path is reconstructed after root verification.
- Target catalogs are exact and closed; every accepted evidence target receives exactly one terminal result; only `complete` evidence is a trusted content digest.
- Never persist raw content, secrets, absolute paths, tree leaf names/lists, link targets, fingerprints, anchors, or runtime provenance.
- Default scans execute no process and perform no network access; discovered content is never executed.
- Cancellation/deadline errors propagate and clear partial runtime state; hostile targets are isolated from safe siblings.
- No new runtime dependency without revising the plan first. Deterministic input produces byte-identical report JSON and snapshot state.

## Completed work

The local content evidence core (Tasks 1–14) is merged to `master`; the full suite, race detector, vet, static audits, and release build all pass. Public contracts are `ssc-init.scan.v3` / `ssc-init.status.v3`; v1/v2 snapshots load as `legacyInventory: true` with no evidence claims. Reference docs:

- design: `docs/superpowers/specs/2026-08-07-local-content-evidence-core-design.md`
- plan: `docs/superpowers/plans/2026-08-07-local-content-evidence-core.md`
- ledger + per-task reports: `.superpowers/sdd/2026-08-07-local-content-evidence-core/`
- validation report: `docs/testing/2026-08-06-use-case-validation.md` (dated v3 revalidation appended)

Known accepted behaviors: the first cache-warm rescan emits a one-time benign `changed` delta for payload-tree evidence (cache metadata miss→hit; digests identical — spec-conformant per design §6.1, disclosed in the validation doc); default scans are overall `partial` because the packages collector is skipped without `--external-probes`. Design non-goals still unimplemented: package payload hashing, immutable Docker identity, code signatures, TI, behavior analysis, policy/warnings/blocking, host adapters.

Development follows strict TDD: observe the named test fail, add the minimum implementation, run the focused package, then the stated regression set. For multi-task plans, SDD conventions apply: controller never edits product code; fresh implementer + separate read-only reviewer per task; ledger lines follow `Task N: dispatched (base <sha>)` / `Task N complete: commits …; task review clean`; review fixes need a reproducing failing test first; adversarial/race-prone suites re-verified with `-count=50`.

## Gotchas

- Package assets have `Source` cleared before append (`internal/collector/packages/collector.go` `appendPackageEvidence`); the ecosystem lives in `observation.Source` (= probe target ID, e.g. `packages.npm`). Don't derive anything from `asset.Source` for packages.
- Release gates and `go test ./scripts` require a clean tracked worktree — keep scratch files outside the repo.
