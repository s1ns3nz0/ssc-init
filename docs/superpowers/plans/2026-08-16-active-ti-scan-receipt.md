# Active TI Scan Receipt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every baseline audit receipt describe the exact active TI bundle used for findings, even when no update was requested.

**Architecture:** Read the existing local verified manager status once before a scan without network access, convert it into a closed non-update receipt, and use the same manager snapshot for finding correlation. Extend validation/rendering without changing explicit update semantics.

**Tech Stack:** Go 1.26, existing bundle manager, CLI orchestration, audit model/archive/rendering.

**Spec:** `docs/superpowers/specs/2026-08-16-public-repository-scan-hardening-design.md`

## Global Constraints

- Default scans remain zero-network.
- Receipt identity/counts are all present or all absent.
- TI finding sequence and receipt sequence must match.
- Existing updated/current/degraded/unavailable tuples remain valid.
- JSON/audit contain no bundle path or raw manifest.

---

### Task 1: Closed non-update active-TI receipt

**Files:**
- Modify: `internal/cli/run.go`
- Test: `internal/cli/run_test.go`
- Modify: `internal/audit/model.go`
- Modify: `internal/audit/privacy.go`
- Test: `internal/audit/model_test.go`
- Test: `internal/audit/privacy_test.go`
- Modify: `internal/audit/render.go`
- Test: `internal/audit/render_test.go`
- Test: `internal/acceptance/ti_update_test.go`

**Interfaces:**
- Adds a local status seam to `cli.App`, returning `bundle.Status` without update/network capability.
- Produces a receipt status `not-requested` with closed freshness and optional complete active identity.

- [x] **Step 1: Add failing real-state matrix tests**

Test fresh and stale active status with sequence/digest/key/counts, missing with zero identity, expired with complete historical identity, and invalid partial tuples. In CLI acceptance, inject an updater that panics if called, a local status returning sequence 7, and a finding service returning a TI finding bound to sequence 7. Assert zero updater calls and matching receipt/finding identity.

- [x] **Step 2: Run RED**

```bash
go test ./internal/cli ./internal/audit ./internal/acceptance -run 'Test.*(NotRequested|ActiveTIReceipt|DefaultScanTI)' -count=1 -v
```

Expected: the current receipt says unavailable or omits active identity while the finding cites it.

- [x] **Step 3: Implement one local status snapshot**

Before baseline collection, read status through the local manager seam. Do not call `Update`. Convert fresh/stale status to `not-requested` with complete identity/counts; convert missing to an empty tuple; preserve expired identity only if the existing status contract supplies a complete verified historical tuple. Pass the receipt through audit completion and rendering.

- [x] **Step 4: Extend closed validation and pretty output**

Accept only the specified `not-requested` matrix. Render update activity separately from freshness. Ensure digest remains JSON/archive-only and all count invariants remain enforced.

- [x] **Step 5: Verify GREEN and two mutations**

```bash
go test -race ./internal/cli ./internal/audit ./internal/acceptance ./cmd/ssc-init -count=1
```

Mutation 1: call the updater in the default branch; zero-network test must fail. Mutation 2: clear active identity before audit completion; receipt/finding consistency test must fail. Restore and rerun GREEN.

- [x] **Step 6: Commit and final corpus gate**

```bash
git add internal/cli/run.go internal/cli/run_test.go internal/audit internal/acceptance/ti_update_test.go
git commit -m "fix: record active TI on default scans"
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
go test ./scripts -count=1
```

Rerun all 20 retained repositories with `--project-only`. Require zero dependency-manifest/lockfile behavior findings, zero malformed errors for the 12 known-valid lockfiles, complete Vue launch coverage, no host collectors, deterministic repeated project result sets, and a clean worktree.

Execution evidence (2026-08-16): all 20 scans persisted successfully and exposed only project-scoped coverage; dependency manifest/lockfile behavior findings were zero; Axios SHA-512, Clap duplicate Cargo source, and Vue JSONC cases were complete; and all 20 canonical result documents were byte-identical on a second isolated-HOME run. Django, Flask, Pydantic, and Ruff retained only the pre-existing closed mutable/unpinned provenance advisories, not content-behavior findings.
