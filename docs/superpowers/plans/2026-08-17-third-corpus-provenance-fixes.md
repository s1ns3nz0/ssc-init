# Third Corpus Provenance Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the requirements, npm SRI, and uv virtual-workspace false positives reproduced by the third public corpus.

**Architecture:** Normalize insignificant PEP 508 whitespace only after direct-reference parsing; reconcile different approved npm integrity algorithms deterministically while rejecting same-algorithm digest conflicts; omit uv virtual workspace packages while preserving mutable git/path/editable dependencies.

**Tech Stack:** Go, table-driven tests, isolated project-only corpus scans.

**Spec:** `docs/superpowers/specs/2026-08-16-public-repository-scan-hardening-design.md`

## Global Constraints

- Never execute cloned repository code, hooks, package managers, or build scripts.
- Preserve bounded parsing, duplicate-key rejection, privacy-safe output, and deterministic ordering.
- Conflicting digests using the same algorithm remain malformed.
- Only uv `virtual` packages are omitted; git, editable, path, and missing-version packages retain mutable provenance.

---

### Task 1: PEP 508 whitespace and markers

**Files:**
- Modify: `internal/provenance/requirements.go`
- Test: `internal/provenance/python_test.go`

- [x] Add an Ansible-derived RED fixture containing `jinja2 >= 3.1.0`, comma-separated bounds, environment markers, and inline comments.
- [x] Normalize spaces and tabs in the non-direct requirement expression after marker/hash handling.
- [x] Run focused and full provenance tests GREEN.

### Task 2: npm multi-algorithm integrity reconciliation

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`

- [x] Add RED fixtures for SHA-1 plus SHA-512 in both input orders and a same-algorithm conflicting-digest rejection.
- [x] Rank exact approved algorithms deterministically and retain the strongest record.
- [x] Run focused and full provenance tests GREEN.

### Task 3: uv virtual workspace packages

**Files:**
- Modify: `internal/provenance/uv.go`
- Test: `internal/provenance/python_test.go`

- [x] Add a RED fixture proving `source = { virtual = "." }` is omitted while registry and path packages remain.
- [x] Skip only a closed single-field virtual source before package-record construction.
- [x] Run focused and full provenance tests GREEN.

### Task 4: Integration and corpus verification

- [x] Run race tests for provenance, projects, findings, and store.
- [x] Rescan Ansible, Bun, and Gitea in fresh isolated homes and require the targeted errors/findings to disappear.
- [x] Re-run all 12 third-corpus repositories and compare result summaries.
- [x] Run full build, vet, race, module, diff, and scripts gates on a clean commit.
- [ ] Push the updated PR branch and record retained artifact paths.

## Execution evidence

- All three focused regressions were observed RED before their production changes and GREEN afterward.
- The scoped race suite passed for provenance, project collection, finding evaluation, and store persistence.
- Fresh targeted scans removed Ansible's two malformed requirements errors, Bun's multi-algorithm integrity error, and Gitea's virtual-workspace finding.
- The complete 12-repository rerun produced 12,264 assets with zero provenance parser errors. The remaining 24 findings are 12 Bun parser fixtures, 11 genuinely range/unpinned Ansible requirements, and one Cargo hostile git-source fixture.
- Clean-tree `go test -race -count=1 ./...` passed, including store (80.214s), TI publication (69.324s), acceptance (48.983s), and release scripts (21.747s); build, vet, module verification, and diff checks also passed.
- Result artifacts are retained under `/Users/s1ns3nz0/Library/Caches/ssc-init-public-corpus-20260817/results-fixed-all`.
