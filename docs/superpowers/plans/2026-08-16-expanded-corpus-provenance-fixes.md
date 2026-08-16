# Expanded Corpus Provenance Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the Cargo and npm false positives reproduced by the second public-repository corpus without weakening malformed-input handling.

**Architecture:** Keep all changes inside the bounded lockfile provenance parser. Classify a Cargo git source with an exact lowercase 40-hex commit as unknown with a retained `git-sha1:` source-integrity fact rather than mutable or canonically immutable; skip npm workspace link entries; parse npm v1 dependency trees; retain npm SHA-1 only as a source-integrity fact rather than canonical SHA-256 provenance.

**Tech Stack:** Go, `encoding/json`, table-driven tests, project-only CLI corpus scans.

**Spec:** `docs/superpowers/specs/2026-08-16-public-repository-scan-hardening-design.md`

## Global Constraints

- Never execute repository code, hooks, package managers, or build scripts.
- Preserve bounded reads, duplicate-key rejection, closed package coordinates, and deterministic record ordering.
- Only SHA-256 may populate `model.Provenance.Integrity`; other accepted algorithms use `Record.SourceIntegrity`.

---

### Task 1: Pinned Cargo git sources

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`

**Interfaces:**
- Consumes: Cargo `source = "git+...#<revision>"`.
- Produces: unknown provenance plus `git-sha1:<hex>` source integrity for an exact lowercase 40-hex revision; mutable provenance otherwise.

- [x] **Step 1: Write the failing test**

```go
func TestParseCargoDistinguishesPinnedAndFloatingGitSources(t *testing.T) {
	// Assert an exact 40-hex fragment is unknown with retained source integrity and a branch/tag/short fragment remains mutable.
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provenance -run TestParseCargoDistinguishesPinnedAndFloatingGitSources -count=1 -v`

- [x] **Step 3: Write minimal implementation**

```go
if strings.HasPrefix(entry.Source, "git+") {
	record.Provenance.Status, record.SourceIntegrity = cargoGitSourceFact(entry.Source)
}
```

- [x] **Step 4: Run the focused and package tests**

Run: `go test ./internal/provenance -count=1`

### Task 2: npm workspace links

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`

**Interfaces:**
- Consumes: npm v2/v3 package entries with `"link": true` and no package version.
- Produces: no external package record for the link while retaining ordinary packages.

- [x] **Step 1: Write the failing test**

```go
func TestParseNPMSkipsWorkspaceLinksWithoutDroppingPackages(t *testing.T) {
	// Assert the linked workspace is skipped and its normal dependency remains.
}
```

- [x] **Step 2: Run RED**

Run: `go test ./internal/provenance -run TestParseNPMSkipsWorkspaceLinksWithoutDroppingPackages -count=1 -v`

- [x] **Step 3: Add `Link bool` to the closed decoded entry and skip links before coordinate validation**

- [x] **Step 4: Run GREEN**

Run: `go test ./internal/provenance -count=1`

### Task 3: npm v1 and legacy SHA-1 source integrity

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`

**Interfaces:**
- Consumes: npm v1 recursive `dependencies` and exact 20-byte SHA-1 SRI.
- Produces: flattened deterministic package records; SHA-1 retained only as `SourceIntegrity`.

- [x] **Step 1: Write separate failing tests for recursive v1 packages and exact SHA-1**

```go
func TestParseNPMV1FlattensNestedDependencies(t *testing.T) {}
func TestParseNPMRetainsExactSHA1AsSourceIntegrity(t *testing.T) {}
```

- [x] **Step 2: Run both tests and observe the existing malformed failures**

Run: `go test ./internal/provenance -run 'TestParseNPM(V1FlattensNestedDependencies|RetainsExactSHA1AsSourceIntegrity)' -count=1 -v`

- [x] **Step 3: Decode the bounded recursive dependency object and extend exact SRI decoding with 20-byte SHA-1**

- [x] **Step 4: Keep malformed length, whitespace, duplicate key, and conflicting duplicate records fail-closed**

- [x] **Step 5: Run provenance and project collector race tests**

Run: `go test -race ./internal/provenance ./internal/collector/projects -count=1`

### Task 4: Corpus and whole-branch verification

**Files:**
- Modify: `docs/superpowers/plans/2026-08-16-expanded-corpus-provenance-fixes.md`

**Interfaces:**
- Consumes: retained 32-repository corpus.
- Produces: stored before/after JSON and findings evidence.

- [x] **Step 1: Rebuild and rescan Biome, Maturin, Ruff, and Kustomize in fresh isolated homes**
- [x] **Step 2: Require zero pinned-git findings and zero malformed errors for the three valid npm locks**
- [x] **Step 3: Re-run the expanded 12 repositories and compare stable result summaries**
- [ ] **Step 4: Run `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `go mod verify`, `git diff --check`, and `go test ./scripts -count=1`**
- [ ] **Step 5: Commit and push the PR branch**

## Execution evidence

- Every focused regression was observed RED before its production change and GREEN afterward.
- `go test -race ./internal/provenance ./internal/collector/projects ./internal/store -count=1` passed; store completed in 69.900 seconds.
- Fresh project-only scans made Biome `12 -> 0` findings, Maturin `5 -> 0` findings, Ruff `1 -> 0` malformed lockfiles, and Kustomize `2 -> 0` malformed lockfiles.
- The expanded 12-repository rerun retained only Poetry's two explicitly invalid/incompatible fixtures and the bounded Terraform/Kubernetes depth-limit coverage notices.
- Result artifacts are retained under `/Users/s1ns3nz0/Library/Caches/ssc-init-public-corpus-20260816/results-expanded-final`.
