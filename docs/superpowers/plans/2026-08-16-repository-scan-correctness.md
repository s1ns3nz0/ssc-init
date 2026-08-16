# Repository Scan Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate lockfile/manifest behavior false positives and accept the valid npm, Cargo, and VS Code formats reproduced by the public corpus.

**Architecture:** Keep the generic analyzer unchanged for executable content, but classify existing sealed evidence subjects before applying it. Extend only the closed npm/Cargo provenance parsers and the launch-config validator; no global decoder becomes permissive.

**Tech Stack:** Go 1.26, existing evidence/analyzer/provenance/project collector packages, SHA-2/Base64, JSONC normalization.

**Spec:** `docs/superpowers/specs/2026-08-16-public-repository-scan-hardening-design.md`

## Global Constraints

- Never execute repository code, package scripts, hooks, or tests.
- Dependency manifests and lockfiles emit no generic lexical, egress, or obfuscation facts.
- npm accepts exactly SHA-256, SHA-384, and SHA-512 SRI with exact digest sizes.
- Conflicting non-empty Cargo checksums remain malformed.
- JSONC support is private to `.vscode/launch.json` validation.
- Existing byte, identity, symlink, mutation, and privacy checks remain unchanged.

---

### Task 1: Subject-aware analyzer policy

**Files:**
- Modify: `internal/analyzer/scanner.go`
- Test: `internal/analyzer/scanner_test.go`
- Test: `internal/acceptance/analyzer_test.go`

**Interfaces:**
- Consumes: `evidence.SealedContent.Subject() string`.
- Produces: `contentClass(subject string) analyzerContentClass` and a scanner that returns no behavior facts for dependency subjects.

- [x] **Step 1: Add failing corpus-derived tests**

Add table tests sealing these exact subjects and representative contents:

```go
{
    subject: "project-lockfile:Cargo.lock",
    raw: []byte(`checksum = "` + strings.Repeat("a", 64) + `"`),
},
{
    subject: "project-lockfile:go.sum",
    raw: []byte("github.com/aws/aws-sdk-go-v2/credentials v1.0.0 h1:..."),
},
{
    subject: "project-manifest:go.mod",
    raw: []byte("require github.com/docker/docker-credential-helpers v0.9.3"),
},
```

Assert zero facts. Retain a source-like agent payload fixture containing a real `os.getenv(` plus `fetch(` and assert the existing credential/egress facts still appear.

- [x] **Step 2: Run RED**

Run:

```bash
go test ./internal/analyzer ./internal/acceptance -run 'Test.*(DependencyEvidence|Analyzer)' -count=1 -v
```

Expected: dependency fixtures currently emit obfuscation or credential-access facts.

- [x] **Step 3: Implement closed subject classification**

Map subjects beginning `project-lockfile:` to dependency-lockfile and `project-manifest:` to dependency-manifest, and return no generic behavior facts for those two classes. Preserve current behavior for every pre-existing exact `model.EvidenceSubject*` value so this task cannot silently suppress agent, IDE, package, shell, hook, MCP, or credential-config coverage. Unknown subjects return no facts. Do not persist the raw subject in a fact or error.

- [x] **Step 4: Verify GREEN and mutation**

Run:

```bash
go test -race ./internal/analyzer ./internal/evidence ./internal/acceptance -count=1
```

Temporarily route dependency-lockfile to the source analyzer; confirm the Cargo checksum test fails, restore, and rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/analyzer/scanner.go internal/analyzer/scanner_test.go internal/acceptance/analyzer_test.go
git commit -m "fix: classify analyzer inputs by evidence subject"
```

### Task 2: npm SHA-384 and SHA-512 provenance

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`
- Test: `internal/collector/projects/collector_test.go`

**Interfaces:**
- Produces: `decodeNpmSRI(string) (algorithm string, digest string, ok bool)`.
- Preserves: SHA-256 in `Record.Provenance.Integrity`; SHA-384/512 in `Record.SourceIntegrity`.

- [x] **Step 1: Add failing exact-digest tests**

Build literal package-lock v3 fixtures for SHA-256, SHA-384, and SHA-512 using `base64.StdEncoding.EncodeToString`. Assert immutable status and exact lowercase hex. Add rejection cases for SHA-1, wrong digest length, whitespace, multiple SRI tokens, and malformed Base64. Add an Axios-shaped SHA-512 collector fixture and assert complete project coverage plus package assets.

- [x] **Step 2: Run RED**

```bash
go test ./internal/provenance ./internal/collector/projects -run 'Test.*(NpmSRI|SHA512|PackageLock)' -count=1 -v
```

Expected: SHA-384/512 fixtures return `ErrMalformed`.

- [x] **Step 3: Implement exact closed SRI decoding**

Replace `decodeSHA256SRI` with algorithm dispatch for `sha256`, `sha384`, and `sha512`; require decoded lengths 32, 48, and 64 respectively. Keep unknown algorithms malformed. Populate canonical asset integrity only for SHA-256 and use `SourceIntegrity` for SHA-384/512.

- [x] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/provenance ./internal/collector/projects ./internal/store -count=1
```

Temporarily accept any decoded length for SHA-512; confirm the wrong-length test fails, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/provenance/parser.go internal/provenance/parser_test.go internal/collector/projects/collector_test.go
git commit -m "fix: parse modern npm integrity records"
```

### Task 3: Cargo workspace and registry duplicate normalization

**Files:**
- Modify: `internal/provenance/parser.go`
- Test: `internal/provenance/parser_test.go`
- Test: `internal/collector/projects/collector_test.go`

**Interfaces:**
- Extends the private Cargo decode struct with `Source string`.
- Produces a single `Record` for an allowed local-plus-registry name/version pair.

- [x] **Step 1: Add failing Clap-shaped tests**

Add a Cargo.lock fixture containing two `clap 4.6.6` entries: one local entry without source/checksum and one `registry+...` entry with a lowercase SHA-256 checksum. Assert one immutable record. Add rejection tests for different non-empty checksums, two different registry sources, malformed checksum, and source strings containing control bytes.

- [x] **Step 2: Run RED**

```bash
go test ./internal/provenance ./internal/collector/projects -run 'Test.*Cargo.*(Duplicate|Workspace|Conflict)' -count=1 -v
```

Expected: the valid local-plus-registry fixture returns `ErrMalformed`.

- [x] **Step 3: Implement safe merge**

Parse source only for classification and never persist it. Merge same name/version records when one has no checksum and the other has an approved checksum, preferring the immutable record. Collapse exact duplicates. Reject differing non-empty checksums and incompatible non-local sources.

- [x] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/provenance ./internal/collector/projects -count=1
```

Temporarily allow two different checksums; confirm the conflict test fails, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/provenance/parser.go internal/provenance/parser_test.go internal/collector/projects/collector_test.go
git commit -m "fix: merge valid Cargo source duplicates"
```

### Task 4: Bounded launch JSONC validation

**Files:**
- Create: `internal/collector/projects/jsonc.go`
- Create: `internal/collector/projects/jsonc_test.go`
- Modify: `internal/collector/projects/collector.go`
- Test: `internal/collector/projects/collector_test.go`

**Interfaces:**
- Produces: `validLaunchJSONC([]byte) bool`.
- Changes: `validLaunchConfig` validates exact verified bytes with JSONC rules before its existing post-read identity checks.

- [x] **Step 1: Add failing Vue-shaped tests**

Use a literal launch file with `//` comments, a block comment, URLs inside strings, and trailing commas; assert accepted. Add duplicate key, unterminated comment, comment marker in an escaped string, malformed escape, raw control byte, and multiple-root-value cases. Assert duplicate keys remain rejected after comment removal.

- [x] **Step 2: Run RED**

```bash
go test ./internal/collector/projects -run 'Test.*(JSONC|LaunchConfig)' -count=1 -v
```

Expected: Vue-style comments fail strict `json.Valid`.

- [x] **Step 3: Implement a launch-only state machine**

Strip comments and trailing commas into a bounded scratch buffer while preserving string contents and byte positions needed for escape correctness. Pass normalized bytes through the existing recursive unique-key JSON validator or an equivalent package-private exact-key validator. Clear scratch bytes after validation.

- [x] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/collector/projects ./internal/provenance -count=1
```

Temporarily skip duplicate-key validation; confirm the adversarial test fails, restore, rerun GREEN.

- [ ] **Step 5: Commit and run program gate**

```bash
git add internal/collector/projects/jsonc.go internal/collector/projects/jsonc_test.go internal/collector/projects/collector.go internal/collector/projects/collector_test.go
git commit -m "fix: validate VS Code launch JSONC"
go test -race ./internal/analyzer ./internal/evidence ./internal/provenance ./internal/collector/projects ./internal/acceptance -count=1
go vet ./internal/analyzer ./internal/evidence ./internal/provenance ./internal/collector/projects
git diff --check
```
