# Program D external and platform evidence implementation plan

> Execute task-by-task with strict RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-d-external-platform-evidence-design.md`.

**Goal:** Persist trustworthy immutable-container, code-signature and local
package-provenance facts plus canonical graph edges without changing the
default scan's zero-process/zero-network boundary.

**Architecture:** Extend the v4 public model first, then teach the evidence
engine to accept sealed command-derived container digests, wire Docker facts,
close relationship vocabulary, add signature inspection behind existing
external-probe executable verification, and finally add bounded local-lockfile
provenance. Each enrichment degrades independently.

---

### Task 1: v4 signature and provenance fact model

**Files:** `internal/model/asset.go`, model tests; `internal/store/validation.go`,
store tests; `internal/inventory/graph.go`, inventory tests.

1. RED: tests reject unknown statuses, malformed team/identifier/integrity,
   paths/secrets/control text, and prove the new facts affect diffing.
2. Implement closed `SignatureStatus`, `ProvenanceStatus`, `Signature`, and
   `Provenance`; add optional pointers to `Asset`; validate fixed shapes.
3. Run `go test ./internal/model ./internal/store ./internal/inventory -count=1`.
4. Commit `feat: add closed signature and provenance facts`.

### Task 2: scan/status v4 and legacy compatibility

**Files:** `internal/model`, `internal/report`, `internal/store`, `internal/cli`,
acceptance fixtures and docs.

1. RED: pin v4 current payloads, v3 legacy reads and policy absence.
2. Advance current scan/status schemas to v4; keep v1–v3 readable as legacy and
   never upgrade claims while loading.
3. Run affected packages plus acceptance.
4. Commit `feat: advance inventory contracts to v4`.

### Task 3: sealed trusted container-identity evidence

**Files:** `internal/model/evidence.go`, `internal/evidence/{issuer,validation,engine,record}.go`
and tests; `internal/store/evidence.go` and tests.

1. RED: a sealed complete container digest succeeds; forged, mutated,
   malformed and unsupported shapes fail; mutation changes evidence ID.
2. Add runtime-only preset algorithm/digest fields to the issuer proof and
   allow only full SHA-256 for complete `container-identity`.
3. Run evidence/store race tests and mutation tests.
4. Commit `feat: trust sealed immutable container identities`.

### Task 4: Docker full-ID parsing

**Files:** `internal/collector/packages/collector.go` and tests.

1. RED: `--no-trunc` is required; full IDs normalize to `Asset.SHA256`;
   truncated/malformed IDs never do; output remains bounded/value-free.
2. Parse exact `sha256:<64 lowercase hex>` only and retain it through package
   normalization.
3. Run package collector tests with parser mutations.
4. Commit `feat: collect full local docker image identities`.

### Task 5: Docker identities become complete evidence

**Files:** `internal/collector/packages/evidence.go`, package/evidence/acceptance tests.

1. RED: external Docker fixture produces complete container evidence; missing
   identity remains unsupported; default scan still invokes no command.
2. Seal the parsed digest through Task 3's runtime target.
3. Run package, evidence and isolated-home acceptance tests.
4. Commit `feat: record immutable docker identity evidence`.

### Task 6: closed graph relationship vocabulary

**Files:** `internal/model/asset.go`, `internal/store/validation.go`,
`internal/inventory/graph.go` and tests.

1. RED: unknown/empty/self-invalid kinds fail and supported kinds normalize
   deterministically without orphans.
2. Add constants and `ValidRelationshipKind`; validate at store and graph
   boundaries.
3. Run model/store/inventory tests.
4. Commit `feat: close the inventory relationship vocabulary`.

### Task 7: executable and declaration graph edges

**Files:** package/MCP/agent/IDE collectors and tests; acceptance matrix.

1. RED: package→tool `probed-by`, manifest→package `declared-by`, and available
   declaration→executable/service edges are exact; absent endpoints add no edge.
2. Emit edges only after both canonical endpoints exist.
3. Run all collectors and acceptance.
4. Commit `feat: connect executable supply chain graph edges`.

### Task 8: bounded macOS signature inspector

**Files:** `internal/platform/signature.go` and tests.

1. RED: valid, invalid, unsigned, unavailable, timeout, oversize, cancellation,
   replacement and hostile-output cases; non-Darwin invokes nothing.
2. Execute exact `/usr/bin/codesign` only through a bounded injected runner,
   map output to closed facts and discard raw diagnostics.
3. Run platform tests under race and repeated adversarial cases.
4. Commit `feat: inspect macos signatures as closed facts`.

### Task 9: signature enrichment wiring

**Files:** collector environment, package/agent/IDE collectors, scan wiring and tests.

1. RED: external probes enrich verified executable/native entrypoint assets;
   default scans do not call the inspector; replacement degrades only target.
2. Wire Task 8 behind `ExternalProbes` and existing descriptor identity seams.
3. Run collector/scan/acceptance tests.
4. Commit `feat: enrich executable assets with signature facts`.

### Task 10: local lockfile provenance parser

**Files:** `internal/provenance` new package and tests.

1. RED: bounded npm/Cargo/Go fixtures, duplicate keys/entries, mutable forms,
   hostile strings, oversize and cancellation.
2. Parse only approved lockfile fields into closed immutable/mutable/unknown
   facts; retain no raw content or path.
3. Run package tests with mutation battery.
4. Commit `feat: parse bounded local package provenance`.

### Task 11: project provenance and declared-by graph

**Files:** project collector/evidence wiring, inventory tests and acceptance.

1. RED: exact package assets and declared-by edges emerge from supported
   lockfiles; malformed files preserve manifest evidence and mark provenance
   partial; no project source tree read.
2. Wire Task 10 through descriptor-rooted project reads and deterministic IDs.
3. Run projects/evidence/acceptance race tests.
4. Commit `feat: connect projects to immutable package provenance`.

### Task 12: Program D acceptance and truthfulness

**Files:** `internal/acceptance/program_d_test.go`, README, CLAUDE, audit/ledger.

1. Prove the nine design acceptance requirements, scan-v4 isolation, byte
   determinism and all value/path/secret exclusions.
2. Update capability docs without claiming verdict or safety.
3. Run:

```sh
go clean -testcache
go test -race -count=1 ./...
go test ./internal/evidence ./internal/collector/packages ./internal/platform -count=50
go test ./internal/acceptance -run 'Docker|Signature|Provenance|Relationship' -count=50
go vet ./...
go mod verify
test -z "$(gofmt -l internal cmd scripts)"
git diff --check
```

4. Commit `test: prove external and platform evidence boundaries` and rerun
   `go test ./scripts -count=1` on the clean worktree.

---

`[APPLE]` real release signing/notarization is intentionally outside this plan;
its scripts and runbook already exist and await credentials only.
