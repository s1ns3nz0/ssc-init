# Task 7 report: agent content evidence

## Implementation

- Issued sealed runtime-only evidence for recognized Claude/Codex plugin manifests and plugin payload trees, plus Claude/Codex/Cursor skills (including accepted bundled skills) and skill payload trees.
- Captured SHA-256, size, mode, file fingerprint, catalog-root fingerprint, and asset-root fingerprint during discovery before the test-only post-read seam runs.
- Added the `afterManifestRead` TOCTOU seam and engine integration proof for `identity_changed`.
- Kept raw runtime target paths, anchors, and provenance out of JSON, and verified full-cap cleanup through the engine.

## Plan integration amendment

The plan intentionally uses catalog suffix IDs, so distinct asset/observation evidence can share one `TargetID`. The pre-existing engine globally rejected duplicate target IDs, which prevented plugin and bundled-skill payload-tree results from collecting together. With parent authorization, Task 7 changed that gate to reject only duplicate evidence identities. The new regression proves two distinct valid records with the same target ID collect deterministically; the existing same-evidence duplicate regression remains fail-closed.

## TDD record

Initial red run:

```text
go test ./internal/collector/agents -run 'Evidence|TargetAnchor' -count=1
FAIL TestAgentEvidenceTargetMatrix: subjects=map[]
FAIL TestAgentEvidenceTargetsAreRuntimeOnly: missing runtime evidence state
```

Integration-amendment red run:

```text
go test ./internal/evidence -run 'SharedCatalogTargetID|DuplicateTarget' -count=1
FAIL TestEngineAcceptsDistinctEvidenceUnderSharedCatalogTargetID
```

Both focused suites passed after the minimal changes.

## Verification

- `go test ./internal/collector/agents -run 'Evidence|TargetAnchor' -count=1` — PASS
- `go test ./internal/evidence -run 'SharedCatalogTargetID|DuplicateTarget' -count=1` — PASS
- `go test ./internal/collector/agents ./internal/evidence -count=1` — PASS
- `go test -race ./internal/collector/agents ./internal/evidence -count=1` — PASS
- `go vet ./internal/collector/agents ./internal/evidence` — PASS
- `git diff --check` — PASS
- `go test ./... -count=1` — expected unrelated failures only: staged Task 13–14 acceptance/CLI baseline JSON fixtures, plus the release build dirty-worktree guard in `scripts`.

## Changed files

- `internal/collector/agents/collector.go`
- `internal/collector/agents/collector_test.go`
- `internal/collector/agents/evidence.go`
- `internal/collector/agents/evidence_test.go`
- `internal/collector/agents/testdata/content/*`
- `internal/evidence/engine.go`
- `internal/evidence/engine_test.go`

Implementation commit: `c8b11ab1a704a83da75fa6ceab7446e0bb1034d4` (`feat: plan agent content evidence`).
