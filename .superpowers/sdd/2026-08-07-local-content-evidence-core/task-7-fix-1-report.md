# Task 7 fix round 1 report

Implementation commit: `06de941836ca65fb60359ff39c3fc2921007fc7e` (`fix: harden agent evidence bindings`).

## Findings fixed

- The evidence engine now rejects duplicate `(TargetID, ObservationID)` bindings while preserving valid shared catalog target IDs across distinct observations and preserving evidence-ID uniqueness.
- Claude and Codex plugin manifests directly below their catalog root are recognized with plugin base `.`.
- Agent integration coverage now runs real plugin, skill, and bundled-skill targets through the evidence engine, asserts complete terminal records and exact asset/observation bindings, covers catalog-root plugin/skill trees, and proves a plugin payload digest excludes an outside sibling.

## TDD record

Red engine regression:

```text
go test ./internal/evidence -run 'SharedTargetID|SharedCatalogTargetID' -count=1
FAIL TestEngineRejectsSharedTargetIDBoundTwiceToSameObservation
ambiguous shared binding accepted with two complete evidence records
```

Red agent regression:

```text
go test ./internal/collector/agents -run 'EvidenceCompletesForCatalogRoot|EvidenceTargetMatrix' -count=1
FAIL TestAgentEvidenceCompletesForCatalogRootPluginsAndSkills
only root-level Claude/Codex skills were collected; both root-level plugin assets and their evidence were absent
```

After the minimal production changes, both focused commands passed.

## Verification

- `go test ./internal/evidence -run 'SharedTargetID|SharedCatalogTargetID' -count=1` — PASS
- `go test ./internal/collector/agents -run 'EvidenceCompletesForCatalogRoot|EvidenceTargetMatrix' -count=1` — PASS
- `go test ./internal/collector/agents ./internal/evidence -count=1` — PASS
- `go test -race ./internal/collector/agents ./internal/evidence -count=1` — PASS
- `go vet ./internal/collector/agents ./internal/evidence` — PASS
- `git diff --check` — PASS
- `go test ./... -count=1` — only the known staged failures remained: acceptance/CLI baseline JSON fixtures for Tasks 13–14 and the `scripts` release-build clean-worktree guard.

## Changed files

- `internal/collector/agents/collector.go`
- `internal/collector/agents/evidence_test.go`
- `internal/evidence/engine.go`
- `internal/evidence/engine_test.go`
