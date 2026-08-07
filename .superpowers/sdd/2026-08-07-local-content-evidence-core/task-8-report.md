# Task 8 report: IDE content evidence

Implemented sealed, observation-scoped content evidence for supported VS Code-family extensions and JetBrains plugins.

## Changed files

- `internal/collector/ide/collector.go`
- `internal/collector/ide/manifest.go`
- `internal/collector/ide/evidence.go`
- `internal/collector/ide/manifest_test.go`
- `internal/collector/ide/evidence_test.go`
- `internal/collector/ide/testdata/content/`

## TDD record

Red command, before production support:

```text
go test ./internal/collector/ide -run 'Evidence|Entrypoint|KeepsIndependent' -count=1
# FAIL: manifestEvidence has no main/browser fields
```

## Verification

```text
go test ./internal/collector/ide ./internal/evidence -count=1  # PASS
go test -race ./internal/collector/ide -count=1                 # PASS
go vet ./...                                                     # PASS
git diff --check                                                 # PASS
go test ./... -count=1                                          # expected unrelated failures below
```

The full test run passed the IDE and evidence packages. Its only failures were the known Task 13--14 acceptance/CLI fixture expectations (they still expect v2 JSON without evidence) and the release build dirty-worktree guard in `scripts`.

## Commit

Commit hash: pending amend.

## Concerns

None within Task 8 ownership. Runtime paths, anchors, raw entry declarations, and manifest bytes remain runtime-only; public `entry_point` metadata retains its legacy main-then-browser behavior.
