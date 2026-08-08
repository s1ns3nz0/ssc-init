# Task 8 fix round 1 report

Corrected IDE evidence anchoring so every filesystem target retains the exact verified discovery manifest content anchor. Entrypoints are no longer read or hashed during discovery, and legacy selected `entry_point` validation behavior is restored.

## Changed files

- `internal/collector/ide/collector.go`
- `internal/collector/ide/evidence.go`
- `internal/collector/ide/evidence_test.go`
- `internal/collector/ide/manifest.go`
- `internal/collector/ide/manifest_test.go`

## TDD red record

```text
go test ./internal/collector/ide -run 'LegacyUnsafeSelected|EveryVSCodeTarget|EveryJetBrainsTarget|SecondaryBrowser' -count=1
```

Failed as intended before production changes:

- VS Code main/browser entry targets remained complete after `package.json` mutation.
- VS Code and JetBrains payload trees remained complete after manifest mutation.
- NUL, control, and overlong selected entry declarations were accepted instead of returning `errInvalidManifest`.

## Verification

```text
go test ./internal/collector/ide ./internal/evidence -count=1       # PASS
go test -race ./internal/collector/ide ./internal/evidence -count=1 # PASS
go vet ./internal/collector/ide ./internal/evidence                 # PASS
go vet ./...                                                        # PASS
git diff --check                                                    # PASS
go test ./... -count=1                                             # known staged failures only
```

The full suite passed `internal/collector/ide`, `internal/evidence`, and all other implemented packages. Its only failures were the known Task 13--14 acceptance/CLI fixtures that still expect pre-evidence JSON shapes and the release dirty-worktree guard in `scripts`.

## Implementation commit

Implementation commit hash: `cfde0000adf416bddfa74352678e4ca03f266da8`.

## Concerns

None within Task 8 ownership. Runtime target paths and anchors remain excluded from JSON, full-cap runtime cleanup is covered, and unsafe secondary browser paths terminate without opening the outside marker.
