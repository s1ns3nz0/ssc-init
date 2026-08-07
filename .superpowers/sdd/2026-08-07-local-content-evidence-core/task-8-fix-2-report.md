# Task 8 fix round 2 report

Invalid IDE entrypoint declarations now use a fixed, secret-free, NUL-containing runtime sentinel. The collector honors `canonicalIDEEntrypointPath`'s boolean and never gives the evidence engine a raw invalid declaration-derived path.

## Changed files

- `internal/collector/ide/evidence.go`
- `internal/collector/ide/evidence_test.go`

## TDD red record

```text
go test ./internal/collector/ide -run 'WhitespaceEntrypoints' -count=1
```

Before the production change, both whitespace cases failed because the engine opened and hashed real files named ` main.js ` and ` web.js `, returning complete entrypoint evidence instead of terminal `path_invalid` evidence.

The zero-open assertion runs the authentic sealed invalid entry target in isolation because a complete payload-tree target legitimately reads every payload leaf, including spaced filenames.

## Verification

```text
go test ./internal/collector/ide ./internal/evidence -count=1       # PASS
go test -race ./internal/collector/ide ./internal/evidence -count=1 # PASS
go vet ./internal/collector/ide ./internal/evidence                 # PASS
go vet ./...                                                        # PASS
git diff --check                                                    # PASS
go test ./... -count=1                                             # known staged failures only
```

The full suite passed the IDE/evidence packages and all other implemented packages. Its only failures were the known Task 13--14 acceptance/CLI fixtures that still expect pre-evidence JSON shapes and the release dirty-worktree guard in `scripts`.

## Implementation commit

Implementation commit hash: `072a1914dd0a97cf0e6942b08ab16a0932e61c45`.

## Concerns

None within Task 8 ownership. Legacy public `entry_point` trimming remains unchanged, raw whitespace declarations and the sentinel are absent from JSON, and existing traversal, absolute, NUL, symlink, privacy, and cleanup coverage remains green.
