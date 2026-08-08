# Task 9 fix round 1 report

Base: `dbb4b414ed15f52439a7cc9540beca63145fa7a8`

Task 9 semantic evidence now has matching collector-side sanitization and
hasher-side fail-closed validation for combined credentials, embedded absolute
paths, decoded URL paths, canonical CWD references, closed MCP tuple structure,
and collector-specific engine defaults.

## Changed files

- `internal/collector/mcp/collector.go`
- `internal/collector/mcp/evidence_test.go`
- `internal/evidence/engine.go`
- `internal/evidence/engine_test.go`
- `internal/evidence/semantic.go`
- `internal/evidence/semantic_test.go`

## TDD red record

```text
go test ./internal/evidence -run 'HashMCPObservation' -count=1
```

Before implementation, malformed host/source/transport and command/URL tuples,
colon credentials, combined short flags, decoded secret URL paths, embedded
absolute paths, and noncanonical `$HOME/` CWD suffixes were accepted.

```text
go test ./internal/collector/mcp -run 'CombinedCredential|EmbeddedAbsolute|URLPaths|RepresentativeSupported' -count=1
```

Before implementation, `--auth:`/`--env:` values and embedded absolute paths
survived observation metadata, unsafe decoded URL paths survived URL shaping,
and credential prefixes were not preserved consistently with redaction.

```text
go test ./internal/evidence -run 'DefaultLeavesNonMCP' -count=1
```

Before implementation, a zero-value engine attempted the MCP hasher for a
non-MCP semantic target and returned `unavailable` instead of the prior
digest-free `unsupported` result.

Additional focused red runs proved that `token//value`, encoded noncanonical
`query_keys`, backslash CWD suffixes, foreign external CWD labels, `-e` combined
forms, and collector-emitted noncanonical CWD values crossed their respective
boundaries before the corresponding minimal fixes.

## Green behavior

- Collector arguments redact `:` and `=` combined sensitive flags, `-H` and
  `-e` combined forms, while leaving `--tokenizer` unchanged. Secret-only
  fixture changes produce identical complete semantic digests.
- Command/argument absolute paths following `:`, `;`, `=`, comma, whitespace,
  or the unit separator are redacted or rejected without rejecting safe HTTP
  URL shapes or `external-*/path-sha256:` references.
- URL shaping decodes and validates paths, rejects invalid escapes, encoded
  separators/controls, credential assignments, and sensitive-name/value path
  sequences, while stripping userinfo/query values/fragments and preserving
  safe `/api/v1/mcp?query_keys=...` shapes.
- `HashMCPObservation` requires matching lowercase `mcp.<host>.<suffix>`, the
  closed transport set, exactly one transport-appropriate command or URL, and
  rejects remote args/CWD and other impossible v1 combinations.
- `$HOME` remains valid; `$HOME/` suffixes, `config-relative` values, and
  `external-cwd` references must be bounded and canonical.
- The default MCP hasher is installed only for `Collector == "mcp"`.
  Explicit simple hashers still override it and context hashers retain highest
  precedence.

## Verification

```text
go test ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1       # PASS
go test -race ./internal/collector/mcp ./internal/evidence -count=1                   # PASS
go vet ./...                                                                          # PASS
git diff --check                                                                      # PASS
go test ./... -count=1                                                               # known staged failures only
```

The full suite passed MCP, evidence, privacy, and every other implemented
package. Its only failures remain the known Task 13--14 acceptance/CLI fixture
expectations and the release build's intentional dirty-worktree guard.

## Implementation commit

Implementation commit hash: `2ef551369c41e6d1c4fe359ac1c766a7431b9953`.

## Concerns

None within Task 9 ownership. Parser behavior, discovery collision/coverage,
sealed target binding, runtime cleanup, callback limits, and secret-value
exclusion remain covered and green. No dependency, command execution, network,
or persistence behavior was added.
