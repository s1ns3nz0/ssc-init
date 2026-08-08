# Task 9 fix round 2 report

Base: `4d66a389609d26f5db3f3c2acf29a9aa4be0f5d8`

Task 9 semantic evidence now uses matching collector-side canonicalization and
hasher-side defensive validation for punctuation-attached credentials,
field-specific semantic lists, repeatedly encoded URL paths, slash-rooted
absolute paths, canonical header placeholders, and ordinary auth/token URL
routes.

## Changed files

- `internal/collector/mcp/collector.go`
- `internal/collector/mcp/evidence_test.go`
- `internal/evidence/semantic.go`
- `internal/evidence/semantic_test.go`

## TDD red record

```text
go test ./internal/evidence ./internal/collector/mcp
```

Before implementation, the hasher accepted punctuation-attached sensitive
flags, field-name/tool injection, slash-rooted paths following quotes, pipes,
or brackets, and repeatedly encoded credential assignments. It also rejected
canonical `Authorization: [redacted]` and `Proxy-Authorization: [redacted]`
arguments and safe `/auth/callback` and `/token/refresh` URL routes. On the
collector side, punctuation-attached values either survived or caused the
server to be rejected, invalid semantic-list siblings reached finalized
observations, quoted/piped/bracketed absolute paths survived, and safe token
routes were over-redacted.

Additional red runs proved three boundary cases before their minimal fixes:

```text
go test ./internal/evidence -run '^TestHashMCPObservationDefensively' -count=1
```

The forged noncanonical form `--auth.actualvalue:[redacted]` was accepted
because the placeholder hid an invalid attached prefix.

```text
go test ./internal/evidence ./internal/collector/mcp -run 'Test(HashMCPObservationDefensivelyRejectsCombinedCredentialsAndEmbeddedPaths|MCPPunctuationAttachedCredentialsAndCanonicalHeadersAreRedacted)' -count=1
```

Split `Authorization:` and `Proxy-Authorization:` arguments did not redact the
following raw value on the collector side.

```text
go test ./internal/evidence ./internal/collector/mcp -run 'Test(HashMCPObservationDetectsSlashRootedPathsAfterPunctuation|MCPEmbeddedAbsolutePathsAreRedactedWithoutRejectingSafeShapes)' -count=1
```

Canonical HTTP URLs with an IPv6 authority were mistaken for raw absolute
paths because their root slash follows `]`.

## Green behavior

- Sensitive long flags use an ASCII flag-name grammar. Exact flags may redact
  their following argument; punctuation-attached forms become a canonical
  placeholder. `-H`/`-e` combined forms remain supported and `--tokenizer`
  remains ordinary. The hasher accepts only collector-canonical redactions.
- `env_keys`, `header_keys`, and tool lists have separate ASCII grammars both
  before `FinalizeObservation` and during hashing. A malformed server is
  quarantined as `partial`/`rejected_metadata` while valid siblings remain.
- URL paths are unescaped once and rejected if a valid `%HH` escape remains.
  Invalid escapes, encoded separators, controls, userinfo, and precise
  same-segment credential assignments remain rejected. Ordinary single
  encoding and `/auth/callback` or `/token/refresh` remain valid and distinct.
- Slash-rooted substrings are found by predecessor context after quotes,
  pipes, colons, semicolons, equals signs, and brackets. Canonical HTTP(S),
  including IPv6 authorities, `$HOME`, `config-relative`, and
  `external-*/path-sha256:` references remain accepted.
- Canonical `Authorization: [redacted]` and
  `Proxy-Authorization: [redacted]` arguments are accepted. Empty colon
  candidates require a following exact placeholder; missing or raw followers
  are rejected. Split collector arguments redact the following value.

## Verification

```text
go test ./internal/evidence ./internal/collector/mcp ./internal/privacy -count=1       # PASS
go test -race ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1 # PASS
go vet ./...                                                                            # PASS
git diff --check                                                                        # PASS
go test ./... -count=1                                                                  # known staged failures only
```

The full suite passed the command package and every implemented internal
package, including MCP, evidence, and privacy. Its only failures remain the
known Task 13--14 acceptance fixtures
(`TestBaselineFixturePersistsWithRealStore`,
`TestBaselinePersistsSameMCPServerFromTwoProjectsWithRealStore`, and
`TestV2BaselineReopenStatusUnchangedAndObservedLocationDelta`), the known CLI
fixture expectations (`TestBaselineJSONReportsPartialCoverageAndPersists` and
the two `TestStatusJSONHasStableEmptyV1AndV2Shapes` subtests), and the release
build's intentional dirty-worktree guard
(`TestBuildScriptWorksOutsideRepositoryAndIsReproducible`).

## Implementation commit

Implementation commit hash: `4aedadf441d006a0d7cd649e7398efc7b9177904`.

## Concerns

None within Task 9 ownership. No parser, discovery, persistence, network, or
external command-execution behavior was added.
