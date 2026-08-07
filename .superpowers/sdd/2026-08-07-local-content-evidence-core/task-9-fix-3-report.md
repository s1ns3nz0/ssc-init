# Task 9 fix round 3 report

Base: `7e61a393ae23b992f243f20a2c5280a0fb7c9e9b`

Task 9 semantic evidence now fails closed on dangling credential arguments,
shares one dependency-neutral credential vocabulary between collector and
hasher, accepts only the exact semantic-v1 redaction spelling, and requires
all semantic lists to be strictly sorted and unique.

## Changed files

- `internal/collector/mcp/collector.go`
- `internal/collector/mcp/evidence_test.go`
- `internal/collector/mcp/semantic_validation_test.go`
- `internal/evidence/semantic.go`
- `internal/evidence/semantic_test.go`
- `internal/privacy/credentials.go`
- `internal/privacy/credentials_test.go`

## TDD red record

```text
go test ./internal/evidence ./internal/collector/mcp -count=1
```

Before implementation:

- terminal exact flags and empty attached separators finalized complete
  observations instead of failing closed;
- `--auth:`, `--token=`, `-H:`, and `-e=` left their following raw markers in
  semantic arguments;
- dangling flags produced eleven observations/assets rather than retaining
  only the valid sibling;
- the hasher accepted `--key=actualvalue`, `/key=actualvalue`, and
  `/authorizationhelper=actualvalue` because its vocabulary had drifted from
  the collector's camel/acronym-aware vocabulary;
- `[REDACTED]`, `redacted`, and mixed-case placeholder variants were accepted
  as semantic commands, arguments, combined values, URLs, and CWDs; and
- every `B,A` and `A,A` list variant was accepted by both semantic validation
  layers.

```text
go test ./internal/privacy -run '^TestContainsCredentialComponent' -count=1
```

The new dependency-neutral vocabulary contract initially failed to compile
because `ContainsCredentialComponent` did not yet exist. Its table fixes the
expected camel/acronym splits, generic `key`, exact vocabulary, tokenizer/key
false-positive boundaries, and the legacy `authorizationHelper` /
`AuthorizationHelper` safelist.

## Green behavior

- Argument sanitization returns explicit validity. Exact standalone flags,
  empty `:`/`=` combined flags, terminal `Authorization:`, and terminal
  `Proxy-Authorization:` consume and redact a following argument. If none
  exists, metadata construction fails before `FinalizeObservation`; the
  server is quarantined as `partial`/`rejected_metadata` and produces no
  asset, observation, or evidence target.
- Present-next credential cases exclude both raw markers and produce equal,
  complete digests when only the marker changes.
- `privacy.ContainsCredentialComponent` is the single vocabulary used by
  collector and hasher wrappers, including URL same-segment assignments. It
  preserves the collector's Unicode separator, camel-case, and acronym
  splitting; generic `key`; exact credential terms; and legacy helper
  safelist behavior.
- Semantic v1 recognizes only exact `[redacted]`. Case variants and the bare
  `redacted` privacy placeholder are rejected for command, argument,
  credential candidate, URL, and CWD positions. Collector output remains the
  exact canonical spelling.
- Environment keys, HTTP header keys, enabled tools, and disabled tools must
  each be strictly lexically increasing in both collector pre-finalization
  validation and defensive hashing. This rejects duplicates and unsorted
  tuples while accepting `A,B`.
- All prior punctuation/path/URL/CWD protections and default/custom engine
  behavior remain covered by the focused suites.

## Verification

```text
go test ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1        # PASS
go test -race ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1  # PASS
go vet ./...                                                                             # PASS
git diff --check                                                                         # PASS
go test ./... -count=1                                                                   # known staged failures only
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

Implementation commit hash: `ba84752c85beb9e794d110565304a9ea48f9a69c`.

## Concerns

None within Task 9 ownership. No parser, discovery, persistence, network, or
external command-execution behavior was added.
