# Task 9 fix round 4 report

Base: `e0e190475bf927711798a0fcd37f68845a93a258`

Task 9 semantic evidence now rejects chained credential syntax while a prior
flag is waiting for its value, and the collector canonicalizes every supported
privacy-placeholder spelling to exact semantic-v1 `[redacted]` before
observation finalization.

## Changed files

- `internal/collector/mcp/collector.go`
- `internal/collector/mcp/evidence_test.go`

## TDD red record

```text
go test ./internal/collector/mcp -run 'TestMCP(ChainedCredentialFlags|CollectorCanonicalizesPrivacyPlaceholderVariants)' -count=1
```

Before implementation, all seven chained credential servers finalized as
complete assets and observations. The failing corpus included exact chains
(`--auth --token hunter`), empty-combined chains
(`--auth: --token= hunter`), authorization/header chains, proxy/Bearer text,
bare `Bearer`, short-flag chains, and dangling text chains.

The same red run showed that standalone placeholder spellings survived public
metadata unchanged: command and argument fields retained `[REDACTED]`,
`[ReDaCtEd]`, or `redacted`, while CWD values became
`config-relative/<variant>`. Even canonical `[redacted]` became
`config-relative/[redacted]` in CWD.

The first broader green attempt exposed and prevented an overbroad guard:

```text
go test ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1
```

`TestMCPCollectorObservationContainsSanitizedSemanticsOnly` failed because an
ordinary next value named `argument-secret` was mistaken for credential
syntax. The guard was narrowed to actual flag/combined/text syntax and exact
bare Bearer/authorization labels; it does not classify arbitrary vocabulary
inside ordinary values.

## Green behavior

- While `redactNext` is active, exact flags, attached/empty combined flags,
  authorization/proxy text, `Bearer <value>`, and exact bare Bearer or
  authorization labels cause argument sanitization to fail closed. The server
  becomes `partial`/`rejected_metadata` before asset, observation, or evidence
  target issuance.
- The chain corpus retains only one valid sibling. Its ordinary next value is
  redacted to `--auth\x1f[redacted]`, complete evidence is issued, and no raw
  tail marker appears in collector or evidence JSON.
- Standalone `privacy.IsRedactedPlaceholder` variants are canonicalized at
  command, individual argument, URL, and CWD collector entry points. Canonical
  authorization argument text remains `Authorization: [redacted]`.
- `[redacted]`, `[REDACTED]`, `[ReDaCtEd]`, and `redacted` inputs produce the
  same exact public metadata and identical complete digests through a
  zero-value evidence engine.
- The semantic hasher's exact-only defensive rule is unchanged, and all prior
  credential vocabulary, list, URL, path, CWD, and engine behavior remains
  covered by the focused suites.

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

Implementation commit hash: `e2119031f2374605381640e3ab51b00bfed46517`.

## Concerns

None within Task 9 ownership. No parser, discovery, persistence, network, or
external command-execution behavior was added.
