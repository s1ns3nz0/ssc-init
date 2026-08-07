# Task 9 — Secret-free semantic MCP evidence

Base: `161ffd4c761d6a7ecfae7599d245694e5b19dbda`
Product commit: pending (corrected in the follow-up report-only commit)

## Delivered

- Added immutable `ssc-init.semantic-mcp.v1` SHA-256 hashing for the fixed MCP
  semantic tuple: host, source, and the ten closed metadata fields.
- The hash ignores `unknown_fields` and every other unknown metadata key. It
  rejects malformed included values, raw absolute paths, credential-bearing
  values, control/invalid UTF-8/oversized values, and unsanitized URL shapes.
- The zero-value evidence engine now defaults to the MCP hasher; explicit
  simple and context hashers retain their existing precedence.
- The MCP collector issues exactly one sealed, path-free semantic target for
  every finalized observation, with deterministic target ordering and
  reentrant collector-result issuer binding.
- Added unit and end-to-end tests for secret-only mutations, public JSON
  exclusion, semantic mutations, user/project observations, shared catalog
  IDs, runtime cleanup, default/override hashing, and race behavior.

## TDD record

- RED: `go test ./internal/evidence -run HashMCPObservation -count=1` failed
  with `undefined: HashMCPObservation` before `semantic.go` existed.
- GREEN: the same focused semantic suite passed after the minimal hasher.
- RED: `go test ./internal/evidence -run 'Default.*MCP|PlannedSimple|PrefersContext' -count=1`
  reported default semantic targets as `unsupported` before installing the
  default hasher.
- GREEN: that engine suite passed after default wiring.
- RED: `go test ./internal/collector/mcp -run 'Semantic|IssuesOneSealed' -count=1`
  found zero local evidence targets before collector issuance.
- GREEN: the MCP integration suite passed after sealed issuance.

## Verification

- PASS: `go test ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1`
- PASS: `go test -race ./internal/collector/mcp ./internal/evidence -count=1`
- PASS: `go vet ./internal/evidence ./internal/collector/mcp ./internal/privacy`
- PASS: `go vet ./...`
- PASS: `git diff --check`
- `go test ./... -count=1` has only the staged known failures: Task 13–14
  acceptance/CLI schema-fixture expectations and the release-build test's
  intentional dirty-worktree guard. All MCP, evidence, privacy, collector,
  model, scan, inventory, store, report, and platform packages passed.

## Concerns

No raw configuration bytes, secret values, paths, target locations,
observation IDs, project IDs, timestamps, or unknown metadata enter the
semantic digest. No persistence work was added ahead of Task 12.
