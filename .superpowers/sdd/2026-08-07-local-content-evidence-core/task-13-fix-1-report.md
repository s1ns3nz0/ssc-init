# Task 13 fix round 1 report

## Finding addressed

Review finding (important, test coverage only): `internal/scan/service.go`
`collectProjectMCP` clears the replaced initial `mcp` collector result via
`collector.ClearLocalEvidenceTargets(results[index : index+1])` before dropping
it from the merged results, but no test failed when that call was removed. A
future refactor could silently reintroduce a sealed runtime-state leak. No
product-code change was required; this round adds the locking test only.

## Change

- `internal/scan/service_test.go`: added `reproClearer` (a
  `model.RuntimeEvidenceClearer` recording whether clearing ran) and
  `TestBaselineClearsRuntimeStateOfReplacedInitialMCPResult`. The fixture is a
  `collectorFunc` named `mcp` whose result carries a `reproClearer` as
  `LocalEvidenceIssuer` and another as `LocalEvidenceTargets[0].Provenance`.
  With an environment supplied (`testEnvironment(t)`), `Baseline` always runs
  the project-MCP follow-up, whose single sealed result replaces the initial
  `mcp` result in the merge — the exact path where `collectProjectMCP` drops
  the initial result and must clear it. The test asserts both clearers fired.

No product code was modified. The temporary RED mutation to
`internal/scan/service.go` was fully reverted; `git diff -- internal/scan/service.go`
was empty before commit.

## TDD evidence

### RED

With `collector.ClearLocalEvidenceTargets(results[index : index+1])` removed
from `collectProjectMCP` (keeping `continue`):

```
$ go test ./internal/scan -run TestBaselineClearsRuntimeStateOfReplacedInitialMCPResult -count=1
--- FAIL: TestBaselineClearsRuntimeStateOfReplacedInitialMCPResult (0.00s)
    service_test.go:356: dropped initial mcp runtime state not cleared: issuer=false provenance=false
FAIL
FAIL	github.com/ssc-init/ssc-init/internal/scan	0.454s
FAIL
```

### GREEN

Call restored (service.go byte-identical to HEAD):

```
$ go test ./internal/scan -run TestBaselineClearsRuntimeStateOfReplacedInitialMCPResult -count=1
ok  	github.com/ssc-init/ssc-init/internal/scan	0.370s
```

## Regression results

| Command | Result |
| --- | --- |
| `go test ./internal/scan -count=1` | ok |
| `go test -race ./internal/scan -count=1` | ok |
| `go test ./internal/scan -run TestBaselineClearsRuntimeStateOfReplacedInitialMCPResult -count=50` | ok |
| `go vet ./...` | clean |
| `git diff --check` | clean |
| `gofmt -l internal/scan/service_test.go` | clean |

## Files changed

- `internal/scan/service_test.go` (+24 lines; test-only)

Commit: `cb5f175` — `test: lock clearing of replaced initial mcp result`
