# Task 6 Report: TI UX, Reasons, and Audit Evidence

Status: DONE

Commit: task commit containing this report

## Implementation

- Added an `INTELLIGENCE` block immediately after `ASSESSMENT`. It presents
  only the closed update status, freshness, active sequence, and closed error
  code. A scan without an explicit update says `not requested` / `unavailable`.
- Restricted semantic color: red is limited to malicious/action-required
  states, yellow to vulnerable/degraded/stale/unavailable states, and green to
  a verified fresh `updated` or `current` TI state. Coverage, saved archives,
  and no-finding output are not painted as host safety claims.
- Distinguished OpenSSF `MAL-...` exact malicious-package matches from ordinary
  public OSV advisory matches. Opaque or malformed intelligence identities do
  not receive a source-category claim.
- Added action-first pretty details for allowlisted public advisory IDs, active
  TI sequence, evidence count, and action. URLs, paths, queries, hostnames,
  response/source text, key material, and opaque evidence IDs are never used as
  presentation values.
- Preserved the existing findings JSON schema and kept archived `ReportText`
  ANSI-free.

## Audit archive scope expansion

Task 6 acceptance exposed that Task 5's in-memory `IntelligenceUpdate` was not
persisted by `internal/audit/archive.go`: reload returned a nil receipt. With
parent approval, Task 6 ownership was narrowly expanded to that file and its
tests. A receipt-bearing archive now adds a canonical, closed, 1 KiB-bounded
`intelligence.json` entry and round-trips it exactly. Receipt-free v1 archives
retain their original catalog and encoding path. Verification rejects unknown
or duplicate JSON members, oversized receipts, invalid/private values,
unexpected catalog placement, traversal, links, and unknown entries through
the existing fail-closed archive boundary.

## TDD and mutation evidence

Tests first failed for the absent intelligence block, generic TI reason,
missing finding details, and dropped archive receipt. They passed after the
minimal implementation.

Required independent privacy mutations were killed and restored:

1. Allowing an HTTPS intelligence source value through `PublicAdvisories`
   failed `TestWriteFindingsPrettyNeverPrintsIntelligenceSourceURL`.
2. Returning the raw first evidence identity failed
   `TestWriteFindingsPrettyNeverPrintsOpaqueEvidenceID`.

Additional tests cover malicious vs OSV reasons, opaque source-category
refusal, fresh/degraded/unavailable colors, no-update state, archived ANSI
absence, archive reload, canonical receipt structure, and JSON compatibility.

## Verification

Before commit, focused race tests and all non-clean-tree-gated packages passed.
The complete clean-tree commands are recorded after the task commit:

```sh
go test -race ./internal/audit ./internal/findingdisplay ./internal/report ./internal/acceptance -count=1
go test ./... -count=1
go vet ./...
git diff HEAD^ --check
```
