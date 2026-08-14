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

## Fix round 1: closed advisory IDs, signed counts, and report bytes

Status: DONE

The independent review's three Important findings were addressed with strict
RED/GREEN cycles:

- Public advisory presentation now accepts only closed producer/source
  namespaces and shapes: CVE, official GHSA, OSV, Go, PYSEC, RUSTSEC, and the
  numeric-year OpenSSF MAL form. Only the publisher's `#NNN` expansion suffix
  is stripped. Plausible opaque hyphenated values and namespace lookalikes are
  neither displayed nor described as affected-version advisories.
- `IntelligenceUpdate` now persists `records`, `malicious`, and `vulnerable`
  from the verified `bundle.UpdateResult`. Counts are bounded to 100,000,
  nonnegative, and must satisfy `records = malicious + vulnerable`. Identity-
  free unavailable receipts require all-zero counts. Updated, current,
  degraded/LKG, and expired identified receipts preserve the exact signed
  bundle composition through canonical archive reload and render all three
  rows in `INTELLIGENCE`.
- Audit reports now use an explicit text policy: valid UTF-8 with LF and tab as
  the only permitted control characters. Encode rejects unsafe bytes before
  ZIP construction, and Verify independently rejects a correctly catalogued
  and rehashed hostile `report.txt`, covering CSI, OSC, NUL, CR, DEL, and C1
  controls while preserving Unicode prose.

Mutation evidence killed and restored a broad advisory allow, omitted count
wiring, missing count-sum validation, and removed Verify-side report control
validation. Legacy archives without an intelligence receipt retain their
existing closed catalog and verification behavior.
