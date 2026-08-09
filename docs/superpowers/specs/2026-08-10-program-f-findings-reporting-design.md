# Program F findings and organization reporting design

Date: 2026-08-10

Authority: foundation design §7.3, §8, §9.1–§9.2, §10–§13 and the approved
policy-layer design §1, §5–§7. Program E's verified bundle files are the only
accepted TI and organization sources.

## Outcome

SSC Init deterministically correlates already-recorded inventory facts with an
active verified TI bundle and active verified organization policy. It emits
closed findings and precedence decisions, persists bounded incident metadata,
and renders Finding JSON, SARIF 2.1.0, and inventory CycloneDX. An explicit
command may deliver the privacy-safe Finding JSON payload to an HTTPS webhook.

This program does not inspect source code, infer behavior, intercept execution,
or claim host enforcement. Program G supplies analyzers; Program H supplies
host capabilities. Exact TI matches and organization deny decisions can be
classified now, but their action is `advisory` until a host declares a real
enforcement capability.

## Closed finding contract

The public scan/status contract advances to v6 and stores findings separately
from assets, observations, relationships, and content evidence. Earlier v1–v5
snapshots remain readable as legacy and never gain retroactive findings.

A finding contains only:

- stable finding ID, canonical asset ID/type, version and SHA-256 when known;
- verdict: `known-malicious`, `behaviorally-malicious`, `suspicious`,
  `needs-review`, or `no-finding`;
- severity: `critical`, `high`, `medium`, `low`, or `informational`;
- confidence: `high`, `medium`, or `low`;
- precedence level 1–5, closed rule/intelligence record IDs and evidence IDs;
- detected time and action: `advisory`, `blocked`, `paused`, `excepted`, or
  `allowed`;
- active bundle family/sequence/digest references and campaign/ATT&CK IDs.

No finding may contain a path, project/repository name, source URL, raw match,
command argument, environment value, hostname, user identity, or source bytes.
`no-finding` means only that no relevant evidence was found in recorded scope.
User-facing output must never label it `safe`, `clean`, or `trusted`.

## Correlation and precedence

Correlation is pure over `(Inventory, TI payload, organization payload, local
policy, pins, exceptions, time)` and performs no I/O.

1. A non-withdrawn exact TI `assetId` match applies. When the TI record carries
   SHA-256, the asset must carry the identical complete SHA-256 fact. A hash
   mismatch is no match, never a fuzzy warning. Version-range-only matching is
   deferred to Program G's package-version engine.
2. `known-malicious` exact evidence decides at level 1 and cannot be excepted.
3. Organization deny decides at level 2. Local exceptions cannot override it.
4. Organization allow decides at level 3 only for the exact asset ID and exact
   SHA-256; changed bytes invalidate the allow.
5. Organization-scoped exceptions are applied only when their signed fields
   and expiry validated in Program E. Local scoped exceptions remain level 4.
6. Default product policy remains level 5.

Multiple TI records may support one finding. The strongest verdict/severity
wins deterministically; all bounded supporting IDs remain sorted. A withdrawn
record is retained for audit but never creates a current finding.

## Storage and retention

Findings and decisions are persisted in child tables of the v6 snapshot.
Critical/high incident metadata is also copied to an independent incident table
with no `scan_id`, so routine snapshot pruning cannot erase it. Explicit
deletion is required until signed organization retention is active. Lower
severity findings follow snapshot retention.

## Reporters

- Finding JSON (`ssc-init.findings.v1`) is the canonical egress contract.
- SARIF 2.1.0 maps rule IDs, severity, asset canonical ID and message, with no
  artifact location or source region unless a future privacy review adds one.
- CycloneDX 1.6 represents the current inventory components and dependency
  relationships. It is inventory output, not the release-build SBOM.
- CLI exit codes: `0` no actionable finding, `3` advisory policy/finding
  violation, `4` known-malicious or organization-denied evidence, `1`
  operational failure, `2` usage error.

Webhook delivery is explicit, never part of scan or status. It accepts only an
HTTPS URL without userinfo, validates the destination before opening a socket,
sends the exact Finding JSON contract with bounded timeout/body, and reports a
generic success/failure without echoing the URL or response. No retry daemon or
credential-bearing header is added here.

## Truthful degraded states

Missing TI yields `intelligence: unavailable`; stale or expired bundles remain
visible and reduce confidence but do not block personal use. Invalid active
bundle state produces no findings and never falls back to unverified bytes.
Organization policy is inactive unless the active policy bundle verifies.

Production keys/publication and network retrieval remain external. Apple
Developer signing/notarization remains deferred and unrelated.
