# TI Publication and Explicit Update Design

Date: 2026-08-14

Authority: the verified-bundle design, findings-reporting design, and the
approved conversation on 2026-08-14.

## Outcome

SSC Init publishes a deterministic, signed threat-intelligence snapshot built
from OSV vulnerability data and OpenSSF malicious-package reports. A user may
explicitly update the local TI bundle, or request an update immediately before
a baseline scan. Default scans remain offline.

The completed flow proves which source records, bundle sequence, digest, and
signing key informed a finding. A failed update never replaces the
last-known-good bundle and never prevents a personal advisory scan.

## Scope

This program adds:

- a publisher that ingests OSV-format source data for npm, PyPI, Go, and
  crates.io;
- deterministic normalization into `ssc-init.bundle.v1` TI records;
- an Ed25519-signed update manifest and detached bundle signature;
- publication to the dedicated public `s1ns3nz0/ssc-init-ti` feed repository
  through an explicit CI workflow;
- bounded, allowlisted client retrieval through `bundle update`;
- `scan --update-ti`, which updates first and then scans;
- pretty and JSON update/status reporting;
- real correlation of vulnerability and malicious-package records with the
  package identities already collected by SSC Init;
- end-to-end tests for publication, update, rollback refusal, correlation,
  degraded operation, and audit evidence.

This program does not add background networking, automatic updates during a
default scan, a daemon, arbitrary feed URLs, user-supplied trust roots, source
code execution, package quarantine, or a claim that unmatched assets are safe.

## Source policy

The publisher consumes two logically distinct inputs:

1. OSV.dev ecosystem data for ordinary vulnerability records.
2. OpenSSF `malicious-packages` records for malicious-package classification.

Although both inputs use the OSV schema and OSV.dev also aggregates OpenSSF,
the publisher retains source provenance and classification separately. An
ordinary vulnerability record cannot become `known-malicious` merely because
it arrived through the same format or aggregator.

Only records whose licenses permit redistribution enter the release bundle.
Each output record retains its public source record ID, public HTTPS reference,
retrieval time, validity, license, and withdrawal state. Withdrawn records may
remain in the bundle for audit history but never create a current finding.

The initial ecosystem catalog is closed to npm, PyPI, Go, and crates.io. Adding
an ecosystem requires a reviewed canonical-name mapping, version semantics,
fixtures, and a bundle-size budget change if necessary.

## Classification contract

OpenSSF malicious-package records use `known-malicious`, critical severity,
and high confidence only when the collected canonical ecosystem, package name,
and version or digest satisfy the source record exactly. False-positive
version exclusions and withdrawn records do not match.

Ordinary OSV affected-version records use `needs-review` by default. They use
`suspicious`, high severity, and high confidence only when the normalized
record contains a valid CVSS base score of at least 9.0 and SSC Init has an
exact affected-version match. Other severity formats remain only in the
publisher's source-attribution report and do not raise the verdict. Absence of
a collected version is no match; it never becomes a fuzzy malicious or
vulnerable verdict.

Every TI-derived finding carries the public intelligence record IDs and the
active TI bundle family, sequence, and digest. User-facing output explains the
source category and affected-version basis without printing raw source
documents, local paths, or opaque evidence identifiers.

## Canonical package matching

Publisher records and collected assets meet at a version-independent canonical
package coordinate composed of normalized ecosystem and package name. Version
ranges are evaluated separately by the existing ecosystem-aware version
matcher. A bundle record does not encode a version into the lookup key.

The mapping is closed and tested:

| OSV ecosystem | SSC Init ecosystem | Canonical coordinate |
| --- | --- | --- |
| npm | npm | `pkg:npm/<normalized-name>` |
| PyPI | pypi | `pkg:pypi/<normalized-name>` |
| Go | go | `pkg:golang/<module-path>` |
| crates.io | cargo | `pkg:cargo/<normalized-name>` |

Normalization follows each ecosystem's package identity rules. It does not
apply filesystem case folding or guess an ecosystem from a bare name. Existing
versioned package asset IDs are projected to the coordinate through one shared
package-identity component used by both collection and correlation.

## Publication artifacts

The dedicated public `s1ns3nz0/ssc-init-ti` repository contains feed artifacts
only; it carries no application binary releases. Each immutable TI release
contains:

- `ti-manifest.json`;
- `ti-manifest.sig`;
- `ti-bundle.json`;
- `ti-bundle.sig`.

The client discovers the current immutable TI release through GitHub's stable
`releases/latest/download/ti-manifest.json` and corresponding signature paths
on that dedicated repository. The closed manifest contains schema version,
family, version, sequence, key ID, generated/valid times, exact bundle byte
length, SHA-256 digest, an immutable release tag, and a relative artifact name.
It contains no arbitrary download URL. The client constructs the bundle URL
from the compiled HTTPS GitHub repository base, validated release tag, and
validated relative name. Redirects may reach only GitHub's documented
release-asset host set compiled into the client.

The manifest signature covers its exact bytes. The bundle signature covers its
exact bytes. Both resolve the same family-scoped key ID through the compiled
trust registry. The client verifies the manifest before trusting its size,
digest, sequence, or artifact name, then verifies the downloaded bundle again
through the existing bundle lifecycle manager before activation.

Publisher output is byte-for-byte deterministic for identical normalized
inputs, sequence, version, time fields, and key. Records and nested lists are
sorted and deduplicated. JSON uses one documented canonical encoding with a
trailing newline.

## Signing trust and rotation

Production Ed25519 private keys are generated outside the repository and
stored only as protected GitHub Actions secrets. They never enter source,
fixtures, logs, workflow artifacts, or release assets. The repository contains
only family-scoped public keys and stable key IDs.

Test keys are visibly test-only and cannot be resolved by a production binary.
Production workflows refuse placeholder or test key IDs. Publisher logs expose
only key ID, sequence, record counts, and output digests.

Rotation adds the new public key in a normal reviewed release before any
manifest uses it. During the overlap, the registry accepts both public keys for
TI only. After all supported clients can trust the new key and old bundles have
expired, a later release removes the old key. Sequence monotonicity continues
across rotation.

## CI publication

Publication is an explicit, manually approved GitHub Actions workflow. It:

1. downloads pinned source snapshots over HTTPS;
2. records source revision/digest metadata;
3. validates OSV schema, ecosystem, licensing, and bounds;
4. normalizes and sorts records;
5. runs publisher unit, mutation, and reproducibility tests;
6. requires a sequence greater than the last published sequence;
7. signs exact manifest and bundle bytes using the protected TI key secret;
8. verifies both signatures using the repository's production public key;
9. uploads the four named assets to an immutable TI release in
   `s1ns3nz0/ssc-init-ti` and marks it as that feed repository's latest
   release;
10. emits checksums and a source-attribution summary.

The workflow does not commit generated feed data to the source branch. It does
not overwrite assets for an existing sequence. A partially uploaded release is
not advertised as current; publication completes only after all four assets
are present and verified.

## Client update protocol

The CLI adds:

```text
ssc-init bundle update --family ti [--json|--pretty]
ssc-init scan --baseline --update-ti [--json|--pretty]
```

Only TI supports remote update in this program. Existing local `bundle
install`, `status`, and `rollback` behavior remains available for both bundle
families.

The update client:

1. opens only the compiled HTTPS GitHub host and
   `s1ns3nz0/ssc-init-ti` repository path;
2. fetches the manifest and signature with fixed time, redirect, and byte
   limits;
3. revalidates the host and path after every redirect;
4. verifies the signed manifest;
5. compares its sequence and digest with local verified state;
6. returns `current` without downloading a bundle when identical;
7. rejects a lower sequence or a same-sequence/different-digest manifest;
8. downloads the exact bounded artifact into a private staging file;
9. verifies byte length, SHA-256, detached signature, closed schema, family,
   key, validity, and sequence;
10. delegates activation to the existing atomic bundle manager;
11. reports a closed update result.

The client sends no machine inventory, package name, version, device ID,
hostname, path, query string, or credential. It performs GET requests only and
uses no cookies or authorization header. Network errors are reduced to closed
codes and never include response bodies or remote error text.

## Scan integration and degraded behavior

A default `scan --baseline` performs no TI network access.

With `--update-ti`, update completes or reaches a closed degraded outcome
before collectors begin. Successful activation makes the new TI bundle
available to the finding service used by that same scan. The scan and its audit
record therefore cite the exact activated sequence and digest.

If update fails:

- a valid fresh or stale last-known-good TI bundle remains active and the scan
  continues with it;
- an expired or invalid bundle produces no TI finding;
- when no valid bundle exists, the scan continues with intelligence
  `unavailable`;
- the result visibly reports update status and a closed error code;
- exit status remains the scan/finding status, except cancellation or a local
  initialization failure before the scan begins;
- no failed bytes become current or previous state.

Update status values are `updated`, `current`, `degraded`, and `unavailable`.
Closed update error codes cover network unavailable, redirect rejected,
response limit, manifest invalid, signature invalid, bundle invalid, rollback
rejected, activation failed, and cancellation.

## User experience

`bundle status --family ti --pretty` shows:

- freshness: missing, fresh, stale, or expired;
- active version and sequence;
- active digest in JSON and a shortened non-identity display in pretty mode;
- validity time;
- update availability only after an explicit update request.

An update followed by a scan adds an `INTELLIGENCE` block near `ASSESSMENT`:

```text
INTELLIGENCE
  update      updated
  freshness   fresh
  sequence    42
  records     18432
  malicious   612
  vulnerable  17820
```

Counts describe the signed bundle, not the number of affected local assets.
Priority findings continue to use the action-first renderer. TI findings add a
plain-language reason such as `verified malicious-package intelligence matched
this exact package version` or `this installed version is affected by OSV-…`.
Known-malicious findings render in red on a terminal. JSON and stored audit
reports contain no ANSI escapes.

## Persistence and audit evidence

The verified bundle directory remains the source of truth for active bytes and
rollback state. A small local update receipt records only family, result,
sequence, digest, key ID, timestamps, and closed error code.

Completed audit records already carry bundle references on TI-derived
findings. This program additionally records the update outcome and TI freshness
used for the run without embedding the manifest, source payload, network URL,
or local file path. Archive verification proves internal digest consistency;
the bundle reference permits independent verification against the published
signed artifact.

## Limits

- Manifest: 64 KiB maximum.
- Manifest signature: exact Ed25519 signature encoding with a 1 KiB file
  ceiling.
- TI bundle: existing 16 MiB verified-bundle ceiling.
- Records: existing 100,000-record ceiling.
- Connect plus request deadline: 15 seconds per file, 45 seconds total.
- Redirects: at most two, with host/path allowlist validation on every hop.
- Source URLs per normalized record and all existing field limits remain
  unchanged.

Publisher generation fails rather than truncating a source silently. If the
signed output approaches a client ceiling, a reviewed schema/budget change or
ecosystem sharding must ship before publication.

## Testing and acceptance

Strict TDD and mutation-sensitive tests cover:

- OSV and OpenSSF parsing, withdrawal, false-positive versions, licenses, and
  ecosystem normalization;
- exact malicious name/version/hash matches and nonmatches;
- vulnerable affected/fixed/range boundaries for all four ecosystems;
- deterministic output under shuffled and duplicated source input;
- manifest and bundle signature verification;
- unknown/wrong-family/test key rejection;
- bad digest, bad length, duplicate JSON keys, unknown fields, expiry, and
  future validity;
- allowlisted HTTPS, redirects, response bounds, timeouts, cancellation, and
  response-body privacy;
- missing to fresh update, no-op current update, newer sequence activation,
  same-sequence equivocation rejection, rollback refusal, and retained
  last-known-good state;
- `scan --update-ti` ordering and default-scan zero-network behavior;
- successful update affecting findings in the same scan;
- degraded update using only a previously verified valid bundle;
- red action-required output for known malicious, reason text, JSON
  compatibility, and ANSI-free audit reports;
- isolated-HOME CLI acceptance with a local allowlisted HTTP/TLS test server;
- audit ZIP reload and bundle-reference verification;
- full build, vet, race, module, reproducibility, and clean-tree release gates.

Before calling production operation complete, acceptance must use a real
published, production-key-signed TI release. It must show `missing` or an older
sequence, perform an explicit update, show `fresh` with the new sequence, scan
the Mac, report TI-derived match counts separately from local analyzer counts,
and verify the saved audit ZIP. A synthetic malicious fixture proves the red
path but is never described as a real infection.

## Delivery sequence

Implementation proceeds in reviewable vertical slices:

1. shared canonical package identity and correlation correction;
2. deterministic OSV/OpenSSF publisher;
3. signed update manifest and production trust registry seam;
4. bounded update client and atomic lifecycle integration;
5. CLI commands, explicit scan orchestration, and UX;
6. GitHub publication workflow, key-provisioning documentation, and release
   checks;
7. isolated and real-release end-to-end acceptance.

Production publication is blocked until the repository owner provisions the
private signing key secret and commits its reviewed public key. All other
implementation and test work can finish with isolated test trust roots without
weakening production's fail-closed behavior.
