# Program E verified bundles design

Date: 2026-08-10

Authority: foundation design §7.2, §8, §10, §11 and the approved policy-layer
design §2, §6, §7.

## Outcome

SSC Init can ingest a bundle file it is explicitly given, verify a detached
Ed25519 signature and SHA-256 digest, validate its closed schema, reject
rollback and expiry violations, stage it, health-check it, and atomically make
it current while preserving the last-known-good version. This program supports
two independent bundle families: threat intelligence and organization policy.

No scan downloads a bundle. No default command opens a network connection.
Fetching and publishing are external workflow concerns; the core accepts only
an explicit local `--from` file. This preserves the current zero-network scan
boundary without weakening the foundation's eventual daily-update design.

## Trust boundary

- Runtime verification uses `crypto/ed25519` and `crypto/sha256` only.
- A bundle names a key ID; the verifier resolves it through a compiled,
  family-scoped public-key registry. A key trusted for TI cannot sign policy.
- Tests use fixture public keys injected through the same registry interface.
  No test private key or placeholder production public key ships in the
  binary.
- The production registry may initially be empty. That makes activation
  unavailable, not unsigned. Adding a production public key is a separate,
  reviewable trust-root change.
- The detached signature covers the exact bundle bytes. JSON canonicalization
  is a publisher responsibility, while the client independently rejects
  duplicate keys and unknown fields.

## Bundle contracts

Both families use a closed `ssc-init.bundle.v1` envelope:

- `schemaVersion`, `family`, `version`, `sequence`, `keyId`;
- `generatedAt`, `validFrom`, `validUntil` in UTC;
- `payload` with a family-specific closed schema.

Sequence is a positive monotonic integer. Version is a display label and never
controls rollback. Activation refuses a sequence below the highest sequence
ever accepted for that family, including after rollback. Exact reactivation of
an already verified sequence is idempotent only when its digest is identical.

TI records preserve canonical identity selectors, version range, exact hashes,
verdict, confidence, source URLs, retrieval/validity times, withdrawal state,
license, redistribution permission, campaign identifiers, and ATT&CK
techniques. This program validates and stores records but does not correlate
them into findings; Program F owns verdict decisions.

Organization-policy payloads contain level-2 denies, digest-bound level-3
allows, scoped exceptions, retention values, and rule tests. They cannot embed
local level-5 policy. This program validates and activates them; Program F
wires them into decisions and reporting.

## Filesystem lifecycle

Bundles live under the existing SSC Init data directory:

```text
bundles/<family>/versions/<sequence>/bundle.json
bundles/<family>/versions/<sequence>/bundle.sig
bundles/<family>/current
bundles/<family>/previous
bundles/<family>/highest-sequence
```

All path operations use the same regular-file, no-symlink, validated-component
rules as core installation. Staging writes a private temporary directory,
re-reads and verifies the staged bytes, fsyncs, renames atomically, then writes
the pointer files atomically. Failed validation never changes current or
previous. Rollback switches only to an already verified retained version and
does not lower `highest-sequence`.

## Freshness and failure behavior

The active bundle is `fresh` through `validUntil`, `stale` for the next seven
days, and `expired` afterward. Missing, stale, and expired states are explicit.
Personal scanning continues with visible component state. Program F may reduce
confidence for stale TI; only a verified organization policy may later request
fail-closed behavior.

Malformed JSON, duplicate keys, unknown fields, bad signatures, unknown keys,
wrong-family keys, digest mismatches, expired-at-install bundles, rollback
attempts, symlinks, replacement races, and cancellation all fail with fixed,
value-free errors. The last-known-good bundle remains active.

## CLI and storage boundary

Program E adds:

```text
ssc-init bundle install --family ti|policy --from <absolute-file> --signature <absolute-file>
ssc-init bundle status --family ti|policy
ssc-init bundle rollback --family ti|policy
```

All commands emit JSON. Install requires explicit local paths and never fetches
them. Bundle indexes may be cached in SQLite, but the verified files and
pointer state remain the rebuildable source for local activation. Inventory
snapshots and `ssc-init.scan.v5` remain unchanged.

## Deferred external evidence

Actual production keys, GitHub-hosted publication, scheduled retrieval, and
key rotation ceremonies require external trust and infrastructure. They do not
block the verifier, lifecycle manager, fixtures, CLI, or failure tests. Apple
Developer signing/notarization is unrelated and remains deferred.
