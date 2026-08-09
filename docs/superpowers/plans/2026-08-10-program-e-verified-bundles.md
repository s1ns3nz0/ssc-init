# Program E verified bundles implementation plan

> Execute every task RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-e-verified-bundles-design.md`.

**Goal:** Implement local, network-free verification and last-known-good
lifecycle management for signed TI and organization-policy bundles. Production
keys and publication remain explicit external evidence.

### Task 1: closed bundle model

Add envelope, family, freshness, TI record and organization-policy payload
types with closed validation and duplicate-key rejection. Commit `feat: add
closed verified bundle contracts`.

### Task 2: detached signature verifier

Add family-scoped Ed25519 key lookup, exact-byte verification, digest reporting,
unknown/wrong-family rejection and value-free errors. Commit `feat: verify
family scoped bundle signatures`.

### Task 3: TI payload validation

Validate identities, ranges, hashes, verdict/confidence/source/license,
withdrawal, campaign and ATT&CK fields with bounded counts and strings. Commit
`feat: validate threat intelligence bundles`.

### Task 4: organization payload validation

Validate deny/allow precedence, digest-bound allows, scoped exceptions,
retention and deterministic policy tests; reject conflicts and prohibited
known-malicious exceptions. Commit `feat: validate organization policy
bundles`.

### Task 5: hardened bundle layout

Create descriptor-rooted family/version layout and regular-file pointer
helpers. Prove symlink, traversal, mode and replacement boundaries. Commit
`feat: add hardened bundle storage layout`.

### Task 6: stage and activate

Verify source, copy bounded bytes, re-verify staged bytes, fsync, atomically
rename and switch current/previous. Commit `feat: stage and activate verified
bundles`.

### Task 7: rollback protection and rollback

Persist highest accepted sequence independently of current, reject downgrade
installs, permit rollback only to retained verified versions, and preserve the
high-water mark. Commit `feat: enforce bundle rollback protection`.

### Task 8: freshness and health

Report missing/fresh/stale/expired and preserve last-known-good on every
validation, health, cancellation and I/O failure. Commit `feat: report bundle
freshness and health`.

### Task 9: CLI contracts

Add `bundle install|status|rollback` option parsing, JSON output, generic
errors, explicit absolute local sources and no network path. Commit `feat: add
verified bundle commands`.

### Task 10: store indexes

Add rebuildable verified-bundle metadata/audit tables without changing scan
snapshots. Test migration, tamper rebuild, retention isolation and concurrent
readers. Commit `feat: index verified bundle state`.

### Task 11: publisher fixtures and CI validation

Add deterministic fixture compiler/signing test tooling, JSON schemas and a CI
validation job with private signing material supplied only by CI secrets.
Commit `ci: validate signed bundle publication`.

### Task 12: adversarial and release gates

Prove tampering, duplicate keys, unknown keys, wrong family, expiry, rollback,
symlink/replacement, cancellation, concurrency, privacy and deterministic
output under race and repetition. Update README, CLAUDE and the audit. Commit
`test: prove verified bundle lifecycle`, then run the full clean release gate.

`[EXTERNAL]` production public keys, actual signed publication and scheduled
retrieval remain unverified. `[APPLE]` release signing/notarization remains
deferred and is not a dependency.
