# TI publication runbook

This runbook publishes the public `s1ns3nz0/ssc-init-ti` feed. Publication is
manual, approved, monotonic, and separate from SSC Init application releases.
It never requires Apple signing or the Mac App Store.

## External provisioning gate

Production trust was provisioned on 2026-08-14 with these reviewed public
identifiers:

- feed: `https://github.com/s1ns3nz0/ssc-init-ti`
- immutable GitHub repository ID: `1333823234`
- key ID: `ti-production-2026-01`
- Ed25519 public key (base64 raw): `513aUPfBg20IaplRs5TMcEi8duIi27DUKpq8EMWgDV4=`
- protected source-repository environment: `ti-production`

The private key exists only as the `TI_ED25519_PRIVATE_KEY` environment secret;
its local staging file was deleted after registration. `TI_FEED_TOKEN` and the
reviewed `TI_KEY_ID` environment variable are also configured. Future rotation
or reprovisioning must complete all of the following outside this repository:

1. Create the public `s1ns3nz0/ssc-init-ti` repository and record its immutable
   numeric repository ID for reviewed compilation into `productionTIRepositoryID`.
2. Run `scripts/generate-ti-key.sh --private-output /absolute/private.key` on a
   trusted offline workstation. Review and commit only the printed raw public
   key in `internal/bundle/trust.go`; never commit the private output.
3. Create the protected `ti-production` GitHub environment with required human
   reviewers. Configure `TI_KEY_ID` as a reviewed repository variable and the
   base64 raw 64-byte private key as `TI_ED25519_PRIVATE_KEY` in that protected
   environment. Because the source and feed are different repositories,
   configure `TI_FEED_TOKEN` as a least-privilege, feed-repository-only release
   credential; the ordinary source-repository `GITHUB_TOKEN` cannot write there.
4. Review the compiled public key, key ID, fixed feed URL, and numeric repository
   ID together. Until then, production update intentionally fails before making
   a request.

Do not substitute a test key, runtime key file, configurable URL, or placeholder
repository ID to bypass this stop.

## Prepare and publish

Pin immutable OSV and OpenSSF malicious-package revisions. Workflow inputs
require each exact public snapshot URL, immutable revision, lowercase SHA-256,
reviewed redistribution license, plus one UTC RFC3339 retrieval timestamp. No
license is inferred or defaulted. Only npm, PyPI, Go, and crates.io records with approved
redistribution licenses are accepted. Run:

```sh
go test ./internal/tipublish ./internal/bundle ./cmd/ssc-init-ti-publisher ./scripts -count=1
go test -race ./internal/acceptance -run TestTIUpdate -count=1
```

Open **Actions → Publish signed TI snapshot → Run workflow**. Enter exact HTTPS
snapshot URLs, their lowercase SHA-256 digests, the public version, the next
strictly increasing sequence, and UTC RFC3339 generation/validity times. The
protected environment reviewer must compare those values to the source record.

The workflow verifies source digests, normalization, licenses, bounds,
reproducibility, and monotonic sequence; signs exact manifest and bundle bytes;
then verifies both signatures with the public key compiled into the checkout.
It creates immutable tag `ti-%08d`, uploads the four client assets, and also
uploads `attribution-report.json`, canonical `source-provenance.json`, and
`checksums.txt` as durable operator evidence. Checksums bind both signatures,
both signed documents, attribution, and provenance. Only after every asset is
present does it mark the release latest. Existing tags/assets are never overwritten.

## Rotation

Use dual-key overlap: add the new reviewed public key in a normal SSC Init
release, wait until supported clients trust both keys, publish a higher sequence
with the new key, then remove the old key only after old bundles expire and the
support window ends. Never reset sequence or reuse an ID for different bytes.
If a private key may be exposed, stop publication, revoke environment access,
and rotate to an already-distributed public key.

## Emergency withdrawal and rollback

Never delete or replace a release as a rollback mechanism. Correct a bad record
by publishing a **higher sequence** that marks it withdrawn or removes its
current match. Clients reject lower sequences and same-sequence different bytes.
Preserve old releases for audit history unless incident policy requires removal.

## Real-release smoke evidence

```sh
ssc-init bundle status --family ti --pretty
ssc-init bundle update --family ti --pretty
ssc-init bundle status --family ti --pretty
ssc-init scan --baseline --update-ti --pretty --label ti-release-smoke
ssc-init findings --json
ssc-init audit list --pretty
ssc-init audit verify /absolute/path/to/the/new/archive.zip --pretty
```

Record release tag/sequence, manifest and bundle digests, key ID, freshness,
signed record counts, TI-derived matches separately from analyzer-only findings,
audit run ID, and archive digest. Verify a default scan makes no feed request.
A synthetic fixture tests detection; it is never evidence the Mac is infected.

The local end-to-end test uses a source file guarded by the exclusive
`ti_acceptance` Go build tag to inject a local TLS certificate, feed base,
repository ID, and test public key into a separately built test binary. Normal
and release builds exclude that file; the same environment variable names have
no effect on them and are not supported configuration.
