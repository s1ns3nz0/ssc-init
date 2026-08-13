# SSC Init v0.5.0 — Draft release notes

This draft describes the changes currently integrated on `master`. The final
release must be built from an exact annotated `v0.5.0` tag following
`docs/release-runbook.md`; the development artifacts produced before tagging
are smoke-test evidence, not release downloads.

## Highlights

- Adds automatic, bounded project discovery from VS Code, Cursor, Windsurf,
  JetBrains, the conventional Projects directory, and reciprocal Git linked
  worktrees. Explicit `--project-root` values remain exact overrides.
- Adds Python lockfile provenance for requirements files, Pipenv, Poetry, and
  uv while preserving mutable/direct-source distinctions.
- Adds progressive human-readable audit output for baseline scans and status.
- Creates a deterministic, self-verifying audit ZIP for complete, partial, and
  failed scans without adding a network or external-command probe.
- Adds offline audit listing, detailed sections, verification, and internal or
  redacted export:

  ```sh
  ssc-init audit list --pretty
  ssc-init audit show <run-id> --section coverage
  ssc-init audit verify /absolute/audit.zip --pretty
  ssc-init audit export <run-id> --output /absolute/internal.zip
  ssc-init audit export <run-id> --output /absolute/redacted.zip --redacted
  ```

## Audit evidence contract

- Managed archives live under
  `$HOME/Library/Application Support/SSC Init/audit`.
- Retention is bounded to 30 days and 1 GiB while always preserving the newest
  valid execution receipt.
- Verification checks the closed ZIP catalog, canonical manifest, entry
  digests, size and expansion limits, and privacy-valid decoded records.
- Redacted exports remove asset names and versions and use fresh export-local
  identifiers, making separate exports non-correlatable by their internal IDs.
- Failed scans retain only a closed failure stage and code. Original paths,
  diagnostics, arguments, endpoints, and secrets are not archived.
- Archives are explicitly `unsigned`. Integrity verification is not an origin
  signature or non-repudiation claim.

## Distribution and macOS

GitHub release archives remain the distribution channel. This release does not
add Mac App Store packaging or Apple signing. The unsigned universal binary may
require normal user approval under macOS Gatekeeper; SSC Init does not advise
removing quarantine metadata or weakening Gatekeeper.

## Release artifacts

The final tagged build publishes:

- `ssc-init-darwin-universal` (arm64 and x86_64);
- Claude, Codex, and Cursor adapter ZIPs;
- `checksums.txt`;
- `sbom.cdx.json`; and
- `provenance.json`.

Consumers should download the complete checksum subject set and run:

```sh
shasum -a 256 -c checksums.txt
```

## Verification performed on the integrated development revision

- Full build and vet gates.
- Full race-enabled Go test suite, including the isolated-HOME audit lifecycle.
- Module verification and reproducible release-script tests.
- Universal development build and checksum verification.
- Real binary smoke test covering scan, list, show, verify, internal export,
  redacted export, and status after the SQLite database was made unavailable.

The release owner must repeat the runbook gates after creating the annotated
tag; the tag itself and GitHub publication are intentionally not created by
this draft.
