# SSC Init release runbook

## 1. Preconditions

Release only from a clean committed worktree at an exact annotated `v*` tag.
Verify modules and the full race gate, then create the annotated tag before
entering explicit release mode. `SSC_INIT_RELEASE=1` fails closed for an
untagged commit, a lightweight tag, or a non-version tag. A build without that
variable remains a developer build and may truthfully report
`dev+git.<commit>`.

```sh
git status --short
go mod verify
go test -race -count=1 ./...
git tag -a vX.Y.Z -m vX.Y.Z
```

## 2. Reproducible build

```sh
go mod download
SSC_INIT_RELEASE=1 sh scripts/build-darwin.sh
(cd dist && shasum -a 256 -c checksums.txt)
go test ./scripts -count=1
```

The build produces reproducible Darwin artifacts and their verification
material. A second run must produce byte-identical files; the script tests
verify that property.

## 3. Publish

Publish the closed reproducible release set:

- `ssc-init-darwin-universal`;
- `ssc-init-adapter-claude.zip`, `ssc-init-adapter-codex.zip`, and
  `ssc-init-adapter-cursor.zip`;
- `checksums.txt`;
- `sbom.cdx.json`; and
- `provenance.json`.

The arm64 and amd64 thin binaries are build intermediates, not release
downloads.

## 4. Consumer verification

Download the complete checksum subject set into one directory, then run:

```sh
shasum -a 256 -c checksums.txt
```

Inspect `sbom.cdx.json` and `provenance.json` before use. Do not make a
hardening claim about the release artifacts.

## 5. Install and rollback

```sh
ssc-init install --from <absolute-path> --version vX.Y.Z --sha256 <digest> --json
ssc-init doctor --json
ssc-init rollback --json
```

The installer stages and verifies the digest and universal Mach-O shape, runs
the staged core's doctor health check, then atomically switches a pointer file.
Rollback succeeds only after at least two versions have been activated; a
first installation correctly reports `rollbackAvailable: false`.
The pointer is never a symlink and is validated on every read. Removing an
adapter must never remove `state.db`, intelligence or policy bundles, reports,
or quarantine contents. Neither `install` nor `rollback` touches that shared
state.

## 6. macOS behavior

The prebuilt binary is intentionally unsigned. macOS may block a downloaded
copy or require explicit approval. Users who require a locally produced binary
can install with `go install` or build from the tagged source. Do not instruct
users to remove quarantine metadata or weaken Gatekeeper.

## 7. Audit evidence smoke test

Each scan attempts to publish a deterministic complete, partial, or failed ZIP
under `$HOME/Library/Application Support/SSC Init/audit`. Before publishing a
release, exercise the operator path:

```sh
ssc-init scan --baseline --pretty --label release-smoke
ssc-init audit list --pretty
ssc-init audit show <run-id> --section coverage
ssc-init audit verify '/absolute/managed.zip' --pretty
ssc-init audit export <run-id> --output /absolute/internal.zip
ssc-init audit export <run-id> --output /absolute/redacted.zip --redacted
```

Confirm the screen order is `SUMMARY`, `FINDINGS`, `CHANGES`, `COVERAGE`,
`ASSETS`, and `AUDIT EVIDENCE`. Retention is 30 days and 1 GiB with the newest
valid archive always preserved. Internal exports retain privacy-safe names and
versions; redacted exports remove them and use fresh unlinkable IDs. Verification
is offline and checks integrity and privacy, but the archive is unsigned and
does not authenticate an organization. Future organization signatures belong
at that explicit boundary. GitHub remains the release channel; Apple signing
and Mac App Store publication are unrelated.

## 8. External gaps

- Production bundle public keys and publication evidence remain external.
- Hosted CI execution evidence remains external.
- Physical arm64 and Intel smoke-test evidence remains external.
