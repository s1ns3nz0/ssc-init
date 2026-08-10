# SSC Init release runbook

## 1. Preconditions

Release only from a clean tracked worktree. Verify modules and the full race
gate, then create the annotated release tag before building; an untagged build
truthfully reports `dev+git.<commit>` instead of the intended version.

```sh
git status --short
go mod verify
go test -race -count=1 ./...
git tag -a vX.Y.Z -m vX.Y.Z
```

## 2. Reproducible build

```sh
go mod download
sh scripts/build-darwin.sh
shasum -a 256 -c dist/checksums.txt
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

## 7. External gaps

- Production bundle public keys and publication evidence remain external.
- Hosted CI execution evidence remains external.
- Physical arm64 and Intel smoke-test evidence remains external.
