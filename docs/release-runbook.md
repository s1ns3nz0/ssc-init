# SSC Init release runbook

## 1. Preconditions

Release only from a clean tracked worktree. Verify modules and the full test
gate, then create the annotated release tag **before** building; an untagged
build truthfully reports `dev+git.<commit>` instead of the intended version.

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

This produces `dist/ssc-init-darwin-amd64`,
`dist/ssc-init-darwin-arm64`, `dist/ssc-init-darwin-universal`,
`dist/checksums.txt`, `dist/sbom.cdx.json`, and `dist/provenance.json`. A second
run must produce byte-identical files; the script tests verify that property.

## 3. Developer ID signing

This step requires an active Apple Developer Program membership and a
`Developer ID Application` certificate plus its private key in the signing
keychain.

```sh
security find-identity -v -p codesigning
SSC_INIT_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)" sh scripts/sign-darwin.sh
codesign --verify --strict --verbose=2 dist/ssc-init-darwin-universal
codesign -dv --verbose=4 dist/ssc-init-darwin-universal 2>&1 | grep -E 'Authority|TeamIdentifier|Timestamp|flags'
```

Expected output includes `valid on disk`, `satisfies its Designated
Requirement`, a Developer ID authority chain, a team identifier, a non-empty
secure timestamp, and hardened-runtime flags. Signing is intentionally outside
the reproducible build because Apple's timestamp makes signed bytes
non-reproducible. `checksums.txt` describes the reproducible unsigned build;
`checksums-signed.txt` describes the signed universal binary.

## 4. Notarization and stapling

Store credentials once, then create, sign, submit, and staple the shipping
disk image:

```sh
xcrun notarytool store-credentials ssc-init-notary \
  --apple-id <apple-id> --team-id <team-id> --password <app-specific-password>
SSC_INIT_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)" \
  SSC_INIT_NOTARY_PROFILE=ssc-init-notary sh scripts/notarize-darwin.sh
xcrun notarytool history --keychain-profile ssc-init-notary | head
xcrun stapler validate dist/ssc-init-darwin.dmg
spctl --assess -vvv --type open --context context:primary-signature dist/ssc-init-darwin.dmg
```

The submission must report `Accepted`; the notary log must contain no issues;
stapler must validate the attached ticket; and Gatekeeper must report an
accepted Notarized Developer ID source. The ticket is stapled to the `.dmg`,
which permits offline first-run verification. A bare Mach-O cannot carry a
stapled ticket and is therefore not the shipping container.

## 5. Publish

Publish these release assets:

- `ssc-init-darwin.dmg` — the signed, notarized, stapled shipping container;
- `checksums-notarized.txt` — digest of the final stapled container;
- `checksums.txt` — reproducible unsigned-build digests;
- `checksums-signed.txt` — signed core digest for adapter verification;
- `sbom.cdx.json` and `provenance.json`.

The thin arm64/amd64 binaries and bare universal binary are build and
diagnostic artifacts, not user-facing downloads.

## 6. Consumer verification

Before trusting the download, verify the final container and its attached
ticket:

```sh
shasum -a 256 -c checksums-notarized.txt
codesign --verify --strict --verbose=2 ssc-init-darwin.dmg
xcrun stapler validate ssc-init-darwin.dmg
spctl --assess -vvv --type open --context context:primary-signature ssc-init-darwin.dmg
```

After mounting the disk image, an adapter additionally verifies the extracted
core against `checksums-signed.txt` and with `codesign --verify --strict
--verbose=2` before handing its absolute path to the installed core.

## 7. Install and rollback

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

## 8. Known external gaps

- No git remote is configured, so `.github/workflows/ci.yml` has not executed
  on a hosted runner. Creating a remote and pushing the repository unblocks it.
- No Developer ID certificate/private key is available in this environment, so
  the real signing success path has not run. Apple Developer Program credentials
  unblock it.
- No notary keychain profile is available, so a real submission and staple have
  not run. An Apple ID app-specific password and team ID unblock it.
