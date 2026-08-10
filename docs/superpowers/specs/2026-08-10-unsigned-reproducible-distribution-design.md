# Unsigned Reproducible Distribution Design

**Status:** Approved on 2026-08-10

## 1. Purpose

SSC Init will use a single official distribution model that does not depend on
Apple Developer Program membership, Developer ID certificates, notarization,
stapling, or a disk-image release container. The official prebuilt release is
an unsigned, reproducible Darwin Universal Binary accompanied by deterministic
integrity and provenance artifacts.

This design supersedes every earlier active requirement to sign, notarize, or
staple SSC Init release artifacts. Historical documents may retain only a
short supersession notice; they must not retain executable Apple credential or
notarization procedures that could be mistaken for current release work.

## 2. Official release contract

The reproducible GitHub release set is closed to:

- `ssc-init-darwin-universal`;
- the Claude, Codex, and Cursor native adapter ZIP files;
- `checksums.txt` covering the Universal Binary, adapter archives, and SBOM;
- `sbom.cdx.json` in CycloneDX format; and
- `provenance.json` describing the reproducible build inputs and checksum
  subjects.

The arm64 and amd64 binaries remain build intermediates and diagnostic aids.
They are not separate shipping products. A release contains no signed copy,
notarized copy, DMG, PKG, notarization archive, or secondary signed/notarized
checksum file.

Two builds from the same committed, exactly tagged source on the same supported
toolchain must produce byte-identical release artifacts. Release metadata must
identify the exact tag and commit. The release workflow must not accept or
reference Apple signing identities, keychain profiles, Apple IDs, team IDs, or
notarization secrets.

`SSC_INIT_RELEASE=1` is the explicit release mode used by the release runbook
and tagged CI path. It fails before creating artifacts unless the worktree is
clean and committed at an exact annotated `v*` tag. An invocation without that
mode is a clearly distinct developer build and may use a `dev+git.<commit>`
version on an untagged commit.

## 3. Consumer trust and installation

Users and adapters verify downloaded artifacts against the published
`checksums.txt` and may validate the build through the SBOM and provenance
statement. The project makes no claim that an unsigned artifact has passed
Gatekeeper notarization.

The managed installation boundary remains unchanged:

1. the caller supplies a regular file and its expected SHA-256 digest;
2. SSC Init verifies the complete digest before activation;
3. SSC Init verifies the expected Universal Mach-O structure;
4. SSC Init stages the file without following symlinks;
5. a bounded doctor health check runs only the staged core; and
6. activation or rollback updates the validated regular-file version pointer
   atomically.

Documentation must state that macOS may block or require explicit approval for
a downloaded unsigned executable. It must not instruct users to remove
quarantine metadata, weaken Gatekeeper, disable security policy, or otherwise
bypass operating-system protections. Source installation with `go install`, a
clone and local build, or a source-building package formula remains available.

## 4. Preserved platform evidence

Bounded `/usr/bin/codesign` inspection of already discovered executables is not
part of the release-signing pipeline and remains supported. It records local
signature facts only when external probes are explicitly enabled. It requires
no Apple Developer account, performs no signing, changes no file, and makes no
publisher-trust or safety claim.

References to this passive inspection must use terms such as “local signature
facts” or “signature inspection,” not “SSC Init release signing.” Its tests and
closed model contracts remain intact.

## 5. Repository changes

The obsolete release paths are removed, including:

- `scripts/sign-darwin.sh` and its tests;
- `scripts/notarize-darwin.sh` and its tests;
- release-runbook sections for Developer ID, hardened runtime signing,
  notary submission, stapling, Gatekeeper acceptance, and DMG publication;
- active documentation, CI comments, audits, and roadmap entries that describe
  Apple release execution as pending, deferred, optional, or blocked; and
- obsolete output names such as `checksums-signed.txt`,
  `checksums-notarized.txt`, and `ssc-init-darwin.dmg`.

The release build, workflow, fixtures, and documentation instead pin the
closed unsigned artifact set. Tests must fail if Apple credential names,
signing/notarization commands, DMG release artifacts, or deleted scripts are
reintroduced into an active release path.

Historical plans and handoffs receive a concise notice naming this design as
their replacement. Detailed obsolete credential commands and task bodies are
removed so repository search does not present them as actionable guidance.

## 6. Failure behavior

A release fails closed when explicit release mode is absent from the release
path, the tree is dirty, the version is not an exact annotated `v*` tag, an
expected artifact is missing, a checksum subject is missing or extra, the
provenance subject set differs from the checksum subject set, an adapter archive
contains a core executable, or a repeat build is not byte-identical. Checksum
and provenance subjects use the exact downloaded basenames so verification
works with all subjects and `checksums.txt` in one directory.

Unsigned status is not itself a build failure; it is the selected release
contract. Conversely, the pipeline must not label artifacts as signed,
notarized, Gatekeeper-approved, or Apple-verified.

## 7. Verification and acceptance

The redesign is complete when:

1. obsolete signing, notarization, stapling, and DMG scripts and tests are
   absent;
2. active repository guidance contains no Apple credential or notarization
   workflow;
3. historical documents contain only unambiguous supersession notices where
   the old direction must be mentioned;
4. release fixtures prove the exact unsigned artifact set and reject obsolete
   Apple release surfaces;
5. isolated repositories reject untagged, lightweight-tagged, and non-`v*`
   release attempts while two clean builds from the same annotated `v*` tag are
   byte-identical;
6. `checksums.txt` and provenance cover the same exact basename subject set,
   the one-directory consumer verification command succeeds, and the SBOM
   accompanies that set;
7. managed install, doctor, rollback, adapter packaging, and passive local
   signature inspection continue to pass their existing tests;
8. the full race, vet, module, formatting, diff, build-script, and acceptance
   gates pass; and
9. the completion audit lists no Apple Developer dependency or blocked Apple
   work.

## 8. Remaining external work

Removing Apple release execution does not resolve unrelated external work.
Hosted CI evidence, production bundle signing keys and publication, and clean
physical Apple Silicon/Intel smoke tests remain separate roadmap items. They
must not be described as dependencies of this distribution redesign unless a
test demonstrates a real dependency.
