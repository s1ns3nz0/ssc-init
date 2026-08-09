# SSC Init

**Initialize Your Software Supply Chain Security.**

SSC Init is an open-source, snapshot-based inventory tool for the developer supply chain. The current build provides macOS local inventory within versioned developer-tool catalogs and configured project roots, records a local baseline with bounded local content evidence, and reports explicit target and evidence coverage.

This tool is not an EDR. There is no daemon, kernel sensor, or arbitrary personal-file scan, and it does not continuously monitor processes or files. No scan result is a guarantee that an asset is safe. This build performs no content analysis and has no threat intelligence, so it produces no malware verdicts and blocks nothing. Missing or failed coverage remains visible instead of being silently treated as success.

## Current coverage

The baseline collector inventories and, where a bounded local implementation exists, hashes:

- manifest-backed plugins and skills found in supported fixed Claude, Codex, and Cursor catalog paths, with SHA-256 file evidence for each recognized plugin manifest and skill `SKILL.md` document plus a bounded `ssc-init.tree.v1` payload-tree digest per plugin or skill directory;
- VS Code, VS Code Insiders, VS Code OSS, Cursor, Windsurf, and JetBrains extensions, with file evidence for each supported manifest and each declared `main`/`browser` entry point validated beneath the extension root, plus a bounded payload-tree digest (JetBrains trees include JAR bytes without enumerating or analyzing archive members);
- user-level and project-level MCP configurations, with one secret-free semantic digest (`ssc-init.semantic-mcp.v1`) per parsed declaration — raw MCP configuration files are never hashed, persisted, or exposed because they can contain credentials;
- an exact, closed project manifest and lockfile filename catalog (npm-compatible, Python, Go, Cargo, and Homebrew names) inside explicitly configured project roots, with per-file SHA-256 evidence; project source trees, vendored dependencies, and caches are never hashed;
- global developer package ecosystems and Docker only when command probes are explicitly enabled; exact full Docker SHA-256 image IDs become complete container-identity evidence, while truncated or missing IDs and ordinary package payloads remain explicit `unsupported` evidence;
- bounded npm, Cargo, and Go lockfile provenance from configured project roots. npm/Cargo SHA-256 facts are immutable; Go `h1` is retained as a source-specific fact rather than being mislabeled as SHA-256. Package-to-lockfile and package-to-probe relationships use a closed graph vocabulary;
- macOS signature facts for verified probe executables when external probes are enabled. The result is a closed `valid`, `invalid`, `unsigned`, `unavailable`, or `unsupported` fact, not a safety verdict; signer diagnostics and certificate chains are discarded.
- the exact six supported shell startup files, the two user Git configuration files, declared global Git credential-helper names (arguments and URL-scoped values are discarded), project Git hooks, and `.vscode/launch.json`, all without executing discovered content;
- a point-in-time process and local TCP-listener snapshot only with `--external-probes`. It retains PID, executable basename, protocol, and local port only; command arguments, hostnames, remote endpoints, and continuous monitoring are out of scope.
- locally supplied TI and organization-policy bundles with closed JSON schemas, family-scoped Ed25519 signatures, monotonic rollback protection, atomic activation/rollback, explicit freshness state, exact TI correlation, and five-level organization decisions. Bundle ingestion never downloads a file.

Target status distinguishes `not_present`, `skipped`, `unsupported`, `unavailable`, and `partial`. A target is `complete` only when its bounded catalog read and parsing completed. Every content-evidence target likewise receives exactly one terminal status (`complete`, `partial`, `oversize`, `unavailable`, `unsupported`, or `skipped`), and only `complete` evidence is a trusted content digest. Evidence collection is passive, descriptor-anchored, and never follows symbolic links; reports and the local database retain digests and aggregate counts only — no file bytes, tree leaf names, link targets, secrets, or raw absolute paths.

Broader package payload hashing, behavior analysis, Git-managed policy compilation, host adapters, warnings, and blocking remain later programs. Finding JSON, privacy-safe SARIF, inventory CycloneDX, and explicit HTTPS webhook delivery are implemented; no command claims host enforcement. Real release signing/notarization is deferred: it requires Apple Developer credentials and is separate from both the product implementation and local signature inspection.

## Commands

All current commands return JSON:

```sh
ssc-init version --json
ssc-init doctor --json
ssc-init scan --baseline --json
ssc-init scan --baseline --json --external-probes
ssc-init scan --baseline --json --project-root '$HOME/Projects' --project-root '$HOME/Developer'
ssc-init scan --baseline --pretty
ssc-init status --json
ssc-init status --pretty
ssc-init hook
ssc-init policy init
ssc-init policy pin
ssc-init policy check
ssc-init policy check --pretty
ssc-init bundle status --family ti --json
ssc-init bundle install --family ti --from /absolute/bundle.json --signature /absolute/bundle.sig --json
ssc-init bundle rollback --family ti --json
ssc-init findings --json
ssc-init findings --pretty
ssc-init findings --json --webhook https://security.example.invalid/ssc-init
```

`doctor` reports runtime and optional-tool availability without reading asset contents. A default `scan --baseline` performs passive filesystem discovery plus bounded local content evidence and persists one baseline; it executes no discovered content, runs no external command, and performs no network access. The default project scope is `$HOME/Projects`; repeat `--project-root` to add explicitly configured roots. Package/Docker and point-in-time process/listener command probes are disabled unless `--external-probes` is supplied. `status` reads the latest persisted inventory snapshot; snapshots from earlier schema versions stay readable but are reported as `legacyInventory` without any evidence claim. `scan --baseline` and `status` accept `--pretty` in place of `--json` to render deterministic human-readable summary tables (names, statuses, counts, and error codes only — never digests, paths, or contents); JSON remains the machine contract. The `scan --baseline --pretty` `DELTA` section uses the same `NEW`/`CHANGED`/`UNVERIFIED`/`UPGRADED`/`REMOVED` ladder as `hook` and always prints, stating `(no changes)` when the snapshot is unchanged.

`hook` is an advisory session hook: it runs one default baseline scan and
prints one line per changed asset (asset types, names, hosts, versions, and
counts only), each tagged `NEW`, `CHANGED`, `UNVERIFIED`, `UPGRADED`, or
`REMOVED`. These tags describe what changed and how well it could be verified,
never whether anything is safe: this build performs no content analysis and has
no threat intelligence, so it issues no verdicts. The hook stays completely
silent when nothing changed, and
a first run reports an initial baseline count instead of tagging every
discovered asset. It always exits zero — including on scan failure, and except
for invalid arguments — so wiring it into an agent session does not block
startup. Claude Code example (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "ssc-init hook"}]}
    ]
  }
}
```

State is local-first and stored at:

```text
$HOME/Library/Application Support/SSC Init/state.db
```

## Local policy

`ssc-init policy init` writes an annotated starter document to
`$HOME/Library/Application Support/SSC Init/policy.json`. Every shipped rule is
disabled until the user enables it. `policy init` and `policy check` accept an
absolute `--policy` path or a path below `$HOME`; the override changes only the
document being initialized or evaluated.

`ssc-init policy pin` records the complete evidence currently present in the
latest snapshot. This is trust on first use: a pin protects against future
change, and pinning a compromised machine approves that compromise. Use
`policy pin --update <asset-id>` to approve one changed asset deliberately.

`ssc-init policy check` reads the policy document and the latest recorded
snapshot; it does not run a scan. JSON is the default and `--pretty` is
available for an interactive summary. It exits `0` when clean, `3` when policy
violations exist, `2` for invalid arguments or documents, and `1` for an
operational failure.

The current capability is advisory plus on-demand. Policy cannot block a
process, installation, or session start. A code `3` can gate a pipeline that
chooses to act on it; it is not an enforcement claim. The session hook reports
new violations in a separate `POLICY` section and collapses standing violations
to one reminder line, while continuing to exit zero.

The executable has no mandatory runtime installation or external runtime dependencies. Enabling external probes records the bounded identity and macOS signature fact of the executable used; neither fact makes that executable safe or trusted.

Bundle commands are local-only. `bundle install` accepts exact local files,
never a URL, and verifies the detached signature again after staging the copied
bytes. The production trust-root registry is intentionally empty until reviewed
TI and policy public keys are committed, so installation currently fails closed;
`bundle status` remains usable and reports `missing`. Publisher signing keys are
CI secrets and are never stored in this repository.

## Retention and store size

Every `scan --baseline` persists one snapshot, and `hook` runs a scan per session, so the store is pruned on each save:

- full snapshots are kept for 30 days. The window includes its own edge — a snapshot finished exactly at the cutoff is kept — so a machine scanning once a day plateaus at 31 stored snapshots rather than 30;
- asset change history is kept for 90 days as one small row per distinct asset, so first-seen and last-seen times survive the pruning of the snapshots that observed them;
- the newest snapshot is never deleted regardless of its age, because without it there is no baseline to diff against and the next scan would report every asset as new.

`doctor --json` reports the footprint under `store`: `sizeBytes` (the database plus its `-wal` and `-shm` files), `reclaimableBytes`, `snapshotCount`, and both retention windows in seconds.

Pruning frees pages for reuse, but those pages return to the filesystem only when a full rewrite runs, and that rewrite is gated: it fires only when the freed pages are at least 256 pages and at least a quarter of the file. Under daily scanning that gate is never reached, so an actively used store plateaus rather than shrinking; the space is recovered after an idle gap or when a batch of snapshots ages out at once. `reclaimableBytes` is the only signal that a store is holding freed pages it cannot yet hand back.

## Download and verify

The current GitHub distribution can publish the reproducible unsigned
Universal Binary `ssc-init-darwin-universal` with `checksums.txt`,
`sbom.cdx.json`, and `provenance.json`. Apple Developer membership is not
needed to build or publish those files. Verify the downloaded bytes before
running them:

```sh
shasum -a 256 -c checksums.txt
```

Because that binary is unsigned and unnotarized, macOS may block a downloaded
copy or require explicit user approval. Developer ID signing and notarization
are an optional later release hardening step that removes that friction; they
are not a Mac App Store requirement and this project does not use the Mac App
Store. The unsigned GitHub flow and deferred Apple hardening flow are separated
in [the release runbook](docs/release-runbook.md).

## Build from source

Building requires the Go version declared in `go.mod`. Fetch the pinned modules explicitly, then run the build script; the script itself disables network and toolchain downloads.

```sh
go mod download
sh scripts/build-darwin.sh
file dist/ssc-init-darwin-*
shasum -a 256 -c dist/checksums.txt
```

The script can be invoked from any working directory and produces CGO-free, self-contained Darwin arm64 and amd64 executables under `dist/`, with no separately installed runtime required. Each executable reports the exact `v*` release tag when the committed HEAD is tagged, and `dev+git.<full-commit>` otherwise. Dirty tracked changes are not represented in that version, so release artifacts must be built from a clean tracked worktree.

## Licensing

Code and first-party rules are licensed under the [Apache License 2.0](LICENSE). Project documentation is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Third-party material retains its upstream license and provenance.
