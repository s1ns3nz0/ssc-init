# SSC Init

**Initialize Your Software Supply Chain Security.**

SSC Init is an open-source, snapshot-based inventory tool for the developer supply chain. The current foundation provides macOS local inventory within versioned developer-tool catalogs and configured project roots, records a local baseline, and reports explicit target coverage.

This foundation is not an EDR. There is no daemon, kernel sensor, arbitrary personal-file scan, malware verdict, or safety guarantee. It does not continuously monitor processes or files. Missing or failed coverage remains visible instead of being silently treated as success.

## Current coverage

The baseline collector inventories:

- manifest-backed plugins and skills found in supported fixed Claude, Codex, and Cursor catalog paths;
- user-level and project-level MCP configurations and their declared commands or endpoints;
- VS Code, Cursor, Windsurf, and JetBrains extensions;
- global developer package ecosystems and Docker only when command probes are explicitly enabled; and
- projects under bounded configured roots, including recognized manifests and lockfiles.

Target status distinguishes `not_present`, `skipped`, `unsupported`, `unavailable`, and `partial`. A target is `complete` only when its bounded catalog read and parsing completed.

Plugin/project content hashing, threat intelligence (TI), Git-managed policy, organization integrations, host adapters, warnings, and blocking remain later programs.

## Commands

All current commands return JSON:

```sh
ssc-init version --json
ssc-init doctor --json
ssc-init scan --baseline --json
ssc-init scan --baseline --json --external-probes
ssc-init scan --baseline --json --project-root '$HOME/Projects' --project-root '$HOME/Developer'
ssc-init status --json
```

`doctor` reports runtime and optional-tool availability without reading asset contents. A default `scan --baseline` performs passive filesystem discovery and persists one baseline. The default project scope is `$HOME/Projects`; repeat `--project-root` to add explicitly configured roots. Package/Docker command probes are disabled unless `--external-probes` is supplied. `status` reads the latest persisted full inventory snapshot.

State is local-first and stored at:

```text
$HOME/Library/Application Support/SSC Init/state.db
```

The executable has no mandatory runtime installation or external runtime dependencies. Enabling external probes records the bounded identity of the executable used; it does not make that executable trusted.

## Download and verify

Release artifacts are named for both supported macOS architectures:

- `ssc-init-darwin-arm64` for Apple silicon;
- `ssc-init-darwin-amd64` for Intel Macs; and
- `checksums.txt` for SHA-256 verification.

After downloading both binaries and `checksums.txt` from the matching release into a `dist` directory, verify them before use:

```sh
shasum -a 256 -c dist/checksums.txt
chmod 0755 dist/ssc-init-darwin-arm64
./dist/ssc-init-darwin-arm64 version --json
```

Use `ssc-init-darwin-amd64` instead on an Intel Mac.

## Build from source

Building requires the Go version declared in `go.mod`. Fetch the pinned modules explicitly, then run the build script; the script itself disables network and toolchain downloads.

```sh
go mod download
sh scripts/build-darwin.sh
file dist/ssc-init-darwin-*
shasum -a 256 -c dist/checksums.txt
```

The script can be invoked from any working directory and produces CGO-free, self-contained Darwin arm64 and amd64 executables under `dist/`, with no separately installed runtime required. Each executable reports `dev+git.<full-commit>` from the committed HEAD of the source worktree. Dirty tracked changes are not represented in that version, so release artifacts must be built from a clean tracked worktree.

## Licensing

Code and first-party rules are licensed under the [Apache License 2.0](LICENSE). Project documentation is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Third-party material retains its upstream license and provenance.
