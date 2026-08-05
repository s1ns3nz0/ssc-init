# SSC Init

**Initialize Your Software Supply Chain Security.**

SSC Init is an open-source, snapshot-based inventory tool for the developer supply chain on macOS. The current foundation scans the current user's developer environment across the laptop, records an immutable local baseline, and reports explicit collection coverage.

This foundation is not an EDR. It installs no daemon or kernel sensor, does not continuously monitor processes or files, and does not scan arbitrary personal data. Inventory and detection results are not a guarantee that an asset is safe; missing or failed coverage is reported as partial rather than silently treated as success.

## Current coverage

The baseline collector inventories:

- Claude, Codex, Cursor, Windsurf, and other supported fixed agent configuration, plugin, and skill paths;
- user-level and project-level MCP configurations and their declared commands or endpoints;
- VS Code, Cursor, Windsurf, and JetBrains extensions;
- global developer package ecosystems and tools when their optional commands are available; and
- projects under bounded configured roots, including recognized manifests and lockfiles.

Project policies and first-party rules are intended to use Git-managed YAML in later implementation slices. This foundation does not yet provide policy enforcement, blocking, threat-intelligence updates, signing/notarization, continuous monitoring, or host-specific Claude/Codex/Cursor adapters.

## Commands

All current commands return JSON:

```sh
ssc-init version --json
ssc-init doctor --json
ssc-init scan --baseline --json
ssc-init status --json
```

`doctor` reports runtime and optional-tool availability without reading asset contents. `scan --baseline` performs read-only discovery and persists one baseline. `status` reads the latest local inventory.

State is local-first and stored at:

```text
$HOME/Library/Application Support/SSC Init/state.db
```

The executable has no mandatory runtime installation or external runtime dependencies. Optional developer tools only enrich their corresponding inventory coverage.

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

The script can be invoked from any working directory and produces static Darwin arm64 and amd64 binaries under `dist/`.

## Licensing

Code and first-party rules are licensed under the [Apache License 2.0](LICENSE). Project documentation is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Third-party material retains its upstream license and provenance.
