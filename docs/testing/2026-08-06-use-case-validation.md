# SSC Init Foundation Use-Case Validation

Date: 2026-08-06  
Revision: `41986274bf71c310d8c44a25ada1bc1647c6f297`  
Host: macOS Darwin 25.5.0, Apple Silicon (`arm64`)

## Purpose

This report tests what the foundation build can actually discover. It covers installed IDE extensions, AI-agent plugins and skills, MCP configurations, project manifests and lockfiles, global developer tools and packages, external command integrations, change detection, credential boundaries, and locally testable operating-system targets.

The result is an inventory-scope assessment. The foundation does not yet contain threat-intelligence ingestion, policy evaluation, registry verification, malicious-code analysis, or enforcement.

## Result summary

| Area | Result | Current trustworthy claim |
|---|---|---|
| AI-agent plugins and skills | Partial | Enumerates direct, non-hidden directory names in fixed catalogs. Does not inspect or hash content. Nested plugin caches can be misclassified as one `cache` plugin. |
| VS Code-family extensions | Partial | Reads selected `package.json` identity and activation metadata in five fixed extension roots. Does not hash extension code or support custom extension directories. |
| JetBrains plugins | Partial | Reads selected `plugin.xml` identity in the macOS plugin tree. Does not inspect JARs, signatures, or code. |
| MCP | Partial with silent false completeness | Parses a small JSON path catalog and VS Code project MCP under `$HOME/Projects`. Several current official paths and Codex TOML are missed while MCP coverage remains `complete`. |
| Project discovery | Partial | Recognizes selected manifest/lockfile names under `$HOME/Projects`. File content and projects elsewhere are not detected. |
| Global packages/tools | Partial | Executes eight fixed command probes and parses names/versions. It trusts `PATH` and command output; it does not verify executable, registry, artifact, integrity, or provenance. |
| External SaaS/services | Identity hint only | An MCP URL can be retained after redaction. Live service inventory, organization approval, permissions, OAuth state, and remote code inspection are not implemented. |
| Change detection | Insufficient for malicious content | Detects changes only in fields collectors populate. No collector populates `SHA256`, so code/content-only replacements are invisible. |
| macOS arm64 | Verified | Native artifact runs and full Go tests are locally executable. |
| macOS amd64 | Partially verified | Artifact runs under Rosetta. A physical Intel runner is still required for a native release gate. |
| Linux amd64/arm64 | Buildable but unsupported | Full static binaries cross-build. Runtime and Linux-specific collection are not tested, and there is no runtime rejection guard. |
| Windows amd64 | Unsupported | Full build fails because store and doctor unconditionally depend on `golang.org/x/sys/unix`. |

## Actual isolated-HOME scenarios

All executable-level scans used a private temporary `HOME`. Package-negative tests used an empty `PATH`. Package-positive tests used inert, locally compiled fixture executables, so no registry, Docker daemon, SaaS endpoint, or real user directory was contacted.

### 1. Existing supported fixture

The repository fixture produced ten assets and a persisted partial baseline:

- Codex plugin directory
- VS Code extension
- JetBrains plugin
- Claude and Cursor user MCP servers
- VS Code project MCP server
- project, manifest, and lockfile assets

The package collector was `skipped` with eight `executable_missing` errors under an empty `PATH`. All other collectors reported `complete`.

### 2. Current official MCP and plugin locations

The official-path fixture contained:

- Claude project `.mcp.json`
- Cursor project `.cursor/mcp.json`
- Codex user and project `.codex/config.toml`
- Windsurf user `.codeium/windsurf/mcp_config.json`
- Claude Desktop `Library/Application Support/Claude/claude_desktop_config.json`
- VS Code user-profile `Library/Application Support/Code/User/mcp.json`
- VS Code Agent Host project `.mcp.json` and user `~/.copilot/mcp-config.json`
- a VS Code project MCP file under `$HOME/Developer`
- nested Claude and Codex plugin cache entries
- direct skills for Claude, Codex, and Cursor
- fixed-root VS Code, Windsurf, and JetBrains extension fixtures

Observed behavior:

- Only `$HOME/Projects/**/.vscode/mcp.json` produced an MCP server.
- Claude project, Cursor project, Codex, Windsurf current-user, Claude Desktop, VS Code user-profile/Agent Host/Copilot, and the `$HOME/Developer` MCP server were absent.
- MCP coverage still reported `complete` with no coverage error.
- Nested Claude and Codex plugin installs were represented as `agent-plugin:<host>:cache`, not as the actual plugin/version.
- `.windsurf/extensions` was represented both as an `agent-plugin:windsurf:extensions` container and as a Windsurf IDE-extension root.

This is a silent false-negative/false-completeness condition, not merely an unsupported feature reported to the user.

### 3. Content-only mutation

Between two baselines, only these bytes changed or appeared:

- Claude plugin manifest
- Claude `SKILL.md`
- VS Code extension JavaScript
- JetBrains plugin JAR
- project `package.json`
- project lockfile

Observed behavior:

- `delta.changes` was empty.
- Every relevant asset had an empty `sha256`.
- The scan remained partial only because package commands were unavailable, not because content visibility was missing.

Therefore the current foundation cannot detect an attacker replacing plugin code, skill instructions, extension code, a JAR, a lifecycle script, or lockfile contents while keeping the inventoried identity stable.

### 4. Identity collisions

Two projects each defined a VS Code MCP server named `workspace`, with different URLs. Both project MCP files were inventoried, but only one `mcp:vscode:workspace` asset survived. Its URL changed according to the winning project, with no collision error and MCP coverage still `complete`.

The same silent overwrite exists when two Claude JSON files define the same server name.

Three fixture probes—pip, pipx, and uv—reported the same PyPI package and version. The result contained one `pkg:pypi/shared@1.0.0`, attributed only to `uv`, with package coverage `complete`.

Collector-local maps discard the losing observations before the inventory graph can report a metadata conflict.

### 5. Mutable Docker tag

Two consecutive scans returned the same repository and tag but different image IDs:

- first: `alpine:3.20`, `sha256:first`
- second: `alpine:3.20`, `sha256:second`

Observed behavior:

- The stored asset was only `pkg:docker/alpine@3.20`.
- The image digest/ID was not retained.
- The second scan had an empty delta and package coverage `complete`.

A mutable tag can therefore point to different image content without producing a change.

### 6. External command and `PATH` trust

An inert executable was copied to the names `npm`, `python3`, `pipx`, `uv`, `cargo`, `go`, `brew`, and `docker` at the front of `PATH`. A real CLI scan executed all eight programs with these exact arguments:

```text
npm root -g
python3 -m pip list --format=json
pipx list --json
uv tool list
cargo install --list
go env GOPATH
brew list --versions
docker image ls --format {{json .}}
```

The resulting package coverage was `complete`, and all fixture-supplied package identities were accepted. This confirms two different properties:

- Good: the collector uses fixed direct arguments and does not invoke `sh -c`.
- Risk: it executes whichever binary `PATH` resolves and trusts its output and inherited environment. A spoofed developer tool can run during a scan, choose directories for subsequent reads, or redirect Docker to a configured daemon.

### 7. Hostile identifier and persistence boundary

A Claude plugin directory was given a high-confidence token-shaped name. The collector created an asset from the directory name, but the store rejected the entire snapshot to avoid persisting the value.

Observed behavior:

- exit code: `1`
- stdout: empty
- stderr: generic `baseline scan failed`
- subsequent status: `initialized: false`

The privacy backstop works, but one hostile asset name can prevent all benign inventory from being saved. A future analyzer should sanitize or quarantine the offending field and preserve a partial baseline.

### 8. Filesystem boundary

When the temporary home path was addressed through macOS `/tmp`, the store refused initialization because `/tmp` is a symlink to `/private/tmp`. Repeating the test with the physical `/private/tmp` path succeeded. This validates the database-parent no-symlink boundary.

## External integration scope

| Integration | Local fixture test | What is not evaluated |
|---|---|---|
| Local MCP stdio | Command/args/env-key identity and redaction | Binary provenance, package source, code hash, permissions, launched child behavior |
| Remote MCP HTTP/SSE | Sanitized URL string in covered JSON formats | Current transport, headers, OAuth, tool permissions, server ownership, live endpoint, remote code |
| Docker CLI | Image tag enumeration | Executable trust, daemon/context locality, immutable digest under a tagged image, signatures/SBOM |
| npm/PyPI/pipx/uv/Cargo/Homebrew/Go | Name/version output | Registry, artifact hash, signature, owner transfer, typosquatting, dependency graph, provenance |
| IDE marketplaces | Installed manifest identity only | Marketplace lookup, publisher verification, withdrawal, signature, install source, organization approval |
| Git repositories | `.git/config` acts only as a project marker | Sanitized remote identity, submodules, worktrees, hooks, provenance |
| Organization-managed tools | Not represented | Git-managed policy evaluation, allow/deny/exception, managed marketplace, external inventory adapters |
| TI feeds | Not implemented | OSV/GHSA/CISA KEV, malicious plugin/MCP/package indicators, signed feed freshness and revocation |

No current foundation code calls package registries, IDE marketplaces, TI feeds, or organization APIs.

Other documented but unrepresented variants include `CLAUDE_CONFIG_DIR`, Cursor's dynamic MCP extension API, VS Code remote-user and Dev Container MCP, multiple VS Code profiles, `--extensions-dir`/`VSCODE_EXTENSIONS` overrides, and organization-managed plugin marketplaces. Dynamic registrations and service-side organization state cannot be proven by a local offline filesystem scan; they require explicit host or organization adapters.

## Operating-system validation

| Target | Verification | Result |
|---|---|---|
| Darwin arm64 | `file`, native `version --json`, checksum | Pass |
| Darwin amd64 | `file`, Rosetta `arch -x86_64 ... version --json`, checksum | Pass under Rosetta |
| Linux amd64 | offline full cross-build | Pass; static ELF produced |
| Linux arm64 | offline full cross-build | Pass; static ELF produced |
| Windows amd64 | offline full cross-build | Fail; undefined POSIX `unix` store/doctor APIs |

Linux runtime was not exercised because the host has no local Linux VM/QEMU runner. The source has no non-Darwin runtime guard, so a Linux build can create the macOS-style `$HOME/Library/Application Support/SSC Init` state path and produce an incomplete inventory that appears supported. Linux and Windows must remain explicitly unsupported until platform-specific collectors, state semantics, tests, and release gates exist.

The release currently contains two thin Mach-O binaries, not one Universal Binary. Signing and notarization are not part of this foundation.

## Existing automated coverage

Fresh focused coverage before the executable scenarios:

| Package | Statement coverage |
|---|---:|
| `internal/collector` | 94.3% |
| `internal/collector/agents` | 75.3% |
| `internal/collector/ide` | 79.0% |
| `internal/collector/mcp` | 89.5% |
| `internal/collector/packages` | 85.3% |
| `internal/collector/projects` | 87.4% |

High statement coverage does not imply correct product scope. Most false negatives above occur because official paths, content hashing, collision semantics, and provenance are outside the implemented model, so existing branches can be thoroughly tested while real assets remain invisible.

## Prioritized follow-up scope

1. Make coverage truthful: publish an explicit path/format catalog in every scan, and mark unimplemented official locations and dynamic integrations as unsupported rather than `complete`.
2. Add current host formats: Claude project/Desktop, Cursor project, Windsurf current user config, VS Code user profile, and Codex user/project TOML.
3. Replace name-only identities with scope-aware observations. Preserve every install/config location and report collisions instead of overwriting.
4. Hash bounded security-relevant content: plugin/skill manifests and code entry points, IDE extension payloads, project manifests/lockfiles, Go binaries, npm packages, and immutable Docker digests.
5. Make external probes opt-in or resolve and record trusted executable paths. Treat Docker locality/context explicitly.
6. Expand project roots through explicit configuration or a bounded discovery policy; do not claim laptop-wide discovery while wiring only `$HOME/Projects`.
7. Add a Darwin-only runtime contract now. Add Linux/Windows collectors and filesystem semantics only with native CI runners.
8. Build analyzer, signed TI bundle, Git-managed organization policy, and warning/blocking adapters as later layers on top of a trustworthy inventory.

## Official references used for the location matrix

- [Claude Code directory and project MCP locations](https://code.claude.com/docs/en/claude-directory)
- [Claude Code plugin structure](https://code.claude.com/docs/en/plugins-reference)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Cursor MCP](https://docs.cursor.com/context/model-context-protocol)
- [Windsurf MCP](https://docs.windsurf.com/windsurf/cascade/mcp)
- [VS Code MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
- [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [VS Code extension locations and marketplace](https://code.visualstudio.com/docs/configure/extensions/extension-marketplace)
- [JetBrains plugin management](https://www.jetbrains.com/help/idea/managing-plugins.html)

## Revalidation — 2026-08-06

The inventory trust foundation was revalidated after the implementation range `8cc39c1^..518e577`. Task 13's official matrix, synthetic fixtures, and corrected public claims are recorded by the commit named `test: validate trustworthy inventory scope` that contains this section. The original evidence above is preserved as the pre-implementation baseline.

Exact acceptance and release commands:

```sh
go test ./internal/acceptance -run 'TestOfficialCatalogMatrix|TestV2BaselineReopenStatus' -count=1
gofmt -w cmd internal
go test -race -count=1 ./...
go vet ./...
go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/ssc-init-linux-compile-guard ./cmd/ssc-init
git diff --check
rg -n 'across the laptop|laptop-wide|all plugins|must-not-persist|super-secret|Bearer secret' README.md docs internal testdata
go test ./scripts -count=1
sh scripts/build-darwin.sh
file dist/ssc-init-darwin-arm64 dist/ssc-init-darwin-amd64
shasum -a 256 -c dist/checksums.txt
./dist/ssc-init-darwin-$(go env GOARCH) version --json
git status --short
```

### Closed gaps

Only these five gaps are closed by this foundation:

1. **Truthful target coverage** — every versioned catalog target is reported with explicit target status; unsupported and bounded expanded surfaces remain visible.
2. **Occurrence preservation** — same-name MCP, same-extension-location, and same-package multi-manager occurrences persist as distinct observations.
3. **Official local catalog parsing** — the isolated matrix covers every user and project MCP path in the approved catalog, both JSON container spellings, and Codex TOML stdio and HTTP.
4. **External-probe opt-in and evidence** — package and Docker commands are skipped by default; enabled fake probes retain executable identity evidence and fixed command provenance.
5. **Non-Darwin rejection** — operational commands reject unsupported systems before home-path or state initialization.

### Open programs

Content hashing and provenance remain open, including plugin/project payload hashes and immutable Docker digest evidence. Threat intelligence, Git-managed policy, organizational integrations, host adapters, warnings, and blocking also remain open. This revalidation makes no malware verdict and does not claim that inventoried assets are safe.
