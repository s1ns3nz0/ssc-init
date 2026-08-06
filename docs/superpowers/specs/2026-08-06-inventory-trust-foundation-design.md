# SSC Init Inventory Trust Foundation Design

Date: 2026-08-06  
Status: approved direction; written-spec review pending  
Parent design: `docs/superpowers/specs/2026-08-05-ssc-init-design.md`  
Validation evidence: `docs/testing/2026-08-06-use-case-validation.md`

## 1. Decision

SSC Init will repair the trustworthiness of its inventory before adding threat intelligence, malicious-code analysis, organization policy, or blocking adapters.

The implementation order is:

1. truthful coverage and an explicit platform boundary;
2. lossless, scope-aware observations;
3. current official local paths and formats;
4. bounded content evidence;
5. analyzers and signed TI;
6. Git-managed organization policy;
7. Claude, Codex, Cursor, and IDE warning or blocking adapters.

This specification covers only steps 1 through 3 plus the external-command safety boundary required to trust collection. Content hashing and later analysis layers receive separate specifications after this slice is verified.

## 2. Why this slice comes first

The foundation validation demonstrated four prerequisite failures:

- documented configurations can be missed while coverage says `complete`;
- collector-local maps overwrite same-identity observations;
- projects are wired only under `$HOME/Projects` while product language suggests laptop-wide discovery;
- package collection executes whichever binaries `PATH` resolves.

Adding more rules or TI on top of these behaviors would analyze incomplete or silently overwritten evidence. Adding paths before fixing identity would increase the number of collisions. The model and coverage contract therefore precede catalog expansion.

## 3. Considered approaches

### A. Patch missing paths first

Add Claude, Codex, Cursor, Windsurf, and VS Code paths to the current collectors without changing the model.

This is the smallest patch, but it worsens same-name overwrites, preserves false `complete` results, and forces another migration when observations are introduced. Rejected.

### B. Trust-model-first evolution

Add target-level coverage and scope-aware observations, migrate persistence and reports, then add official paths through the new catalog.

This requires a schema change now, but every new detector gains truthful status and lossless identity. Selected.

### C. Build a parallel scanner v2

Leave the foundation untouched and build a second pipeline, store, and CLI surface.

This gives maximum isolation but duplicates secure filesystem, redaction, reporting, and migration work. The current foundation has strong reusable boundaries, so a parallel implementation is unnecessary. Rejected.

## 4. Scope

### 4.1 Goals

This slice will:

- declare the exact local targets each collector knows about;
- report target-level `complete`, `not_present`, `partial`, `unavailable`, or `unsupported` outcomes;
- prevent a collector from reporting `complete` when an advertised target is unhandled;
- represent every installation or configuration occurrence as an observation;
- retain canonical assets without discarding duplicate locations or sources;
- parse current JSON MCP configurations and Codex TOML configurations;
- discover supported project MCP configurations under explicitly configured roots;
- support bounded, repeatable project-root selection;
- make external command probes opt-in;
- record the resolved executable identity for every enabled probe;
- reject operational use on non-Darwin systems before creating product state;
- preserve the single, statically linked Go-binary distribution model.

### 4.2 Non-goals

This slice will not:

- decide whether an asset is malicious;
- download TI, marketplace, or registry data;
- hash entire plugin or project trees;
- inspect JavaScript, Python, JAR, WASM, native binaries, or install scripts;
- evaluate organization allow/deny policy;
- block Claude, Codex, Cursor, an IDE, or a subprocess;
- inspect service-side organization state or dynamically registered MCP servers without a host adapter;
- claim Linux or Windows runtime support;
- recursively crawl the entire home directory or mounted volumes.

## 5. Program decomposition

The broader product work is divided into four independently reviewable programs:

1. **Inventory trust foundation** — this specification.
2. **Content evidence** — bounded hashes, entry-point evidence, immutable Docker identity, signature and provenance fields.
3. **Analysis and intelligence** — local behavioral rules, signed TI bundles, registry and publisher correlation.
4. **Policy and enforcement** — Git YAML policy, exceptions, host adapters, warning and high-confidence blocking.

Each program must leave the preceding layer usable on its own. A user can run inventory without TI; TI can run without organization policy; adapters remain thin consumers of the core verdict contract.

## 6. Data model

### 6.1 Canonical asset

`Asset` continues to describe a logical component such as one named MCP server or one package coordinate. It must no longer carry the only record of where the component was observed.

Examples:

```text
mcp:vscode:workspace
pkg:pypi/requests@2.32.3
ide-extension:vscode:acme.safe@1.2.3
```

Canonical assets are deduplicated only after every occurrence has been retained as an observation.

Host-specific user and IDE configurations keep the existing `mcp:<host>:<name>` identity for compatibility. A project `.mcp.json` shared by multiple consumers uses `mcp:shared:<name>` and lists those consumers on its observation.

### 6.2 Observation

The model adds:

```go
type Observation struct {
    ID           string            `json:"id"`
    AssetID      string            `json:"assetId"`
    Collector    string            `json:"collector"`
    Host         string            `json:"host,omitempty"`
    Consumers    []string          `json:"consumers,omitempty"`
    Scope        string            `json:"scope"`
    LocationRef  string            `json:"locationRef"`
    ProjectID    string            `json:"projectId,omitempty"`
    Source       string            `json:"source,omitempty"`
    Metadata     map[string]string `json:"metadata,omitempty"`
}
```

`Scope` is one of `user`, `project`, `ide-profile`, `tool-environment`, or `system`. New values require a schema change and tests.

`LocationRef` contains a home-redacted path when that path is safe to persist. Paths outside the configured home are represented by a deterministic path digest plus a user-supplied root label, not a raw absolute path. The digest prevents accidental disclosure but is not claimed to provide cryptographic secrecy for guessable paths.

`Consumers` is a sorted, unique list used when one configuration is shared by more than one host, such as a project `.mcp.json` consumed by Claude and VS Code Agent Host.

`Observation.ID` is `observation:sha256:<digest>` over a length-prefixed canonical tuple of collector, host, consumers, scope, safe location identity, project identity, and canonical asset ID. The tuple format is versioned and unit-tested. Raw absolute paths and raw credentials are never embedded in the ID.

`Inventory` gains a deterministic `Observations []Observation` field between assets and relationships in the JSON contract. Empty and nil shapes receive the same explicit persistence treatment as existing inventory collections.

### 6.3 Relationships

Relationships remain asset-to-asset so existing graph validation and consumers do not receive mixed endpoint types. Observation associations are expressed directly through `AssetID`, `ProjectID`, and `Consumers`.

Project-to-configuration `contains` relationships continue to reference canonical assets. The exact project occurrence remains unambiguous because its observation carries `ProjectID`. A package observation produced by a command probe records the probe target ID and executable observation ID in safe metadata.

No collector may collapse its result with `map[assetID]Asset` before observations reach inventory normalization.

### 6.4 Identity collision behavior

Same canonical ID with multiple observations is normal and preserved. Conflicting canonical metadata produces a deterministic `metadata-conflict` inventory error without discarding observations.

A credential-shaped or invalid identity is not persisted and does not abort the whole baseline. That occurrence is quarantined from inventory, its target becomes `partial`, and a generic `identity_rejected` coverage error is recorded without the raw value or raw path.

### 6.5 Schema versioning and persistence

New scan output uses `ssc-init.scan.v2`, and status output containing the new inventory uses `ssc-init.status.v2`. Existing `v1` snapshots remain readable.

SQLite migration 4 adds:

- `observations` keyed by `(scan_id, observation_id)`;
- `observation_state` preserving deterministic order plus nil metadata and consumers shape;
- `observation_count` and `observations_nil` to `inventory_state`;
- foreign keys from observations to their scan and canonical asset.

Migration is additive. Existing snapshots load with an empty observation list and are explicitly marked `legacyInventory: true` in status output; absence of observations in a v1 snapshot is never presented as a completed v2 inventory. New snapshots round-trip assets, observations, relationships, coverage targets, and errors atomically. The status reader returns the persisted scan schema alongside the inventory so the CLI can make this distinction.

Delta records add an entity discriminator so asset and observation changes cannot be confused:

```json
{"kind":"added","entity":"observation","entityId":"observation:sha256:..."}
```

The v2 status payload is explicit about snapshot provenance:

```json
{
  "schemaVersion": "ssc-init.status.v2",
  "initialized": true,
  "inventorySchemaVersion": "ssc-init.scan.v1",
  "legacyInventory": true,
  "inventory": {"assets": [], "observations": [], "relationships": []}
}
```

For a v2 snapshot, status also returns its safe scan scope and collector coverage. The store exposes a latest-snapshot read rather than inventory alone; it does not reconstruct missing v1 target coverage.

## 7. Truthful coverage contract

### 7.1 Target declaration

Every collector exposes immutable `TargetSpec` entries:

```go
type TargetSpec struct {
    ID        string
    Collector string
    Host      string
    Scope     string
    Platform  string
    Format    string
    Method    string
}
```

`Method` is `file`, `directory`, `command`, `dynamic-api`, or `service-api`. The catalog exposes logical identifiers, never a secret-bearing resolved path.

`ScanResult` gains a scope block:

```go
type ScanScope struct {
    Platform       string   `json:"platform"`
    CatalogVersion string   `json:"catalogVersion"`
    ProjectRoots   []string `json:"projectRoots"`
    ExternalProbes bool     `json:"externalProbes"`
}
```

The first catalog identifier is `ssc-init.catalog.v1`. Project roots are safe labels or home-redacted paths. This block is stored with the snapshot and returned by both scan and v2 status output.

### 7.2 Target result

Each scan emits one `TargetCoverage` for every applicable target:

```go
type TargetCoverage struct {
    TargetID     string          `json:"targetId"`
    InstanceRef  string          `json:"instanceRef,omitempty"`
    Status       TargetStatus    `json:"status"`
    Assets       int             `json:"assets"`
    Observations int             `json:"observations"`
    Errors       []CoverageError `json:"errors,omitempty"`
}
```

`TargetID` references the immutable catalog specification. `InstanceRef` distinguishes bounded expansions such as the same project target in two projects using a safe project identifier. The pair is unique within one collector result.

Statuses mean:

- `complete`: target existed and was fully read and parsed within bounds;
- `not_present`: optional fixed target did not exist;
- `partial`: some target content or entries could not be evaluated;
- `unavailable`: the environment prevented attempting the target;
- `unsupported`: the target is documented but this build has no safe local implementation.

### 7.3 Aggregate rule

Collector status is deterministic:

- `failed` if the collector cannot establish its security boundary;
- `unavailable` if all applicable supported targets are unavailable;
- `partial` if any target is partial, unavailable alongside successful targets, or unsupported;
- `complete` only when every applicable target is `complete` or `not_present`;
- `skipped` only for an explicitly disabled optional capability such as external probes.

Unknown locations are not magically enumerable. The report includes the configured project roots and the catalog version so the user can distinguish “not found in scanned scope” from “not installed anywhere on the laptop.”

## 8. Discovery catalog

### 8.1 MCP user targets on macOS

The first catalog includes:

| Host/consumer | Location | Format |
|---|---|---|
| Claude Code | `~/.claude.json` | JSON |
| Claude legacy compatibility | `~/.claude/settings.json` | JSON |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | JSON |
| Codex | `~/.codex/config.toml` | TOML |
| Cursor | `~/.cursor/mcp.json` | JSON |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON |
| VS Code user profile | `~/Library/Application Support/Code/User/mcp.json` | JSON |
| VS Code Insiders user profile | `~/Library/Application Support/Code - Insiders/User/mcp.json` | JSON |
| Copilot Agent Host | `~/.copilot/mcp-config.json` | JSON |

Legacy locations already supported remain cataloged as legacy rather than silently removed.

Profile-specific, remote-user, Dev Container, environment-relocated, and dynamic API targets are declared as `unsupported` until a bounded implementation or host adapter exists.

### 8.2 MCP project targets

Within each configured project root:

| Consumer | Location | Format |
|---|---|---|
| Claude and compatible Agent Host | `.mcp.json` | JSON |
| Cursor | `.cursor/mcp.json` | JSON |
| Codex | `.codex/config.toml` | TOML |
| VS Code | `.vscode/mcp.json` | JSON |

A shared `.mcp.json` is parsed once and records each declared consumer in its observation. It is not duplicated under competing host IDs.

### 8.3 Agent and IDE catalogs

Agent collectors distinguish catalog containers from installed plugin versions. They inventory a plugin only after a bounded recognized manifest or `SKILL.md` is found. A top-level `cache`, `extensions`, or marketplace container is never emitted as a plugin solely because it is a directory.

IDE roots retain the current macOS fixed catalogs. Custom extension directories are declared unsupported unless passed explicitly in a later adapter/configuration surface. JetBrains remains macOS-specific in this slice.

### 8.4 TOML dependency

Codex TOML is parsed with a pinned, pure-Go TOML v1.0 parser (`github.com/pelletier/go-toml/v2`). This adds a build-time module but no runtime installation, service, interpreter, or CGO dependency. A hand-written partial TOML parser is rejected because silently misreading security configuration is worse than one audited static dependency.

Recognized normalized MCP fields are command, arguments, URL, transport/type, working directory, enabled state, tool allow/deny names, environment key names, and header key names. Values for environment variables, authorization headers, bearer tokens, and other credential fields are never persisted. Unrelated top-level settings outside the MCP container are ignored because they are outside this target. Any unrecognized field inside an MCP server definition is retained only by sanitized field name and makes the target `partial` with `unknown_field`; it is never silently ignored.

## 9. Project roots

The CLI accepts repeated project roots:

```text
ssc-init scan --baseline --json \
  --project-root '$HOME/Projects' \
  --project-root '$HOME/Developer'
```

Rules:

- zero flags preserves `$HOME/Projects` as the compatibility default;
- values must be absolute or begin with the literal `$HOME` boundary;
- roots are canonicalized, deduplicated, and bounded independently;
- missing roots are `not_present` and do not fail the scan;
- symlink roots and traversal escapes are rejected;
- raw outside-home paths are not written to reports;
- the scan output lists safe root labels and explicitly avoids the phrase “laptop-wide.”

A Git-managed YAML configuration file belongs to the later policy program. This slice does not add a YAML runtime dependency merely to select roots.

## 10. External command probes

Passive filesystem collection is the default. Package and Docker probes run only with:

```text
ssc-init scan --baseline --json --external-probes
```

When enabled, each probe:

1. resolves the executable before execution;
2. resolves a bounded symlink chain and requires the final target to be a regular executable, retaining only safe redacted chain information;
3. records the final home-redacted path, bounded SHA-256, file mode, and pre-launch file identity;
4. uses the existing fixed argument list and output/time bounds;
5. records the probe executable as an observation;
6. verifies the final path identity again after execution and marks replacement as `partial`;
7. marks output truncation or parser loss as `partial`;
8. reports Docker context locality as unknown unless explicitly proven local.

Opt-in does not imply trust. It means the user accepted execution after SSC Init recorded which executable would run. Organization allowlists and enforced executable identity are later policy work.

The before/after identity check detects replacement but cannot eliminate every same-UID race between verification and process launch. The report states this boundary instead of calling the executable trusted.

macOS code-signature and notarization verification belongs to the next content-evidence specification; this slice does not label an executable trusted merely because its path and hash were recorded.

`doctor` may resolve command availability read-only, but it must not run probes.

## 11. Platform boundary

The supported operational platform remains macOS.

- `version --json` may run on any target that compiles.
- `doctor`, `scan`, and `status` check `runtime.GOOS` before resolving home paths or opening state.
- non-Darwin operational commands return a stable unsupported-OS error and nonzero exit without creating files.
- Darwin arm64 and amd64 remain required build targets.
- Linux cross-build is a guard test, not a support claim.
- Windows remains non-buildable until POSIX store and doctor code are separated behind platform files.

The documentation will say “macOS local inventory within declared catalogs and configured project roots.”

The exact unsupported contract is exit code `2`, no stdout, and the generic stderr line `unsupported operating system`. It executes before `os.UserHomeDir`, collector creation, or SQLite initialization.

## 12. Data flow

```text
Target catalog
  -> applicable target expansion
  -> bounded collector read
  -> raw in-memory occurrence
  -> redaction / identity validation
  -> canonical Asset + Observation
  -> graph normalization without collector-local loss
  -> target and collector coverage aggregation
  -> atomic SQLite v4 snapshot
  -> scan.v2 JSON and observation-aware delta
```

Dynamic and service-side targets stop at the catalog with `unsupported`; the offline scanner does not fabricate absence.

## 13. Error and privacy behavior

- No raw environment value, authorization header, bearer token, URL credential, command secret argument, or secret-shaped identity is persisted.
- One rejected occurrence does not discard unrelated inventory.
- Coverage errors use stable codes and generic messages; raw OS, parser, command stderr, and filesystem errors stay in memory.
- Missing optional files are not errors.
- Duplicate semantic identities are observations, not errors by themselves.
- Conflicting metadata is reported generically and deterministically.
- Target count, entry count, file size, output size, recursion depth, command time, and concurrent collectors remain bounded.

## 14. Compatibility and rollout

The repository has no stable public release, so the CLI may move to `scan.v2` without carrying a permanent dual-write path. Compatibility requirements are limited to:

- opening and reading existing migration-3 databases;
- preserving old snapshots unchanged;
- marking v1 snapshots as legacy when surfaced through `status.v2`;
- writing only the new observation-aware shape after migration 4;
- keeping `version --json`, `doctor --json`, `status --json`, and baseline command names;
- preserving current fixed-path positives while adding target detail;
- documenting the new default-disabled external probes.

README claims are narrowed in the same change set as behavior, not deferred.

## 15. Test strategy

Implementation is divided into three sequential milestones:

1. **Model and coverage** — observations, deterministic identity, target coverage, graph behavior, scan v2, migration 4, and persistence compatibility.
2. **Discovery catalog** — official MCP/agent/IDE catalogs, JSON and TOML normalization, project roots, collision preservation, and identity quarantine.
3. **Execution and platform boundary** — default-disabled command probes, executable evidence, non-Darwin rejection, README corrections, and executable-level acceptance.

Each milestone must pass its focused and full regression tests before the next begins. This keeps failures attributable while retaining one coherent public schema.

Implementation is test-driven. Required suites are:

### Model and graph

- deterministic observation ID vectors;
- multiple observations for one canonical asset;
- metadata conflict without occurrence loss;
- observation-aware delta;
- credential-shaped identity quarantine.

### Coverage

- every catalog target emits exactly one target result;
- `not_present` can aggregate to complete;
- any unsupported or partial target prevents complete;
- unsupported dynamic API is visible;
- output order is deterministic.

### Persistence

- migration 3 to 4;
- fresh migration 4 schema verification;
- v1 snapshot read compatibility;
- v2 asset, observation, target coverage, relationship, error, and nil-shape round trip;
- rollback on any observation write failure;
- observation corruption detection.

### Discovery matrix

- every user and project MCP path in section 8;
- JSON `mcpServers` and `servers` forms;
- Codex TOML stdio and streamable HTTP;
- malformed, duplicate, oversized, symlink, identity-swap, secret, and unknown-field fixtures;
- two projects with the same server name;
- nested plugin caches without `cache` misclassification;
- custom/dynamic targets reported unsupported.

### CLI and platform

- repeated project roots and compatibility default;
- invalid and symlink root rejection;
- external probes skipped by default;
- opt-in executable observation and fixed argv;
- spoofed `PATH` executable is identified rather than silently trusted;
- Linux operational commands fail before state creation;
- Darwin arm64 native and amd64 release smoke.

### End to end

- isolated home containing all official fixtures;
- baseline, status, SQLite reopen, and second-scan delta;
- no real-home marker read;
- no network or real Docker daemon contact;
- hostile sibling produces partial inventory rather than total baseline loss.

## 16. Acceptance criteria

This slice is complete only when:

1. the official isolated-home matrix has no silent misses for implemented targets;
2. every documented target included in the versioned catalog but not implemented is visible as unsupported;
3. same-name MCP and same-package multi-manager observations all survive;
4. no top-level cache/container is falsely reported as a plugin;
5. external probes do not execute without explicit opt-in;
6. enabled probes record the executable evidence used;
7. a hostile identity cannot abort storage of unrelated assets;
8. non-Darwin operational commands create no state;
9. migration and old-snapshot compatibility tests pass;
10. fresh race, vet, module, Darwin build, checksum, and isolated-home gates pass;
11. README and report language match the tested scope;
12. the worktree is clean and the implementation is independently reviewed.

## 17. Next specification

After these acceptance criteria pass, the next design will cover bounded content evidence:

- manifest and entry-point hashes;
- plugin and skill content manifests;
- project manifest and lockfile hashes;
- immutable Docker digest identity;
- executable and package provenance;
- efficient re-scan caching and bounded Merkle trees.

No TI, policy, or blocking implementation begins before that evidence layer is verified.
