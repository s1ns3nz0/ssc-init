# SSC Init Design

**Status:** Approved  
**Date:** 2026-08-05  
**License:** Apache-2.0 for code and first-party rules; CC BY 4.0 for documentation; upstream licenses retained for third-party intelligence.

## 1. Product definition

SSC Init is an open-source, snapshot-based developer supply-chain scanner for macOS laptops. Its expanded brand line is **“Software Supply Chain Security, Initialized.”** The repository, package, and CLI identifier is `ssc-init`; the primary tagline is **“Software supply chain security starts here.”**

SSC Init inventories and analyzes developer-executable assets across the current user's environment without behaving like an EDR: it does not install kernel components, intercept network packets, recursively scan arbitrary personal files, or continuously monitor processes and filesystem events.

The same local engine is exposed through separate Claude, Codex, and Cursor plugins. Those plugins provide host-specific skills, hooks, rules, and feedback while sharing one scanner, one inventory, one policy state, and one threat-intelligence state.

SSC Init detects malicious and suspicious assets based on provenance, known intelligence, static behavior, change history, and organization policy. It does not claim that a scan proves an asset safe. Threat-actor names are presented only as sourced campaign correlations, never as independent attribution.

## 2. Goals

- Inventory the developer attack surface across a macOS laptop under the current user's permissions.
- Detect known malicious assets, vulnerable components, suspicious provenance, obfuscation, dangerous execution paths, credential-access flows, and risky updates.
- Scan Claude, Codex, Cursor, Windsurf, MCP configurations, IDE extensions, developer tools, global packages, containers, and relevant projects.
- Prevent high-confidence malicious execution where the host exposes a pre-execution enforcement point.
- Provide evidence-based warnings and reversible remediation without silently deleting user data.
- Consume trustworthy public intelligence and generate local observations for ecosystems that lack CVE-like catalogs.
- Support organization policy through Git-managed YAML compiled into signed policy bundles.
- Remain usable offline and degrade explicitly when a collector, feed, permission, or integration is unavailable.
- Require no user-installed language runtime, package manager, database, YARA binary, or container runtime.

## 3. Non-goals

- General-purpose antivirus or EDR behavior.
- Kernel, packet, keystroke, or continuous filesystem monitoring.
- Scanning personal documents, photos, mail, browsing history, or arbitrary disk contents.
- Proving that an artifact is safe when no finding exists.
- Attributing an artifact or incident to a nation-state actor.
- Inspecting proprietary code inside a remote SaaS service.
- Requiring administrator privileges in the MVP.
- A central organization database or commercial control plane.
- Dynamic sandbox execution in the MVP.

## 4. Scope

### 4.1 AI agents and extensions

- Claude Code and Claude Desktop configurations.
- Codex plugins, skills, apps, hooks, and relevant configuration.
- Cursor and Windsurf plugins, skills, rules, hooks, MCP servers, and extensions.
- Agent instructions that invoke external scripts, tools, package managers, or remote services.

### 4.2 MCP

- Known user- and project-level MCP configuration paths.
- Local commands, package coordinates, versions, Git references, transports, endpoints, environment-variable references, and declared tools.
- Underlying npm, Python, container, executable, and repository artifacts.
- Permissions and potential data exposure to filesystems, shells, credentials, databases, and remote APIs.

### 4.3 IDEs and developer tooling

- VS Code-compatible extensions and JetBrains plugins.
- Shell startup files, terminal plugins, Git hooks, credential helpers, and developer-facing launch configuration.
- Homebrew packages, Docker images and plugins, and current developer processes/listening endpoints where discoverable without elevated privileges.

### 4.4 Packages and projects

- Global npm, pnpm, yarn, bun, pip, pipx, uv, Cargo, and Go installations where present.
- Project lockfiles and manifests, lifecycle scripts, direct and transitive dependencies.
- Projects discovered from IDE/agent recent-workspace records, Git worktrees, conventional development roots, and user-configured roots.
- Full-home recursive project discovery is excluded. Personal media, Library data unrelated to developer tooling, build caches, backups, network volumes, and external volumes are excluded by default.

### 4.5 External integrations

- Local and downloaded tools are inspected down to their package or code artifacts.
- Remote SaaS and APIs are evaluated by identity, domain, transport, authentication, permissions, requested data, and organization approval. Their private server-side code is not scanned.

## 5. Architecture

### 5.1 Host adapters

Claude, Codex, and Cursor receive separate, thin plugin packages. They share common Agent Skills source but translate manifests, hooks, rules, naming, and invocation to each host's native format.

Each adapter:

- invokes the same structured core API;
- renders concise findings and remediation choices;
- declares whether pre-execution enforcement is supported in the current host;
- never claims enforcement when only advisory scanning is possible;
- contains or bootstraps the exact compatible core version;
- does not maintain a separate inventory or policy database.

### 5.2 Core executable

The core executable is named `ssc-init`. It is a signed, notarized macOS Universal Binary built from Go for arm64 and amd64 with `CGO_ENABLED=0`. The MVP has no mandatory external runtime dependencies. Optional developer tools enrich coverage but their absence skips only the corresponding collector.

Core modules have stable JSON contracts:

1. **Collectors:** read-only discovery of hosts, MCP, IDEs, packages, projects, and process snapshots. Each collector has an independent timeout and returns complete, partial, skipped, unavailable, or failed status.
2. **Inventory graph:** canonical identities and relationships between logical assets, packages, repositories, executables, remote services, permissions, and projects.
3. **Analyzers:** hashes, manifests, provenance, rules, entropy, limited deobfuscation, dangerous APIs, simple source-to-sink flows, and version diffs.
4. **Decision engine:** deterministic combination of intelligence, behavior evidence, organization policy, and valid exceptions.
5. **TI manager:** bundle retrieval, signature and schema validation, staging, atomic activation, freshness, withdrawal, and rollback.
6. **Policy manager:** validation and indexing of signed organization policy bundles.
7. **Local store:** asset metadata, hashes, observations, findings, decisions, exceptions, and audit history. It does not retain full source files or secret values.
8. **Reporters:** conversational summaries, local evidence reports, SARIF 2.1.0, CycloneDX, common Finding JSON, webhooks, and CLI exit codes.

### 5.3 Shared installation

All adapters use one installation under `~/Library/Application Support/SSC Init/`:

- versioned core binaries and a current-version pointer;
- a single state database;
- TI and policy bundles;
- local reports;
- reversible quarantine.

The first adapter atomically installs a verified compatible core. Later adapters reuse it. Updates stage a new version, run integrity and doctor checks, and switch only on success. At least one previous known-good version remains available for rollback. Removing an adapter does not silently remove shared data or quarantine contents.

Claude can bundle the executable in its plugin `bin/` directory. Other channels may bundle it or automatically bootstrap a pinned release after checksum, project-signature, and macOS code-signing verification. Users never run `pip install`, `npm install`, `brew install`, or compile source.

### 5.4 Scheduling

- The first run offers an explicit opt-in for one shared daily `launchd` incremental scan.
- Host adapters never create duplicate scheduled jobs.
- The exact command, schedule, log location, and removal command are shown before registration.
- On-demand scanning remains available without scheduling.
- Host hooks request pre-execution checks where supported.

## 6. Analysis strategy

### 6.1 Quick scan

Quick scans collect identity, version, publisher, repository, signature, hash, package provenance, intelligence matches, organization policy, suspicious installation forms, dangerous API tokens, and basic obfuscation indicators. Unchanged assets use cached results.

### 6.2 Deep scan

New, changed, or suspicious assets are automatically promoted to deep analysis:

- limited Base64, hex, URL, string-array, compression, and constant-expression recovery;
- bundled dependency extraction;
- higher-cost static analysis;
- sensitive source to execution/network sink flows;
- behavioral and semantic differences from the previous known version;
- inspection of WASM and native-binary metadata, with unsupported analysis reported explicitly.

Dynamic sandboxing is a future adapter, invoked only with explicit user approval.

### 6.3 Mutable dependencies

- Exact versions and hashes receive normal verification.
- Registry versions must match registry integrity metadata.
- `latest`, unspecified versions, and mutable Git branches produce a High warning for personal use and are blocked by default under organization policy.
- Direct remote-script execution such as `curl ... | sh` is blocked by default. SSC Init recommends download, verification, scan, then execution.

## 7. Threat intelligence

### 7.1 Sources

- Tier 1: OSV, GitHub Advisory Database, CISA KEV, MITRE ATT&CK, and official package, IDE, and MCP registry metadata.
- Tier 2: original CERT and established security-research advisories with attributable evidence.
- Tier 3: community YARA, research IOC, and open-source malicious-asset feeds.
- Local observations: artifact hashes, publisher and repository changes, permissions, code behavior, execution form, and version differences.

Official MCP and IDE registries are treated as discovery metadata, not security endorsements. CVE feeds identify vulnerable underlying packages but do not represent the full MCP, skill, or plugin security state.

### 7.2 Ingestion and distribution

An open-source GitHub Actions pipeline fetches, validates, normalizes, correlates, tests, signs, and publishes versioned bundles. Each record preserves canonical identity, applicable version range, hashes, verdict, confidence, source URLs, retrieval time, validity interval, withdrawal state, license, redistribution permission, campaign correlations, and ATT&CK techniques.

News and social posts cannot independently trigger automatic blocking. Tier 3 data raises investigation confidence unless corroborated. Data that cannot legally be redistributed is fetched directly by users from the original source or excluded from public bundles.

Clients check daily, download only changed bundles, verify checksums, signatures, schema, and rollback protections, and stage before atomic activation. Failure preserves the last known-good bundle. Seven-day staleness produces a warning; prolonged staleness reduces result confidence. Staleness alone does not block personal development. Organizations may explicitly select fail-closed behavior.

### 7.3 Verdicts

- **Known malicious:** exact, strong intelligence evidence such as a matching malicious artifact/version/hash.
- **Behaviorally malicious:** deterministic evidence of malicious behavior, such as credential collection followed by unauthorized external transmission.
- **Suspicious:** meaningful risk signals requiring review, including obfuscation, dynamic execution, mutable provenance, or excessive capability.
- **Needs review:** legitimate functionality may explain the capability, but evidence is insufficient.
- **No finding:** no relevant evidence was discovered within the scanned scope; this is not a safety guarantee.

Campaign correlations show source, observation time, matched evidence, and confidence. They never state actor attribution as fact.

## 8. Organization policy

Organization policy uses Git-managed YAML as the source of truth. Pull requests provide review and audit history. CI validates JSON Schema, duplicate keys, conflicts, exception expiry, and policy test cases, then compiles deterministic JSON and signs a versioned release bundle.

Local SQLite is only a verified-policy index and audit cache, not the policy source of truth. A modified local database can be rebuilt from the signed bundle.

Policy precedence is:

1. known malicious evidence, which cannot be overridden;
2. organization deny policy, which users cannot override locally;
3. organization allow policy, invalidated by artifact hash changes;
4. time- and scope-bound user exceptions where organization policy permits;
5. default product policy.

Organization integration in the MVP consists of signed policy bundles, SARIF, CycloneDX, Finding JSON, HTTPS webhooks, and CLI exit codes. Vendor-specific MDM, SIEM, EDR, and ticketing connectors remain separate open-source modules.

Outbound organization findings contain an opaque device identity, asset type and canonical identifier, version/hash, severity, rule identifiers, detection time, and action status. Source code, secret values, raw environment variables, personal paths, project/repository names, and raw matched data are excluded by default.

## 9. Enforcement, feedback, and remediation

### 9.1 Enforcement

- Known malicious assets and organization-denied assets are automatically blocked when the host supports enforcement.
- High-confidence but uncertain findings pause execution and request informed approval.
- External changes that cannot be intercepted are detected during the next scan and produce remediation guidance.
- Host capability is reported as pre-execution, scheduled detection, on-demand, advisory, or enforced.

### 9.2 Feedback

The host conversation shows overall status, the three to five most urgent findings, a one-sentence reason, confidence, and the available actions. Critical and High findings interrupt. Medium findings appear in the completion summary. Low and Informational findings remain in the local report.

Local reports retain the complete inventory graph, file/line evidence where safe, redacted data-flow evidence, version differences, TI provenance and time, ATT&CK mapping, skipped/failed scope, and export controls. Models receive structured findings and minimal redacted code slices by default. Full-code model analysis requires explicit approval. Model judgment alone never causes automatic blocking.

### 9.3 Exceptions

Exceptions are limited to a run, exact asset/version/hash, project, or organization-approved scope. Project exceptions expire within 30 days by default. Organization exceptions require approver, reason, ticket, and expiry, with 90 days as the default maximum. Publisher-wide permanent trust, all-version trust, disabling a high-risk rule globally, and exceptions for known malicious hashes are prohibited.

### 9.4 Remediation

For known malicious installed assets, SSC Init blocks further execution where possible, identifies running related processes, proposes IDE/MCP disablement, offers reversible quarantine, and creates credential-exposure follow-up steps. Quarantine removes execution permission, preserves original path/hash/permissions, remains current-user-only, and is reversible. SSC Init never automatically deletes quarantined artifacts.

## 10. Privacy and storage

The local store records canonical asset metadata, versions, hashes, normalized commands, capability summaries, rule IDs, severity, TI bundle version, user decisions, exception expiry, and observation times. It does not store full source, environment values, tokens, credentials, or matched raw data by default. Home paths are tokenized in reports.

Default retention:

- full snapshots: 30 days;
- asset change history: 90 days;
- Critical and High incident metadata: until explicit deletion;
- organization retention: configurable through signed policy.

## 11. Failure behavior

Scan status is one of Complete, Partial, Stale, or Blocked, with component detail. A missing npm executable skips npm command enrichment; Docker being stopped marks Docker collection unavailable; denied paths are listed as unscanned; timeouts preserve the unscanned asset list. Component failure does not silently convert to a successful full scan.

Core, TI, and policy updates use stage, verify, health check, atomic switch, and rollback. The last known-good state remains active on any checksum, signature, schema, migration, or doctor failure.

## 12. Performance requirements

- Initial baseline: at most 10 minutes on the reference laptop.
- Daily incremental scan: at most 60 seconds.
- Pre-execution cache hit: at most 500 milliseconds.
- New package metadata preflight: at most 3 seconds before progress is surfaced.
- Average scanner consumption: approximately one CPU core and at most 500 MB memory.
- Local binary, bundles, state, and retained routine reports: at most 500 MB under default retention.

Exceeding a time budget produces a Partial result with the unscanned targets; it never silently skips them.

## 13. MVP acceptance tests

1. Detect and block an exact known-malicious IDE extension identifier/version/hash.
2. Detect an MCP flow from environment or SSH data to an unauthorized external destination.
3. Warn or block mutable versions and block direct remote-script piping.
4. Detect malicious agent instructions, hidden commands, and external script invocation in a skill/plugin.
5. Recover safe fixture encoding and detect resulting dynamic execution and network behavior.
6. Detect publisher, hash, permission, and behavior changes from a previous normal version.
7. Match vulnerable packages through OSV/GHSA and prioritize CISA KEV.
8. Enforce signed organization denial, apply a signed scoped exception, and re-block after expiry.
9. Produce the same core verdict for the same asset from Claude, Codex, and Cursor adapters.
10. Preserve scanning and explicitly report scope when TI, network, permissions, or a collector fails.

Every malicious fixture has a behaviorally similar benign fixture to prevent trivial pattern matching and control false positives. Real malware is replaced by inert fixtures. UI tests verify the wording “No finding” rather than “Safe.”

Release gates also include clean macOS arm64 and Intel smoke tests, plugin contract tests, database migration and rollback tests, secret redaction, path privacy, bundle tampering, expired exceptions, concurrent host access, and installation doctor diagnostics.

## 14. Repository and release model

The monorepo contains the Go core, shared skill sources, host adapters, policy and rule schemas, ingestion pipeline, fixtures, and documentation. A single versioned release produces the Universal Binary, Claude plugin, Codex plugin, Cursor plugin, bootstrap rule bundle, checksums, signatures, SBOM, and build provenance.

Code and first-party rules use Apache-2.0. Documentation uses CC BY 4.0. Third-party intelligence retains its original license and provenance. The project has no paid or closed-source tier.

## 15. Deferred work

- Linux collectors, then Windows and WSL support.
- Optional sandbox execution adapter.
- Native IDE extension UX beyond host plugins.
- Optional privileged organization helper.
- Vendor-specific open-source MDM, SIEM, EDR, and ticketing connectors.
- Central open-source fleet dashboard if GitOps plus standard exports become insufficient.
