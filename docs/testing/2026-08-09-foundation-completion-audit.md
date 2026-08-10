# Foundation completion audit — 2026-08-09

Authority: `docs/superpowers/specs/2026-08-05-ssc-init-design.md`.

This is a requirement audit, not a roadmap-completion claim. “Proved” means a
current implementation plus direct tests or an executable release check.
“Partial” means the requirement has an honest subset but not the full designed
capability. “Missing” means current-state evidence contradicts completion or no
implementation exists.

## Requirement matrix

| Foundation requirement | State | Current evidence | Missing evidence/work |
|---|---|---|---|
| §5.1 Claude/Codex/Cursor adapters | Proved | Native `adapters/{claude,codex,cursor}` packages, closed capability manifests, common bounded evaluation endpoint, cross-host verdict parity, deterministic release ZIPs, and package contract tests | Production marketplace publication remains external |
| §5.2.1 collectors | Partial | `internal/collector/{agents,ide,mcp,packages,projects,surfaces,runtime}` and isolated-home acceptance suite; bounded developer files plus full local Docker identity and point-in-time process/listener facts behind external probes | Broader package managers and recent-workspace discovery |
| §5.2.2 inventory graph | Partial | Canonical assets, observations and relationships in `internal/model`; normalization in `internal/inventory` | Executable/package/repository/service/permission dependency edges across all collectors |
| §5.2.3 analyzers | Partial | Bounded hashes, semantic MCP digest, closed macOS signature facts, local npm/Cargo/Go provenance, supported version ranges, mutable-reference signals, dangerous APIs, bounded obfuscation and narrow credential-egress flows | Dependency extraction beyond supported lockfiles and deeper language-aware analysis |
| §5.2.4 decision engine | Proved | Exact and version-range verified TI correlation, analyzer findings, deterministic five-level precedence, and capability-bounded adapter response choices | Automatic execution remains deliberately absent |
| §5.2.5 TI manager | Partial | Closed signed TI schema, lifecycle, freshness, withdrawal and exact asset/hash correlation | Production trust root, signed publication and scheduled retrieval |
| §5.2.6 policy manager | Partial | Local policy plus verified signed organization deny, digest-bound allow and scoped exception precedence | Git-managed YAML compiler and production trust root/publication |
| §5.2.7 local store | Partial | Atomic snapshots, retention, asset history, policy/bundle state, v7 analyzer coverage/facts, findings, independent critical/high incidents, and privacy-validated quarantine records | Signed organization retention controls |
| §5.2.8 reporters | Partial | Finding JSON, privacy-safe SARIF 2.1.0, inventory CycloneDX, explicit HTTPS webhook and existing local formats | Complete local evidence report and downstream connector modules |
| §5.3 shared installation | Partial | Separately installed Universal core plus digest/Mach-O verified stage/activate/rollback and doctor v2; adapter ZIPs contain no executable | TI/policy/report/quarantine lifecycle |
| §5.4 scheduling | Proved | Exact preview plus explicit install/remove, one stable private launchd plist, tokenized logs/removal instructions, atomic publication, rollback, and process/thread concurrency tests | None for the designed opt-in local scheduler |
| §6.1 quick scan | Partial | Identity/version/publisher/hash, Docker identity, code-signature facts, supported lockfile provenance, bounded developer surfaces, optional process/listener facts, dangerous-API/obfuscation facts and explicit coverage gaps | Broader package and language coverage |
| §6.2 deep scan | Partial | Two-layer bounded decoding and narrow within-file credential-egress flow | Bundled dependencies, cross-file semantic flows, WASM/native metadata and promotion scheduler |
| §6.3 mutable dependencies | Partial | Normalized absent/latest version, mutable Git ref and direct remote-script facts feed advisory findings | Proven registry integrity, organization default deny and host enforcement |
| §7 intelligence | Partial | Closed records, signed lifecycle, freshness, withdrawal/campaign/ATT&CK fields and exact/version-range verified correlation | Licensed ingestion and production publication |
| §8 organization policy | Partial | Active five-level precedence, unoverrideable malicious evidence, deny, digest-bound allow, exceptions and privacy-safe outbound formats | Git YAML source/compiler and production publication |
| §9 enforcement/feedback/remediation | Partial | Truthful advisory host feedback, deterministic urgent-finding selection, explicit remediation choices, preview-bound reversible quarantine, and one shared scheduler | Automatic host blocking, process termination guidance, and credential rotation workflow |
| §10 privacy/storage | Partial | Path/secret/value-free validation, 30/90-day pruning and size diagnostics, finding/incident persistence, and tokenized quarantine persistence/privacy tests | Signed organization retention controls |
| §11 failure behavior | Partial | Complete/partial status, bounded collectors, atomic core and verified-bundle update/rollback, last-known-good and explicit bundle freshness | Scan stale/blocked reachability and remote retrieval failure behavior |
| §12 performance | Partial | Ten-minute baseline budget, store cap accounting, optional performance harness | 60-second incremental gate, 500 ms pre-execution cache gate, 3-second metadata preflight/progress, full 500 MB product-footprint gate |
| §13 acceptance cases | Partial | Inventory/evidence/adversarial coverage, local exception expiry, TI/organization failure behavior, analyzer twins, cross-host verdict parity, quarantine drift/collision recovery, and scheduler idempotence | Automatic enforcement cases remain intentionally unimplemented |
| §14 release model | Partial | Closed reproducible artifact set: Universal Binary, three deterministic native adapter ZIPs, checksums, SBOM, provenance, and CI definition | Hosted CI execution and physical arm64/Intel smoke evidence |

## Verified completed programs

- Local content-evidence core and inventory trust foundation.
- Hook command and severity ladder.
- Program B: status vocabulary, retention, budgets and store diagnostics.
- Program C `[NOW]`: local advisory policy, pins, exceptions, audit decisions,
  policy check and hook integration.
- Program A managed install lifecycle and explicit reproducible release mode.
  Isolated repository tests prove clean-source rejection, exact annotated `v*`
  tag enforcement, and repeat-build identity without blocking untagged
  developer builds.
- Program D: Docker identity, macOS signature inspection, supported lockfile
  provenance and closed graph relationships.
- Program I: bounded developer-file surfaces and opt-in point-in-time
  process/listener inventory. This is snapshot collection, not monitoring.
- Program E local core: signed TI/organization bundle schemas, verification,
  stage/activate/rollback, monotonic sequence protection, freshness, CLI,
  rebuildable indexes and publisher gates. Production keys/publication remain
  external.
- Program F: exact TI correlation, organization precedence, v6 finding and
  incident persistence, Finding JSON, SARIF, CycloneDX, explicit HTTPS webhook,
  policy-check consumption and advisory hook reporting.
- Program G: supported version comparison, version-scoped TI, mutable-reference
  signals, sealed bounded lexical/obfuscation/credential-egress analysis, v7
  persistence and truthful analyzer coverage. Production bundle publication is
  still external.
- Program H: closed host contracts, deterministic shared verdict evaluation,
  Claude/Codex/Cursor advisory packages, cross-host parity, privacy-safe
  reversible quarantine, and one explicit shared launchd schedule. Adapter ZIPs
  ship in the reproducible GitHub release set; no adapter bundles the core.

## Remaining dependency order

1. Final automatic-enforcement acceptance cases and broader collector/analyzer coverage.
2. Production bundle publication, clean physical arm64/Intel smoke tests, and
   hosted CI evidence.

The order keeps facts below decisions, decisions below enforcement, and avoids
an adapter inventing a verdict that the shared core cannot yet produce.
