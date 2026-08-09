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
| §5.1 Claude/Codex/Cursor adapters | Missing | No adapter/package directories exist | Three native host packages, common structured invocation, capability declarations, bootstrap verification, contract tests |
| §5.2.1 collectors | Partial | `internal/collector/{agents,ide,mcp,packages,projects,surfaces,runtime}` and isolated-home acceptance suite; bounded developer files plus full local Docker identity and point-in-time process/listener facts behind external probes | Broader package managers and recent-workspace discovery |
| §5.2.2 inventory graph | Partial | Canonical assets, observations and relationships in `internal/model`; normalization in `internal/inventory` | Executable/package/repository/service/permission dependency edges across all collectors |
| §5.2.3 analyzers | Partial | Bounded hashes, semantic MCP digest, closed macOS signature facts, local npm/Cargo/Go provenance and version diff | Dependency extraction beyond supported lockfiles, entropy/obfuscation, dangerous APIs and source-to-sink flows |
| §5.2.4 decision engine | Partial | Exact verified TI correlation and deterministic five-level local/organization precedence | Program G behavior findings and host-capability actions |
| §5.2.5 TI manager | Partial | Closed signed TI schema, lifecycle, freshness, withdrawal and exact asset/hash correlation | Production trust root, signed publication and scheduled retrieval |
| §5.2.6 policy manager | Partial | Local policy plus verified signed organization deny, digest-bound allow and scoped exception precedence | Git-managed YAML compiler and production trust root/publication |
| §5.2.7 local store | Partial | Atomic snapshots, retention, asset history, policy/bundle state, v6 findings and independent critical/high incidents | Signed incident retention and quarantine metadata |
| §5.2.8 reporters | Partial | Finding JSON, privacy-safe SARIF 2.1.0, inventory CycloneDX, explicit HTTPS webhook and existing local formats | Complete local evidence report and downstream connector modules |
| §5.3 shared installation | Partial | Universal build, versioned stage/activate/rollback, doctor v2, signed/notarized/stapled-DMG scripts and runbook | Real Developer ID signing/notary execution; adapter bootstrap; TI/policy/report/quarantine lifecycle |
| §5.4 scheduling | Missing | No launchd module or command | Explicit opt-in preview, one shared job, logs/removal instructions, idempotence tests |
| §6.1 quick scan | Partial | Identity/version/publisher/hash, Docker identity, code-signature facts, supported lockfile provenance, bounded shell/Git-hook/credential-helper/launch surfaces, optional process/listener facts, and explicit coverage gaps | TI, suspicious forms and dangerous-token/obfuscation facts |
| §6.2 deep scan | Missing | No deep-analysis package or promotion scheduler | Bounded decoding, bundled dependencies, static flows, semantic version differences, WASM/native metadata |
| §6.3 mutable dependencies | Partial | Local policy can match exact recorded metadata and pin digest changes | Proven registry integrity, normalized mutable-reference facts, warning/finding decisions, organization default deny |
| §7 intelligence | Partial | Closed records, signed lifecycle, freshness, withdrawal/campaign/ATT&CK fields and exact verified correlation | Licensed ingestion, production publication and Program G version/range analysis |
| §8 organization policy | Partial | Active five-level precedence, unoverrideable malicious evidence, deny, digest-bound allow, exceptions and privacy-safe outbound formats | Git YAML source/compiler and production publication |
| §9 enforcement/feedback/remediation | Missing | Hook and policy check truthfully report `advisory`; no blocking claim | Host enforcement points, structured urgent feedback, reversible quarantine, process guidance and credential follow-up |
| §10 privacy/storage | Partial | Path/secret/value-free validation, 30/90-day pruning and size diagnostics | Finding/incident retention, signed organization retention, report and quarantine persistence/privacy tests |
| §11 failure behavior | Partial | Complete/partial status, bounded collectors, atomic core and verified-bundle update/rollback, last-known-good and explicit bundle freshness | Scan stale/blocked reachability and remote retrieval failure behavior |
| §12 performance | Partial | Ten-minute baseline budget, store cap accounting, optional performance harness | 60-second incremental gate, 500 ms pre-execution cache gate, 3-second metadata preflight/progress, full 500 MB product-footprint gate |
| §13 acceptance cases | Partial | Inventory/evidence/adversarial coverage and local exception expiry | Cases 1–9 requiring TI, analyzers, organization bundles, adapters and enforcement; case 10 still lacks TI failure |
| §14 release model | Partial | Universal binary, checksums, SBOM, provenance, CI definition and DMG release scripts | Hosted CI execution, real Apple signing/notarization, three plugin artifacts and bootstrap rule bundle |

## Verified completed programs

- Local content-evidence core and inventory trust foundation.
- Hook command and severity ladder.
- Program B: status vocabulary, retention, budgets and store diagnostics.
- Program C `[NOW]`: local advisory policy, pins, exceptions, audit decisions,
  policy check and hook integration.
- Program A implementation and fail-closed release automation. Real Apple
  signing/notarization remains externally unverified because credentials are
  absent.
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

## Remaining dependency order

1. Program G1/G2 — vulnerability and bounded static/deep analyzers.
2. Program H — adapters, enforcement, remediation, quarantine and scheduling.
3. Final §13 acceptance matrix, production bundle publication, deferred Apple release execution, clean arm64/Intel
   smoke tests and hosted CI evidence.

The order keeps facts below decisions, decisions below enforcement, and avoids
an adapter inventing a verdict that the shared core cannot yet produce.
