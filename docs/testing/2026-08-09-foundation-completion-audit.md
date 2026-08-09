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
| §5.2.1 collectors | Partial | `internal/collector/{agents,ide,mcp,packages,projects}` and isolated-home acceptance suite | Developer surfaces, process/listener snapshots, immutable Docker evidence, broader package managers and recent-workspace discovery |
| §5.2.2 inventory graph | Partial | Canonical assets, observations and relationships in `internal/model`; normalization in `internal/inventory` | Executable/package/repository/service/permission dependency edges across all collectors |
| §5.2.3 analyzers | Partial | Bounded hashes, semantic MCP digest, manifest facts and version diff | Signature analysis, provenance validation, dependency extraction, entropy/obfuscation, dangerous APIs and source-to-sink flows |
| §5.2.4 decision engine | Partial | Deterministic local shape/change/pin policy in `internal/policy` | TI evidence, behavior findings, signed organization policy and final verdict correlation |
| §5.2.5 TI manager | Missing | Precedence level exists but reports `no evidence available` | Signed schema, trust root, ingestion/retrieval, stage/activate/rollback, freshness and withdrawal |
| §5.2.6 policy manager | Partial | Local `ssc-init.policy.v1`, scoped expiring exceptions, pins and decision audit | Git-managed YAML compiler, deterministic signed bundle, signature/schema verification, organization deny/allow indexing |
| §5.2.7 local store | Partial | Atomic snapshots, retention, asset history, policy pins/exceptions/decisions | Findings, TI/policy bundle state, incident retention, reports and quarantine metadata |
| §5.2.8 reporters | Partial | Scan/status/doctor/install/policy JSON and human hook/pretty output | Finding JSON, SARIF 2.1.0, inventory CycloneDX, HTTPS webhook and complete local evidence report |
| §5.3 shared installation | Partial | Universal build, versioned stage/activate/rollback, doctor v2, signed/notarized/stapled-DMG scripts and runbook | Real Developer ID signing/notary execution; adapter bootstrap; TI/policy/report/quarantine lifecycle |
| §5.4 scheduling | Missing | No launchd module or command | Explicit opt-in preview, one shared job, logs/removal instructions, idempotence tests |
| §6.1 quick scan | Partial | Identity/version/publisher/hash and explicit coverage gaps | Code signatures, immutable package provenance, TI, suspicious forms and dangerous-token/obfuscation facts |
| §6.2 deep scan | Missing | No deep-analysis package or promotion scheduler | Bounded decoding, bundled dependencies, static flows, semantic version differences, WASM/native metadata |
| §6.3 mutable dependencies | Partial | Local policy can match exact recorded metadata and pin digest changes | Proven registry integrity, normalized mutable-reference facts, warning/finding decisions, organization default deny |
| §7 intelligence | Missing | None; level 1 is explicitly inert | Licensed source ingestion, normalized records, signed distribution, freshness, verdict matching and campaign provenance |
| §8 organization policy | Partial | Five-level precedence shape and local exception prohibitions | Git YAML source, CI compiler/tests, signed bundle, unoverridable deny, hash-sensitive allow, outbound privacy contract |
| §9 enforcement/feedback/remediation | Missing | Hook and policy check truthfully report `advisory`; no blocking claim | Host enforcement points, structured urgent feedback, reversible quarantine, process guidance and credential follow-up |
| §10 privacy/storage | Partial | Path/secret/value-free validation, 30/90-day pruning and size diagnostics | Finding/incident retention, signed organization retention, report and quarantine persistence/privacy tests |
| §11 failure behavior | Partial | Complete/partial status, bounded collectors, atomic core update and rollback | TI/policy update failure states, stale/blocked reachability and last-known-good bundle tests |
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

## Remaining dependency order

1. Program D — immutable/platform/package evidence and real graph edges.
2. Program I — bounded developer-surface and process/listener collectors.
3. Program E — signed TI and organization-policy bundle lifecycle.
4. Program F — findings, verdict correlation and reporters.
5. Program G1/G2 — vulnerability and bounded static/deep analyzers.
6. Program H — adapters, enforcement, remediation, quarantine and scheduling.
7. Final §13 acceptance matrix, Apple release execution, clean arm64/Intel
   smoke tests and hosted CI evidence.

The order keeps facts below decisions, decisions below enforcement, and avoids
an adapter inventing a verdict that the shared core cannot yet produce.
