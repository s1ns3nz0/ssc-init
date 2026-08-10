# Program G bounded analyzers design

Date: 2026-08-10

Authority: foundation design §5.2.3, §6.2–§7.3 and Program F's explicit
version-range deferral.

## Outcome

SSC Init derives reviewable findings from already-authorized local evidence
without persisting source text. G1 adds exact ecosystem version/range advisory
matching and mutable-dependency decisions. G2 adds bounded lexical signals,
limited literal decoding, dangerous API facts, and narrow source-to-sink flows.
It does not execute code, recursively unpack arbitrary archives, contact a
registry, or ask a model to decide.

## G1: package and mutable-reference analysis

- Parse only canonical package assets and closed ecosystems already emitted by
  collectors. Versions are compared with ecosystem-specific deterministic
  adapters; malformed or unsupported ranges become explicit `needs-review`,
  never a guessed match.
- A TI version range matches only the same canonical asset ID. A record with a
  hash still requires the exact hash and stays on Program F's stronger path.
- Exact registry integrity remains evidence. `latest`, absent versions,
  mutable Git branches, and remote-script forms produce closed suspicious
  signals; they are advisory until policy or a host supplies enforcement.
- No registry or advisory network request occurs during scan/evaluation.

## G2: bounded content analysis

Analysis runs inside the sealed local-evidence lifetime, after target
authorization and before runtime paths are cleared. The analyzer receives a
bounded reader rather than a path and returns only closed facts:

- entropy/encoded-literal thresholds with strict byte and nesting limits;
- dynamic execution, process launch, credential access and outbound-network
  API tokens using language-specific lexical scanners;
- a narrow same-file credential-source → outbound-sink flow when both tokens
  occur in deterministic order and within a bounded distance;
- package/version differences using current and previous normalized facts.

Comments and string handling are language-aware enough to avoid treating a
commented API name as executable evidence. Findings store rule IDs, evidence
IDs and redacted categories only. No source line, path, argument, literal,
URL, hostname, repository name, environment value or decoded bytes persist.

## Safety and budgets

Per file: 1 MiB; per asset: 8 MiB; at most 2 decode layers; at most 4 analyzer
workers; existing scan cancellation and 30-second target bounds apply. Binary,
oversize, unreadable and unsupported inputs yield coverage facts, not a clean
claim. Analyzer panics are contained as failed coverage.

Verdicts remain deterministic: corroborated credential-source → outbound-sink
is `behaviorally-malicious` only when a closed rule proves unauthorized
transmission semantics; otherwise dangerous APIs/obfuscation are `suspicious`
or `needs-review`. No heuristic alone blocks.

## Deferred boundaries

WASM/native semantic inspection, archive recursion, whole-program data flow,
registry retrieval, model review and host enforcement remain outside Program
G. Production bundle keys/publication remain external. Release distribution
follows the [unsigned reproducible contract](2026-08-10-unsigned-reproducible-distribution-design.md).
