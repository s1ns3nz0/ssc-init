# Program D — external and platform evidence design

**Status:** Approved by continuation direction  
**Date:** 2026-08-10  
**Authority:** foundation design §4.2–§4.5, §5.2, §6.1, §6.3, §10–§13

## 1. Purpose

Program D turns facts already available from explicitly enabled developer tools
and macOS into durable, deterministic evidence. It does not add threat
intelligence, findings, verdicts, warnings, or enforcement. A fact collector
must not imply that a valid signature or immutable identifier makes an artifact
safe.

## 2. Execution boundary

The default scan remains passive: it starts no process and opens no network
connection. Every command-backed fact in this program requires
`--external-probes`. Commands are restricted to the already configured package
manager executable or an exact Apple system executable. The executable is
inspected before use and re-verified after every invocation. Supplied paths,
stderr, signer text, registry responses and command output are never persisted
or echoed.

No probe performs a registry or internet request. Package provenance is derived
only from locally installed metadata and lockfiles. TI and live registry
correlation belong to later programs.

## 3. Public facts and contract version

The scan/status contract advances from v3 to `ssc-init.scan.v4` and
`ssc-init.status.v4`. Older snapshots remain readable as legacy inventory.

`Asset` gains two optional, closed fact objects:

```go
type Signature struct {
    Status     SignatureStatus `json:"status"` // valid|invalid|unsigned|unavailable|unsupported
    Identifier string          `json:"identifier,omitempty"`
    TeamID     string          `json:"teamId,omitempty"`
}

type Provenance struct {
    Status    ProvenanceStatus `json:"status"` // immutable|mutable|unknown|unavailable|unsupported
    Ecosystem string           `json:"ecosystem"`
    Source    string           `json:"source,omitempty"` // closed normalized source, never URL/path
    Integrity string           `json:"integrity,omitempty"` // sha256:<lowercase hex> only
}
```

Signer display names, certificate subjects, full authority chains, registry
URLs, repository names, local paths and raw package metadata are excluded.
Identifier and team ID use bounded conservative token grammars. An invalid or
unavailable signature carries no identity fields. Facts participate in normal
inventory diffing.

Container identity remains `ContentEvidence` with kind `container-identity`.
It may now be `complete` when Docker reports a full lowercase `sha256:<64 hex>`
image ID. The persisted evidence digest omits the `sha256:` prefix and records
algorithm `sha256`. Truncated, malformed or absent IDs remain `unsupported`;
they are never padded, hashed again, or treated as immutable.

## 4. Docker identity

The Docker inventory probe adds `--no-trunc` to `docker image ls`. Each parsed
row must have a repository, an exact tag or repository digest, and may have one
full image ID. The asset keeps its canonical package URL identity; the image ID
becomes complete container evidence bound to the finalized observation.

Conflicting rows for the same canonical asset produce a deterministic metadata
conflict/partial result rather than choosing an ID. Docker daemon failures stay
`unavailable`; missing immutable identity is `unsupported`. No `docker inspect`,
container start, pull, or registry command is introduced.

## 5. macOS code-signature facts

The executable-inspection boundary gains an optional signature inspector. On
Darwin with external probes enabled it invokes exact `/usr/bin/codesign` paths
with bounded output and timeout. It verifies first, then obtains machine-readable
identifier/team facts. Exit status is mapped to the closed status vocabulary;
raw diagnostic output is discarded.

Signature collection covers discovered tool executables and native entrypoints
whose descriptor-anchored identity can be rechecked before and after the probe.
An artifact that changes during inspection is `unavailable`, and the associated
collector becomes partial. Non-Darwin test builds report `unsupported` without
executing anything.

## 6. Local package provenance

Program D supports provenance only where a local source provides an exact,
bounded integrity fact without network access:

- npm-compatible lockfile `integrity` values using SHA-256;
- Go module `h1` checksums are recorded as source-specific immutable facts but
  are not mislabeled SHA-256;
- Cargo lockfile checksums using SHA-256;
- Docker full image IDs;
- package-manager entries with only a name/version are `unknown`, not immutable.

Because the current `Provenance.Integrity` grammar is SHA-256-only, non-SHA-256
integrity uses a closed source fact in observation metadata until a later schema
adds an algorithm-tagged digest. No hash is converted into another algorithm.

Mutable forms (`latest`, absent versions, branch-like Git references and
untagged Docker forms) are normalized to `mutable`. This program records that
fact only; Program F turns it into a warning and organization policy later may
deny it.

## 7. Graph relationships

Relationship kinds become a closed vocabulary. This program adds:

- `probed-by`: package/container → verified tool executable;
- `declared-by`: package → project manifest or lockfile asset;
- `resolves-to`: mutable/logical package coordinate → immutable evidence-bearing asset;
- `executes`: plugin/extension/MCP declaration → discovered executable when both assets exist;
- `connects-to`: MCP declaration → normalized remote-service asset when both exist.

Only relationships whose endpoints are already canonical assets are persisted.
Collectors never synthesize a placeholder endpoint merely to preserve an edge.
Duplicate edges normalize deterministically; unknown relationship kinds fail
store validation.

## 8. Privacy and failure behavior

All new validation errors are fixed and value-free. New fields are included in
the existing secret/path/control-character audits. Probe output is capped before
parsing. Cancellation and deadlines clear runtime-only targets and persist
nothing partial. A failed enrichment degrades only its target and cannot erase
the underlying inventory asset.

## 9. Acceptance evidence

Program D is complete only when tests prove:

1. a full Docker ID becomes complete container evidence and a one-character
   mutation preserves the stable evidence ID while producing an evidence
   `changed` delta;
2. truncated/malformed IDs never become trusted evidence;
3. default scans invoke no signature, Docker or package command;
4. valid/invalid/unsigned/replaced code-signature fixtures map to closed facts
   without persisting signer output or paths;
5. immutable and mutable package fixtures remain distinguishable without
   network access;
6. graph edges are canonical, closed, deterministic and orphan-free;
7. v3 snapshots load as legacy while v4 round-trips byte-deterministically;
8. malicious outputs containing paths, tokens and control characters are
   rejected without echo; and
9. full race, vet, module, source-audit and release-build gates pass.

## 10. Deferred boundaries

- `[TI]` registry/advisory correlation and signed bundles;
- `[FINDINGS]` severity, warnings and verdicts;
- `[DEEP]` archive/native/WASM code analysis;
- `[HOST]` pre-execution enforcement.

Release distribution follows the [unsigned reproducible contract](2026-08-10-unsigned-reproducible-distribution-design.md).
