# Public Repository Scan Hardening Design

Date: 2026-08-16

Authority: the 20-repository public corpus spike performed on 2026-08-16 and
the user's approval to implement the recommended corrections.

## Outcome

SSC Init scans an explicitly selected public source repository without turning
ordinary dependency metadata into behavior findings, without rejecting common
valid lockfile syntax, and without mixing unrelated host findings into a
project-only result. Existing default laptop scans retain their current broad
host coverage and all filesystem, symlink, privacy, and network boundaries.

## Corpus evidence

The spike scanned five npm, five Python, five Go, and five Rust repositories.
It discovered 391 project assets. All 20 scans were partial, 13 project
findings across eight repositories were traced to lockfile/manifest false
positives, 12 valid lockfiles failed provenance parsing, and one valid VS Code
JSONC launch file was rejected. Eight repeated project-only result sets were
byte-identical.

The retained corpus is a local diagnostic fixture only. Production tests use
small literal fixtures copied from the relevant public syntax and never clone
or access the network.

## Program decomposition

Implementation is split into three independently testable programs:

1. evidence-aware analysis and provenance parsing correctness;
2. explicit project-only scan semantics and project UX;
3. active TI receipt consistency for scans that do not request an update.

Each program receives strict RED/GREEN tests, a focused mutation, full race
verification, and an independent review before the next program begins.

## Evidence-aware behavior analysis

Generic source-code behavior rules must not run over dependency lockfiles or
declarative dependency manifests. A package name containing `credential` is
not credential access, and a registry checksum that happens to decode as
Base64 is not obfuscation.

`evidence.SealedContent` gains a closed content class derived by the evidence
issuer, not guessed from bytes:

- `source`: executable or script-like content on which lexical and obfuscation
  rules may run;
- `launch-config`: launch configuration on which only reviewed configuration
  rules may run;
- `dependency-manifest`: `package.json`, `pyproject.toml`, `go.mod`,
  `Cargo.toml`, and comparable manifests;
- `dependency-lockfile`: package manager lockfiles;
- `other`: closed fallback with no behavior facts.

For this program, dependency manifests and lockfiles emit no generic lexical,
credential-egress, or obfuscation facts. Their security facts come from their
closed structural parsers. `package.json` script analysis is not silently
discarded: it is deferred until a dedicated script-only sealed subject exists;
the complete dependency document is never treated as source code.

Unknown content classes fail closed by producing no behavior fact and a
closed skipped analyzer-coverage reason. Paths and raw subjects never enter an
analyzer fact.

## npm integrity support

The npm provenance parser accepts exact SRI values for SHA-256, SHA-384, and
SHA-512. It rejects malformed Base64, whitespace, multiple algorithms in one
field, wrong digest lengths, and unrecognized algorithms.

SHA-256 continues to populate `Provenance.Integrity` as `sha256:<hex>`.
Approved non-SHA-256 SRI is retained in the existing closed
`Record.SourceIntegrity` field as `sha384:<hex>` or `sha512:<hex>`, while the
record remains immutable. This generalizes the field's existing Go `h1:` use
without weakening the model's SHA-256-only canonical asset-integrity field.
One unsupported entry must not be silently truncated; it remains a malformed
record until a reviewed algorithm is added.

## Cargo duplicate source support

Cargo lock parsing reads the optional `source` field. Multiple entries with
the same name and version are valid when they describe a local/workspace copy
and a registry copy.

Normalization emits one package coordinate per name/version:

- an immutable checksummed registry record wins over an otherwise identical
  local/path entry with no checksum;
- identical checksummed duplicates collapse;
- two different non-empty checksums for the same name/version remain
  malformed;
- git sources remain mutable unless a separate approved immutable digest is
  available;
- source URLs and local paths are never persisted.

This accepts Clap's valid workspace/registry shape without accepting genuine
equivocation.

## VS Code JSONC validation

`.vscode/launch.json` is validated as bounded JSONC rather than strict JSON.
Only line comments, block comments, and trailing commas are added to the
accepted grammar. Comment markers inside strings remain literal. Duplicate
keys, unterminated comments, malformed escapes, multiple top-level values,
unknown control bytes, and the existing byte limit remain rejected.

The JSONC normalizer is private to launch configuration validation. It does
not weaken manifest, lockfile, audit, bundle, or policy JSON decoding.

## Explicit project-only scan

The CLI adds:

```text
ssc-init scan --baseline --project-only --project-root <absolute-or-$HOME-path> --json|--pretty
```

`--project-only` requires at least one explicit `--project-root`. It is
rejected on automatic discovery, hook, status, audit, update, and external
probe forms. The mode configures only the projects collector and the evidence
engine required for its issued targets. It does not read agent, IDE, MCP,
runtime, package-manager installation, shell, credential-helper, or launchd
host catalogs outside the selected roots.

The ordinary `scan --baseline` and explicit-root scan without
`--project-only` keep their existing broad laptop semantics for compatibility.
JSON records the mode in the closed scan scope so a project-only artifact
cannot be confused with a full host audit.

## Project display identity

Project assets remain privacy-safe and never expose absolute paths. Within one
scan, rendering assigns deterministic ordinal aliases after sorting project
asset IDs:

```text
project-1
project-2
```

When a closed manifest parser already provides a safe public package/module
name, the renderer may show that name followed by the ordinal. Raw relative
paths, workspace directory names, hashes, and location references are not
printed. JSON retains canonical asset IDs and does not add host paths.

The alias is presentation-only and is not persisted as identity or used for
delta matching.

## Symlink coverage semantics

Symlinks remain unfollowed. A symlink encountered during a bounded project
walk is reported as `skipped` with `symlink_rejected`; it does not make an
otherwise complete project partial when the symlink itself was not an issued
required evidence target.

A required manifest, lockfile, or launch configuration that resolves to or is
replaced by a symlink remains partial/unavailable. Identity-change and
post-open mutation checks are unchanged. Pretty output reports a count such as
`3 symlinks safely skipped` without printing their names.

## Active TI receipt consistency

Update activity and active intelligence are separate facts. Before every
baseline scan, the CLI reads the verified TI manager status without network
access.

When `--update-ti` is absent and a valid bundle is active, the receipt records:

```text
update      not requested
freshness   fresh|stale
sequence    <active sequence>
digest      <active digest in JSON/archive only>
records     <signed counts>
```

When no valid bundle exists it records `not requested` plus `missing` or
`expired` as appropriate. TI-derived findings and the receipt must reference
the same manager snapshot. The audit state validator gains closed support for
these non-update tuples; it still rejects partial identity tuples and
impossible count combinations.

No status read performs network access. Default scans remain zero-network.

## Limits and privacy

- No repository source code, build hook, package script, or test command is
  executed.
- Existing project walk depth, entry, byte, and target limits are unchanged.
- Project-only mode accepts no arbitrary analyzer configuration or exclusion
  file in this program.
- Absolute paths, relative private paths, source URL queries, raw lockfile
  contents, and opaque evidence IDs remain absent from pretty output and audit
  receipts.
- Archive and JSON output remain ANSI-free.
- Parser permissiveness is format-specific; no global JSON/TOML decoder is
  relaxed.

## Acceptance

Literal fixtures reproduce all corpus findings:

- Cargo checksum strings do not produce obfuscation facts;
- `credentials`, `docker-credential-helpers`, and `go-keychain` dependency
  names do not produce credential-access facts;
- npm SHA-512 and SHA-384 SRI parse with exact digest length and provenance;
- Clap-style local plus registry Cargo duplicates normalize safely;
- conflicting Cargo checksums still fail;
- Vue-style commented launch JSON parses, while duplicate keys and malformed
  comments fail;
- project-only scan invokes only the project collector and cannot read host
  catalogs;
- ordinary explicit-root scan retains prior broad behavior;
- skipped non-required symlinks do not force partial, while required symlinked
  evidence does;
- default zero-network scan records the active sequence and counts used by a
  TI-derived finding;
- repeated project-only runs are byte-stable apart from run/time identifiers;
- full build, vet, race, module, diff, and clean-tree script gates pass.

After implementation, rerun the retained 20-repository corpus. Acceptance
requires zero lockfile/manifest behavior findings, zero malformed errors for
the 12 known-valid lockfiles, Vue launch coverage complete, and no unrelated
host collectors in project-only output. Any remaining project finding must be
manually traced to non-lockfile evidence before it is accepted as signal.
