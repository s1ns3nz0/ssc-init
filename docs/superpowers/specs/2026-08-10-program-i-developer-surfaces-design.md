# Program I — bounded developer surfaces and runtime snapshots

## 1. Purpose

Program I closes the remaining developer-surface inventory gaps in foundation
§4.3 without turning SSC Init into an EDR. It inventories a fixed catalog of
shell startup files, project Git hooks, Git credential-helper declarations,
developer launch configurations and, only with explicit external probes,
one point-in-time process/listener snapshot.

## 2. Execution and privacy boundary

Default scans remain process-free and network-free. File-backed surfaces use
descriptor-rooted, no-follow reads and persist only canonical identity plus
bounded content or semantic digests. Raw shell, hook, launch and Git config
content is never persisted. Credential values, command arguments, environment
values, URLs, process arguments, usernames, hostnames and raw absolute paths
are excluded.

Runtime snapshots require `--external-probes`. They invoke only exact catalog
executables through the bounded runner. They record executable identity,
process ID only as an ephemeral observation discriminator, protocol and local
port. They do not retain command lines, remote endpoints, open files or socket
payloads, and do not continuously monitor anything.

## 3. Closed catalogs

User shell startup catalog:

- `.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`;
- `.config/fish/config.fish`.

Project catalog, restricted to explicitly configured roots and discovered
project directories:

- `.git/hooks/<closed Git hook name>` excluding `*.sample`;
- `.vscode/launch.json`.

Git credential configuration is read from `$HOME/.gitconfig` and
`$HOME/.config/git/config`. Only normalized `credential.helper` command names
are represented; helper arguments and credential sections scoped to URLs are
not retained.

Runtime command catalog:

- `/bin/ps -axo pid=,comm=` for a one-shot process list;
- `/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -Fpcn` for local TCP listeners.

Missing catalog entries are `not_present`; unsupported platforms and disabled
runtime probes are explicit `unsupported`/`skipped`, never silently complete.

## 4. Public model and evidence

Program I advances scan/status contracts to v5 because it adds closed asset
types and runtime snapshot facts. v1–v4 remain readable as legacy without
upgrading claims.

New asset types are `shell-startup`, `git-hook`, `credential-helper`,
`launch-config`, `process` and `listening-endpoint`. File assets receive sealed
file SHA-256 evidence. Git credential configuration receives a secret-free
semantic digest. Runtime assets carry no content-evidence claim; their target
coverage describes the point-in-time probe.

Relationships use the existing closed vocabulary:

- project `contains` Git-hook and launch-config assets;
- process `executes` a canonical executable asset when both endpoints exist;
- listening endpoint `connects-to` its owning process when both endpoints
  exist (the direction is intentionally endpoint → process).

No placeholder endpoint is synthesized to preserve an edge.

## 5. Identity and failure behavior

File-backed asset IDs derive from persistence-safe location references, never
raw paths or content. Credential-helper IDs derive from a normalized helper
basename and fixed source. Runtime process IDs combine the verified executable
identity with the observed PID so concurrent instances remain distinct within
a snapshot; PID reuse across scans is not treated as durable identity.

Each parser is bounded and fail-closed. Unknown Git config syntax, malformed
launch JSON, oversized files, replacement, cancellation and hostile process
output degrade only their target with fixed value-free errors. Safe siblings
remain visible. Output order and duplicate normalization are deterministic.

## 6. Explicit non-goals

- no shell or hook command execution;
- no arbitrary `.git` traversal, Git object reads or repository command;
- no credential lookup, Keychain access or helper invocation;
- no launchd installation (Program H/scheduling);
- no continuous process monitoring, remote connection inventory or packet
  inspection;
- no verdict, warning, enforcement or safety claim.

## 7. Acceptance

Program I is complete when tests prove:

1. every closed file catalog entry is discovered and hashed without following
   symlinks or reading unrelated files;
2. credential helper semantics exclude arguments, URL scopes and secrets;
3. Git hooks and launch configs attach only to canonical project endpoints;
4. default scans invoke no runtime command;
5. opt-in process/listener fixtures normalize only approved facts and edges;
6. malformed, oversized, replaced and hostile siblings fail independently;
7. v4 loads as legacy while v5 round-trips deterministically;
8. reports and snapshots contain no raw content, absolute paths, credentials,
   process arguments, usernames, hostnames or remote endpoints; and
9. race, vet, module, formatting, release-script and repeated adversarial
   gates pass.

## 8. Deferred boundaries

`[TI]`, findings, deep analysis, organization reporting, launchd scheduling,
enforcement and host adapters remain outside Program I. Release distribution
follows the [unsigned reproducible contract](2026-08-10-unsigned-reproducible-distribution-design.md).
