# Program H host boundaries design

## Scope

Program H delivers the host/remediation/scheduling components. The GitHub
distribution channel uses an already-installed `ssc-init` binary. Adapters do
not download, copy, replace, or independently trust a core binary. Release
distribution follows the [unsigned reproducible contract](2026-08-10-unsigned-reproducible-distribution-design.md).

## Safety boundary

- The core alone evaluates findings and policy. An adapter cannot manufacture,
  upgrade, downgrade, or suppress a verdict.
- Every invocation declares one closed host and event, carries only canonical
  identifiers, and returns a versioned structured response.
- Capability is reported per host event as `pre-execution`, `scheduled`,
  `on-demand`, or `advisory`. `enforced` is an action result, never a host
  capability.
- Unknown hosts/events and malformed input fail closed without echoing values.
- Claude, Codex, and Cursor adapters render the same core response. Host copy
  may differ, but verdict, severity, rule IDs, and action must not.
- The first GitHub package is advisory unless a documented native hook supplies
  a deterministic pre-execution blocking contract. Rules or skills alone never
  count as enforcement.

## Adapter packages

`internal/adapter` owns the common v1 request, response, capability manifest,
validation, and deterministic urgent-finding selection. Thin packages under
`adapters/{claude,codex,cursor}` contain native manifests/instructions/hooks and
invoke `ssc-init adapter evaluate --host ...` rather than maintaining state.

The packages contain no binary in the unsigned GitHub channel. They resolve the
managed current binary through the installer-owned layout or a documented
explicit executable path. Automatic download and implicit shell installation
are prohibited.

## Reversible quarantine

Quarantine is an explicit user-approved operation over an exact observation and
complete digest. It uses descriptor-rooted, no-follow operations, copies into a
current-user-only managed directory, removes executable permission from the
quarantined copy, records tokenized original location, digest, mode, and state,
then removes the original only after durable verification. Restore revalidates
the record and refuses overwrite or identity drift. Nothing is automatically
deleted, and advisory findings never trigger quarantine by themselves.

The first tranche may implement record/state contracts and a filesystem seam
before enabling the CLI mutation. Tests must prove symlink, replacement,
collision, cancellation, and concurrent-operation behavior.

## Scheduling

Scheduling is opt-in. A preview always precedes mutation and shows the exact
daily command, calendar interval, tokenized log locations, and removal command.
One stable launchd label is shared by all adapters. Registration is atomic and
idempotent; removal affects only that exact regular plist. On-demand scanning
works without scheduling.

## Delivery order

1. Common adapter contracts and closed capability vocabulary.
2. Deterministic finding presentation and CLI adapter endpoint.
3. Claude/Codex/Cursor package fixtures and contract tests.
4. Exact same-verdict cross-host acceptance.
5. Quarantine contracts/store, then descriptor-rooted quarantine/restore.
6. Launchd preview, registration/removal, and duplicate-host tests.
7. Integrated remediation choices and final gates.

Production marketplace publication and production bundle publication remain
external.
