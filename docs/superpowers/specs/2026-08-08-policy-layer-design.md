# Policy layer design

Date: 2026-08-08
Status: approved (supersedes the first draft of this file, which designed a
local-only policy layer and contradicted §8/§9 of the foundation design)

**Authority:** `docs/superpowers/specs/2026-08-05-ssc-init-design.md` §8
(Organization policy) and §9 (Enforcement, feedback, and remediation) define
this feature. This document is the implementation design for that target, not a
new proposal. Where the two disagree, the foundation design wins.

## Readiness legend

Every element below is marked with what it depends on. The full architecture is
designed now so that the current build is an honest *subset* of it rather than
a contradiction to be retrofitted later.

| Mark | Meaning |
|---|---|
| **[NOW]** | Buildable against facts the current build already establishes (identity, version, hash, MCP command/args/env-key names, entry points, evidence status, ladder rungs) |
| **[BUNDLE]** | Needs the Git→CI→signed-bundle pipeline; no new detection capability required |
| **[TI]** | Needs the threat-intelligence manager and/or analyzers that do not exist yet |
| **[HOST]** | Needs host adapters capable of pre-execution enforcement |

The correction that produced this document: *"no verdicts, never blocks"* is a
description of what the **current build** can support, not a product principle.
The foundation design has verdicts (§7.3), automatic blocking (§9.1), and
reversible quarantine (§9.4). Designing those away would foreclose the product.

## 1. Precedence

Foundation §8. Evaluated in this order; the first level that decides, decides.

| # | Level | Override | Mark |
|---|---|---|---|
| 1 | Known malicious evidence | **cannot be overridden by anyone** | **[TI]** |
| 2 | Organization deny | **users cannot override locally** | **[BUNDLE]** — matching is [NOW] |
| 3 | Organization allow | invalidated by artifact hash change | **[BUNDLE]** — invalidation is [NOW] |
| 4 | Time- and scope-bound user exceptions, where organization policy permits | expire | **[NOW]** |
| 5 | Default product policy | user-configurable | **[NOW]** |

Level 1 exists in the engine from day one and evaluates to *"no evidence
available"* until the TI manager ships. It is not designed out and added back;
it is present and inert, so nothing above it can be silently reordered later.

Level 3's invalidation rule is important and buildable today: an organization
*allow* is bound to an artifact hash, so the moment the bytes change the allow
stops applying. That is precisely the `pin-mismatch` mechanic below, reused.

## 2. Policy source of truth

Foundation §8. **[BUNDLE]**

- Git-managed YAML is the source of truth. Pull requests provide review and
  audit history.
- CI validates JSON Schema, duplicate keys, conflicts, exception expiry, and
  policy test cases; then compiles deterministic JSON and signs a versioned
  release bundle.
- **Local SQLite is only a verified-policy index and audit cache, never the
  source of truth.** A tampered local database is rebuildable from the signed
  bundle — so local modification is a recoverable event, not a policy change.
- Bundle activation follows the same stage → verify → health check → atomic
  switch → rollback discipline as core and TI updates (foundation §11); the
  last known-good bundle stays active on any checksum, signature, schema, or
  migration failure.

### Local-only mode **[NOW]**

Without a bundle, only levels 4 and 5 exist: user exceptions and default
product policy, from
`$HOME/Library/Application Support/SSC Init/policy.json`, with `--policy <path>`
so an individual or team can version-control it. This is the mode the current
build can ship.

A local file **cannot** express levels 2 or 3. Organization deny is
unoverridable precisely because it does not come from a file the user can edit;
letting a local file claim that authority would make the precedence a lie.
`policy check` states which levels are active, so an unsigned local-only setup
never appears to be enforcing organization policy.

## 3. Rules

A rule may only test facts the tool established. Content inspection is excluded
until analyzers exist **[TI]**; nothing in the current model knows what code
*does*, so *"this plugin reads `~/.ssh`"* is not expressible, while *"this MCP
server's command is a shell"* is.

| Family | Matches on | Mark |
|---|---|---|
| **Shape** | recorded asset/observation facts — asset type, host, name, version, MCP `command`/`args`/`env_keys`/transport, IDE entry points, evidence status | **[NOW]** |
| **Change** | severity-ladder rungs — `NEW`, `CHANGED`, `UPGRADED`, `REMOVED`, `UNVERIFIED` | **[NOW]** |
| **Pin** | expected digests per asset ID | **[NOW]** |
| **Behavioral** | analyzer output — obfuscation, dynamic execution, credential-access flows, dangerous APIs | **[TI]** |

Two shape rules the foundation design names explicitly as blocked by default
under organization policy (§6.3): `latest`/unspecified versions and mutable Git
branches; and direct remote-script execution (`curl … | sh`). Both are
expressible **[NOW]** from recorded command and version facts.

### Pins **[NOW]**

`pin-mismatch` — a pinned asset ID hashes differently than approved. Because the
ID embeds the version, this means *same asset, same version, different bytes*:
the tamper shape. It is also the mechanism behind precedence level 3.

`unpinned` — an asset has no pin. A legitimate upgrade mints a new ID with no
pin, so this fires on every install and upgrade until re-approved.

They are separate, independently enabled rules. Merged, the noisy one buries
the sharp one — a dozen `unpinned` lines after a routine update batch, with the
single `pin-mismatch` that matters somewhere inside.

Pins are seeded trust-on-first-use (`ssc-init policy pin`) and re-approved
explicitly (`policy pin --update <assetID>`). **The command itself must state
the caveat, not only the docs: pinning records whatever is on the machine right
now, so pinning a compromised machine approves the compromise.** A pin protects
against future change, not against what is already there. Under an organization
bundle, pins are authored in the bundle and TOFU is unavailable — level 3 is not
something a local machine may self-grant.

### Default product policy **[NOW]**

Shipped rules are **inert until adopted**: present in the file with
`enabled: false` and a human-readable `description`. A rule firing on a fresh
install would be *us* asserting risk about content we never analysed, and would
be tuned against machines we have never seen — misfiring and teaching the reader
to ignore the section.

This applies to level 5 only. Organization deny (level 2) is **not** opt-in;
that is the point of it.

JSON, because the stdlib parses it and the project is already all-JSON. Go's
stdlib has no YAML or TOML, and the narrow reader the MCP collector uses for
Codex's `config.toml` was built for a far simpler shape — extending it would
risk the release-blocking "no new runtime dependency" invariant. The bundle
pipeline authors YAML **[BUNDLE]** and compiles to this JSON, so YAML never
needs parsing on the client.

## 4. Exceptions

Foundation §9.3. **[NOW]** for the model and enforcement of limits; **[BUNDLE]**
for organization-approved scopes.

Scope is limited to a run, an exact asset/version/hash, a project, or an
organization-approved scope.

- Project exceptions expire within **30 days** by default.
- Organization exceptions require **approver, reason, ticket, and expiry**, with
  **90 days** as the default maximum.

**Prohibited, and the engine must refuse to load a policy containing them:**

- publisher-wide permanent trust;
- all-version trust;
- disabling a high-risk rule globally;
- any exception for a known-malicious hash.

These are structural refusals, not warnings. An exception file expressing one is
a policy error, reported precisely by `policy check` and rejected at load — the
same way CI rejects it before a bundle is ever signed.

Expiry is evaluated at decision time, so an expired exception simply stops
applying; it is never silently renewed.

## 5. Enforcement

Foundation §9.1. Host capability is declared, never assumed:
**pre-execution**, **scheduled detection**, **on-demand**, **advisory**, or
**enforced**.

| Behaviour | Requires |
|---|---|
| Known-malicious and organization-denied assets are automatically blocked | **[TI]** + **[HOST]** for pre-execution; **[BUNDLE]** + **[HOST]** for deny |
| High-confidence but uncertain findings pause execution and request informed approval | **[HOST]** |
| External changes that could not be intercepted are detected on the next scan and produce remediation guidance | **[NOW]** |
| Reversible quarantine — removes execute permission, preserves path/hash/permissions, current-user-only, never auto-deletes | **[TI]** to justify, mechanism is **[NOW]** |

**The current build's honest capability is `advisory` plus `on-demand`.** It has
no execution interception and no host adapters, so it cannot block anything. It
must therefore *report* `advisory` — foundation §5.1 requires that an adapter
"never claims enforcement when only advisory scanning is possible", and the same
obligation applies to the core.

`ssc-init policy check` exiting nonzero **[NOW]** is a gate for CI, pre-commit,
and deliberate manual use. That is genuine enforcement *of a pipeline*, and it
is the only enforcement available today. It is not pre-execution blocking and
must not be described as such.

## 6. Surfaces

### `ssc-init hook` — advisory, always exit 0 **[NOW]**

Blocking session start because a plugin auto-updated would be hostile, and the
advisory contract is locked and tested. Violations render in their own section
below the severity ladder:

```
ssc-init: 3 changes since last snapshot
  NEW        agent-plugin  helpful-utils (claude)
  NEW        mcp-server    helpful-utils (claude-code)
  CHANGED    ide-extension prettier-vscode (vscode)

POLICY (2 violations)
  no-shell-mcp        mcp-server    helpful-utils (claude-code)
  unpinned            agent-plugin  helpful-utils (claude)
```

A section, not a rung, because: a rung would collapse an asset's multiple
violations into one line and lose the rule names, which are the actionable
content; the ladder answers *what moved* while policy answers *what violates my
expectations*, and a violation needs no change at all (a plugin quietly
violating a rule for six months has no rung and would be invisible); and the
split keeps facts the tool established visually separate from claims the policy
author made.

Once enforcement exists **[HOST]**, a blocked asset is reported here too, with
its decision level named — the hook reports the block; it does not perform it.

### Silence **[NOW]**

Standing violations **do** break the silence rule — the one place policy departs
from `UNVERIFIED`. A quiet machine prints exactly one line:

```
ssc-init: 2 policy violations standing (run: ssc-init policy check)
```

New violations get detail lines; standing ones collapse to that count. A
coverage gap is the tool admitting what it *cannot* do, and nagging teaches the
reader to ignore the hook. A violation is the tool reporting what the user or
their organization said *should not be* — a to-do, not a boundary. Suppressing
it would make silence a lie.

### `ssc-init policy check` — gates, exits nonzero **[NOW]**

Same engine, different exit-code policy. Lists every violation, standing and
new, and states which precedence levels are active and which are inert.

**It reads the latest snapshot and does not scan** — it opens only the policy
document and the store, and touches no collector root, no discovered asset, and
no path outside its own state directory — so
adopting a rule and seeing what it would flag against yesterday's inventory is
instant, and CI can evaluate a committed snapshot without touching a developer's
machine.

### `scan --baseline --json` — unchanged **[NOW]**

Nothing about policy enters the snapshot, the database, or `ssc-init.scan.v3`.
The snapshot records what is on the machine; policy is a question asked of those
facts, and the two change independently — editing policy must not invalidate a
snapshot, and two people with different policy must be able to evaluate the same
snapshot differently.

The audit cache (§8: local SQLite as verified-policy index and audit history) is
a **separate** store from the inventory snapshot, for decisions, exception
expiry, and audit trail. It is not part of the scan contract.

### Organization reporting **[BUNDLE]**

Foundation §8: signed policy bundles, SARIF 2.1.0, CycloneDX, Finding JSON,
HTTPS webhooks, and CLI exit codes. Outbound findings carry an opaque device
identity, asset type and canonical identifier, version/hash, severity, rule
identifiers, detection time, and action status — and **exclude** source code,
secret values, raw environment variables, personal paths, project/repository
names, and raw matched data by default. That exclusion list is the existing
privacy invariant restated for a new egress path, and it is release-blocking.

## 7. Implementation shape

- `internal/policy` — rule schema, load-time validation (including structural
  refusal of prohibited exceptions), and evaluation against
  `(model.Inventory, model.Delta)` plus pins/exceptions. Pure: no filesystem
  access during evaluation. **[NOW]**
- `internal/policy/bundle` — signature and schema verification, staging, atomic
  activation, rollback, freshness. **[BUNDLE]**
- `internal/report` — `POLICY` section and standing-count line, reusing the
  existing rung row formatter. **[NOW]**
- `internal/cli` — `policy init`, `policy pin`, `policy check`; `hook` evaluates
  policy between scan and render. **[NOW]**
- Audit store — decisions, exceptions, expiry, history; separate from the
  inventory snapshot. **[NOW]** for the local subset.
- No new runtime dependency. No scan schema change.

## 8. Non-goals

- No content inspection until analyzers exist; no heuristic that guesses what
  code does.
- No shipped rule enabled by default at level 5.
- No auto-deletion. Quarantine is reversible and preserves the original path,
  hash, and permissions.
- No claim of enforcement while the host is advisory-only.
- No central organization database or commercial control plane (foundation §3);
  organization integration is signed bundles plus standard report formats.
- No policy state in the inventory snapshot.
