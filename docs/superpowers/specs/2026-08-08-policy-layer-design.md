# Policy layer design

Date: 2026-08-08
Status: approved

## Problem

SSC Init reports what appeared and what changed. It cannot say whether any of
it is acceptable, and by design it never will — a planted plugin that reads
`~/.ssh/id_rsa` renders as `NEW agent-plugin helpful-utils (claude)`, byte for
byte identical to a benign skill, and its evidence is `complete` because
`complete` means *fully hashed*, not *safe*.

The gap is not detection. It is that the user has expectations the tool cannot
know: *no MCP server should run a shell*, *these plugins must hash to what I
approved*, *nothing new should appear in my agent catalog without me*. A policy
layer lets those expectations be stated, and reports when the machine departs
from them.

## The invariant this must not break

A policy violation expresses **the rule author's judgment, never the tool's**.
SSC Init performs no content analysis, so it has no basis for a risk claim, and
`README.md` promises exactly that. The output therefore says *"this violates a
rule you wrote"* — it names the rule, so any judgment traces back to a human who
made it — and never *"this is dangerous"*.

This has a consequence worth stating plainly in the README so nobody is
misled: **SSC Init ships no out-of-box threat detection, and adding the policy
layer does not change that.** A fresh install reports no violations until rules
are adopted.

## Decisions (settled with the user)

1. **User-declared rules, with shipped templates.** The engine evaluates rules
   the user has declared. We ship templates as packaging, not as opinion.
2. **Templates are inert until adopted.** A rule that fired on a fresh install
   would be *us* asserting risk about content we never analysed. Default-on
   rules would also be tuned against machines we have never seen, misfire, and
   teach the reader to ignore the section — the alert fatigue the severity
   ladder exists to avoid.
3. **Three rule families, content inspection permanently excluded.**
4. **Advisory in the hook, gating in `policy check`.**
5. **`POLICY` is its own section, not a rung.**
6. **Standing violations break the silence rule.**
7. **JSON rule files** with explicit `enabled` flags.
8. **Trust-on-first-use pins with explicit re-approval.**
9. **`pin-mismatch` and `unpinned` are separate, independently enabled rules.**
10. **Evaluation-time only** — nothing about policy enters the snapshot or the
    scan JSON contract.

## Rule families

A rule may only test facts the tool established. Three families qualify.

| Family | Matches on | Example |
|---|---|---|
| **Shape** | recorded asset/observation facts | an `mcp-server` whose `command` is a shell; an MCP declaring an env key matching `*_TOKEN`; an IDE extension whose entry point is `unavailable` |
| **Change** | the severity ladder | any `NEW mcp-server`; any `CHANGED` (same version, different bytes) |
| **Pin** | expected digests | this asset ID must hash to this digest |

**Content inspection is excluded permanently.** No grepping payloads for
`curl`, no scanning for suspicious strings. That requires reading and reasoning
about content the tool deliberately never interprets, would need raw content in
memory and probably persisted, and is a different product — a scanner, not an
inventory.

The limitation this leaves, which the docs must state: shape rules see only
what collectors already record. `sh -c` is catchable because MCP observations
carry `command`/`args`. *"This plugin reads `~/.ssh`"* is **not** catchable,
because nothing in the model knows what the code does. The policy layer narrows
the blind spot; it does not close it.

### Pins

Pins are the strongest family because a mismatch is a hard fact with no
interpretation. They are seeded by trust-on-first-use:

```sh
ssc-init policy pin                     # approve the current state
ssc-init policy pin --update <assetID>  # re-approve after reviewing a change
```

**The TOFU caveat is permanent and must be echoed by the command itself, not
only documented: pinning records whatever is on the machine right now. Pinning
a compromised machine approves the compromise.** A pin protects against future
change, not against what is already there.

`unpinned` and `pin-mismatch` are different signals and separate rules:

- **`pin-mismatch`** — a pinned asset ID hashes differently than approved. The
  asset ID embeds the version, so this means *same plugin, same version,
  different bytes*: the tamper shape. Rare, and almost always worth
  interrupting for. Mechanically restricted to the `CHANGED` shape, so enabling
  it gives a hard version of a signal the ladder already reports softly —
  `CHANGED` says bytes moved, `pin-mismatch` says bytes moved away from what
  you approved.
- **`unpinned`** — an asset has no pin. A legitimate upgrade mints a *new*
  asset ID that simply has no pin yet, so this fires on every install and every
  upgrade until re-pinned. Useful for a locked toolchain, noisy otherwise.

Merged into one rule the noisy case buries the sharp one: a dozen `unpinned`
lines after a routine update batch, with the single `pin-mismatch` that matters
somewhere inside.

## Rule file

Default `$HOME/Library/Application Support/SSC Init/policy.json`, beside the
state database; `--policy <path>` overrides it so a team can commit rules and
run `ssc-init policy check --policy .ssc-policy.json` in CI.

JSON, because the stdlib parses it and the project is already all-JSON. Go's
stdlib has no TOML, and the hand-rolled reader the MCP collector uses for
Codex's `config.toml` was built for a much narrower shape than this schema —
pushing it further would risk a release-blocking invariant ("no new runtime
dependency") or a bespoke grammar to specify and adversarially test.

JSON has no comments, so a template carries its intent in data instead:
`enabled: false` plus a human-readable `description`. Adopting a rule is
flipping a bool, and the description survives parsing rather than being
discarded.

```json
{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [
    { "id": "no-shell-mcp", "enabled": false,
      "description": "An MCP server whose command is a shell runs arbitrary code at session start.",
      "match": { "assetType": "mcp-server", "command": ["sh", "bash", "zsh"] } },
    { "id": "pin-mismatch", "enabled": false,
      "description": "A pinned asset must hash to its approved digest." },
    { "id": "unpinned", "enabled": false,
      "description": "Every agent plugin must be explicitly approved." }
  ],
  "pins": { "agent-plugin:claude:superpowers@6.2.0": "sha256:…" }
}
```

`ssc-init policy init` writes this annotated starter with every rule disabled.

## Surfaces

### `ssc-init hook` — advisory, always exit 0

The advisory contract is unchanged: blocking session start because a plugin
auto-updated would be hostile. Violations render in their own section below the
ladder:

```
ssc-init: 3 changes since last snapshot
  NEW        agent-plugin  helpful-utils (claude)
  NEW        mcp-server    helpful-utils (claude-code)
  CHANGED    ide-extension prettier-vscode (vscode)

POLICY (2 violations)
  no-shell-mcp        mcp-server    helpful-utils (claude-code)
  unpinned            agent-plugin  helpful-utils (claude)
```

A section rather than a rung, for three reasons:

1. **A rung would destroy information.** "Highest rung wins" means one line per
   asset; an asset violating three rules would show one, losing the other rule
   names — and the rule name is the actionable content.
2. **They answer different questions.** The ladder answers "what moved since
   last snapshot". Policy answers "what currently violates my expectations",
   and a violation needs no change at all — a plugin quietly violating
   `no-shell-mcp` for six months has no rung and would be invisible as one.
3. **It keeps the honesty split legible.** Everything above the section is a
   fact the tool established; everything inside it is a claim the user made.

### Silence

Standing violations **do** break the silence rule — the one place policy
departs from `UNVERIFIED`. On an otherwise-quiet machine the hook prints
exactly one line:

```
ssc-init: 2 policy violations standing (run: ssc-init policy check)
```

Newly-violating assets get detail lines; standing ones collapse to that count.
The principle: a coverage gap is the tool admitting what it *cannot* do, and
nagging about a 240 MB extension teaches the reader to ignore the hook. A
violation is the tool reporting what the user said *should not be* — a to-do,
not a boundary. Suppressing it would make silence a lie: "nothing changed"
would read as "nothing to do" while a rule is being violated.

Accepted cost: a machine with a standing violation is never fully silent again
until the state is fixed or the rule amended. That pressure is deliberate, and
both escapes are in the user's hands.

### `ssc-init policy check` — gates, exits nonzero

Same engine, different exit-code policy, for CI, pre-commit, or a deliberate
manual gate — contexts where a nonzero exit is a normal outcome rather than an
emergency. Lists every violation, standing and new.

**It reads the latest snapshot and does not scan.** No filesystem access, so
adopting a rule and seeing what it would flag against yesterday's inventory is
instant and safe to experiment with, and CI can evaluate a committed snapshot
without touching a developer machine.

### `scan --baseline --json` — unchanged

Nothing about policy enters the snapshot, the database, or `ssc-init.scan.v3`.
The snapshot records what is on the machine; rules are a question asked of
those facts, and they change independently — editing `policy.json` must not
invalidate a snapshot, and two people with different rules must be able to
evaluate the same snapshot differently. Baking violations into the persisted
record would conflate observation with judgment.

Machine consumers lose nothing: every fact a rule matches on is already in the
scan JSON, so a pipeline can run `policy check --json` or evaluate the same
predicates itself.

Documented consequence: the hook renders violations that are not in the JSON.
JSON is the record of facts; the hook is a triage view over facts **plus** the
user's rules.

## Implementation shape

- `internal/policy` — new package. Rule schema, parsing with precise error
  reporting, and evaluation against `(model.Inventory, model.Delta)`. Pure: no
  I/O beyond reading the rule file, no filesystem access during evaluation.
- `internal/report` — renders the `POLICY` section and the standing-count line;
  reuses the existing row formatter.
- `internal/cli` — `policy init`, `policy pin`, `policy check`; `hook` gains
  policy evaluation between scan and render.
- No new runtime dependency. No store or scan changes. No schema change.

## Non-goals

- No content inspection, ever.
- No shipped rule that is enabled by default.
- No severity ranking *between* rules — a violation is a violation; the user
  decides what matters by choosing what to enable.
- No auto-remediation. The tool never removes, quarantines, or modifies a
  discovered asset.
- No policy state in the snapshot.
