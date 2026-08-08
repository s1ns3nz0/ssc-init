# Hook severity ladder design

Date: 2026-08-08
Status: approved
Supersedes the output-format section of
`docs/superpowers/specs/2026-08-08-hook-command-design.md`.

## Problem

The shipped hook renders one grouped line per asset per entity type
(`changed  1 evidence records (academic-research-skills)`). On a real machine
that is 16 lines of undifferentiated prose in which a new MCP server and a
cache-metadata echo look identical. The reader cannot triage.

## Non-goal, and the invariant that forbids it

No rung expresses a safety verdict. SSC Init hashes bytes; it performs no
content analysis, so it has no basis for `DANGER`, `BLOCKED`, or any risk
claim, and `README.md` promises exactly that ("no malware verdicts, no safety
guarantees"). Every rung below is a **fact the tool established**: either a
change classification derived from the delta, or an evidence-confidence
statement derived from a terminal status.

## The ladder

One line per asset, highest rung wins, rendered in this order:

| Rung | Means | Derived from |
|---|---|---|
| `NEW` | a surface exists that never existed before | added asset whose `type:host:name` has no removed counterpart |
| `CHANGED` | same version, different bytes | changed evidence/observation attributed to an existing asset |
| `UNVERIFIED` | something moved in a place that cannot be fully verified | added/changed evidence whose current status is not `complete` |
| `UPGRADED` | version moved and bytes moved with it | added+removed asset pair sharing `type:host:name`, **both carrying a version** |
| `REMOVED` | a surface disappeared with no replacement | removed asset with no added counterpart |

Four merge rules follow from "highest rung wins" and are worth stating,
because each one is a place the renderer could otherwise assert more than it
established:

- **A transition needs both endpoints.** `agent-plugin` and `agent-skill` IDs
  append `@<version>` only when a version is known, so a plugin that gains or
  loses the `version` field in its `plugin.json` produces two genuine IDs under
  one identity with one version between them. That is reported as the two
  events it is — `NEW` and `REMOVED` — never as `UPGRADED` with an empty side
  of the arrow.
- **`UNVERIFIED` is never masked by `UPGRADED`.** A plugin whose version moved
  while its payload tree came back `partial` reports `UNVERIFIED`: the version
  bump is the less useful of the two facts, and hiding "the new bytes could not
  be hashed" is exactly the failure the rung exists to prevent. `NEW` still
  outranks it — a surface that did not exist before is the stronger statement.
- **An added asset's own new records make no `CHANGED` claim.** An upgrade
  mints a new asset ID, hence new observation and evidence IDs, so all of the
  asset's records arrive as *added*. `CHANGED` means "same version, different
  bytes", which a new asset ID contradicts, so those records are subsumed by
  the asset-level rung — unless one of them is not `complete`, which still
  raises `UNVERIFIED`.
- **A `REMOVED` row is never merged with a current asset's row.** A removed
  asset is absent from the current inventory, so no current record can belong
  to it. Where its `type:host:name` collides with a current asset's, the two
  are distinct assets and each gets its own line.

Ordering rationale: `NEW` is the actual supply-chain event. `CHANGED`
outranks `UPGRADED` because a byte change under a frozen version number is
tamper-shaped, while a version bump is what an update looks like.
`UNVERIFIED` sits between them — evasion-shaped, but with mundane causes
(a payload crossing the size bound). `REMOVED` is last because it reduces
surface; last is not invisible.

There is deliberately no `DOWNGRADED` rung. Version strings here are
arbitrary text (259 of 314 assets on the reference machine carry no version at
all; formats range from `1.0.0` to `26.805.11740`), so a hand-rolled
comparator would assert direction it cannot justify — the same fiction failure
as `DANGER`. `UPGRADED` prints both strings and lets the reader judge.

## Output

```
ssc-init: 3 changes since last snapshot
  NEW        mcp-server    github (claude-code)
  CHANGED    agent-skill   docx (claude)
  UPGRADED   agent-plugin  superpowers (claude)  6.1.1 → 6.2.0
  11 targets unverified (standing — run: ssc-init status --pretty)
```

- Header carries a deterministic count, so the first line alone answers "how
  bad is this".
- Rung is uppercase and fixed-width: the left edge is a scannable column.
- Asset type is retained — it is the risk-surface tell; an `mcp-server`
  appearing is categorically different from an `agent-skill` appearing.
- Host in parentheses disambiguates the same name under several hosts
  (`superpowers` exists five times on the reference machine).
- Versions appear only on `UPGRADED`, where they carry the meaning.
- Evidence counts are dropped. Subject-level detail lives in `status --pretty`
  and in JSON.
- Cap stays at 20 detail rows plus `…and N more changes`. Because rows sort by
  rung, the cap can never drop a `NEW` to make room for a `REMOVED`.
- Row order is total: rung, then type, name and host, then the asset ID. The
  display columns are not unique — an `ide-extension` name drops the publisher
  its ID keeps, and package rows carry no host — so without the ID tiebreaker
  colliding rows would order by map iteration and the report would not be
  byte-identical run to run, breaking a release-blocking invariant.

### Standing unverified line

Rendered only when drift output is already printing, never alone: a quiet
machine stays completely silent. It converts "here is what changed" into
"here is what changed, and here is how much I still cannot see" for one line.

### First run

With no previous snapshot, every asset is `added`; labelling 314 assets `NEW`
would train the reader to ignore the top rung on day one. A first baseline
prints exactly one line and no rungs:

```
ssc-init: initial baseline recorded — 314 assets, 934 evidence records, 11 unverified
```

"First run" is a fact the scan service holds — `LatestSnapshot` reported no
previous snapshot — and it is plumbed to the renderer as a flag. It is **not**
inferred from the delta. The original inference ("every change is an addition
and the additions cover the whole inventory") is wrong whenever the first
baseline recorded zero assets: on a clean machine the run that finds the first
tool ever installed produces exactly that delta, and the inference swallowed a
genuine `NEW` behind a line claiming to be the initial baseline — the opposite
of the rationale above. Only the absence of a predecessor suppresses the
ladder; a predecessor recording zero assets does not.

An empty delta stays byte-silent either way: silence is decided before the
first-run flag is consulted.

## Required upstream fix: cache provenance must not be a change signal

`internal/inventory/graph.go:245` `canonicalEvidence` marshals the whole
`ContentEvidence`, including `Metadata`, which carries `cache: hit|miss`.
`internal/evidence/session.go:53` persists that outcome, and
`internal/evidence/cache.go` keys the cache on size/mtime/ctime, so any file
that changed **must** miss on the run that first observes it, then hit on the
next. `internal/evidence/tree.go` `noteCache` takes the max rank, so a single
changed leaf drags a whole tree record to `miss`.

Consequence, verified over six runs on an isolated fixture: **every content
change produces a two-run echo, forever** — run N reports the real change, run
N+1 reports the identical record as `changed` with the same digest, run N+2 is
silent. Under a severity ladder that is not cosmetic noise; it prints a
fictional `CHANGED` rung on a permanent schedule.

Fix: exclude cache provenance from `canonicalEvidence`, exactly as
`canonicalAssetForDiff` already excludes `ObservedAt` and
`MetadataObservedAt`. One point of change, fixes JSON, `--pretty`, and the
hook simultaneously. `cache` remains visible on the evidence record for
debugging; it stops being a change signal.

Accepted cost: a cache status flipping `hit`→`rejected` (cached entry
distrusted, file rehashed) also stops producing a delta entry. The rehash
proves the content, and genuine identity violation still surfaces as
`identity_changed` on the record.

This amends `2026-08-08-hook-command-design.md` (which calls the echo
"one-time") and spec §6.1 of the evidence core design (which says diffing
"excludes only explicit observation timestamps"). Both sentences become wrong
and are corrected in the same change.

## Data available to the renderer

`WriteHookSummary(inventory, delta, firstRun)` is a pure function of the
current inventory, the delta, and one boolean the scan service already knows:
whether a previous snapshot existed. No previous inventory is plumbed through.

Carrying `firstRun` widens the internal `BaselineScanner` interface and
`scan.Service.Baseline` by one return value. That is deliberate: it is an
internal Go interface, not a published contract, and the alternative — a field
on `model.ScanResult` or `model.Delta` — would change a serialized, persisted
`ssc-init.scan.v3` shape to carry a renderer hint.

`UNVERIFIED` is therefore approximate: it fires on added/changed evidence
whose current status is not `complete`, which conflates "was complete, now
oversize" (a regression) with "was already oversize, bytes moved". Both reduce
to the same actionable sentence — *something moved in a place I cannot fully
verify* — so the distinction does not earn a contract change. After the cache
fix, standing gaps produce no delta entry at all, so a permanently `oversize`
tree stays silent.

If exact regression detection is ever needed, the honest upgrade path is to
classify the change at diff time in `internal/inventory`, where both
inventories are already in hand, and carry the class on the delta entry.

### Name vocabulary on REMOVED rows

The same missing previous inventory costs one more thing, and it is accepted
rather than papered over. Every other rung describes an asset that is present
in the current inventory, so its NAME column is `asset.Name`. A removed asset
is absent from the current inventory by definition, so its row is built from
its ID — and for two asset types the ID carries a **more qualified name** than
the inventory record does:

| Type | Inventory `Name` | Name recovered from the ID |
|---|---|---|
| `ide-extension` | `errorlens` | `usernamehw.errorlens` |
| `pkg` | `@scope/server` | `npm/%40scope/server` |

An `ide-extension` ID is `publisher.name` (`internal/collector/ide/manifest.go`
sets `Name` to the name alone), and a `pkg` ID is a PURL whose name segment is
`ecosystem/percent-encoded-name` (`internal/collector/packages` clears
`Source`, so the ecosystem survives nowhere else). So the same extension prints
`errorlens` when it is upgraded and `usernamehw.errorlens` when it is removed.

This asymmetry is **known and accepted**, not a defect to normalise in the
renderer. Stripping a `publisher.` prefix by last-dot is unreliable — extension
names legitimately contain dots — and percent-decoding a PURL segment would
reconstruct a name the tool never observed in this snapshot. Either would be an
unearned claim of the same family as `DANGER`: output asserting something the
tool did not establish. A removed row prints what the ID actually says.

The only honest way to remove the asymmetry is to plumb the previous inventory
into the renderer, which the section above declines for the same reason it
declines exact `UNVERIFIED` classification. If that plumbing ever lands, removed
rows should read their names from the previous inventory and this section goes
away.

Note that the asymmetry is invisible whenever an asset is upgraded rather than
removed: the added side is in the inventory and wins the row. It shows up only
on a bare `REMOVED`, and on a removed asset whose identity collides with a
current one (each gets its own line).

## Surfaces

- **`ssc-init hook`** — the ladder, silent when the delta is empty.
- **`scan --baseline --pretty`** — the same renderer replaces the bare
  `DELTA  added=0 changed=12 removed=0` line. The hook's silence rule does not
  propagate: an interactive scan states "no changes" explicitly.
- **`status --pretty`** — unchanged. It reads one snapshot and computes no
  delta, so four of the five rungs are uncomputable there; its `ISSUES` table
  is a standing-coverage report, a different job.
- **JSON** — untouched. It is the machine contract and stays lossless.

## What falls through

Observation-only changes map to `CHANGED` (the tool's recorded description of
an existing asset moved). Evidence or observation changes that cannot be
attributed to any named asset are omitted: an unattributable record yields no
actionable line, and printing `1 evidence records` would launder an
attribution bug into output. A test asserts such orphans do not arise in a
realistic scan; if one ever does, it fails a test rather than decorating the
hook.

The hook is explicitly a triage view, not a lossless one. JSON remains
lossless.
