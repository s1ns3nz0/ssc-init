# Claude handoff — local content evidence core

Date: 2026-08-07 (Asia/Seoul)

## Start here

Continue in the existing isolated worktree. Do not start from `master` and do
not use the older `foundation` worktree.

```sh
cd <repository-root>/.worktrees/local-content-evidence-core
git status --short
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
```

Expected state at handoff:

- repository: `<repository-root>`
- worktree: `<repository-root>/.worktrees/local-content-evidence-core`
- branch: `feature/local-content-evidence-core`
- HEAD before this handoff document commit: `ab504ae3859124227ba9ec394d7ca9974c866d12`
- branch base: `5cc6dca629a40133b22f7b29d3f77846e3e9c1de`
- remote: none configured
- toolchain at handoff: `go1.26.5 darwin/arm64`

Read these files before changing code:

1. `docs/superpowers/specs/2026-08-07-local-content-evidence-core-design.md`
2. `docs/superpowers/plans/2026-08-07-local-content-evidence-core.md`
3. `.superpowers/sdd/2026-08-07-local-content-evidence-core/progress.md`
4. `.superpowers/sdd/2026-08-07-local-content-evidence-core/task-10-report.md`

The active plan is intentionally staged. Tasks 1–10 are complete. Start with
Task 11; do not jump directly to public v3 output.

## Product direction and boundary

`ssc-init` is a lightweight, dependency-minimized, standalone Darwin binary
for developer supply-chain inventory and bounded local content evidence. It is
not an EDR and does not claim a malware verdict or safety guarantee.

This sub-project establishes deterministic local evidence only. TI feeds,
analyzers, organization Git/YAML policy, warnings/blocking, Claude/Codex/Cursor
host adapters, signing/notarization, and behavioral monitoring remain outside
Tasks 1–14. Do not silently widen this branch into those later layers.

Security invariants already implemented and expected to remain true:

- descriptor-rooted/no-follow filesystem access;
- exact, closed target catalogs and explicit byte/tree bounds;
- discovery identity is sealed to evidence identity;
- only complete evidence is trusted as a content digest;
- every accepted target eventually receives a terminal result;
- raw content, secrets, absolute paths, leaf names/lists, link targets,
  fingerprints, anchors, and runtime provenance are not persisted;
- no discovered content is executed and the evidence engine performs no
  process or network access;
- cancellation/deadline errors propagate and clear partial runtime state;
- hostile targets are isolated from safe siblings;
- no new runtime dependency has been added.

## Completed implementation

| Task | Result | Commits |
|---|---|---|
| 1 | Evidence model, status/kind/subject contracts, privacy-safe validation | `de6816a`, `862a39e` |
| 2 | Descriptor-rooted identity and safe references | `eaaa6bd` |
| 3 | Verified bounded file hashing and mutation hooks | `c57505c`, `0d1d661` |
| 4 | Bounded, deterministic, no-follow tree evidence | `345c111`, `1090e54`, `f903640` |
| 5 | Trusted leaf cache, cancellation-safe writes and finalization | `65599e9`, `2953fa4`, `d6cc4c6`, `b2d0c10`, `cfe002e` |
| 6 | Sealed runtime targets, evidence engine, lifecycle and callback bounds | `ff2b1dc`, `82390c9`, `7999ab4`, `2da5e47` |
| 7 | Claude/Codex/Cursor agent plugin/skill manifest, document and payload evidence | `c8b11ab`, `2d21270`, `06de941`, `f38ab55` |
| 8 | VS Code-family and JetBrains manifest, entry-point and payload evidence | `48fa008`, `6759bd6`, `cfde000`, `ca30bfb`, `072a191`, `161ffd4` |
| 9 | Fixed-domain, secret-free MCP semantic evidence | `20ce4f2`, `dbb4b41`, `2ef5513`, `4d66a38`, `4aedadf`, `7e61a39`, `ba84752`, `e0e1904`, `e211903`, `6b1d7fc` |
| 10 | Exact project manifest/lockfile content evidence | `2bf7aca`, `70ba98b`, `1993e58`, `ab504ae` |

Every task above received a separate implementation review. Task 10's final
re-review found no Critical, Important, or Minor issues.

### Task 10 exact scope

The project collector now recognizes only these exact basenames, each capped at
32 MiB:

- manifests: `package.json`, `pyproject.toml`, `Pipfile`,
  `requirements.txt`, `go.mod`, `Cargo.toml`, `Brewfile`;
- lockfiles: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`,
  `yarn.lock`, `bun.lock`, `bun.lockb`, `poetry.lock`, `Pipfile.lock`,
  `uv.lock`, `go.sum`, `Cargo.lock`.

It creates one project asset/observation per discovered project and reuses that
binding for each file. Existing project MCP config assets, observations,
relationships, sealed `LocalTarget` handoff, and downstream MCP collection are
preserved.

Review fixes in `1993e58` are important context:

- cancellation/deadline is propagated at every collection phase and partial
  graph/runtime issuer state is cleared;
- a stat-known oversize file is classified after verified no-follow identity
  checks with zero content reads;
- a file that grows after enumeration is read only to `maxBytes + 1`;
- project evidence, preset and filesystem alike, must bind to collector
  `projects`, `AssetProject`, project scope, matching `ProjectID`, and source
  `projects.root` before filesystem access;
- the full mutation matrix keeps a safe sibling, proves stable evidence IDs,
  and requires exactly one evidence delta.

## Verification state

The following passed at Task 10 completion:

```sh
go test ./internal/collector/projects ./internal/model ./internal/evidence ./internal/inventory ./internal/collector/mcp -count=1
go test ./internal/collector/projects -run 'Cancellation|Deadline|Oversize|Identity|Mutation|RuntimePaths|External|Bounded|ExactCatalog' -count=50
go test ./internal/evidence -run 'Project|Preset' -count=50
go test -race ./internal/collector/projects ./internal/evidence -count=1
go vet ./internal/collector/projects/... ./internal/evidence/... ./internal/model/... ./internal/inventory/...
git diff --check
go test ./scripts -count=1
```

`go test ./... -count=1` was rerun from clean HEAD after Task 10. All packages
except `internal/acceptance` and `internal/cli` passed, including `scripts`.
The remaining failures are expected staged contract failures owned by Tasks
13–14, not Task 10 regressions:

- `internal/acceptance.TestBaselineFixturePersistsWithRealStore` still expects
  the pre-evidence/project-observation v2 fixture shape;
- `internal/cli.TestBaselineJSONReportsPartialCoverageAndPersists` still
  expects inventory JSON without the new evidence field;
- `internal/cli.TestStatusJSONHasStableEmptyV1AndV2Shapes` still expects the
  old v1/v2 nil-evidence shape.

Do not “fix” these by removing evidence fields or project observations. Task 13
owns public scan/status v3 and legacy behavior; Task 14 owns final fixtures and
goldens.

## Required next work

Follow the written plan in this order.

### Task 11 — explicit unsupported package/container identities

Add one path-free sealed preset evidence target for each surviving
`AssetPackage` observation:

- Docker package observations: kind `container-identity`, subject
  `container-image`, target `packages.docker.container-identity`;
- all other package observations: kind and subject `package-content`, target
  `packages.<asset.Source>.content`;
- no new target for `AssetTool` executables.

Prove terminal `unsupported` engine records, partial evidence coverage when
packages exist, no filesystem/runner call during evidence collection, privacy,
and race safety. Preserve existing probe behavior. Commit with
`feat: report unsupported artifact evidence`, write the Task 11 report, then
request an independent read-only review and close every finding.

### Task 12 — snapshot v3, migration 5, SQLite cache

Implement the exact migration/schema in the plan for `evidence`,
`evidence_state`, `evidence_coverage`, and opaque-key `content_cache`. Preserve
nil/order shape, v1/v2 reads, database guard, atomic snapshot rollback, and
cache transaction isolation. The Store should implement `evidence.LeafCache`
and `evidence.CacheWriter`; cache failure must never roll back a saved scan.

### Task 13 — pipeline and public v3 contracts

Wire evidence after graph normalization and before diff/persistence, then do a
best-effort cache write only after `SaveScan`. Clear all runtime targets before
snapshot/report output. Move baseline to `ssc-init.scan.v3`, status to
`ssc-init.status.v3`, expose evidence coverage/inventory evidence, and preserve
truthful legacy v1/v2 reads.

### Task 14 — isolated acceptance and release gates

Build the complete mutation/adversarial fixture matrix, update v3 goldens and
truthful README boundaries, and run the full clean release gate. This task owns
the currently expected acceptance/CLI fixture failures.

### Final branch review

After Task 14, request an independent whole-range review against all design
acceptance criteria. Every finding needs a reproducing failing test before a
fix. Finish only after clean full race/vet/module/diff/migration/acceptance,
Darwin arm64/amd64 build/checksum/smoke, privacy static audits, and an empty
worktree.

## Execution discipline

Continue the existing subagent-driven-development workflow:

1. Use a fresh implementer for each new task and a separate fresh reviewer.
2. Give each implementer explicit file ownership; other work may exist in the
   shared repository, so never revert unrelated edits.
3. Require RED→GREEN TDD evidence and focused/race/vet/diff verification.
4. The controller should not directly edit product code.
5. Send reviewer findings back to the original implementer; add a reproducing
   failing test before each fix. Stop after five fix rounds and escalate rather
   than looping indefinitely.
6. Record commits and verification in
   `.superpowers/sdd/2026-08-07-local-content-evidence-core/progress.md` and a
   task report.
7. Do not mark the overall goal complete before Tasks 11–14 and the final
   whole-branch review are clean.

## Copy/paste continuation prompt for Claude

> Continue the local content evidence core plan from the existing worktree
> `<repository-root>/.worktrees/local-content-evidence-core`, branch
> `feature/local-content-evidence-core`. Read
> `docs/handoff-2026-08-07-local-content-evidence-core.md`, the design, the full
> implementation plan, the SDD ledger, and the Task 10 report before acting.
> Verify the expected HEAD and clean worktree. Tasks 1–10 are complete and Task
> 10's independent re-review is clean. Start Task 11 only, using strict TDD, a
> fresh implementer with explicit ownership, and a separate read-only reviewer.
> Preserve all filesystem/privacy/cancellation invariants and do not repair the
> staged CLI/acceptance v3 fixture failures ahead of Tasks 13–14. Continue
> autonomously through review findings, then update the ledger/report and stop
> at the Task 11 boundary unless I explicitly ask you to continue.
