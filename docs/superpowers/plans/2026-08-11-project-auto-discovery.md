# Project Auto-Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover `$HOME`-local projects from bounded VS Code-family, JetBrains, and Git linked-worktree metadata before scan scope is fixed, while explicit `--project-root` remains an exact override.

**Architecture:** Add a pure, bounded discovery prepass inside `internal/collector/projects`. Host-specific parsers yield ephemeral candidate paths; descriptor-rooted validators canonicalize, deduplicate, minimize, cap, and seal them into existing `Root` values. Command construction runs the prepass only when no explicit roots were supplied and passes its privacy-safe coverage into the unchanged project inventory owner.

**Tech Stack:** Go 1.26 standard library (`encoding/json`, `encoding/xml`, `net/url`) and existing descriptor-rooted filesystem abstractions; no new dependency, process, socket, schema, or CLI flag.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-11-project-auto-discovery-design.md` exactly.
- Explicit `--project-root` disables every automatic metadata read.
- Only verified directories strictly below `$HOME` may become automatic roots; reject `Library`, media, caches, backups, Trash, external volumes, remote URIs, and symlinks.
- Discovery finishes before `model.ScanScope.ProjectRoots` is constructed.
- Never persist or report raw paths, URIs, workspace IDs, repository/worktree IDs, product directory names, or metadata content.
- Default discovery executes no process and opens no socket; cancellation persists nothing.
- Deterministic input yields byte-identical roots, scope, coverage, inventory, reports, and snapshots.

---

## File responsibility map

- `internal/collector/projects/discovery.go`: public `Discovery`, source orchestration, candidate aggregation, root minimization and sealing.
- `internal/collector/projects/discovery_vscode.go`: unique-key bounded VS Code-family `workspace.json` parser.
- `internal/collector/projects/discovery_jetbrains.go`: bounded strict recent-project XML parser.
- `internal/collector/projects/discovery_fs.go`: descriptor-rooted source enumeration, candidate validation, metadata-only repository walk.
- `internal/collector/projects/discovery_git.go`: `.git` administration parsing and reciprocal linked-worktree validation.
- `internal/collector/projects/discovery_test.go`: aggregation, validation, privacy, bounds and cancellation.
- `internal/collector/projects/discovery_parsers_test.go`: host parser grammar tests.
- `internal/collector/projects/discovery_git_test.go`: Git reciprocity and stale/forged metadata tests.
- `internal/collector/projects/collector.go`: accept and prepend discovery coverage without changing project ownership.
- `cmd/ssc-init/main.go`: explicit-vs-automatic configuration and pre-scan scope construction.
- `cmd/ssc-init/main_test.go`: override, no-process, fixed-scope and failure behavior.
- `internal/acceptance/program_d_test.go`: isolated-home end-to-end privacy and determinism.
- `README.md`, `CLAUDE.md`, `docs/testing/2026-08-09-foundation-completion-audit.md`: current capability truth.

### Task 1: Closed host metadata parsers

**Files:**
- Create: `internal/collector/projects/discovery_vscode.go`
- Create: `internal/collector/projects/discovery_jetbrains.go`
- Create: `internal/collector/projects/discovery_parsers_test.go`

**Interfaces:**
- Produces: `parseVSCodeWorkspace([]byte) (string, candidateKind, error)` and `parseJetBrainsRecent([]byte) ([]string, error)`.
- Produces closed `candidateKind`: `candidateFolder` or `candidateWorkspaceFile`.
- Errors are package-private fixed sentinels `errMetadataMalformed` and `errRemoteUnsupported`.

- [ ] **Step 1: Write failing VS Code-family parser tests**

Cover one canonical `file:///Users/example/project` folder, percent-decoding,
one local `.code-workspace` URI, duplicate JSON keys, trailing JSON, authority,
userinfo, query, fragment, `vscode-remote`, `vscode-vfs`, HTTP, relative and
NUL/control values. The test must assert returned errors only by sentinel and
must prove no input value appears in `err.Error()`.

- [ ] **Step 2: Run VS Code parser RED**

Run: `go test ./internal/collector/projects -run TestParseVSCodeWorkspace -count=1`

Expected: FAIL because the parser and candidate kind do not exist.

- [ ] **Step 3: Implement strict unique-key JSON parsing**

Decode exactly one object with either `folder` or `workspace`, never both.
Reuse or locally implement token-based duplicate-key rejection. Parse with
`url.Parse`, require scheme `file`, empty host/user/query/fragment, valid UTF-8,
and a canonical absolute decoded path. Return the workspace-file kind without
opening that file.

- [ ] **Step 4: Write failing JetBrains XML parser tests**

Cover the exact accepted hierarchy, `$USER_HOME$`, `~`, multiple values,
unrelated component/options, relative paths, URLs, unknown variables, DTD,
directive/entity/processing instruction, wrong nesting, more than 4,096
tokens, and deterministic source-order output.

- [ ] **Step 5: Run JetBrains parser RED**

Run: `go test ./internal/collector/projects -run TestParseJetBrainsRecent -count=1`

Expected: FAIL because the XML parser does not exist.

- [ ] **Step 6: Implement bounded streaming XML parser**

Use `xml.Decoder.Token` and an explicit state machine for only:

```text
application/component[@name=RecentProjectsManager|RecentDirectoryProjectsManager]
  /option[@name=recentPaths]/list/option[@value]
```

Reject directives and processing instructions, cap tokens at 4,096, and emit
only copied path strings. Do not resolve paths in the parser.

- [ ] **Step 7: Run GREEN and commit**

```sh
go test ./internal/collector/projects -run 'TestParseVSCodeWorkspace|TestParseJetBrainsRecent' -count=1
git add internal/collector/projects/discovery_vscode.go internal/collector/projects/discovery_jetbrains.go internal/collector/projects/discovery_parsers_test.go
git commit -m "feat: parse project discovery metadata"
```

### Task 2: Candidate validation and deterministic aggregation

**Files:**
- Create: `internal/collector/projects/discovery.go`
- Create: `internal/collector/projects/discovery_test.go`
- Modify: `internal/collector/projects/collector.go`

**Interfaces:**
- Produces:

```go
type Discovery struct {
    Roots []Root
    Coverage []model.TargetCoverage
}

type discoveryCandidate struct {
    path string
    source string
    priority int
}
```

- Produces `finalizeDiscoveredRoots(home string, fs platform.FileSystem, candidates []discoveryCandidate) (Discovery, error)`.
- Consumes existing `Root`, `sealRoot`, `maxConfiguredRoots`, and `validateResolvedRoots`.

- [ ] **Step 1: Write failing candidate tests**

Test canonical HOME path acceptance, `$HOME` rejection, outside-home,
`Library`, `.Trash`, Downloads media fixture, caches/backups, relative/NUL,
symlink, non-directory, missing directory, identity replacement, same-inode
deduplication, parent-child minimization, source priority, lexicographic tie,
and 32-root cap. Assertions must inspect only `$HOME/...` refs and fixed error
codes; JSON-encode the result and reject every raw absolute marker.

- [ ] **Step 2: Run RED**

Run: `go test ./internal/collector/projects -run 'TestFinalizeDiscoveredRoots|TestDiscoveryCandidate' -count=1`

Expected: FAIL because aggregation does not exist.

- [ ] **Step 3: Implement validation and minimization**

Require `platform.NoFollowFileSystem` and `platform.RootedFileSystem`. Perform
Lstat → rooted open → identity comparison → locality check when available →
final identity recheck. Normalize sources to the five closed target IDs.
Keep `$HOME/Projects` first, minimize nested roots, sort by priority/ref, cap at
32, and add fixed `root_limit` coverage without candidate values.

- [ ] **Step 4: Add collector coverage constructor**

Add:

```go
func NewWithDiscovery(roots []Root, coverage []model.TargetCoverage) collector.TargetedCollector
```

`New` delegates with nil coverage. `projectCollector.Collect` prepends a deep
copy of discovery target coverage and derives overall partial status when any
discovery target is partial/unavailable, without changing assets or ownership.

- [ ] **Step 5: Run GREEN, mutation and commit**

Temporarily remove strict HOME containment and prove the outside-home test
fails; restore it.

```sh
go test -race ./internal/collector/projects -run 'TestFinalizeDiscoveredRoots|TestDiscoveryCoverage' -count=1
git add internal/collector/projects/discovery.go internal/collector/projects/discovery_test.go internal/collector/projects/collector.go
git commit -m "feat: validate discovered project roots"
```

### Task 3: Descriptor-rooted IDE source discovery

**Files:**
- Create: `internal/collector/projects/discovery_fs.go`
- Modify: `internal/collector/projects/discovery.go`
- Modify: `internal/collector/projects/discovery_test.go`

**Interfaces:**
- Produces `discoverIDERoots(ctx context.Context, env collector.Environment) ([]discoveryCandidate, []model.TargetCoverage, error)`.
- Consumes Task 1 parsers and Task 2 finalization.
- Source limits: 256 workspace children, 64 KiB JSON; 32 JetBrains products, 256 KiB XML.

- [ ] **Step 1: Write failing VS Code-family filesystem tests**

Use rooted test filesystems for Code, Cursor and Windsurf. Cover absent source,
valid sorted children, workspace-file parent conversion, 257-child cap,
oversize, malformed sibling isolation, source/file symlink, source/file
replacement, cancellation, and no raw path/workspace hash in coverage.

- [ ] **Step 2: Write failing JetBrains filesystem tests**

Cover sorted product dirs, exact options path, 33-product cap, oversize,
malformed product isolation, symlink/replacement, and `$USER_HOME$` resolution.

- [ ] **Step 3: Run RED**

Run: `go test ./internal/collector/projects -run 'TestDiscoverVSCode|TestDiscoverJetBrains' -count=1`

Expected: FAIL because source discovery does not exist.

- [ ] **Step 4: Implement bounded rooted enumeration**

Open every fixed source component with `OpenVerifiedRoot`. Enumerate with
`OpenVerifiedDirectory` in sorted bounded batches. Open only the exact target
file with `OpenVerifiedFile`, read `limit+1` through a context-aware reader,
parse, then compare file and source identities after parsing. Clear byte/path
buffers on every return path.

- [ ] **Step 5: Run GREEN and commit**

```sh
go test -race ./internal/collector/projects -run 'TestDiscoverVSCode|TestDiscoverJetBrains' -count=1
git add internal/collector/projects/discovery_fs.go internal/collector/projects/discovery.go internal/collector/projects/discovery_test.go
git commit -m "feat: discover ide project roots"
```

### Task 4: Git linked-worktree discovery

**Files:**
- Create: `internal/collector/projects/discovery_git.go`
- Create: `internal/collector/projects/discovery_git_test.go`
- Modify: `internal/collector/projects/discovery_fs.go`
- Modify: `internal/collector/projects/discovery.go`

**Interfaces:**
- Produces `discoverGitWorktrees(ctx context.Context, env collector.Environment, seeds []discoveryCandidate) ([]discoveryCandidate, model.TargetCoverage, error)`.
- Metadata walk limits: depth 12, 100,000 entries, sorted batches of 256, existing excluded directories.
- Worktree limits: 64 admin children per repository and 4 KiB per `gitdir`/`.git` file.

- [ ] **Step 1: Write failing metadata-walk tests**

Cover a main repository below `$HOME/Projects`, an exact IDE candidate repo,
nested excluded/build directories, depth/entry limits, cancellation, symlinked
`.git`, and stopping descent at a repository root.

- [ ] **Step 2: Write failing reciprocity tests**

Create real fixture pairs:

```text
main/.git/worktrees/feature/gitdir -> $HOME/work/feature/.git
$HOME/work/feature/.git           -> main/.git/worktrees/feature
```

Cover valid reciprocal candidate, stale missing target, outside-home target,
noncanonical path, missing `/.git` suffix, mismatched backlink, symlinked admin
entry, oversize, 65-entry cap, linked-repo seed, and fixed privacy-safe errors.

- [ ] **Step 3: Run RED**

Run: `go test ./internal/collector/projects -run 'TestDiscoverGit|TestGitWorktree' -count=1`

Expected: FAIL because Git discovery does not exist.

- [ ] **Step 4: Implement metadata-only walk and reciprocal validation**

Reuse bounded directory helpers rather than `filepath.WalkDir`. Never invoke
Git. Open `.git` as either a verified directory or verified regular file,
parse one trimmed absolute path, validate both directions by exact canonical
path and file identity, and emit only the linked working directory candidate.

- [ ] **Step 5: Run mutation, GREEN and commit**

Temporarily remove reciprocal comparison and prove the forged-backlink test
fails; restore it.

```sh
go test -race ./internal/collector/projects -run 'TestDiscoverGit|TestGitWorktree' -count=1
git add internal/collector/projects/discovery_git.go internal/collector/projects/discovery_git_test.go internal/collector/projects/discovery_fs.go internal/collector/projects/discovery.go
git commit -m "feat: discover git linked worktrees"
```

### Task 5: Public discovery orchestration

**Files:**
- Modify: `internal/collector/projects/discovery.go`
- Modify: `internal/collector/projects/discovery_test.go`

**Interfaces:**
- Produces `DiscoverRoots(ctx context.Context, env collector.Environment) (Discovery, error)` exactly as specified.
- Consumes IDE discovery, Git discovery, and finalization from Tasks 2–4.

- [ ] **Step 1: Write failing orchestration test**

Build an isolated home containing `$HOME/Projects`, one Code candidate, one
JetBrains candidate, and one linked worktree. Assert finalized root refs,
nesting minimization, five closed discovery targets in deterministic order,
and stable repeated JSON. Add safe-sibling failure and cancellation cases.

- [ ] **Step 2: Run RED**

Run: `go test ./internal/collector/projects -run TestDiscoverRoots -count=1`

Expected: FAIL because the public orchestrator is absent.

- [ ] **Step 3: Implement orchestration**

Create the conventional `$HOME/Projects` placeholder through the existing
resolver even when absent; do not send a missing placeholder through discovered
candidate validation. Discover IDE candidates, pass the existing conventional
seed and verified IDE candidates to Git discovery, combine coverage, finalize
the discovered candidates once, merge the placeholder, clear ephemeral
candidates with `defer`, and return caller cancellation without partial roots.

- [ ] **Step 4: Run GREEN and package regression**

```sh
go test -race ./internal/collector/projects -count=1
git diff --check
```

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add internal/collector/projects/discovery.go internal/collector/projects/discovery_test.go
git commit -m "feat: orchestrate project auto discovery"
```

### Task 6: Command and scan-scope integration

**Files:**
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`

**Interfaces:**
- Adds injectable `discoverRootsForRun = projects.DiscoverRoots`.
- Changes `scanConfiguration` to accept `context.Context` and return the same environment/collector outputs.
- Explicit options call only `ResolveRoots`; empty options call only `DiscoverRoots`.

- [ ] **Step 1: Write failing explicit-override test**

Inject a discovery function that fatals if called, provide one explicit root,
and assert scope/collector behavior remains unchanged.

- [ ] **Step 2: Write failing automatic-discovery test**

Inject deterministic discovery roots/coverage and assert they appear in scope
before service construction and in project coverage. Assert the configured
runner receives zero calls and cancellation returns operational failure without
opening the store.

- [ ] **Step 3: Run RED**

Run: `go test ./cmd/ssc-init -run 'TestScanConfiguration.*Discovery|TestScanExplicitRoot' -count=1`

Expected: FAIL because scan configuration always resolves conventional roots.

- [ ] **Step 4: Implement context-aware branch**

Construct a base `collector.Environment` with Home/Platform/FS/Runner/Now,
perform explicit resolution or automatic discovery, then set the final scope
and construct `projects.New` or `projects.NewWithDiscovery`. Preserve external
probe setup and all other collector ordering.

- [ ] **Step 5: Run GREEN, regressions and commit**

```sh
go test -race ./cmd/ssc-init ./internal/cli ./internal/scan -count=1
git add cmd/ssc-init/main.go cmd/ssc-init/main_test.go
git commit -m "feat: enable automatic project discovery"
```

### Task 7: Acceptance, documentation, mutation gates and release gates

**Files:**
- Modify: `internal/acceptance/program_d_test.go`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/testing/2026-08-09-foundation-completion-audit.md`

**Interfaces:**
- Consumes the completed automatic discovery path.
- Produces end-to-end privacy/determinism evidence and current documentation.

- [ ] **Step 1: Add isolated-home acceptance**

Create Code, Cursor, Windsurf, JetBrains, main Git and linked-worktree fixtures
with unique private path/URI/workspace/worktree markers. Run automatic scan and
assert recognized projects from every source, fixed final scope, zero process
calls, expected discovery coverage, real-store reload, and absence of every
private marker from report/snapshot JSON.

- [ ] **Step 2: Prove explicit override and test sensitivity**

Run the same home with an explicit root and assert no metadata-source path is
opened and no automatic project appears. Temporarily remove the empty-options
discovery branch and prove the automatic acceptance fails; restore it.

- [ ] **Step 3: Run adversarial mutation battery**

Verify focused tests fail independently when temporarily applying each
mutation, then restore:

1. allow candidates outside `$HOME`;
2. follow a metadata symlink;
3. remove Git reciprocity validation;
4. retain a raw workspace URI in coverage;
5. call discovery despite an explicit root;
6. construct scope before discovered roots are finalized.

- [ ] **Step 4: Update current documentation**

Document automatic sources, explicit override, HOME-only/privacy boundaries,
and no-process behavior. Narrow the completion-audit collector gap from recent
workspace discovery to broader ecosystems only; keep deep analysis and
enforcement gaps truthful.

- [ ] **Step 5: Run full gates and commit**

```sh
gofmt -w internal/collector/projects/*.go cmd/ssc-init/*.go internal/acceptance/program_d_test.go
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
```

Expected: all PASS and `go.mod`/`go.sum` unchanged.

```sh
git add internal/acceptance/program_d_test.go README.md CLAUDE.md docs/testing/2026-08-09-foundation-completion-audit.md
git commit -m "test: prove bounded project auto discovery"
```

- [ ] **Step 6: Run clean release-script gate**

```sh
go test ./scripts -count=1
git status --short
```

Expected: PASS and clean output.
