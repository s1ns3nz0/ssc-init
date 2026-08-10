# Program I developer surfaces implementation plan

> Execute each task RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-i-developer-surfaces-design.md`.

**Goal:** Add bounded passive developer-surface inventory and explicitly
opted-in point-in-time process/listener facts while preserving zero-process
default scans and privacy-safe persistence.

### Task 1: v5 developer-surface model

Add the six closed asset types, v5 scan/status contracts and v4 legacy reads.
Pin deterministic JSON/store round trips. Commit `feat: add v5 developer
surface contracts`.

### Task 2: sealed user-file evidence helper

Create a reusable collector helper for exact home-relative regular files with
descriptor anchors, size bounds and terminal evidence. Prove no-follow,
replacement, oversize and cancellation. Commit `feat: add sealed user file
evidence targets`.

### Task 3: shell startup collector

Discover the exact six-file catalog, emit safe assets/observations and file
evidence, and reject aliases/symlinks/unrelated files. Commit `feat: inventory
bounded shell startup files`.

### Task 4: Git credential-helper semantic parser

Parse only `credential.helper` from the two exact Git config files. Normalize
helper basenames, discard arguments and URL-scoped credential blocks, reject
duplicates/hostile syntax, and produce a semantic digest. Commit `feat: parse
secret free git credential helpers`.

### Task 5: credential-helper collector wiring

Emit helper assets and observations plus one semantic config evidence record;
prove no helper execution or Keychain access. Commit `feat: inventory declared
git credential helpers`.

### Task 6: project developer-file discovery

Extend descriptor-rooted project discovery only for `.vscode/launch.json` and
the closed Git hook-name catalog, excluding samples and Git internals. Commit
`feat: discover project launch configs and git hooks`.

### Task 7: project developer-file evidence and graph

Emit file assets, observations, sealed evidence and project `contains` edges.
Malformed launch JSON remains hashed but marks semantic coverage partial.
Commit `feat: connect project developer surface evidence`.

### Task 8: runtime snapshot contracts and parsers

Implement bounded parsers for exact `ps` and `lsof` formats, retaining only
approved process/executable/protocol/local-port facts. Prove hostile output
cannot echo. Commit `feat: parse bounded developer runtime snapshots`.

### Task 9: runtime collector opt-in boundary

Add the runtime collector behind `ExternalProbes`; exact absolute commands,
timeouts, truncation, cancellation and independent target degradation are
tested. Default collection calls nothing. Commit `feat: collect opt in runtime
snapshots`.

### Task 10: runtime graph edges

Connect processes to existing executable assets and listener endpoints to
their owning processes without placeholders or orphans. Commit `feat: connect
runtime snapshot graph edges`.

### Task 11: orchestration and CLI wiring

Register shell/developer/runtime collectors and catalogs in scan, acceptance
and coverage matrices. Keep default zero-process behavior. Commit `feat: wire
developer surface collectors`.

### Task 12: privacy and adversarial matrix

Prove all catalog, path, secret, process-argument, hostname, remote-endpoint,
symlink, replacement, duplicate and cancellation boundaries repeatedly under
race. Commit `test: prove developer surface privacy boundaries`.

### Task 13: truthfulness and release gates

Update README, CLAUDE and audit without claiming monitoring or verdicts. Run:

```sh
go clean -testcache
go test -race -count=1 ./...
go test ./internal/collector/surfaces ./internal/collector/runtime -count=50
go test ./internal/acceptance -run 'Shell|GitHook|Credential|Launch|Process|Listener' -count=50
go vet ./...
go mod verify
test -z "$(gofmt -l internal cmd scripts)"
git diff --check
```

Commit `test: prove bounded developer surface inventory`, then run
`go test ./scripts -count=1` on the clean worktree.

Release distribution follows the [unsigned reproducible contract](../specs/2026-08-10-unsigned-reproducible-distribution-design.md).
