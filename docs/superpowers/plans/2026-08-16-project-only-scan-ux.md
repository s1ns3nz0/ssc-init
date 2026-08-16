# Project-Only Scan UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide an explicit repository-only scan whose coverage and findings contain no unrelated laptop collectors, while preserving existing broad scan behavior.

**Architecture:** Add a closed CLI mode that selects only the project collector at configuration time. Keep canonical project identities private and add presentation-only deterministic aliases. Reclassify incidental walked symlinks as safe exclusions without weakening required-evidence symlink rejection.

**Tech Stack:** Go 1.26, existing CLI/scanconfig/project collector/report/audit packages.

**Spec:** `docs/superpowers/specs/2026-08-16-public-repository-scan-hardening-design.md`

## Global Constraints

- `--project-only` requires explicit roots and never triggers auto-discovery.
- Ordinary scans retain their current collector set and JSON behavior.
- No symlink is followed; required evidence symlinks remain partial.
- No absolute or relative private path is rendered or archived.
- Project aliases are deterministic within a result and are never identity.

---

### Task 1: Closed project-only CLI and orchestration

**Files:**
- Modify: `internal/cli/options.go`
- Test: `internal/cli/options_test.go`
- Modify: `internal/scanconfig/configuration.go`
- Test: `internal/scanconfig/configuration_test.go`
- Modify: `cmd/ssc-init/main.go`
- Test: `cmd/ssc-init/main_test.go`
- Modify: `internal/model/scan.go`
- Test: `internal/model/scan_test.go`

**Interfaces:**
- Adds: `cli.Options.ProjectOnly bool`.
- Adds: a closed scope mode field with values `host` and `project-only`.

- [x] **Step 1: Add failing parser and zero-host-read tests**

Accept only `scan --baseline --project-only --project-root <root> --json|--pretty`. Reject missing roots, automatic discovery, `--external-probes`, `--update-ti`, duplicate flag, and non-scan commands. Inject fatal host collectors and assert project-only configuration constructs/invokes only `projects`; assert ordinary explicit-root scan still constructs the full collector list.

- [x] **Step 2: Run RED**

```bash
go test ./internal/cli ./internal/scanconfig ./cmd/ssc-init -run 'Test.*ProjectOnly' -count=1 -v
```

- [x] **Step 3: Implement minimal mode selection**

Parse the flag, require explicit roots, write the closed mode into scope, and choose only the projects collector before orchestrator construction. Do not instantiate or probe host collector filesystems in this branch.

- [x] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/cli ./internal/scanconfig ./cmd/ssc-init ./internal/scan -count=1
```

Temporarily append the agents collector in project-only mode; confirm the fatal host-read test fails, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/cli internal/scanconfig cmd/ssc-init internal/model/scan.go internal/model/scan_test.go
git commit -m "feat: add explicit project-only scans"
```

### Task 2: Privacy-safe deterministic project aliases

**Files:**
- Create: `internal/findingdisplay/project_alias.go`
- Create: `internal/findingdisplay/project_alias_test.go`
- Modify: `internal/report/findings.go`
- Test: `internal/report/findings_test.go`
- Modify: `internal/audit/render.go`
- Test: `internal/audit/render_test.go`

**Interfaces:**
- Produces: `findingdisplay.ProjectAliases([]model.Asset) map[string]string`.
- Aliases sorted project asset IDs as `project-1`, `project-2`, ... for presentation only.

- [x] **Step 1: Add failing ordering/privacy tests**

Create three project assets in shuffled orders and assert identical aliases. Render findings twice and assert aliases identify separate projects without containing root paths, relative directories, hashes, location refs, or opaque evidence IDs. Assert non-project asset names are unchanged.

- [x] **Step 2: Run RED**

```bash
go test ./internal/findingdisplay ./internal/report ./internal/audit -run 'Test.*ProjectAlias' -count=1 -v
```

- [x] **Step 3: Implement presentation-only aliases**

Sort copies of canonical project IDs, assign ordinals, and consult the mapping only when rendering an asset of type project. Do not mutate inventory or finding identities.

- [x] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/findingdisplay ./internal/report ./internal/audit -count=1
```

Temporarily derive aliases from input order; confirm shuffle determinism fails, restore, rerun GREEN.

- [ ] **Step 5: Commit**

```bash
git add internal/findingdisplay/project_alias.go internal/findingdisplay/project_alias_test.go internal/report internal/audit/render.go internal/audit/render_test.go
git commit -m "feat: distinguish projects with private aliases"
```

### Task 3: Incidental symlink exclusion semantics

**Files:**
- Modify: `internal/collector/projects/walk.go`
- Test: `internal/collector/projects/walk_test.go`
- Modify: `internal/collector/projects/collector.go`
- Test: `internal/collector/projects/collector_test.go`
- Modify: `internal/audit/render.go`
- Test: `internal/audit/render_test.go`

**Interfaces:**
- Produces a counted, closed incidental-symlink exclusion separate from required evidence target failures.

- [ ] **Step 1: Add failing boundary tests**

Create one unrelated symlink during a bounded walk and assert it is not followed, collector status remains complete, and one safe exclusion is reported without its name. Create a symlink at a required `Cargo.lock`/`package-lock.json` target and assert partial plus `symlink_rejected`. Add swap-after-discovery mutation coverage to preserve identity rejection.

- [ ] **Step 2: Run RED**

```bash
go test ./internal/collector/projects ./internal/audit -run 'Test.*Symlink.*(Incidental|Required|Skipped)' -count=1 -v
```

- [ ] **Step 3: Separate walk exclusions from target failures**

Count incidental symlinks without issuing an unavailable evidence target. Preserve required target status and post-open identity checks. Render only the count in pretty output; keep raw names absent from JSON/audit.

- [ ] **Step 4: Verify GREEN and mutation**

```bash
go test -race ./internal/collector/projects ./internal/audit ./internal/acceptance -count=1
```

Temporarily follow the incidental symlink; confirm the no-follow probe fails, restore, rerun GREEN.

- [ ] **Step 5: Commit and program gate**

```bash
git add internal/collector/projects internal/audit/render.go internal/audit/render_test.go
git commit -m "fix: report safely skipped project symlinks"
go test -race ./internal/cli ./internal/scanconfig ./cmd/ssc-init ./internal/collector/projects ./internal/findingdisplay ./internal/report ./internal/audit ./internal/acceptance -count=1
go vet ./internal/cli ./internal/scanconfig ./cmd/ssc-init ./internal/collector/projects ./internal/findingdisplay ./internal/report ./internal/audit
git diff --check
```
