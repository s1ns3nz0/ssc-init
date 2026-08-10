# Unsigned Reproducible Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the Apple Developer release pipeline and make the unsigned, reproducible Universal Binary plus checksums, SBOM, provenance, and adapter archives the only official release contract.

**Architecture:** Keep `scripts/build-darwin.sh` as the sole artifact producer and add a repository-level contract test that rejects obsolete signing/notarization surfaces. Delete the two Apple release scripts, rewrite active release guidance around deterministic checksum verification, and reduce historical Apple directions to supersession notices while preserving passive `/usr/bin/codesign` inspection.

**Tech Stack:** Go 1.26 standard library, POSIX `sh`, GitHub Actions YAML, Markdown. No new module or runtime dependency.

## Global Constraints

- Preserve bounded `/usr/bin/codesign` inspection in `internal/platform`; it is passive external-probe evidence, not release signing.
- Preserve caller-supplied SHA-256 verification, Universal Mach-O verification, bounded doctor execution, atomic activation, and rollback.
- Do not add a Gatekeeper bypass, quarantine-removal command, alternative signing service, new key, or new secret.
- The official release set is the Universal Binary, three adapter ZIPs, `checksums.txt`, `sbom.cdx.json`, and `provenance.json`; thin binaries remain build intermediates covered by checksums/provenance.
- Historical documents may retain only a concise supersession notice and must not retain actionable Apple credential, signing, notarization, stapling, or DMG instructions.
- Default scans remain process-free and network-free; no new runtime dependency is permitted.

---

## File responsibility map

- `scripts/release_contract_test.go`: owns the negative repository contract that prevents obsolete Apple release surfaces from returning.
- `scripts/sign-darwin.sh`, `scripts/sign-darwin_test.go`, `scripts/notarize-darwin.sh`, `scripts/notarize-darwin_test.go`: obsolete release implementation and tests to delete.
- `scripts/build-darwin_test.go`, `scripts/workflow_test.go`: own the exact reproducible artifact set and CI secret boundary.
- `docs/release-runbook.md`, `README.md`, `CLAUDE.md`, `docs/testing/2026-08-09-foundation-completion-audit.md`: active product and release truth.
- `docs/superpowers/specs/*.md`, `docs/superpowers/plans/*.md`, `docs/handoff-*.md`: historical records; obsolete executable guidance is replaced with a supersession notice.
- `internal/platform/signature.go` and its tests: explicitly out of edit scope.

### Task 1: Enforce the closed unsigned release surface

**Files:**
- Create: `scripts/release_contract_test.go`
- Modify: `scripts/workflow_test.go`
- Delete: `scripts/sign-darwin.sh`
- Delete: `scripts/sign-darwin_test.go`
- Delete: `scripts/notarize-darwin.sh`
- Delete: `scripts/notarize-darwin_test.go`
- Test: `scripts/release_contract_test.go`

**Interfaces:**
- Consumes: `repositoryRoot(t) string` from the existing `scripts_test` helpers and the existing `releaseArtifactNames` contract.
- Produces: `TestRepositoryHasNoAppleReleasePipeline`, a permanent negative contract over exact obsolete paths and active release files.

- [ ] **Step 1: Write the failing repository contract**

Create `scripts/release_contract_test.go`:

```go
package scripts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryHasNoAppleReleasePipeline(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		"scripts/sign-darwin.sh",
		"scripts/sign-darwin_test.go",
		"scripts/notarize-darwin.sh",
		"scripts/notarize-darwin_test.go",
	} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Errorf("obsolete Apple release surface exists: %s", name)
		}
	}

	active := []string{
		".github/workflows/ci.yml",
		"CLAUDE.md",
		"README.md",
		"docs/release-runbook.md",
		"docs/testing/2026-08-09-foundation-completion-audit.md",
	}
	forbidden := []string{
		"Developer ID", "notarytool", "notarization", "stapler",
		"checksums-signed.txt", "checksums-notarized.txt",
		"ssc-init-darwin.dmg", "sign-darwin.sh", "notarize-darwin.sh",
	}
	for _, name := range active {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if strings.Contains(string(raw), value) {
				t.Errorf("active release file %s contains obsolete surface %q", name, value)
			}
		}
	}
}
```

- [ ] **Step 2: Run the test and observe RED**

Run: `go test ./scripts -run TestRepositoryHasNoAppleReleasePipeline -count=1`

Expected: FAIL naming all four existing script/test paths and active documentation references.

- [ ] **Step 3: Delete only the obsolete scripts and tests**

Use `apply_patch` to delete the four exact files. Do not change
`internal/platform/signature.go`, `internal/platform/signature_test.go`, or the
Program D collector tests.

- [ ] **Step 4: Tighten the CI secret assertion wording**

In `scripts/workflow_test.go`, rename
`TestCIWorkflowIsLeastPrivilegeAndUsesOnlyTheBundlePublicationSecret` to
`TestCIWorkflowIsLeastPrivilegeAndUsesOnlyBundlePublicationSecrets`. Keep the
two allowed bundle secret names and the four forbidden Apple credential tokens;
change the fatal message from “deferred Apple credential” to “obsolete Apple
release credential.”

- [ ] **Step 5: Verify the deletion half is GREEN while documentation remains RED**

Run: `go test ./scripts -run 'TestRepositoryHasNoAppleReleasePipeline|TestCIWorkflowIsLeastPrivilege' -count=1`

Expected: the deleted-path assertions pass; the repository contract still
fails only on active documentation. This proves Task 2 owns the remaining RED.

- [ ] **Step 6: Commit the executable-surface removal**

```sh
git add scripts/release_contract_test.go scripts/workflow_test.go
git add -u scripts
git commit -m "test: remove apple release pipeline"
```

### Task 2: Rewrite the active release contract

**Files:**
- Modify: `docs/release-runbook.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/testing/2026-08-09-foundation-completion-audit.md`
- Test: `scripts/release_contract_test.go`

**Interfaces:**
- Consumes: the forbidden-token contract from Task 1 and the existing build artifact names in `scripts/build-darwin_test.go`.
- Produces: one current release story with no Apple credential or hardened-container branch.

- [ ] **Step 1: Rewrite the release runbook as the sole current procedure**

Replace `docs/release-runbook.md` with these sections in order:

1. Preconditions: clean tree, `go mod verify`, full race gate, annotated tag before build.
2. Reproducible build: `go mod download`, `sh scripts/build-darwin.sh`, checksum verification, `go test ./scripts -count=1`.
3. Publish: Universal Binary, three adapter ZIPs, `checksums.txt`, `sbom.cdx.json`, `provenance.json`; thin binaries are intermediates.
4. Consumer verification: download the complete checksum subject set into one directory and run `shasum -a 256 -c checksums.txt`; inspect SBOM/provenance; make no signed/notarized claim.
5. Install and rollback: retain the exact `install`, `doctor`, and `rollback` commands and shared-state guarantees.
6. macOS behavior: say an unsigned download may be blocked or require explicit approval; offer source build paths; forbid weakening Gatekeeper or removing quarantine metadata.
7. External gaps: production bundle keys/publication, hosted CI evidence, and physical arm64/Intel smoke evidence only.

- [ ] **Step 2: Update README download guidance**

Keep the artifact list and `shasum -a 256 -c checksums.txt`. Replace the
optional-hardening paragraph with:

```markdown
The prebuilt binary is intentionally unsigned. macOS may block a downloaded
copy or require explicit approval. SSC Init does not instruct users to remove
quarantine metadata or weaken Gatekeeper; users who require a locally produced
binary can install with `go install` or build from the tagged source. See
[the release runbook](docs/release-runbook.md) for the complete artifact and
verification contract.
```

- [ ] **Step 3: Update CLAUDE architecture and completion truth**

State that the release set is reproducible and unsigned, remove every pending
or optional Apple release item, retain the `internal/platform` bounded local
signature-inspection description, and add: “Release signing is not a product
roadmap item; local signature inspection must not be conflated with artifact
publication.”

- [ ] **Step 4: Update the completion audit**

Change §5.3 evidence to Universal build plus digest/Mach-O verified
stage/activate/rollback and doctor v2. Remove signed/notarized/DMG evidence and
missing work. Change §14 to the closed reproducible artifact set, leaving only
hosted CI and physical cross-architecture evidence. Remove Apple execution from
completed programs and remaining dependency order.

- [ ] **Step 5: Run active-contract tests and observe GREEN**

Run: `go test ./scripts -run 'TestRepositoryHasNoAppleReleasePipeline|TestCIWorkflowIsLeastPrivilege|TestBuildScript' -count=1`

Expected: PASS.

- [ ] **Step 6: Prove preserved passive signature inspection**

Run: `go test ./internal/platform -run 'Signature|Codesign' -count=1`

Expected: PASS with `/usr/bin/codesign` inspection still covered.

- [ ] **Step 7: Commit active documentation**

```sh
git add docs/release-runbook.md README.md CLAUDE.md docs/testing/2026-08-09-foundation-completion-audit.md
git commit -m "docs: define unsigned reproducible releases"
```

### Task 3: Supersede obsolete historical requirements

**Files:**
- Modify: `docs/superpowers/specs/2026-08-05-ssc-init-design.md`
- Modify: `docs/superpowers/specs/2026-08-10-program-{d,e,f,g,h,i}-*.md`
- Modify: `docs/superpowers/plans/2026-08-09-program-a-distribution-lifecycle.md`
- Modify: `docs/superpowers/plans/2026-08-10-program-{d,e,f,g,h,i}-*.md`
- Modify: `docs/handoff-2026-08-09.md`
- Modify: other historical documents returned by the exact audit command below
- Test: repository audit commands

**Interfaces:**
- Consumes: the approved design at `docs/superpowers/specs/2026-08-10-unsigned-reproducible-distribution-design.md`.
- Produces: historical records that point to the new authority without exposing obsolete procedures as pending work.

- [ ] **Step 1: Capture the historical RED inventory**

Run:

```sh
rg -l -i 'Developer ID|notarytool|notariz|stapl|checksums-signed|checksums-notarized|ssc-init-darwin\.dmg|sign-darwin|\[APPLE\]' \
  docs --glob '!superpowers/specs/2026-08-10-unsigned-reproducible-distribution-design.md'
```

Expected: multiple historical specs, plans, handoffs, and validation reports.

- [ ] **Step 2: Replace the foundation distribution requirement**

In `docs/superpowers/specs/2026-08-05-ssc-init-design.md`, replace the sentence
requiring a signed/notarized binary with a short supersession note linking to
the new design and stating the closed unsigned reproducible artifact set. Do
not alter unrelated foundation requirements.

- [ ] **Step 3: Collapse Program A obsolete task bodies**

In `docs/superpowers/plans/2026-08-09-program-a-distribution-lifecycle.md`,
replace the Apple-specific preamble, Task 10, Task 11, Apple portions of Task
12, and the open-decision appendix with one notice:

```markdown
> **Superseded distribution direction (2026-08-10):** Developer ID signing,
> notarization, stapling, and DMG publication are no longer product work. See
> `docs/superpowers/specs/2026-08-10-unsigned-reproducible-distribution-design.md`.
> The completed reproducible build and digest/Mach-O verified install lifecycle
> remain authoritative; obsolete credential commands and artifact names have
> been removed from this historical plan.
```

Renumbering completed historical tasks is unnecessary; preserve their commit
record and non-Apple implementation details.

- [ ] **Step 4: Normalize later program references**

For Programs D–I, delete `[APPLE]` deferred/boundary statements. Where a
boundary sentence is needed for clarity, replace it with “Release distribution
follows the unsigned reproducible contract” and link the new design. Preserve
all references to passive macOS signature facts in Program D.

- [ ] **Step 5: Sanitize handoffs and validation history**

Replace actionable credential commands, cost/blocker discussions, DMG
decisions, and “later Apple work” with a concise supersession notice. Preserve
historical commit IDs, completed engineering results, passive `codesign`
testing statements, and host facts such as “Apple Silicon.”

- [ ] **Step 6: Run the historical audit**

Run the Step 1 command again.

Expected: only the approved new design and concise supersession notices may
match; no command containing `notarytool`, `stapler`, `sign-darwin.sh`,
`notarize-darwin.sh`, `checksums-signed.txt`, `checksums-notarized.txt`, or
`ssc-init-darwin.dmg` remains outside the new design.

- [ ] **Step 7: Verify docs and commit**

Run: `git diff --check`

Then:

```sh
git add docs
git commit -m "docs: retire apple distribution direction"
```

### Task 4: Release and regression gates

**Files:**
- Modify only files required by a reproducing test failure from this task.
- Test: full repository and clean release build.

**Interfaces:**
- Consumes: Tasks 1–3 committed on a clean tracked tree.
- Produces: executable evidence that distribution, install lifecycle, adapters, passive signature facts, and documentation agree.

- [ ] **Step 1: Run focused release and install regressions**

```sh
go test ./scripts ./internal/install ./internal/doctor ./internal/platform ./internal/adapter -count=1
```

Expected: PASS.

- [ ] **Step 2: Run the full clean quality gate**

```sh
go clean -testcache
go test -race -count=1 ./...
go vet ./...
go mod verify
test -z "$(gofmt -l cmd internal scripts)"
git diff --check
```

Expected: every command exits zero.

- [ ] **Step 3: Fix only reproduced failures with RED-first evidence**

For each failure, add or tighten the smallest focused test, run it to observe
the failure, apply the minimum fix, rerun the focused test, then rerun Step 2.
Do not change `internal/platform/signature.go` unless its preserved behavior is
actually broken.

- [ ] **Step 4: Commit any gate-driven correction**

If Step 3 changed files, stage only those files and commit with a message that
names the reproduced defect. If no correction was needed, create no empty
commit.

- [ ] **Step 5: Run the clean reproducible release test**

Run on the clean committed tree:

```sh
go test ./scripts -count=1
```

Expected: PASS, including two byte-identical builds and the exact adapter ZIP
fixture contract.

- [ ] **Step 6: Final repository audit**

```sh
git status --short
rg -n -i 'notarytool|stapler|checksums-signed|checksums-notarized|ssc-init-darwin\.dmg|sign-darwin|notarize-darwin' \
  . --glob '!.git/**' --glob '!docs/superpowers/specs/2026-08-10-unsigned-reproducible-distribution-design.md'
```

Expected: clean worktree; no obsolete executable guidance or artifact name.
Passive `/usr/bin/codesign` inspection and the new design's description of
removed surfaces are allowed.
