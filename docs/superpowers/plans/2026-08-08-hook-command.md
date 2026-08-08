# Hook Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ssc-init hook`, an advisory Claude Code SessionStart command that runs one baseline scan and prints a compact, silent-when-clean toolchain-drift summary.

**Architecture:** New single-argument CLI command reusing the existing `BaselineScanner` pipeline unchanged; a new pure renderer in `internal/report` turns the delta + current inventory into capped, privacy-preserving drift lines. Advisory contract: exit 0 on every outcome except argument errors.

**Tech Stack:** Go stdlib only. Spec: `docs/superpowers/specs/2026-08-08-hook-command-design.md`.

Conventions (apply to every task): strict TDD; after GREEN run `go vet ./...`, `gofmt -l` on touched dirs, `git diff --check`; commit messages end with the trailer `Claude-Session: https://claude.ai/code/session_01YCnH78bwuqahh8qmL5wpu6`.

---

### Task 1: Parse the `hook` command

**Files:**
- Modify: `internal/cli/options.go` (the `ParseOptions` switch)
- Test: `internal/cli/options_test.go`

- [ ] **Step 1: Write the failing tests**

In `TestParseOptionsAcceptsOnlyDocumentedCommandForms`, add:

```go
{args: []string{"hook"}, want: Options{Command: "hook"}},
```

In `TestParseOptionsRejectsAmbiguousForms`, add:

```go
{"hook", "--json"},
{"hook", "--pretty"},
{"hook", "extra"},
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/cli -run TestParseOptions -count=1`
Expected: FAIL — `accepted ["hook" ...]` not reached yet; the accept case fails with the generic parse error.

- [ ] **Step 3: Implement**

In `ParseOptions`, add a case before `default`:

```go
	case "hook":
		if len(args) != 1 {
			return Options{}, ErrInvalidOptions
		}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/cli -run TestParseOptions -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/options.go internal/cli/options_test.go
git commit -m "feat: parse hook command"
```

---

### Task 2: Drift summary renderer

**Files:**
- Create: `internal/report/hook.go`
- Test: `internal/report/hook_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/report/hook_test.go`:

```go
package report_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/report"
)

func hookFixture() (model.Inventory, model.Delta) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:claude:alpha@1.0.0", Type: model.AssetAgentPlugin, Name: "alpha", Version: "1.0.0", Source: "claude"},
		},
		Observations: []model.Observation{
			{ID: "observation:sha256:1111", AssetID: "agent-plugin:claude:alpha@1.0.0", Collector: "agents", Source: "agents.claude.plugins"},
		},
		Evidence: []model.ContentEvidence{
			{ID: "evidence:sha256:aaaa", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial, Errors: []model.EvidenceError{{Code: "symlink_rejected", Message: "symbolic link was not followed"}}},
			{ID: "evidence:sha256:bbbb", AssetID: "agent-plugin:claude:alpha@1.0.0", ObservationID: "observation:sha256:1111", Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 1},
			{ID: "evidence:sha256:cccc", AssetID: "pkg:pypi/charlie@3.0.0", ObservationID: "observation:sha256:3333", Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, Status: model.EvidenceUnsupported},
		},
	}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:bravo@2.0.0"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityAsset, EntityID: "mcp:claude-code:github"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:aaaa"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:bbbb"},
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: "evidence:sha256:gone"},
	}}
	return inventory, delta
}

func TestWriteHookSummaryRendersCappedGroupedDrift(t *testing.T) {
	inventory, delta := hookFixture()
	var first, second bytes.Buffer
	if err := report.WriteHookSummary(&first, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if err := report.WriteHookSummary(&second, inventory, delta); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("hook summary not deterministic:\n%q\n%q", first.String(), second.String())
	}
	output := first.String()
	for _, pattern := range []string{
		`^ssc-init: toolchain drift since last snapshot\n`,
		`(?m)^  added\s+ide-extension bravo@2\.0\.0 \(vscode\)$`,
		`(?m)^  removed\s+mcp github \(claude-code\)$`,
		`(?m)^  changed\s+2 evidence records \(alpha\)$`,
		`(?m)^  removed\s+1 evidence records$`,
		`(?m)^  issues: 1 non-complete evidence records \(partial 1\)$`,
	} {
		if !regexp.MustCompile(pattern).MatchString(output) {
			t.Fatalf("missing pattern %q in:\n%s", pattern, output)
		}
	}
	if strings.Contains(output, strings.Repeat("a", 64)) || strings.Contains(output, "unsupported") {
		t.Fatalf("summary leaks digests or counts unsupported:\n%s", output)
	}
}

func TestWriteHookSummaryIsSilentOnEmptyDelta(t *testing.T) {
	inventory, _ := hookFixture()
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, inventory, model.Delta{}); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("expected silence, got:\n%s", buffer.String())
	}
}

func TestWriteHookSummaryCapsDetailRows(t *testing.T) {
	var delta model.Delta
	for index := 0; index < 25; index++ {
		delta.Changes = append(delta.Changes, model.Change{
			Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset,
			EntityID: "agent-skill:claude:" + string(rune('a'+index)),
		})
	}
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, model.Inventory{}, delta); err != nil {
		t.Fatal(err)
	}
	output := buffer.String()
	if got := strings.Count(output, "\n  added"); got != 20 {
		t.Fatalf("detail rows=%d want 20:\n%s", got, output)
	}
	if !strings.Contains(output, "…and 5 more changes") {
		t.Fatalf("missing overflow line:\n%s", output)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/report -run TestWriteHookSummary -count=1`
Expected: FAIL — `undefined: report.WriteHookSummary`.

- [ ] **Step 3: Implement**

Create `internal/report/hook.go`:

```go
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const maxHookDetailRows = 20

var hookKindOrder = map[model.ChangeKind]int{
	model.ChangeAdded:   0,
	model.ChangeChanged: 1,
	model.ChangeRemoved: 2,
}

// WriteHookSummary renders an advisory toolchain-drift summary for hook
// consumers. An empty delta writes nothing. Output carries asset types,
// names, hosts, statuses, and counts only — never digests, paths, or
// contents.
func WriteHookSummary(writer io.Writer, inventory model.Inventory, delta model.Delta) error {
	if len(delta.Changes) == 0 {
		return nil
	}
	observationAsset := make(map[string]string, len(inventory.Observations))
	for _, observation := range inventory.Observations {
		observationAsset[observation.ID] = observation.AssetID
	}
	evidenceAsset := make(map[string]string, len(inventory.Evidence))
	for _, evidence := range inventory.Evidence {
		evidenceAsset[evidence.ID] = evidence.AssetID
	}
	assetName := make(map[string]string, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assetName[asset.ID] = asset.Name
	}

	type groupKey struct {
		kind   model.ChangeKind
		entity model.ChangeEntity
		label  string
	}
	rows := make([]struct {
		kind  model.ChangeKind
		label string
	}, 0, len(delta.Changes))
	groups := make(map[groupKey]int)
	unresolved := make(map[groupKey]int)
	for _, change := range delta.Changes {
		switch change.Entity {
		case model.ChangeEntityAsset:
			rows = append(rows, struct {
				kind  model.ChangeKind
				label string
			}{change.Kind, describeHookAssetID(change.EntityID)})
		case model.ChangeEntityObservation, model.ChangeEntityEvidence:
			assetID := observationAsset[change.EntityID]
			if change.Entity == model.ChangeEntityEvidence {
				assetID = evidenceAsset[change.EntityID]
			}
			if name := assetName[assetID]; name != "" {
				groups[groupKey{change.Kind, change.Entity, name}]++
			} else {
				unresolved[groupKey{kind: change.Kind, entity: change.Entity}]++
			}
		default:
			unresolved[groupKey{kind: change.Kind, entity: change.Entity}]++
		}
	}
	for key, count := range groups {
		rows = append(rows, struct {
			kind  model.ChangeKind
			label string
		}{key.kind, fmt.Sprintf("%d %s records (%s)", count, key.entity, key.label)})
	}
	for key, count := range unresolved {
		rows = append(rows, struct {
			kind  model.ChangeKind
			label string
		}{key.kind, fmt.Sprintf("%d %s records", count, key.entity)})
	}
	sort.Slice(rows, func(a, b int) bool {
		if hookKindOrder[rows[a].kind] != hookKindOrder[rows[b].kind] {
			return hookKindOrder[rows[a].kind] < hookKindOrder[rows[b].kind]
		}
		return rows[a].label < rows[b].label
	})

	printer := &prettyPrinter{writer: writer}
	printer.line("ssc-init: toolchain drift since last snapshot")
	detail := rows
	overflow := 0
	if len(detail) > maxHookDetailRows {
		overflow = len(detail) - maxHookDetailRows
		detail = detail[:maxHookDetailRows]
	}
	for _, row := range detail {
		printer.line(fmt.Sprintf("  %-8s %s", row.kind, row.label))
	}
	if overflow > 0 {
		printer.line(fmt.Sprintf("  …and %d more changes", overflow))
	}
	printer.hookIssuesLine(inventory)
	return printer.err
}

// hookIssuesLine appends the non-complete evidence counts, excluding the
// deliberate unsupported non-claims (same rule as the pretty ISSUES table).
func (p *prettyPrinter) hookIssuesLine(inventory model.Inventory) {
	counts := make(map[model.EvidenceStatus]int)
	total := 0
	for _, evidence := range inventory.Evidence {
		if evidence.Status == model.EvidenceComplete || evidence.Status == model.EvidenceUnsupported {
			continue
		}
		counts[evidence.Status]++
		total++
	}
	if total == 0 {
		return
	}
	parts := make([]string, 0, len(counts))
	for _, status := range evidenceStatusOrder {
		if counts[status] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", status, counts[status]))
		}
	}
	p.line(fmt.Sprintf("  issues: %d non-complete evidence records (%s)", total, strings.Join(parts, ", ")))
}

// describeHookAssetID renders "<type> <name>[@version] (<host>)" from the
// structured asset ID "<type>:<host>:<name>[@version]"; two-segment IDs
// render "<type> <rest>", anything else renders verbatim.
func describeHookAssetID(id string) string {
	parts := strings.SplitN(id, ":", 3)
	switch len(parts) {
	case 3:
		return parts[0] + " " + parts[2] + " (" + parts[1] + ")"
	case 2:
		return parts[0] + " " + parts[1]
	default:
		return id
	}
}
```

Note: `prettyPrinter`, `evidenceStatusOrder`, and `prettyPrinter.line` already exist in `internal/report/pretty.go` — reuse, do not redeclare.

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/report -count=1`
Expected: PASS (new hook tests plus the existing pretty/JSON tests).

- [ ] **Step 5: Commit**

```bash
git add internal/report/hook.go internal/report/hook_test.go
git commit -m "feat: render hook drift summary"
```

---

### Task 3: Wire `hook` into the CLI

**Files:**
- Modify: `internal/cli/run.go` (the `RunOptions` switch)
- Test: `internal/cli/run_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/cli/run_test.go`:

```go
func TestHookIsAdvisoryAcrossDriftCleanAndFailure(t *testing.T) {
	drift := model.Delta{Changes: []model.Change{{Kind: model.ChangeAdded, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:alpha@1.0.0"}}}
	scan := model.ScanResult{SchemaVersion: "ssc-init.scan.v3"}

	var out, errOut bytes.Buffer
	app := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, error) {
		return scan, model.Inventory{}, drift, nil
	})}
	if code := app.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("drift: code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "toolchain drift") || !strings.Contains(out.String(), "agent-plugin alpha@1.0.0 (claude)") {
		t.Fatalf("drift output wrong:\n%s", out.String())
	}

	out.Reset()
	clean := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, error) {
		return scan, model.Inventory{}, model.Delta{}, nil
	})}
	if code := clean.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("clean: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	failing := App{BaselineScanner: baselineScannerFunc(func(context.Context) (model.ScanResult, model.Inventory, model.Delta, error) {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, errors.New("store locked at /private/path")
	})}
	out.Reset()
	errOut.Reset()
	if code := failing.Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("failure must stay advisory: code=%d", code)
	}
	if out.Len() != 0 || errOut.String() != "ssc-init hook: baseline scan failed\n" {
		t.Fatalf("failure output wrong: stdout=%q stderr=%q", out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := (App{}).Run(context.Background(), []string{"hook"}, &out, &errOut); code != 0 {
		t.Fatalf("nil scanner must stay advisory: code=%d", code)
	}
	if out.Len() != 0 || errOut.String() != "ssc-init hook: baseline scan failed\n" {
		t.Fatalf("nil scanner output wrong: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}
```

Add `"errors"` to the test file imports if absent.

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/cli -run TestHookIsAdvisory -count=1`
Expected: FAIL — `hook` reaches the `default` case (`invalid command arguments`, exit 2).

- [ ] **Step 3: Implement**

In `RunOptions`, add before `default`:

```go
	case "hook":
		if a.BaselineScanner == nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		_, inventory, delta, err := a.BaselineScanner.Baseline(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		if err := report.WriteHookSummary(stdout, inventory, delta); err != nil {
			fmt.Fprintln(stderr, "ssc-init hook: baseline scan failed")
			return 0
		}
		return 0
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./internal/cli -count=1 && go test -race ./internal/cli ./internal/report -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/run.go internal/cli/run_test.go
git commit -m "feat: add advisory hook command"
```

---

### Task 4: End-to-end lifecycle test and README

**Files:**
- Create: `internal/acceptance/hook_test.go`
- Modify: `README.md` (command list + new hook paragraph after the command explanations)

- [ ] **Step 1: Write the failing acceptance test**

Create `internal/acceptance/hook_test.go`. Follow the package's existing isolated-home pattern: reuse the same helpers the real-store baseline tests use (see `real_store_test.go` for the store-backed service construction and isolated `testutil.Environment`; mirror its setup verbatim). The test drives `cli.App{BaselineScanner: service}.Run` three times with `[]string{"hook"}`:

```go
func TestHookLifecycleFirstDriftThenCacheWarmThenSilent(t *testing.T) {
	// setup: isolated home with one Claude plugin fixture (manifest +
	// payload file) and a real SQLite store, mirroring real_store_test.go.
	// run 1: expect exit 0, stdout containing "toolchain drift" and
	//        "added" (initial baseline = everything added).
	// run 2: expect exit 0; stdout either empty or containing only grouped
	//        "changed  N evidence records" lines (cache-warm metadata flip);
	//        assert no digest hex and no home path substring in stdout.
	// run 3: expect exit 0 and stdout exactly empty.
}
```

The comment lines above are the required assertions — implement each as real code against the actual helper names found in the package (the implementer reads `real_store_test.go` first; do not invent new fixture helpers if existing ones fit).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/acceptance -run TestHookLifecycle -count=1`
Expected: FAIL before Tasks 1–3 land in the same branch (unknown command → exit 2); PASS once they have. If executing tasks in order, this runs after Task 3 and the failure step instead verifies the test compiles and passes on first run — in that case observe RED by temporarily changing the expected first-run substring to `"nonsense"`, watching it fail, then restoring.

- [ ] **Step 3: README**

In the command block after `ssc-init status --pretty`, add:

```sh
ssc-init hook
```

After the command-explanation paragraph, add:

```markdown
`hook` is an advisory session hook: it runs one default baseline scan and
prints a compact toolchain-drift summary (asset names, hosts, statuses, and
counts only), staying completely silent when nothing changed. It always exits
zero — including on scan failure — so wiring it into an agent session can
never block startup. Claude Code example (`~/.claude/settings.json`):

​```json
{
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "ssc-init hook"}]}
    ]
  }
}
​```
```

(Remove the zero-width characters before the inner code fence when writing the file — they exist only to nest fences in this plan.)

- [ ] **Step 4: Full verification**

Run: `go test ./... -count=1` (expect only the known pre-commit `scripts` clean-tree failure if the worktree is dirty), then commit and run `go test ./scripts -count=1`.
Expected: all PASS post-commit.

- [ ] **Step 5: Commit**

```bash
git add internal/acceptance/hook_test.go README.md
git commit -m "test: lock hook lifecycle and document hook"
```
