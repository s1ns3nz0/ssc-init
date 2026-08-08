# Program B — Truthful Status, Retention, and Budgets

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the scan-status vocabulary closed and truthful, implement §10 retention so the local store stops growing without bound, and enforce the §12 time budget as an explicit `partial` rather than a silent overrun.

**Architecture:** `model` gains a closed `ScanStatus` vocabulary validated at the store boundary. `internal/store` gains retention pruning inside the same atomic transaction that saves a snapshot, and a size accounting query. `internal/scan` gains an overall deadline that degrades to `partial` with the unscanned targets named. A `scripts`-level benchmark harness measures the §12 budgets.

**Authority:** `docs/superpowers/specs/2026-08-05-ssc-init-design.md` §10 (privacy and storage), §11 (failure behavior), §12 (performance requirements). Gap inventory: Program B.

**Why first:** unbounded growth is a live defect, not a missing feature. Measured on the reference machine after one day of use: 87 MB, 36 snapshots, 11,246 assets, 16,184 observations, 32,609 evidence rows, with `ssc-init hook` persisting a full snapshot per session. Only `content_cache` prunes (`internal/store/content_cache.go:96-110`); nothing else ever does.

Conventions (every task): strict TDD; after GREEN run `go vet ./...`, `gofmt -l` on touched dirs, `git diff --check`; commit messages end with the trailer `Claude-Session: https://claude.ai/code/session_01YCnH78bwuqahh8qmL5wpu6`. Do not run `go test ./scripts` before committing (clean-tree gate). Never run `go test ./...` inside a `git archive` export — it corrupts the export; use a real `git clone` or exclude `./scripts`.

---

### Task 1: Close the scan-status vocabulary

**Files:**
- Modify: `internal/model/scan.go`
- Modify: `internal/model/scan_test.go`

§11 defines exactly four scan statuses: Complete, Partial, Stale, Blocked. `ScanResult.Status` is currently a free `string` set from `overallStatus` in `internal/scan/service.go`, so nothing prevents a typo or an invented value from being persisted and served as a public contract value.

- [ ] **Step 1: Write the failing test**

Add to `internal/model/scan_test.go`:

```go
func TestScanStatusVocabularyIsClosed(t *testing.T) {
	for _, status := range []model.ScanStatus{
		model.ScanComplete, model.ScanPartial, model.ScanStale, model.ScanBlocked,
	} {
		if !status.Valid() {
			t.Fatalf("documented status %q rejected", status)
		}
	}
	for _, invalid := range []model.ScanStatus{"", "COMPLETE", "ok", "failed", "unknown"} {
		if invalid.Valid() {
			t.Fatalf("undocumented status %q accepted", invalid)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/model -run TestScanStatusVocabularyIsClosed -count=1`

Expected: FAIL — `undefined: model.ScanStatus`.

- [ ] **Step 3: Implement**

In `internal/model/scan.go`, add beside the other closed vocabularies:

```go
// ScanStatus is the closed set of overall scan outcomes (design §11).
type ScanStatus string

const (
	// ScanComplete means every collector and every accepted evidence target
	// reached a terminal successful result.
	ScanComplete ScanStatus = "complete"
	// ScanPartial means discovery or evidence coverage is incomplete; the
	// unscanned targets are named in coverage.
	ScanPartial ScanStatus = "partial"
	// ScanStale means the scan completed but its inputs are past their
	// freshness window. Unreachable until the TI manager ships (design §7.2);
	// present so the vocabulary is complete and cannot be reordered later.
	ScanStale ScanStatus = "stale"
	// ScanBlocked means the scan could not produce a usable result at all.
	ScanBlocked ScanStatus = "blocked"
)

// Valid reports whether status is one of the four documented outcomes.
func (s ScanStatus) Valid() bool {
	switch s {
	case ScanComplete, ScanPartial, ScanStale, ScanBlocked:
		return true
	default:
		return false
	}
}
```

Change `ScanResult.Status` from `string` to `ScanStatus`. Fix the compile errors this produces in `internal/scan`, `internal/report`, `internal/cli`, `internal/store`, and tests by converting literals to the constants — do **not** add a `string(...)` cast at the JSON boundary; the wire values are unchanged because the constants carry the same lowercase strings.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/model ./internal/scan ./internal/report ./internal/cli ./internal/store -count=1`

Expected: PASS. The serialized JSON must be byte-identical to before — confirm with the existing golden tests.

- [ ] **Step 5: Commit**

```bash
git add internal/model internal/scan internal/report internal/cli internal/store
git commit -m "feat: close the scan status vocabulary"
```

---

### Task 2: Reject undocumented status at the store boundary

**Files:**
- Modify: `internal/store/validation.go`
- Modify: `internal/store/snapshots_test.go`

Task 1 makes the vocabulary expressible; this makes it enforced. `internal/store/validation.go` already rejects raw paths, secrets, and runtime state — status belongs in the same gate.

- [ ] **Step 1: Write the failing test**

```go
func TestSaveScanRejectsUndocumentedStatus(t *testing.T) {
	store, cleanup := newTestStore(t) // use whatever the package's existing helper is
	defer cleanup()
	scan := validV3ScanFixture(t) // existing helper; adapt to the package's real name
	scan.Status = "ok"
	if err := store.SaveScan(context.Background(), scan, validV3InventoryFixture(t)); err == nil {
		t.Fatal("SaveScan accepted an undocumented status")
	}
}
```

Read `internal/store/snapshots_test.go` first and reuse its existing fixture helpers rather than inventing new ones.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/store -run TestSaveScanRejectsUndocumentedStatus -count=1`

Expected: FAIL — `SaveScan accepted an undocumented status`.

- [ ] **Step 3: Implement**

In `validateSnapshot` in `internal/store/validation.go`:

```go
	if !result.Status.Valid() {
		return errors.New("scan status is not a documented value")
	}
```

Keep the message value-free — the existing validation errors never echo the offending value, and that is a privacy invariant.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/store -count=1` and `go test ./internal/acceptance -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat: reject undocumented scan status at persistence"
```

---

### Task 3: Snapshot retention — prune scans older than the window

**Files:**
- Modify: `internal/store/snapshots.go`
- Modify: `internal/store/snapshots_test.go`

§10: full snapshots retained 30 days. Nothing prunes them today. Pruning must happen inside the same atomic transaction as `SaveScan` so a crash cannot leave the store half-pruned, and it must **never** delete the most recent snapshot regardless of age — a machine untouched for a year must still have a baseline to diff against.

- [ ] **Step 1: Write the failing test**

```go
func TestSaveScanPrunesSnapshotsBeyondRetention(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Three snapshots: two well outside the window, one inside.
	for index, age := range []time.Duration{90 * 24 * time.Hour, 60 * 24 * time.Hour, 1 * time.Hour} {
		scan := validV3ScanFixture(t)
		scan.ScanID = fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", index)
		scan.StartedAt = base.Add(-age)
		scan.FinishedAt = base.Add(-age)
		if err := store.SaveScanAt(ctx, scan, validV3InventoryFixture(t), base); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := store.snapshotCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("retention kept %d snapshots, want 1", remaining)
	}

	// The newest snapshot must survive even when it is older than the window.
	old := validV3ScanFixture(t)
	old.ScanID = "00000000-0000-4000-8000-00000000000a"
	old.StartedAt, old.FinishedAt = base.Add(-365*24*time.Hour), base.Add(-365*24*time.Hour)
	fresh, cleanup2 := newTestStore(t)
	defer cleanup2()
	if err := fresh.SaveScanAt(ctx, old, validV3InventoryFixture(t), base); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := fresh.LatestSnapshot(ctx); err != nil || !ok {
		t.Fatalf("retention deleted the only snapshot: ok=%v err=%v", ok, err)
	}
}
```

`SaveScanAt` is a new package-private seam taking the clock explicitly, so retention is testable without sleeping; `SaveScan` calls it with `time.Now().UTC()`. `snapshotCount` is a package-private test helper on the store.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/store -run TestSaveScanPrunesSnapshotsBeyondRetention -count=1`

Expected: FAIL — `undefined: SaveScanAt` (and, once that exists, `retention kept 3 snapshots, want 1`).

- [ ] **Step 3: Implement**

Add to `internal/store/snapshots.go`:

```go
// snapshotRetention is the §10 full-snapshot window. The most recent snapshot
// is always kept regardless of age: without it there is no baseline to diff
// against, and a machine that has been idle longer than the window would
// silently report every asset as new on its next scan.
const snapshotRetention = 30 * 24 * time.Hour

func (s *Store) pruneSnapshots(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		DELETE FROM scans
		WHERE finished_at < ?
		  AND scan_id <> (SELECT scan_id FROM scans ORDER BY finished_at DESC, scan_id DESC LIMIT 1)`,
		formatTime(now.Add(-snapshotRetention)))
	if err != nil {
		return fmt.Errorf("prune snapshots: %w", err)
	}
	return nil
}
```

Call it from inside the existing `SaveScan` transaction, after the insert. Verify the child tables (`assets`, `observations`, `evidence`, `evidence_coverage`, and any others keyed by `scan_id`) are removed with the parent — check whether the schema declares `ON DELETE CASCADE` and whether the connection enables `PRAGMA foreign_keys`. If either is absent, delete the children explicitly in the same transaction. **State in your report which mechanism you relied on and how you proved it**, because a partial delete would orphan rows and inflate the store instead of shrinking it.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/store -count=1 && go test -race ./internal/store -count=1`

Add and run an assertion that no orphan rows remain: for each child table, `SELECT COUNT(*) FROM <t> WHERE scan_id NOT IN (SELECT scan_id FROM scans)` must be 0.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat: retain snapshots for the documented window"
```

---

### Task 4: Prove retention actually reclaims space

**Files:**
- Modify: `internal/store/snapshots_test.go`

Deleting rows in SQLite does not shrink the file; freed pages are reused but the file stays large. §12's 500 MB budget is about disk, so row deletion alone does not satisfy it.

- [ ] **Step 1: Write the failing test**

```go
func TestRetentionReclaimsFileSpace(t *testing.T) {
	// Save enough snapshots beyond the window to grow the file, then save one
	// more inside the window and assert the on-disk size shrinks rather than
	// merely holding steady.
}
```

Write it concretely: create a store on a real temp path, save ~20 snapshots aged beyond the window with non-trivial inventories, record `os.Stat` size, save one fresh snapshot, then assert the file is smaller than the recorded peak. Use the package's existing fixture helpers.

- [ ] **Step 2: Run it to verify it fails**

Expected: FAIL — the file does not shrink after pruning.

- [ ] **Step 3: Implement**

Run `PRAGMA incremental_vacuum` (with `auto_vacuum=INCREMENTAL` set at schema creation) or a periodic `VACUUM` after pruning. **`auto_vacuum` cannot be enabled on an existing database without a full `VACUUM`**, so decide and state whether this needs a migration step for existing stores, and make sure the choice keeps `SaveScan` atomic — `VACUUM` cannot run inside a transaction.

- [ ] **Step 4: Verify**

Run: `go test ./internal/store -count=1 && go test -race ./internal/store -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat: reclaim space after snapshot pruning"
```

---

### Task 5: Asset change history retention

**Files:**
- Modify: `internal/store/snapshots.go`, `internal/store/snapshots_test.go`

§10 retains asset change history for 90 days — a longer window than full snapshots, because history is small and answers "when did this first appear". Determine from the schema whether a separate history table exists; if it does not, this task creates the minimum one needed to satisfy §10 (asset ID, first-seen, last-seen, digest transitions) rather than retaining whole snapshots for 90 days.

Write the failing test first: history rows older than 90 days are pruned, history newer is kept, and history survives the pruning of the snapshot that produced it.

- [ ] **Steps 1–5** follow the same RED → implement → GREEN → commit shape as Task 3, committing as:

```bash
git commit -m "feat: retain asset change history for the documented window"
```

---

### Task 6: Configurable retention with documented defaults

**Files:**
- Modify: `internal/store/snapshots.go`, `internal/platform/paths.go` (or wherever configuration belongs), plus tests

§10 says organization retention is configurable through signed policy. Signed policy does not exist yet (Program C/E), so this task provides the seam and the defaults **without** inventing a config file format that Program C will have to replace: retention windows become fields on the store's construction options, defaulting to 30 and 90 days. Program C wires policy into them.

Test that a store constructed with a shorter window prunes accordingly, and that the zero value yields the documented defaults rather than "retain nothing".

```bash
git commit -m "feat: make retention windows configurable"
```

---

### Task 7: Overall scan deadline degrades to partial

**Files:**
- Modify: `internal/scan/service.go`, `internal/scan/service_test.go`

§12: "Exceeding a time budget produces a Partial result with the unscanned targets; it never silently skips them." Today each collector has its own timeout (`internal/cli`/`cmd` construct `collector.Orchestrator{Timeout: 30 * time.Second}`) but there is no overall scan deadline, so a slow machine can exceed the §12 baseline budget with no signal.

- [ ] **Step 1: Write the failing test**

A scan whose context deadline expires mid-collection must return a `ScanPartial` result naming the collectors that did not finish, must still persist a valid snapshot, and must not return an error. Assert the unscanned collectors appear in coverage with a non-complete status — never silently absent.

- [ ] **Steps 2–5:** RED, implement the deadline, GREEN with `-race`, commit:

```bash
git commit -m "feat: degrade to partial when the scan budget is exceeded"
```

Do **not** change the existing cancellation semantics: an explicitly cancelled context must still propagate as an error and clear partial runtime state (a release-blocking invariant). A budget overrun is a different outcome from a cancellation, and both must be tested.

---

### Task 8: Report store size and retention in `doctor`

**Files:**
- Modify: `internal/doctor/doctor.go`, `internal/store` (size query), plus tests

§12 budgets 500 MB for binary, bundles, state, and retained reports combined. Nothing measures this. `doctor` already reports runtime and tool availability; add the store's on-disk size, the snapshot count, and the active retention windows, so a user can see the budget rather than discover it.

Test that the reported size matches `os.Stat` within a tolerance and that the payload carries no absolute path (the existing privacy invariant).

```bash
git commit -m "feat: report store size and retention in doctor"
```

---

### Task 9: Performance budget harness

**Files:**
- Create: `scripts/benchmark_test.go` (or `internal/acceptance/benchmark_test.go` — choose and justify)

§12 sets: baseline ≤10 min, daily incremental ≤60 s, pre-execution cache hit ≤500 ms, average ~1 CPU core, ≤500 MB memory. None are measured.

Build a harness that measures baseline and incremental scan wall time against the isolated fixture home, plus peak RSS. It must be a `testing.B`-style or explicitly-skipped test that does **not** run in the normal suite (CI machines vary too much for hard assertions), but that prints comparable numbers on demand. Assert only the one budget that is machine-independent: the incremental scan must be strictly faster than the baseline on the same fixture.

```bash
git commit -m "test: measure the documented performance budgets"
```

---

### Task 10: Documentation and truthfulness pass

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `docs/superpowers/specs/2026-08-05-ssc-init-design.md` (only if something is now obsolete)

State the retention windows and the store-size behaviour in the README — a tool that writes a snapshot per session must say what it keeps and for how long. Record in CLAUDE.md that `ScanStatus` is a closed vocabulary validated at the store boundary, and that `stale` is present-but-unreachable pending the TI manager.

Verify every claim against the code, and run the full gate: `go clean -testcache && go test -race -count=1 ./...`, `go vet ./...`, `go mod verify`, `git diff --check`, then commit and confirm `go test ./scripts -count=1` passes on the clean tree.

```bash
git commit -m "docs: state retention windows and status vocabulary"
```
