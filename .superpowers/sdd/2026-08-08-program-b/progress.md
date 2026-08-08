# SDD ledger — plan: docs/superpowers/plans/2026-08-08-program-b-status-retention-budgets.md

Program B of the full-design roadmap (gap inventory: 142 capabilities, 33 BUILT / 24 PARTIAL / 85 MISSING).
Authority: docs/superpowers/specs/2026-08-05-ssc-init-design.md sections 10, 11, 12.
Branch base: 39e444e, working on master.
Why first: unbounded growth is a LIVE DEFECT. Measured on the reference machine after one day: state.db 87 MB, 36 snapshots, 11246 assets, 16184 observations, 32609 evidence rows. Only content_cache prunes (internal/store/content_cache.go:96-110); scans/assets/observations/evidence never do. ssc-init hook persists a full snapshot per session and is wired to SessionStart, so the section 12 500 MB cap is already fiction.
Correction to the gap inventory: it reported CLAUDE.md "Active work" as stale. It is not — that section was rewritten earlier; the only remaining "worktree" mentions are build-script wording.
Task 1: dispatched (base 39e444e)
Task 1 implementation: 9dd0d3b; RED (undefined ScanStatus), GREEN 7 packages + race + vet + gofmt + diff. Wire format proven unchanged — no golden edited; repo has no .golden files, contracts are inline expected-JSON in report/model/acceptance tests, all passed unmodified. Adaptation: scan_test.go is package model (not model_test), so the plan's model.* qualifiers were dropped. Compile fixes in 4 files: report/json.go (payload retyped, no boundary cast), report/pretty.go (human-render cast only), store/validation.go (cast inside the existing required-string gate; Task 2 owns Valid()), scan/service.go (overallStatus return type). internal/cli needed none — statusPayload carries no status field. database/sql round-trip verified by passing store+acceptance suites, not inspection.
Task 1 review: dispatched (base bf34c91, head 9dd0d3b)
Task 2: dispatched (base 9dd0d3b)
Task 2 implementation: e0b3c1f; RED both cases (save accepted "ok"; load accepted after UPDATE scans SET status='ok'), GREEN store/acceptance/scan + race + 20x. Reused real helpers openTestStore/assertNoSnapshotRows (snapshots_test.go) and validV3Snapshot/saveValidV3Snapshot (evidence_test.go) — the plan's placeholder helper names do not exist. Both checks kept: required-string proves presence AND runs validateOptionalString (UTF-8 + secret scan), Valid() proves vocabulary.
Task 2 review: dispatched (base 9dd0d3b, head e0b3c1f)
Task 3: dispatched (base e0b3c1f) — the live-defect fix
