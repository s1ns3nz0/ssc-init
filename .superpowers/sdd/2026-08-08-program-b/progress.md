# SDD ledger — plan: docs/superpowers/plans/2026-08-08-program-b-status-retention-budgets.md

Program B of the full-design roadmap (gap inventory: 142 capabilities, 33 BUILT / 24 PARTIAL / 85 MISSING).
Authority: docs/superpowers/specs/2026-08-05-ssc-init-design.md sections 10, 11, 12.
Branch base: 39e444e, working on master.
Why first: unbounded growth is a LIVE DEFECT. Measured on the reference machine after one day: state.db 87 MB, 36 snapshots, 11246 assets, 16184 observations, 32609 evidence rows. Only content_cache prunes (internal/store/content_cache.go:96-110); scans/assets/observations/evidence never do. ssc-init hook persists a full snapshot per session and is wired to SessionStart, so the section 12 500 MB cap is already fiction.
Correction to the gap inventory: it reported CLAUDE.md "Active work" as stale. It is not — that section was rewritten earlier; the only remaining "worktree" mentions are build-script wording.
Task 1: dispatched (base 39e444e)
