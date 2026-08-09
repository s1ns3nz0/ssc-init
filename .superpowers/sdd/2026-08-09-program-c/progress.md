# SDD ledger — plan: docs/superpowers/plans/2026-08-09-program-c-local-policy-engine.md

Design: docs/superpowers/specs/2026-08-08-policy-layer-design.md (approved, readiness-tagged NOW/BUNDLE/TI/HOST).
Scope: the [NOW] slice only — precedence levels 4 and 5. Levels 1-3 present and inert, never designed out.
Plan: 1809c87, 14 tasks.

CONTROLLER DECISIONS on the plan's six ambiguities:
1. Exit code on violation = 3. APPROVED (2 is argument errors, 1 is operational failure).
2. Audit store = separate TABLES in state.db, not a separate file. APPROVED — foundation section 5.3 says "a single state database" and section 5.2 module 7 lists findings, decisions, exceptions and audit history in that same local store. A separate file would contradict both and duplicate the hardened open path.
3. Ladder extraction (Task 4) to internal/inventory. APPROVED — policy importing internal/report would invert the layering; classification is inventory logic that report merely renders. Requires byte-identical output proof.
4. "policy check performs no filesystem access" was CONTROLLER IMPRECISION, not a design ambiguity. Corrected in the design doc: it opens the policy document and the store, and touches no collector root, no discovered asset, and no path outside its own state directory.
5. Local level-5 document may NOT set retention — section 10 scopes retention configuration to signed policy, i.e. [BUNDLE]. Task 13 shrinks to the seam plus a comment.
6. No throttle on unpinned bursts. APPROVED, matches the design's stated intent.

Also noted by the planner: internal/report/rung.go render() hard-codes %-10s; the plan generalizes to render(label, width, row) so ladder output stays byte-identical while POLICY gets a 19-wide column.
Task 1: dispatched (internal/policy, new package — zero conflict with Program A's in-flight cli/cmd work)
Task 1 complete: 43cd9d2
Task 2 complete: 2b19060
Task 3 complete: 8f54f2b
Task 4 complete: a89ceb4
Task 5 complete: 6f137f4
Task 6 complete: 62e305f
Task 7 complete: 201db7c
Task 8 complete: c6a210d
Task 9 complete: d86c510
Task 10 complete: 63828a3
Task 11 complete: 28f5765
Task 12 complete: 406dbc4
Task 13 complete: a18fdf5
Task 14 complete: 277ba20

Program complete. Verification at 277ba20: `go test -race -count=1 ./...`,
`go test ./internal/policy -count=50`,
`go test ./internal/acceptance -run Policy -count=50`, `go vet ./...`,
`go mod verify`, formatting, diff, and clean-worktree checks all passed.
