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
