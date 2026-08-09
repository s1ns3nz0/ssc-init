# Program H host boundaries plan

> Execute RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-h-host-boundaries-design.md`.

### Task 1: closed adapter contracts

Add the v1 host/event/capability/request/response model with bounded,
value-free validation. Prove unknown and contradictory capability claims fail.
Commit `feat: add host adapter contracts`.

### Task 2: deterministic adapter evaluation

Select three to five urgent findings from the shared finding result without
changing severity, action, confidence, or rule identity. Emit explicit
coverage and remediation choices. Commit `feat: evaluate adapter findings`.

### Task 3: adapter CLI endpoint

Add bounded stdin JSON evaluation and stdout JSON response. Preserve existing
advisory hook behavior and fixed errors. Commit `feat: expose adapter evaluation`.

### Task 4: native host packages

Create Claude, Codex, and Cursor package fixtures from current official host
contracts. Each uses the existing GitHub-installed core, declares truthful
capabilities, keeps no database, and contains no bundled unsigned executable.
Commit `feat: package advisory host adapters`.

### Task 5: cross-host acceptance

Prove the same canonical input yields the same core verdict through all three
adapters, including TI/org failure and benign twins. Commit
`test: prove cross host verdict parity`.

### Task 6: quarantine contracts and persistence

Add closed requested/quarantined/restored/failed records with exact digest,
tokenized origin, original mode, timestamps, and privacy validation. Commit
`feat: persist quarantine records`.

### Task 7: reversible quarantine filesystem

Implement explicit descriptor-rooted quarantine and restore with no-follow,
collision, identity-drift, cancellation, and concurrent-operation tests.
Commit `feat: quarantine assets reversibly`.

### Task 8: quarantine CLI and remediation choices

Expose preview-first quarantine/restore commands and connect eligible findings
to choices without automatic execution. Commit `feat: expose safe remediation`.

### Task 9: launchd preview

Generate one stable daily-job preview with exact command, interval, tokenized
logs, and removal command. Commit `feat: preview daily scan schedule`.

### Task 10: launchd registration and removal

Implement explicit atomic idempotent registration/removal over the exact
managed plist; prove multiple adapters never duplicate it. Commit
`feat: manage shared daily scan`.

### Task 11: documentation and gates

Update README, architecture, audit, plugin validation, privacy, race,
repetition, clean release gates, and GitHub packaging evidence. Commit
`test: prove host boundary safety`.

`[APPLE]` Developer ID verification and notarized bootstrap success remain
deferred. They do not block Tasks 1–11.
