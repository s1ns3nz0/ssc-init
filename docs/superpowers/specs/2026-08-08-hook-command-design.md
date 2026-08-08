# Hook command design

Date: 2026-08-08
Status: approved

## Purpose

`ssc-init hook` is an advisory Claude Code SessionStart hook command. It runs
one normal baseline scan (passive, no probes, persists a snapshot) and prints a
compact toolchain-drift summary to stdout so the session starts with awareness
of agent-adjacent supply-chain changes: plugins, skills, MCP declarations, IDE
extensions, and their content evidence.

## Decisions (settled with the user)

1. Target: Claude Code hook first. The command itself is neutral enough for
   any hook runner.
2. Behavior: advisory only. It never gates or blocks.
3. Scan model: full baseline scan + persist per run, using the existing
   `internal/scan` pipeline and delta unchanged. Every hook run advances the
   baseline.
4. Quiet mode: silent when clean. Empty stdout when the delta is empty; output
   only when there is drift.

## Command contract

- Invocation: `ssc-init hook` — exactly one argument, no flags in v1. Any
  other form is rejected by `ParseOptions` with the existing generic error and
  exit code 2.
- Success with no drift: empty stdout, empty stderr, exit 0.
- Success with drift: summary on stdout (format below), exit 0.
- Scan or persistence failure: one fixed, value-free line on stderr
  (`ssc-init hook: baseline scan failed`), empty stdout, **exit 0**. An
  advisory hook must never break session start; diagnostics belong to
  `scan`/`doctor`.
- Missing scanner wiring behaves like the failure case (exit 0), unlike the
  operational commands which exit 1; this asymmetry is deliberate and tested.

## Output format

```
ssc-init: toolchain drift since last snapshot
  added    agent-plugin ponytail (claude)
  changed  mcp-server github (claude-code)
  removed  ide-extension errorlens@3.16.0 (vscode)
  …and 12 more changes
  issues: 24 non-complete evidence records (partial 10, oversize 2, unavailable 12)
```

Rules:

- Privacy identical to `--pretty`: asset type, name, version, host/source, and
  closed-vocabulary statuses only. Never digests, paths, leaf names, link
  targets, secrets, or file contents.
- Asset and observation rows are rendered from the delta `entityId` structure
  (`<type>:<host>:<name>@<version>`), so removed entities render without
  needing the previous inventory. Evidence IDs are opaque
  (`evidence:sha256:…`); added/changed evidence resolves its asset name
  through the current inventory and is **grouped per asset with a count**
  (collapsing the one-time cache-warm flood); removed evidence that cannot be
  resolved is summarized as one `removed  N evidence records` line.
- Deterministic ordering: kind (added, changed, removed), then entity type,
  then name.
- Hard cap: 20 detail rows, then `…and N more changes`.
- The `issues:` line renders only when drift output is already being printed
  (an empty delta stays fully silent even if non-complete evidence exists) and
  only when the current snapshot has non-complete evidence, with counts by
  status in the fixed vocabulary order. `unsupported` is excluded from the
  count line (deliberate non-claim, same rule as `--pretty` ISSUES).

## Implementation shape

- `internal/cli/options.go`: accept `{"hook"}` (single argument form).
- `internal/report/hook.go`: `WriteHookSummary(w io.Writer, scan
  model.ScanResult, inventory model.Inventory, delta model.Delta) error` —
  pure renderer, no I/O beyond the writer, deterministic.
- `internal/cli/run.go`: `hook` case calls the existing `BaselineScanner`,
  then `WriteHookSummary`; failure path prints the fixed stderr line and
  returns 0.
- README: hook section with the Claude Code `settings.json` SessionStart
  snippet and the advisory/exit-code contract.
- No new dependency, no store or scan changes, no new binary.

## Testing

Strict TDD, in this order:

1. `ParseOptions` accepts `hook`, rejects `hook --json`, `hook extra`.
2. Renderer: drift rendering (each entity kind), clean → zero bytes, cap +
   overflow line, per-asset evidence grouping, issues line inclusion and
   `unsupported` exclusion, determinism (double render byte-equal), privacy
   (no digest/path strings from fixture leak into output).
3. CLI: drift → summary + exit 0; clean → empty stdout + exit 0; scanner error
   → stderr line + exit 0; nil scanner → same.
4. Acceptance-style isolated-home run through the real pipeline: first run
   prints drift (initial baseline = all added), second run prints the grouped
   cache-warm summary, third run is silent.

## Non-goals (v1)

- No gating/exit-code policy, no `--gate`, no thresholds.
- No hook-runner detection, no settings.json self-installation.
- No staleness policy; every run scans.
- No JSON output for `hook` (machine consumers use `scan --baseline --json`).
