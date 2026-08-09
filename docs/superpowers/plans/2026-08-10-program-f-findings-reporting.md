# Program F findings and organization reporting plan

> Execute RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-f-findings-reporting-design.md`.

### Task 1: v6 finding model

Add closed finding/verdict/severity/confidence/action contracts, v6 scan/status
round trips and v1–v5 legacy behavior. Commit `feat: add v6 finding contracts`.

### Task 2: active verified bundle reader

Expose a read-only, signature-reverified active payload API with freshness and
no state creation. Commit `feat: load active verified bundle payloads`.

### Task 3: exact TI correlation

Purely match exact asset IDs and optional complete SHA-256 facts, ignore
withdrawn/range-only records, and merge supporting records deterministically.
Commit `feat: correlate exact intelligence evidence`.

### Task 4: five-level organization decisions

Wire level-1 unoverrideable evidence, signed deny, digest-bound allow, signed
and local exceptions, and level-5 rules without claiming host blocking. Commit
`feat: evaluate signed organization precedence`.

### Task 5: finding persistence and incidents

Migrate v6 finding/decision snapshot tables and independent critical/high
incident retention. Prove legacy reads, pruning isolation and privacy. Commit
`feat: persist findings and incident metadata`.

### Task 6: finding service and CLI

Add `ssc-init findings --json|--pretty`, explicit bundle degraded state and
closed exit codes. It evaluates the latest snapshot without rescanning. Commit
`feat: add finding evaluation command`.

### Task 7: Finding JSON reporter

Render the exact privacy-safe organization egress contract with opaque device
identity and deterministic ordering. Commit `feat: render finding json`.

### Task 8: SARIF 2.1.0 reporter

Render rules/results without paths, source regions or raw matches. Commit
`feat: render privacy safe sarif`.

### Task 9: inventory CycloneDX 1.6 reporter

Render canonical components, hashes and graph relationships without local
locations. Commit `feat: render inventory cyclonedx`.

### Task 10: explicit HTTPS webhook

Add bounded opt-in delivery of exact Finding JSON, reject non-HTTPS/userinfo,
and prove scan/status never call the network. Commit `feat: deliver findings
to explicit webhook`.

### Task 11: hook and policy integration

Report new findings in a separate truthful section, keep advisory hook exit
zero, and make policy check consume signed levels 1–3. Commit `feat: integrate
verified findings with policy`.

### Task 12: acceptance and release gates

Prove malicious/benign twins, hash mismatch, withdrawal, stale/missing TI,
deny/allow/exception precedence, privacy, deterministic output, concurrency
and migration under race/repetition. Update docs/audit and run clean release
gates. Commit `test: prove finding and reporting boundaries`.

`[EXTERNAL]` production bundle keys/publication remain pending. `[APPLE]`
signing/notarization remains deferred and is not a dependency.
