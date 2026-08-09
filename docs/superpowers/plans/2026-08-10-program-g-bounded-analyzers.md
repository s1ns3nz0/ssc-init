# Program G bounded analyzers plan

> Execute RED → GREEN → regression → commit. Design:
> `docs/superpowers/specs/2026-08-10-program-g-bounded-analyzers-design.md`.

### Task 1: closed analyzer facts

Add v7 analyzer fact, rule and coverage contracts with privacy validation and
v1–v6 legacy reads. Commit `feat: add bounded analyzer contracts`.

### Task 2: deterministic version engine

Implement closed ecosystem version parsing/comparison and supported range
operators with adversarial limits. Commit `feat: compare supported package versions`.

### Task 3: TI version-range correlation

Match range-only TI records against exact canonical asset/version facts,
preserving withdrawal and malformed-range fail-closed behavior. Commit
`feat: correlate version scoped intelligence`.

### Task 4: mutable dependency signals

Derive closed findings for absent/latest versions, mutable Git refs and direct
remote-script forms from recorded facts. Commit `feat: detect mutable dependency forms`.

### Task 5: sealed analyzer reader

Expose authorized bounded content to analyzers inside the evidence lifecycle;
prove no path/source survives clearing. Commit `feat: add sealed analyzer boundary`.

### Task 6: language-aware lexical scanner

Strip comments safely and detect closed dynamic-exec/process/network/credential
API categories without regex denial-of-service. Commit `feat: detect bounded dangerous APIs`.

### Task 7: entropy and limited decoding

Detect bounded encoded/obfuscated literals with two decode layers and strict
size limits. Commit `feat: analyze bounded obfuscation signals`.

### Task 8: narrow source-to-sink flows

Correlate closed credential sources to outbound sinks within one file without
persisting raw matches. Commit `feat: detect narrow credential egress flows`.

### Task 9: analyzer finding integration

Merge analyzer facts into Program F precedence, reports, hook and policy
without claiming enforcement. Commit `feat: correlate behavioral findings`.

### Task 10: persistence and CLI coverage

Persist v7 facts/coverage and expose truthful analyzer coverage in scan/status
and finding output. Commit `feat: persist analyzer coverage`.

### Task 11: acceptance and gates

Prove commented-code twins, oversized/binary input, decoding bombs, mutable
references, version edges, privacy, determinism, cancellation and concurrency
under race/repetition. Update docs/audit and run clean release gates. Commit
`test: prove bounded analyzer boundaries`.

`[EXTERNAL]` production bundle publication remains pending. `[APPLE]`
signing/notarization remains deferred and is not a dependency.
