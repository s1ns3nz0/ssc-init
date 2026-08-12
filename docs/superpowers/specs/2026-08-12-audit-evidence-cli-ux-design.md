# Audit Evidence and Detailed CLI UX Design

## 1. Goal

SSC Init must make a completed scan understandable to a human operator without
requiring them to read the full status JSON. The same run must also produce a
self-contained audit artifact that can be retained, verified offline, and
submitted later without reconstructing historical state from the mutable local
database.

This design adds:

- a progressive-detail terminal report for baseline scans and current status;
- one deterministic audit ZIP for every complete, partial, or failed scan;
- offline list, show, export, and verify commands;
- an audit-friendly internal profile and a separately generated redacted
  profile; and
- bounded automatic retention with an extension point for a future
  organization signature.

It does not add a web dashboard, remote upload, Apple signing, automatic
organization signing, or any new process or network probe.

## 2. User-visible contract

### 2.1 Progressive-detail report

`ssc-init scan --baseline --pretty` renders a compact summary followed by
findings, changes, coverage, asset-type counts, and the audit artifact result.
Long record lists are not dumped into the default terminal view. Each section
names the command that opens its detailed form.

The report shape is:

```text
SSC Init audit
  run        <opaque run ID>
  state      COMPLETE | PARTIAL | FAILED
  started    <UTC timestamp>
  device     <opaque device ID>
  label      <optional user label>

SUMMARY
  assets        <count>
  observations  <count>
  evidence      <count>
  findings      <count>
  changes       <count>

FINDINGS
  CRITICAL  <count>
  HIGH      <count>
  MEDIUM    <count>
  next: ssc-init findings --pretty

CHANGES
  NEW         <count>
  CHANGED     <count>
  UNVERIFIED  <count>
  UPGRADED    <count>
  REMOVED     <count>
  next: ssc-init audit show <run-id> --section changes

COVERAGE
  complete     <count>
  partial      <count>
  unavailable  <count>
  next: ssc-init audit show <run-id> --section coverage

ASSETS
  <asset type>  <count>
  next: ssc-init audit show <run-id> --section assets

AUDIT EVIDENCE
  state      saved | unavailable
  file       $SSC_INIT_DATA/audit/<timestamp>-<run-id>.zip
  sha256     <digest when saved>
  verify     ssc-init audit verify <absolute-zip> --pretty
```

The exact rows are deterministic. Empty severity, change, and asset-type rows
may be omitted, while each section heading remains present. The report makes no
safety or enforcement claim.

`ssc-init status --pretty` uses the latest valid audit ZIP when one exists. If
only a legacy snapshot exists, it preserves the existing explicit legacy
notice and does not invent current-version coverage.

### 2.2 Audit commands

The new closed command surface is:

```text
ssc-init audit list --pretty|--json
ssc-init audit show <run-id> --pretty|--json
ssc-init audit show <run-id> --section findings|changes|coverage|assets|evidence
ssc-init audit export <run-id> --output <absolute.zip>
ssc-init audit export <run-id> --output <absolute.zip> --redacted
ssc-init audit verify <absolute.zip> --pretty|--json
```

`audit list` reports only run time, run state, optional label, artifact state,
and ZIP digest. `audit show` verifies the ZIP before rendering it. `audit
export` verifies the source and atomically writes a new ZIP without overwriting
an existing destination. `audit verify` needs neither the database nor the
network.

The optional scan label is supplied by a scan flag and is part of the verified
manifest. It has a closed length and character set. It never enters the ZIP
filename.

## 3. Architecture and data flow

A new `internal/audit` package owns the audit model, archive codec,
verification, retention, redaction, and render inputs. It does not run a scan
or open the inventory database itself.

The command layer creates run metadata before scanning:

- opaque run ID;
- start time;
- existing opaque local device ID; and
- optional validated label.

The data flow is:

```text
run metadata
  -> discovery / collection / analysis / snapshot persistence
  -> normalized audit model or failure receipt
  -> deterministic ZIP bytes
  -> self-verification
  -> private temporary file
  -> atomic rename into managed audit storage
  -> retention
  -> progressive-detail rendering from the same normalized model
```

Successful and partial runs build their audit model from the exact scan result,
inventory, delta, findings, and coverage used by the command. They do not read
the newly written snapshot back and reconstruct a different view. Failed runs
build a minimal receipt from run metadata, a closed stage, and a closed error
code.

The automatic archive directory is:

```text
$HOME/Library/Application Support/SSC Init/audit/
```

Managed archive names contain a canonical UTC timestamp and opaque run ID.
They contain no label, username, hostname, path, project name, or asset name.

An archive write failure after snapshot persistence does not turn a durable
scan into a failed scan. The command reports the truthful scan state and
`audit evidence unavailable`. A scan failure remains a failure even when its
receipt is saved successfully.

## 4. Archive contract

### 4.1 Complete and partial runs

The closed entry catalog is:

```text
manifest.json
summary.json
report.txt
inventory.json
findings.json
coverage.json
changes.json
```

### 4.2 Failed runs

The closed entry catalog is:

```text
manifest.json
summary.json
report.txt
failure.json
```

No other entry is valid. Missing required entries, duplicate names, nested
names, traversal components, links, or oversized entries invalidate the ZIP.

### 4.3 Manifest

The versioned manifest contains:

- schema version;
- run ID and optional scan ID;
- canonical start and finish UTC timestamps;
- opaque device ID;
- optional user label;
- `internal` or `redacted` profile;
- `complete`, `partial`, or `failed` run state;
- generator product and version;
- exact entry names, byte lengths, and SHA-256 digests; and
- a versioned authentication envelope whose initial state is explicitly
  `unsigned`.

The unsigned envelope is not an Apple-signing contract. A future organization
signature may authenticate the canonical manifest without changing inventory
collection or claiming that an Apple identity signed the executable.

### 4.4 Determinism and verification

The archive codec fixes entry order, compression method, entry timestamp,
mode, JSON encoding, and newline handling. Identical normalized input produces
byte-identical ZIP bytes.

Verification is fail-closed and bounded. It validates the outer ZIP size,
entry count, names, duplicate absence, compression ratio, uncompressed size,
manifest schema, manifest catalog, and every entry digest before decoding
report data. An invalid archive cannot be shown or exported.

SHA-256 detects mutation only when its expected value is held independently.
Without a trusted external digest or organization signature, SSC Init does not
claim origin authentication or non-repudiation.

## 5. Privacy profiles

Both profiles exclude absolute paths, raw URIs, usernames, hostnames, source
bytes, environment values, command arguments, remote endpoints, secrets,
workspace identifiers, product directory identifiers, and Git worktree
identifiers.

The `internal` profile may contain asset type, privacy-reviewed display name,
version, closed status and fact vocabularies, opaque canonical IDs, counts,
and digests already permitted by the public report contracts.

The `redacted` profile removes asset names and versions. It retains aggregate
counts and replaces internal opaque asset IDs with export-local tokens derived
from a fresh export salt. The salt is not reused between exports, preventing
straightforward correlation between internal and externally submitted
archives. Redaction creates and verifies a new deterministic archive relative
to its newly generated export model; it is not a byte copy of the internal
archive.

Privacy validation runs before archive encoding and again when an archive is
opened. A privacy-invalid model cannot be stored, shown, or exported.

## 6. Failure receipts and error handling

Failure stages form a closed vocabulary:

```text
initialize
discover
collect
analyze
persist
render
archive
```

A failure receipt stores only the stage, a closed error code, run metadata,
and timestamps. It never stores an original error string, OS diagnostic, path,
URI, or input value.

Existing command exit-code meanings remain unchanged. The detailed screen may
add a fixed diagnostic such as `FAILED stage=collect code=collector_failed`,
but it cannot expose the underlying error value.

If host-path initialization or the audit directory itself is unavailable, no
receipt can be promised. The command writes a fixed privacy-safe archive status
to stderr. Archive failures never suppress or replace the original command
failure.

Labels reject control characters, whitespace at either edge, path separators,
newlines, and values outside the fixed length and character set. Export paths
must be absolute. Export rejects unsafe parents, symlinked destinations, and
existing files.

## 7. Retention and concurrency

Managed automatic ZIPs are retained for 30 days and share a 1 GiB total size
cap. Cleanup removes the oldest valid managed archive first until both bounds
hold. The newest archive is retained regardless of age or size so there is
always a last execution receipt.

Corrupt archives are reported as `invalid` and are not silently deleted.
Explicitly exported ZIPs live outside managed storage and are never pruned by
SSC Init.

Archive publication and retention use a private lock and atomic rename. Two
concurrent scans cannot choose the same path, expose a partial ZIP, prune a
file another operation is reading, or corrupt the managed index. Temporary
files are private and cleaned up best-effort after interruption.

## 8. Testing and acceptance

The implementation must prove:

- deterministic pretty-output golden tests;
- byte-identical ZIPs for identical normalized input;
- complete, partial, and failed CLI-to-ZIP acceptance cases;
- offline ZIP verify, show, internal export, and redacted export;
- checksum, manifest, duplicate-entry, zip-slip, compression-ratio,
  oversize, and truncation mutations fail closed;
- privacy marker batteries for internal and redacted profiles;
- redacted exports from separate runs are not ID-correlatable;
- label control-character and path-injection rejection;
- export destination symlink, existing-file, and unsafe-parent rejection;
- retention edges at 30 days and 1 GiB, with the newest archive retained;
- concurrent scan, list, show, export, and pruning behavior under the race
  detector;
- snapshot success plus archive failure reports the durable scan truthfully;
- failure receipts contain no injected underlying error string;
- the progressive report and archive derive from the same audit model;
- existing JSON schemas and command exit codes do not change; and
- the full build, vet, race, module, diff, and reproducible release-script
  gates remain green.

Mutation tests must remove or bypass checksum verification, privacy validation,
redaction retokenization, atomic publication, newest-file retention, failure
string sanitization, and progressive-report model sharing; the named tests must
fail before each guard is restored.

## 9. Non-goals

This design does not add:

- a browser or desktop dashboard;
- remote storage, telemetry, or automatic upload;
- Apple App Store distribution or Apple code signing;
- automatic organization signing or key management;
- arbitrary archive formats other than the single ZIP contract;
- automatic host blocking or remediation; or
- any new process, network, or external-command probe during a default scan.
