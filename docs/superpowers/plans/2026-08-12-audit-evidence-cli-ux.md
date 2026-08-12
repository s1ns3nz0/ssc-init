# Audit Evidence and Detailed CLI UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a deterministic, privacy-safe audit ZIP for every complete, partial, or failed baseline scan and expose progressive-detail CLI commands that verify and render those artifacts offline.

**Architecture:** A new `internal/audit` package owns one normalized audit model, deterministic ZIP encoding/verification, privacy profiles, managed retention, and rendering inputs. The command layer creates run metadata, gives completed scan data or a closed failure receipt to the audit service, and renders from the same normalized model that was archived; archive failure never rewrites the truthful scan outcome.

**Tech Stack:** Go standard library (`archive/zip`, `crypto/sha256`, `encoding/json`, `io/fs`, `os`), existing `internal/model`, `internal/privacy`, `internal/platform`, `internal/report`, SQLite snapshot store, table-driven Go tests, race detector.

## Global Constraints

- Default scans execute no process, network request, or discovered content.
- Existing `ssc-init.scan.v7`, `ssc-init.status.v7`, findings, policy, hook, and command exit-code contracts remain compatible.
- Audit ZIPs never contain raw paths, URIs, usernames, hostnames, source bytes, environment values, command arguments, remote endpoints, secrets, workspace/product/worktree identifiers, or original error strings.
- Automatic archives live only under `$HOME/Library/Application Support/SSC Init/audit` and use a canonical UTC timestamp plus opaque run ID as their filename.
- Managed retention is exactly 30 days and 1 GiB; the newest archive is always retained. Explicit exports are never pruned.
- The only artifact format is ZIP. Complete/partial and failed entry catalogs are closed and versioned.
- ZIP entry count, compressed bytes, uncompressed bytes, compression ratio, names, and JSON decode sizes are bounded before allocation or decode.
- The initial authentication envelope is explicitly `unsigned`; this work adds no Apple signing, organization signing, remote upload, or key management.
- All writes are private temporary files followed by atomic rename. Existing export destinations, unsafe parents, and symlinked destinations are rejected.
- Every production fix follows RED → GREEN → refactor, with the named test observed failing before implementation.

## File responsibility map

- `internal/audit/model.go`: closed audit schemas, validation, normalization, label and failure vocabularies.
- `internal/audit/privacy.go`: internal/redacted transformations and privacy validation.
- `internal/audit/archive.go`: deterministic ZIP encoding and bounded fail-closed verification.
- `internal/audit/manager.go`: atomic managed storage, list/show/export, lock, and retention.
- `internal/audit/render.go`: progressive summary and section renderers derived only from `audit.Record`.
- `internal/cli/options.go`: closed audit command and scan-label parsing.
- `internal/cli/run.go`: dependency-driven scan/audit/status/audit command execution.
- `cmd/ssc-init/main.go`: host wiring, run metadata, audit manager, findings evaluation, and failure-stage mapping.
- `internal/platform/paths.go`: owned audit directory path.
- `internal/acceptance/audit_evidence_test.go`: real CLI/store/archive end-to-end and mutation battery.
- `README.md`, `CLAUDE.md`, `docs/release-runbook.md`: user, maintainer, and verification contracts.

---

### Task 1: Closed audit model, normalization, and privacy profiles

**Files:**
- Create: `internal/audit/model.go`
- Create: `internal/audit/model_test.go`
- Create: `internal/audit/privacy.go`
- Create: `internal/audit/privacy_test.go`
- Modify: `internal/platform/paths.go`
- Modify: `internal/platform/paths_test.go`

**Interfaces:**
- Consumes: `model.ScanResult`, `model.Inventory`, `model.Delta`, `[]model.Finding`, opaque `device:sha256:<64 hex>` identity.
- Produces:

```go
package audit

type Profile string
const (
    ProfileInternal Profile = "internal"
    ProfileRedacted Profile = "redacted"
)

type State string
const (
    StateComplete State = "complete"
    StatePartial  State = "partial"
    StateFailed   State = "failed"
)

type Stage string
const (
    StageInitialize Stage = "initialize"
    StageDiscover   Stage = "discover"
    StageCollect    Stage = "collect"
    StageAnalyze    Stage = "analyze"
    StagePersist    Stage = "persist"
    StageRender     Stage = "render"
    StageArchive    Stage = "archive"
)

type Run struct {
    ID, ScanID, DeviceID, Label, Product, Version string
    StartedAt, FinishedAt time.Time
}

type Failure struct { Stage Stage `json:"stage"`; Code string `json:"code"` }

const (
    CodeInitializeFailed  = "initialize_failed"
    CodeDiscoveryFailed   = "discovery_failed"
    CodeCollectorFailed   = "collector_failed"
    CodeAnalyzerFailed    = "analyzer_failed"
    CodePersistenceFailed = "persistence_failed"
    CodeRenderFailed      = "render_failed"
    CodeAuditUnavailable  = "audit_unavailable"
)

type Record struct {
    SchemaVersion string
    Profile Profile
    State State
    Run Run
    Summary Summary
    Inventory model.Inventory
    Findings []model.Finding
    Coverage []model.CollectorResult
    EvidenceCoverage *model.EvidenceCoverage
    Changes model.Delta
    Failure *Failure
}

func Build(scan model.ScanResult, inventory model.Inventory, delta model.Delta, findings []model.Finding, run Run) (Record, error)
func BuildFailure(run Run, stage Stage, code string) (Record, error)
func Redact(record Record, salt [32]byte) (Record, error)
func Validate(record Record) error
func ValidLabel(string) bool
```

- `platform.Paths.Install().AuditDir` returns `<DataDir>/audit`.

- [ ] **Step 1: Write failing model and label tests**

```go
func TestBuildCreatesClosedCompleteAndPartialRecords(t *testing.T) {
    complete, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, validRun())
    if err != nil || complete.State != StateComplete { t.Fatalf("complete=%+v err=%v", complete, err) }
    partial, err := Build(model.ScanResult{Status: model.ScanPartial}, model.Inventory{}, model.Delta{}, nil, validRun())
    if err != nil || partial.State != StatePartial { t.Fatalf("partial=%+v err=%v", partial, err) }
}
func TestBuildFailureAcceptsOnlyClosedStageAndCode(t *testing.T) {
    if _, err := BuildFailure(validRun(), StageCollect, "collector_failed"); err != nil { t.Fatal(err) }
    if _, err := BuildFailure(validRun(), Stage("/Users/alice"), "secret=value"); err == nil { t.Fatal("accepted open failure values") }
}
func TestValidLabelRejectsPathsWhitespaceAndControls(t *testing.T) {
    for _, value := range []string{"/tmp/a", `a\\b`, "a\nb", " edge", "edge ", strings.Repeat("a", 65)} {
        if ValidLabel(value) { t.Fatalf("accepted label %q", value) }
    }
}
```

- [ ] **Step 2: Run the model tests and observe RED**

Run: `go test ./internal/audit -run 'Test(Build|ValidLabel)' -count=1 -v`

Expected: FAIL because `internal/audit` and its public types do not exist.

- [ ] **Step 3: Implement the closed model and validation**

Implement exact schema `ssc-init.audit-record.v1`, sorted/deep-copied slices, UTC timestamps, valid scan/failure state pairing, opaque run/device IDs, the seven failure codes above, and summary counts. Run IDs are `run:hex:` plus 32 lowercase random hex characters. Labels are 1–64 ASCII characters from letters, digits, spaces, `.`, `_`, and `-`, with an alphanumeric first and last character. Do not retain an `error` or arbitrary message field.

- [ ] **Step 4: Write failing internal/redacted privacy tests**

```go
func TestValidateRejectsEverySensitiveMarker(t *testing.T) {
    for _, marker := range []string{"/Users/alice/private", "file:///Users/alice", "vscode-remote://ssh-remote+secret", "worktree-secret"} {
        record := validRecord(); record.Run.Label = marker
        if Validate(record) == nil { t.Fatalf("accepted marker %q", marker) }
    }
}
func TestRedactRemovesNamesVersionsAndRetokenizesIDs(t *testing.T) {
    first, _ := Redact(namedRecord(), [32]byte{1}); second, _ := Redact(namedRecord(), [32]byte{2})
    if first.Inventory.Assets[0].Name != "" || first.Inventory.Assets[0].Version != "" { t.Fatal("identity display survived") }
    if first.Inventory.Assets[0].ID == second.Inventory.Assets[0].ID { t.Fatal("tokens correlate across salts") }
}
func TestRedactPreservesCountsStatusesAndRelationships(t *testing.T) {
    source := namedRecord(); redacted, err := Redact(source, [32]byte{3})
    if err != nil || len(redacted.Inventory.Assets) != len(source.Inventory.Assets) || len(redacted.Inventory.Relationships) != len(source.Inventory.Relationships) || redacted.State != source.State { t.Fatalf("redacted=%+v err=%v", redacted, err) }
}
```

- [ ] **Step 5: Run the privacy tests and observe RED**

Run: `go test ./internal/audit -run 'Test(ValidateRejects|Redact)' -count=1 -v`

Expected: FAIL because privacy validation and redaction are not implemented.

- [ ] **Step 6: Implement privacy validation and redaction**

Use the existing `privacy.ContainsSensitiveValue` boundary plus audit-specific closed-value validation. Generate export-local tokens as `asset:export-sha256:<HMAC-SHA256(salt, canonical-id)>`; rewrite every reference consistently, clear name/version/digest-bearing display fields not allowed by the redacted profile, and validate again after transformation.

- [ ] **Step 7: Add the owned audit path**

```go
type InstallLayout struct {
    AuditDir string
}
```

Lock `PathsForHome(home).Install().AuditDir == filepath.Join(home, "Library", "Application Support", "SSC Init", "audit")` in a platform test.

- [ ] **Step 8: Run focused and race tests**

Run: `go test -race ./internal/audit ./internal/platform -count=1`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/audit internal/platform/paths.go internal/platform/paths_test.go
git commit -m "feat: define privacy-safe audit records"
```

---

### Task 2: Deterministic ZIP codec and fail-closed verifier

**Files:**
- Create: `internal/audit/archive.go`
- Create: `internal/audit/archive_test.go`

**Interfaces:**
- Consumes: validated `audit.Record` from Task 1.
- Produces:

```go
type EntryDigest struct { Name string `json:"name"`; Size int64 `json:"size"`; SHA256 string `json:"sha256"` }
type Manifest struct {
    SchemaVersion string `json:"schemaVersion"`
    Run Run `json:"run"`
    Profile Profile `json:"profile"`
    State State `json:"state"`
    Authentication string `json:"authentication"` // exactly "unsigned" in v1
    Entries []EntryDigest `json:"entries"`
}
type Verified struct { Manifest Manifest; Record Record; ZIPSHA256 string }

func Encode(record Record, reportText []byte) ([]byte, error)
func Verify(reader io.ReaderAt, size int64) (Verified, error)
```

- [ ] **Step 1: Write failing deterministic catalog tests**

```go
func TestEncodeIsByteIdenticalAndUsesClosedCatalog(t *testing.T) {
    first, err := Encode(validRecord(), []byte("report\n")); if err != nil { t.Fatal(err) }
    second, err := Encode(validRecord(), []byte("report\n")); if err != nil { t.Fatal(err) }
    if !bytes.Equal(first, second) { t.Fatal("archive is nondeterministic") }
    assertZIPNames(t, first, "manifest.json", "summary.json", "report.txt", "inventory.json", "findings.json", "coverage.json", "changes.json")
}
func TestEncodeFailureUsesFailureCatalogOnly(t *testing.T) {
    encoded, err := Encode(validFailureRecord(), []byte("failed\n")); if err != nil { t.Fatal(err) }
    assertZIPNames(t, encoded, "manifest.json", "summary.json", "report.txt", "failure.json")
}
```

- [ ] **Step 2: Run the codec tests and observe RED**

Run: `go test ./internal/audit -run 'TestEncode' -count=1 -v`

Expected: FAIL because `Encode` does not exist.

- [ ] **Step 3: Implement canonical entry payloads and ZIP encoding**

Use fixed order, `zip.Deflate`, `time.Unix(0, 0).UTC()`, mode `0600`, UTF-8 flag, canonical JSON followed by one newline, and caller-supplied `report.txt` bytes. Task 4 supplies the production renderer; codec tests use a fixed privacy-safe fixture. Hash non-manifest entries first, then encode the manifest and ZIP in one deterministic pass.

- [ ] **Step 4: Write failing adversarial verifier tests**

```go
func TestVerifyRejectsChecksumMutation(t *testing.T) { assertVerifyError(t, mutateEntry(validArchive(), "summary.json")) }
func TestVerifyRejectsDuplicateTraversalAndUnknownEntries(t *testing.T) {
    for _, archive := range [][]byte{zipWithNames("manifest.json", "manifest.json"), zipWithNames("../secret"), zipWithNames("unknown.json")} { assertVerifyError(t, archive) }
}
func TestVerifyRejectsOuterEntryExpansionAndRatioLimits(t *testing.T) {
    for _, archive := range [][]byte{zipOverOuterLimit(), zipWithNineEntries(), zipWithExpandedBytes(128<<20+1), zipWithRatio(101)} { assertVerifyError(t, archive) }
}
func TestVerifyRejectsPrivacyInvalidDecodedRecords(t *testing.T) { assertVerifyError(t, archiveContainingMarker("/Users/alice/private")) }
```

The fixtures cover an outer limit of 256 MiB, at most 8 entries, at most 128 MiB total uncompressed bytes, at most 64 MiB per entry, and compression ratio at most 100:1.

- [ ] **Step 5: Run the verifier tests and observe RED**

Run: `go test ./internal/audit -run 'TestVerifyRejects' -count=1 -v`

Expected: FAIL because invalid archives are accepted or verification is absent.

- [ ] **Step 6: Implement bounded verification**

Reject the archive before JSON decode if any outer bound, entry name, duplicate, catalog, size, ratio, CRC/read, or manifest digest check fails. Decode each JSON through an `io.LimitedReader`, require EOF after one value, rebuild `Record`, and call `Validate`.

- [ ] **Step 7: Run focused, repeat, and race tests**

Run: `go test ./internal/audit -run 'Test(Encode|Verify)' -count=20`

Run: `go test -race ./internal/audit -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/audit/archive.go internal/audit/archive_test.go
git commit -m "feat: encode verifiable audit archives"
```

---

### Task 3: Atomic audit manager, export, and bounded retention

**Files:**
- Create: `internal/audit/manager.go`
- Create: `internal/audit/manager_test.go`

**Interfaces:**
- Consumes: Task 2 `Encode`, `Verify`, and Task 1 `Redact`.
- Produces:

```go
type Stored struct { RunID, SafePath, SHA256 string; State State; Profile Profile; CreatedAt time.Time; Size int64; Valid bool }
type Manager struct { Root, Home string; Now func() time.Time; Random io.Reader; Render func(Record) ([]byte, error) }

func (m *Manager) Save(ctx context.Context, record Record) (Stored, error)
func (m *Manager) List(ctx context.Context) ([]Stored, error)
func (m *Manager) Open(ctx context.Context, runID string) (Verified, error)
func (m *Manager) Export(ctx context.Context, runID, absoluteOutput string, redacted bool) (Stored, error)
func (m *Manager) Prune(ctx context.Context) error
```

`SafePath` is `$SSC_INIT_DATA/audit/<filename>`, never an absolute host path.

- [ ] **Step 1: Write failing atomic save and safe-list tests**

```go
func TestManagerSavePublishesOnlyVerifiedPrivateZIP(t *testing.T) { assertSavedModeAndVerification(t, newTestManager(t), validRecord(), 0o600) }
func TestManagerListMarksCorruptArchiveInvalidWithoutDeletingIt(t *testing.T) { assertCorruptArchiveListedAndPreserved(t, newTestManager(t)) }
func TestManagerRejectsSymlinkedRootAndArchive(t *testing.T) { assertManagedSymlinksRejected(t, newTestManager(t)) }
```

- [ ] **Step 2: Run manager tests and observe RED**

Run: `go test ./internal/audit -run 'TestManager(Save|List|Rejects)' -count=1 -v`

Expected: FAIL because `Manager` does not exist.

- [ ] **Step 3: Implement descriptor-safe managed storage**

Create root mode `0700`, lock a fixed private lock file, use exclusive mode `0600` temp files in the verified root, fsync file and parent, verify temp bytes, then rename. Enumerate a closed filename pattern in sorted bounded batches and never follow symlinks.

- [ ] **Step 4: Write failing export and retention tests**

```go
func TestManagerExportIsAtomicNoClobberAndRejectsUnsafeParents(t *testing.T) { assertExportNoClobberAndNoSymlinkTraversal(t, newTestManager(t)) }
func TestManagerRedactedExportsUseFreshUnlinkableTokens(t *testing.T) { assertTwoRedactedExportsHaveDifferentTokens(t, newTestManager(t)) }
func TestManagerPruneEnforcesThirtyDaysAndOneGiBButKeepsNewest(t *testing.T) { assertAgeAndSizeBoundsKeepNewest(t, newTestManager(t), 30*24*time.Hour, 1<<30) }
func TestManagerConcurrentSaveOpenExportAndPrune(t *testing.T) { assertConcurrentManagerOperations(t, newTestManager(t), 32) }
```

- [ ] **Step 5: Run export/retention tests and observe RED**

Run: `go test ./internal/audit -run 'TestManager(Export|Redacted|Prune|Concurrent)' -count=1 -v`

Expected: FAIL because export, retention, and locking are absent.

- [ ] **Step 6: Implement export and retention**

Internal export verifies and atomically copies identical bytes. Redacted export decodes, calls `Redact` with 32 fresh random bytes, renders the transformed record through the injected deterministic `Render` function, re-encodes, verifies, and atomically publishes. Manager tests inject a fixed renderer; Task 5 wires `audit.ReportText`. Prune valid managed archives oldest-first after every save; preserve the newest even if it alone exceeds either bound. Leave corrupt archives and exports outside `Root` untouched.

- [ ] **Step 7: Run focused and race tests**

Run: `go test ./internal/audit -count=1`

Run: `go test -race ./internal/audit -run 'TestManager' -count=20`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/audit/manager.go internal/audit/manager_test.go
git commit -m "feat: retain and export audit archives"
```

---

### Task 4: Progressive-detail audit renderer

**Files:**
- Create: `internal/audit/render.go`
- Create: `internal/audit/render_test.go`
- Modify: `internal/report/pretty.go`
- Modify: `internal/report/pretty_test.go`

**Interfaces:**
- Consumes: Task 1 `Record`, Task 3 `Stored`.
- Produces:

```go
type Section string
const (
    SectionFindings Section = "findings"
    SectionChanges Section = "changes"
    SectionCoverage Section = "coverage"
    SectionAssets Section = "assets"
    SectionEvidence Section = "evidence"
)

func WritePretty(w io.Writer, record Record, stored *Stored) error
func WriteSection(w io.Writer, record Record, section Section) error
func WriteList(w io.Writer, records []Stored) error
func WriteVerify(w io.Writer, verified Verified, safePath string) error
func ReportText(record Record) ([]byte, error)
```

- [ ] **Step 1: Write failing golden tests for layout C**

```go
func TestWritePrettyRendersProgressiveAuditSummary(t *testing.T) {
    var output bytes.Buffer
    if err := WritePretty(&output, populatedRecord(), &Stored{SafePath: "$SSC_INIT_DATA/audit/run.zip", SHA256: strings.Repeat("a", 64)}); err != nil { t.Fatal(err) }
    assertOrdered(t, output.String(), "SSC Init audit", "SUMMARY", "FINDINGS", "CHANGES", "COVERAGE", "ASSETS", "AUDIT EVIDENCE")
}
func TestWritePrettyFailureShowsOnlyClosedStageAndCode(t *testing.T) { assertFailureOutputEquals(t, validFailureRecord(), "FAILED stage=collect code=collector_failed") }
func TestReportTextMatchesStoredReportEntry(t *testing.T) { assertReportTextEqualsVerifiedEntry(t, populatedRecord()) }
```

- [ ] **Step 2: Run renderer tests and observe RED**

Run: `go test ./internal/audit -run 'Test(WritePretty|ReportText)' -count=1 -v`

Expected: FAIL because progressive rendering is absent.

- [ ] **Step 3: Implement deterministic summary and section renderers**

Reuse the existing tabwriter/rung vocabulary without importing CLI. Sort severity, change rung, coverage status, asset type, and record rows by closed rank then canonical ID. Never print a digest-anchored ID as a display name. Always render `AUDIT EVIDENCE` with saved/unavailable state.

- [ ] **Step 4: Preserve legacy status rendering**

Keep `report.WriteStatusPretty` unchanged for legacy snapshots. Add a test proving v3 status still renders the four-line legacy notice and makes no current coverage claim.

- [ ] **Step 5: Run focused and race tests**

Run: `go test -race ./internal/audit ./internal/report -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/audit/render.go internal/audit/render_test.go internal/report/pretty.go internal/report/pretty_test.go
git commit -m "feat: render progressive audit reports"
```

---

### Task 5: Closed CLI audit commands and offline operations

**Files:**
- Modify: `internal/cli/options.go`
- Modify: `internal/cli/options_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`

**Interfaces:**
- Consumes: Task 3 `audit.Manager`, Task 4 renderers.
- Produces additions to `cli.Options`:

```go
AuditCommand string
AuditRunID string
AuditSection string
AuditOutput string
AuditRedacted bool
ScanLabel string
```

and `cli.App`:

```go
AuditManager interface {
    List(context.Context) ([]audit.Stored, error)
    Open(context.Context, string) (audit.Verified, error)
    Export(context.Context, string, string, bool) (audit.Stored, error)
}
```

- [ ] **Step 1: Write failing parser tests for every accepted and rejected form**

```go
func TestParseOptionsAcceptsClosedAuditForms(t *testing.T) { assertAcceptedAuditForms(t, documentedAuditArgumentVectors()) }
func TestParseOptionsRejectsAmbiguousAuditFormsAndInvalidLabels(t *testing.T) { assertRejectedOptions(t, ambiguousAuditArgumentVectors()) }
func TestParseOptionsAcceptsScanLabelOnlyOnBaselineScan(t *testing.T) { assertScanLabelIsBaselineOnly(t, "audit-mac") }
```

- [ ] **Step 2: Run parser tests and observe RED**

Run: `go test ./internal/cli -run 'TestParseOptions.*Audit|TestParseOptionsAcceptsScanLabel' -count=1 -v`

Expected: FAIL because command/flags are rejected.

- [ ] **Step 3: Implement exact command-aware parsing**

Require one of `--pretty|--json` for list/show/verify, allow `--section` only with show and pretty, require absolute `--output` only for export, and allow `--redacted` only for export. Validate run IDs and labels through closed helpers without echoing values in errors.

- [ ] **Step 4: Write failing injected-service command tests**

```go
func TestAuditListShowVerifyAndExportUseInjectedManager(t *testing.T) { assertAuditCommandsCallOnlyExpectedManagerMethod(t) }
func TestAuditShowRejectsInvalidArchiveWithoutRendering(t *testing.T) { assertInvalidArchiveProducesFixedErrorAndEmptyStdout(t) }
func TestStatusPrettyPrefersLatestValidAuditButKeepsLegacyFallback(t *testing.T) { assertAuditPreferredAndLegacyFallbackPreserved(t) }
```

- [ ] **Step 5: Run command tests and observe RED**

Run: `go test ./internal/cli -run 'Test(Audit|StatusPrettyPrefers)' -count=1 -v`

Expected: FAIL because `RunOptions` has no audit branch or manager.

- [ ] **Step 6: Implement offline CLI behavior and main wiring**

Wire `audit.Manager{Root: paths.Install().AuditDir, Home: home, Render: audit.ReportText}` for `audit` and `status`. `audit verify` receives an absolute path but never echoes it; expose `$SSC_INIT_DATA` safe references. No audit command opens the snapshot DB except legacy status fallback. Add `audit` to operational macOS commands.

- [ ] **Step 7: Run focused and race tests**

Run: `go test -race ./internal/cli ./cmd/ssc-init -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/options.go internal/cli/options_test.go internal/cli/run.go internal/cli/run_test.go cmd/ssc-init/main.go cmd/ssc-init/main_test.go
git commit -m "feat: expose offline audit commands"
```

---

### Task 6: Successful/partial scan archiving and truthful progressive output

**Files:**
- Create: `internal/audit/service.go`
- Create: `internal/audit/service_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`

**Interfaces:**
- Consumes: scanner result, finding evaluation, Task 1 builder, Task 3 manager, Task 4 renderer.
- Produces:

```go
type Service struct { Manager *Manager; Product, Version, DeviceID string; Now func() time.Time; Random io.Reader }
type Outcome struct { Record Record; Stored *Stored; ArchiveErrorCode string }

func (s Service) Complete(ctx context.Context, run Run, scan model.ScanResult, inventory model.Inventory, delta model.Delta, findings []model.Finding) Outcome
func (s Service) Fail(ctx context.Context, run Run, stage Stage, code string) Outcome
```

and `cli.App.AuditService` as a narrow interface around these methods.

- [ ] **Step 1: Write failing service truthfulness tests**

```go
func TestServiceCompleteArchivesExactModelUsedForRendering(t *testing.T) { assertOutcomeRecordEqualsVerifiedArchiveRecord(t) }
func TestServiceArchiveFailurePreservesCompleteOrPartialScanState(t *testing.T) { assertArchiveFailureOnlySetsUnavailableCode(t) }
func TestServicePrunesOnlyAfterVerifiedPublication(t *testing.T) { assertPruneOccursAfterVerifyAndRename(t) }
```

- [ ] **Step 2: Run service tests and observe RED**

Run: `go test ./internal/audit -run 'TestService' -count=1 -v`

Expected: FAIL because the service is absent.

- [ ] **Step 3: Implement service composition**

Build once, save once, and return the same deep-copied `Record` for rendering. Convert archive errors to a closed `audit_unavailable` code without changing `Record.State`. Never embed the error text.

- [ ] **Step 4: Write failing scan integration tests**

```go
func TestScanPrettyArchivesAndRendersTheSameCompleteRecord(t *testing.T) { assertPrettyRunMatchesArchivedRecord(t) }
func TestScanJSONPreservesV7PayloadAndStillArchives(t *testing.T) { assertExistingV7JSONBytesAndArchiveBothProduced(t) }
func TestScanArchiveFailureReturnsScanSuccessWithUnavailableEvidence(t *testing.T) { assertExitZeroAndUnavailableEvidence(t) }
```

- [ ] **Step 5: Run scan integration tests and observe RED**

Run: `go test ./internal/cli ./cmd/ssc-init -run 'TestScan.*Archiv' -count=1 -v`

Expected: FAIL because scan bypasses the audit service.

- [ ] **Step 6: Integrate run metadata, findings, archive, and output**

Create run ID and load device ID before the scan. After `Baseline`, evaluate findings over the returned inventory using already wired managers, call `AuditService.Complete`, then render pretty from `Outcome.Record` or preserve the existing JSON output. Print only the safe archive reference and digest. Hook scans also archive automatically but retain the existing advisory/silent hook output contract.

- [ ] **Step 7: Run focused and race tests**

Run: `go test -race ./internal/audit ./internal/cli ./cmd/ssc-init -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/audit/service.go internal/audit/service_test.go internal/cli/run.go internal/cli/run_test.go cmd/ssc-init/main.go cmd/ssc-init/main_test.go
git commit -m "feat: archive every completed scan"
```

---

### Task 7: Failed-run receipts, acceptance, retention proof, and documentation

**Files:**
- Create: `internal/acceptance/audit_evidence_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/release-runbook.md`

**Interfaces:**
- Consumes: all prior tasks.
- Produces: end-to-end automatic audit evidence for every scan attempt and documented operator workflow.

- [ ] **Step 1: Write failing closed failure-receipt tests**

```go
func TestScanFailureArchivesPrivacySafeReceiptAndKeepsExitCode(t *testing.T) { assertFailureReceiptHasClosedValuesAndExitOne(t) }
func TestInitializationWithoutWritableAuditRootReportsUnavailableWithoutRawError(t *testing.T) { assertFixedUnavailableMessageWithoutInjectedMarker(t) }
func TestHookFailureArchivesReceiptButKeepsAdvisoryExitZero(t *testing.T) { assertHookReceiptExistsAndExitIsZero(t) }
```

Inject unique secret/path/error markers and assert none appear in stdout, stderr, ZIP entries, archive names, list/show output, or persisted DB values.

- [ ] **Step 2: Run failure tests and observe RED**

Run: `go test ./internal/cli ./cmd/ssc-init -run 'Test(ScanFailureArchives|InitializationWithout|HookFailureArchives)' -count=1 -v`

Expected: FAIL because error paths do not call `AuditService.Fail`.

- [ ] **Step 3: Add structural failure-stage mapping**

Carry a typed closed failure from main initialization/discovery and CLI scanning instead of classifying by string. Best-effort call `Fail` exactly once. Preserve original exit codes and hook exit zero. An archive failure appends only `audit evidence unavailable` and never replaces the original fixed command message.

- [ ] **Step 4: Write full isolated-home acceptance**

The acceptance creates a private HOME and real SQLite store, runs:

```text
scan --baseline --pretty --label audit-mac
audit list --pretty
audit show <run-id> --section assets
audit verify <managed-zip> --pretty
audit export <run-id> --output <external.zip>
audit export <run-id> --output <redacted.zip> --redacted
status --pretty
```

It verifies the snapshot reload, exact progressive section order, matching run/scan IDs, managed ZIP digest, offline reopen after DB removal, internal names/versions, redacted name/version absence, unlinkable redacted IDs, and no process/network runner calls.

- [ ] **Step 5: Run acceptance and observe RED**

Run: `go test ./internal/acceptance -run TestAuditEvidenceLifecycle -count=1 -v`

Expected: FAIL until the complete production path is wired.

- [ ] **Step 6: Close acceptance gaps without broadening scope**

Make only the minimal production changes needed for the actual CLI/store/archive path. Do not add test-only production callbacks when an existing injected filesystem, clock, random source, manager, or service interface suffices.

- [ ] **Step 7: Execute and record the mutation battery**

For each mutation, apply it temporarily, run the named test and observe failure, then restore before the next mutation:

1. Skip entry SHA-256 comparison → checksum mutation test RED.
2. Skip archive privacy validation → acceptance privacy battery RED.
3. Reuse internal IDs in redacted export → unlinkability test RED.
4. Publish before verify/rename → atomic publication test RED.
5. Allow retention to delete newest → retention edge test RED.
6. Persist original error string → failure marker test RED.
7. Render from scan separately from archived record → exact report/model test RED.

- [ ] **Step 8: Update documentation**

Document the C-layout screen, automatic complete/partial/failed ZIP, 30-day/1-GiB policy, latest preservation, exact audit commands, internal/redacted distinction, offline verification, unsigned limitation, and future organization-signature boundary. State that GitHub remains the distribution channel and Apple signing is unrelated.

- [ ] **Step 9: Format and run pre-commit gates**

Run:

```bash
gofmt -w internal/audit/*.go internal/acceptance/audit_evidence_test.go internal/cli/*.go cmd/ssc-init/*.go internal/platform/*.go
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 10: Commit**

```bash
git add internal/acceptance/audit_evidence_test.go internal/cli/run.go internal/cli/run_test.go cmd/ssc-init/main.go cmd/ssc-init/main_test.go README.md CLAUDE.md docs/release-runbook.md
git commit -m "test: prove audit evidence lifecycle"
```

- [ ] **Step 11: Run clean-tree release gates sequentially**

Run:

```bash
git status --short
go test -race -count=1 ./...
go test ./scripts -count=1
git status --short
```

Expected: both status commands print nothing and both tests exit 0. Run the scripts test only after the full race command exits so their shared `dist` fixtures cannot collide.

---

## Final review gate

- Generate one review package for the full branch from the design commit to HEAD.
- Review every requirement in `docs/superpowers/specs/2026-08-12-audit-evidence-cli-ux-design.md` against code, mutation evidence, acceptance output, and gate logs.
- No open Critical or Important finding may remain.
- Run a fresh clean-tree `go test -race -count=1 ./...` and then `go test ./scripts -count=1` sequentially.
- Exercise the built CLI once in an isolated HOME and retain the resulting ZIP, `audit verify --pretty`, and `audit show --pretty` output as final evidence.
