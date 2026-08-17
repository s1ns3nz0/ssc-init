# Signed TI Publication and Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish signed OSV/OpenSSF threat intelligence and let an explicit CLI update affect findings in the same baseline scan without adding network access to default scans.

**Architecture:** A deterministic offline publisher converts pinned OSV-format inputs into the existing signed TI envelope plus a separately signed update manifest. A bounded GitHub-only updater verifies that manifest and delegates final activation to the existing atomic bundle manager. Package correlation uses a shared canonical coordinate, and CLI orchestration exposes explicit update/status state while preserving last-known-good behavior.

**Tech Stack:** Go 1.26 standard library, Ed25519/SHA-256, existing SSC Init bundle/finding/audit packages, `net/http`, GitHub Actions, OSV JSON fixtures.

**Spec:** `docs/superpowers/specs/2026-08-14-ti-publication-update-design.md`

## Global Constraints

- Default `scan --baseline` performs zero network requests; only `bundle update --family ti` and `scan --update-ti` may fetch.
- Production accepts only family-scoped compiled Ed25519 public keys; test private keys never enter production packages or release assets.
- Feed source repository is fixed to `s1ns3nz0/ssc-init-ti`; arbitrary URLs and user trust roots are forbidden.
- Initial ecosystems are exactly npm, PyPI, Go, and crates.io.
- OpenSSF exact package/version or digest matches alone may produce `known-malicious`; ordinary OSV records default to `needs-review`, with `suspicious/high` only for valid CVSS base score ≥ 9.0.
- Missing versions, withdrawn records, false-positive exclusions, unsupported ranges, and ambiguous identities do not match.
- Manifest limit is 64 KiB, signature limit 1 KiB, bundle limit 16 MiB, record limit 100,000, total update deadline 45 seconds, per-request deadline 15 seconds, and redirect limit two.
- Update failures preserve last-known-good bytes and expose only closed codes; no response body, URL query, local path, hostname, package inventory, or raw source record enters output or audit evidence.
- JSON contracts remain ANSI-free and machine-stable; terminal color remains TTY-only and never means an unmatched asset is safe.
- Every task follows strict RED → GREEN, includes a mutation-sensitive assertion, receives independent review, and ends in a focused commit.

---

### Task 1: Canonical Package Coordinate and Correct TI Correlation

**Files:**
- Create: `internal/packageid/coordinate.go`
- Create: `internal/packageid/coordinate_test.go`
- Modify: `internal/finding/correlate.go`
- Modify: `internal/finding/correlate_test.go`
- Modify: `internal/bundle/ti_test.go`

**Interfaces:**
- Produces: `packageid.Coordinate(asset model.Asset) (string, bool)` and `packageid.FromOSV(ecosystem, name string) (string, bool)`.
- Changes: `bundle.TIRecord.AssetID` stores a version-independent canonical coordinate such as `pkg:pypi/requests`; `VersionRange` and `SHA256` remain separate selectors.
- Consumes: existing `versionanalyzer.Match(asset.ID, asset.Version, record.VersionRange)`.

- [x] **Step 1: Write failing coordinate and correlation tests**

```go
func TestCoordinateMatchesCollectorAndOSVIdentities(t *testing.T) {
    cases := []struct{ asset model.Asset; ecosystem, name, want string }{
        {model.Asset{ID: "pkg:npm/%40scope/tool@2.0.0", Type: model.AssetPackage, Name: "@scope/tool", Version: "2.0.0"}, "npm", "@scope/tool", "pkg:npm/%40scope/tool"},
        {model.Asset{ID: "pkg:pypi/Foo_Bar@1.0.0", Type: model.AssetPackage, Name: "Foo_Bar", Version: "1.0.0"}, "PyPI", "Foo_Bar", "pkg:pypi/foo-bar"},
        {model.Asset{ID: "pkg:golang/example.com/mod@v1.2.0", Type: model.AssetPackage, Name: "example.com/mod", Version: "v1.2.0"}, "Go", "example.com/mod", "pkg:golang/example.com/mod"},
        {model.Asset{ID: "pkg:cargo/serde_core@1.0.0", Type: model.AssetPackage, Name: "serde_core", Version: "1.0.0"}, "crates.io", "serde_core", "pkg:cargo/serde_core"},
    }
    for _, tc := range cases {
        gotAsset, okAsset := Coordinate(tc.asset)
        gotOSV, okOSV := FromOSV(tc.ecosystem, tc.name)
        if !okAsset || !okOSV || gotAsset != tc.want || gotOSV != tc.want { t.Fatalf("asset=%q osv=%q", gotAsset, gotOSV) }
    }
}
```

Add correlation cases proving a versioned inventory asset matches a coordinate record only when the range/hash matches, while missing version, unsupported ecosystem, withdrawn record, false name, and hash mismatch do not match.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/packageid ./internal/finding ./internal/bundle -run 'Test(Coordinate|Correlate.*Coordinate|ThreatIntelligence)' -count=1 -v`

Expected: FAIL because `internal/packageid` and version-independent lookup do not exist; the current correlator indexes records by the full versioned `asset.ID`.

- [x] **Step 3: Implement strict identity parsing and correlation**

Implement percent-decoding/encoding with closed ecosystem normalization. Reject malformed escapes, qualifiers, fragments, empty names/versions, control bytes, absolute paths, and mismatched `Asset.Name`. Change `Correlate` to index records by coordinate and derive each package asset's coordinate before applying hash/range selectors.

```go
coordinate, ok := packageid.Coordinate(asset)
if !ok { continue }
for _, record := range records[coordinate] {
    matched := exactSelectorMatch(asset, record)
    if matched { matches = append(matches, record) }
}
```

- [x] **Step 4: Verify GREEN and mutation sensitivity**

Run: `go test -race ./internal/packageid ./internal/finding ./internal/bundle -count=1`

Temporarily index records by `asset.ID`; confirm `TestCorrelateMatchesVersionIndependentCoordinate` fails, restore, and rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/packageid internal/finding/correlate.go internal/finding/correlate_test.go internal/bundle/ti_test.go
git commit -m "fix: correlate TI by canonical package coordinate"
```

### Task 2: Deterministic OSV and OpenSSF Publisher

**Files:**
- Create: `internal/tipublish/osv.go`
- Create: `internal/tipublish/normalize.go`
- Create: `internal/tipublish/publish.go`
- Create: `internal/tipublish/publish_test.go`
- Create: `internal/tipublish/testdata/osv-vulnerable.json`
- Create: `internal/tipublish/testdata/openssf-malicious.json`
- Create: `cmd/ssc-init-ti-publisher/main.go`
- Create: `cmd/ssc-init-ti-publisher/main_test.go`

**Interfaces:**
- Produces: `tipublish.Build(input Input) (bundleBytes []byte, report Report, err error)`.
- `Input` contains exact source file paths, `Version`, `Sequence`, `KeyID`, `GeneratedAt`, `ValidFrom`, and `ValidUntil`; it contains no network client.
- Produces sorted `bundle.TIRecord` values with canonical coordinate, OSV range, verdict/confidence, license, public source URL, and withdrawal state.

- [x] **Step 1: Write failing normalization tests using literal fixtures**

```go
func TestBuildSeparatesMaliciousFromVulnerableClassification(t *testing.T) {
    raw, report, err := Build(fixtureInput(t))
    if err != nil { t.Fatal(err) }
    envelope, err := bundle.Load(raw, fixtureInput(t).GeneratedAt)
    if err != nil { t.Fatal(err) }
    assertRecord(t, envelope.TI.Records, "MAL-2026-1", "pkg:npm/evil", "known-malicious", "high")
    assertRecord(t, envelope.TI.Records, "GHSA-2026-1", "pkg:pypi/requests", "needs-review", "medium")
    assertRecord(t, envelope.TI.Records, "GO-2026-1", "pkg:golang/example.com/mod", "suspicious", "high")
    if report.Malicious != 1 || report.Vulnerable != 2 { t.Fatalf("report=%+v", report) }
}
```

Add literal tests for CVSS 8.9 vs 9.0, withdrawn records, false-positive versions, unsupported ecosystem, disallowed/absent license, duplicate records, malformed ranges, and shuffled input producing byte-identical output.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/tipublish ./cmd/ssc-init-ti-publisher -count=1 -v`

Expected: FAIL because publisher packages and command do not exist.

- [x] **Step 3: Implement a closed OSV subset and deterministic builder**

Decode with `DisallowUnknownFields` into bounded structs for `id`, `modified`, `withdrawn`, `affected`, `ranges/events`, `versions`, `severity`, `references`, and approved license metadata. Convert OSV events into the existing supported range syntax; fail the build if a range cannot be represented exactly. Sort/dedupe every list and encode once with a trailing newline.

The CLI accepts only explicit local paths and metadata flags, writes `ti-bundle.json` plus a public attribution report, and never signs.

- [x] **Step 4: Verify publisher behavior and reproducibility**

Run: `go test -race ./internal/tipublish ./cmd/ssc-init-ti-publisher -count=1`

Run the publisher twice with shuffled source fixture order and compare: `cmp "$first/ti-bundle.json" "$second/ti-bundle.json"`.

Mutation: change the malicious source classifier to treat all OSV input as malicious; confirm the separation test fails, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/tipublish cmd/ssc-init-ti-publisher
git commit -m "feat: build deterministic OSV TI bundles"
```

### Task 3: Signed Update Manifest and Production Trust Registry

**Files:**
- Create: `internal/bundle/manifest.go`
- Create: `internal/bundle/manifest_test.go`
- Create: `internal/bundle/trust.go`
- Create: `internal/bundle/trust_test.go`
- Modify: `cmd/ssc-init-ti-publisher/main.go`
- Modify: `cmd/ssc-init-ti-publisher/main_test.go`
- Modify: `cmd/ssc-init/main.go`

**Interfaces:**
- Produces: `bundle.Manifest`, `bundle.LoadManifest(raw []byte, now time.Time)`, and `bundle.VerifyManifest(raw, sig []byte, keys KeyRegistry, now time.Time) (VerifiedManifest, error)`.
- Produces: `bundle.ProductionKeys() KeyRegistry`, returning copies so callers cannot mutate global trust.
- Publisher gains explicit signing subcommand consuming a private-key file only in the publication environment and emitting exact detached signatures.

- [x] **Step 1: Write failing manifest/trust tests**

```go
func TestVerifyManifestBindsImmutableReleaseArtifact(t *testing.T) {
    verified, err := VerifyManifest(manifestFixture(t), signatureFixture(t), testKeys(), testNow)
    if err != nil || verified.Manifest.ReleaseTag != "ti-00000042" || verified.Manifest.Artifact != "ti-bundle.json" { t.Fatalf("verified=%+v err=%v", verified, err) }
}
```

Test duplicate/unknown fields, wrong family, unknown/wrong-family/test key, invalid times, digest/length bounds, traversal or URL artifact names, mutable/noncanonical release tags, signature changes, and returned registry mutation isolation. Production trust test must assert no key ID starts with `test` and no private-key length material is present.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/bundle ./cmd/ssc-init-ti-publisher -run 'Test(VerifyManifest|ProductionKeys|PublisherSigns)' -count=1 -v`

Expected: FAIL because manifest and production registry APIs do not exist.

- [x] **Step 3: Implement closed manifest verification and trust seam**

Use exact Ed25519 verification over raw bytes. Manifest schema is `ssc-init.ti-manifest.v1`, family is `ti`, artifact is exactly `ti-bundle.json`, release tag is `ti-` plus zero-padded sequence, and digest is 64 lowercase hex. Wire `cmd/ssc-init` to `bundle.ProductionKeys()` instead of an empty literal registry.

Initially `ProductionKeys()` remains empty until the owner provides the reviewed public key; this preserves production fail-closed operation. The signing command refuses key IDs prefixed `test` and private key files that are not regular, private, bounded files.

- [x] **Step 4: Verify GREEN and key-confusion mutations**

Run: `go test -race ./internal/bundle ./cmd/ssc-init-ti-publisher ./cmd/ssc-init -count=1`

Mutations: resolve a policy key for TI and accept an unknown key; confirm targeted tests fail, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/bundle/manifest.go internal/bundle/manifest_test.go internal/bundle/trust.go internal/bundle/trust_test.go cmd/ssc-init-ti-publisher cmd/ssc-init/main.go
git commit -m "feat: verify signed TI update manifests"
```

### Task 4: Bounded GitHub-Only Update Client

**Files:**
- Create: `internal/bundle/update.go`
- Create: `internal/bundle/update_http.go`
- Create: `internal/bundle/update_test.go`
- Modify: `internal/bundle/status.go`
- Modify: `internal/bundle/status_test.go`

**Interfaces:**
- Produces: `type Updater struct { Manager *Manager; Client *http.Client; Base *url.URL; Keys KeyRegistry; Now func() time.Time }`.
- Produces: `func (u Updater) Update(ctx context.Context) UpdateResult` where result is closed and contains `Status`, `ErrorCode`, `Sequence`, `Digest`, `KeyID`, `Freshness`, and record counts.
- Adds digest and record counts to verified `bundle.Status` without exposing storage paths.

- [x] **Step 1: Write failing updater lifecycle tests with a local TLS server**

```go
func TestUpdaterMovesMissingToFreshAndNoOpsWhenCurrent(t *testing.T) {
    server := signedFeedServer(t, sequence(42))
    updater := testUpdater(t, server)
    first := updater.Update(context.Background())
    second := updater.Update(context.Background())
    if first.Status != UpdateUpdated || first.Sequence != 42 { t.Fatalf("first=%+v", first) }
    if second.Status != UpdateCurrent || server.BundleRequests() != 1 { t.Fatalf("second=%+v requests=%d", second, server.BundleRequests()) }
}
```

Add tests for newer activation, lower sequence, same-sequence/different-digest, tampered manifest/signature/bundle, bad length, >64 KiB manifest, >16 MiB bundle, timeout, cancellation, HTTP status, response-body secret, redirect host/path rejection, third redirect, cookies/auth/query absence, and last-known-good retention.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/bundle -run 'TestUpdater' -count=1 -v`

Expected: FAIL because `Updater` is undefined.

- [x] **Step 3: Implement the updater and closed transport**

Build URLs only from constants plus validated release tag/artifact. Use a custom `CheckRedirect` that rechecks `github.com` and documented release asset hosts, limits redirects to two, and removes authorization/cookie headers. Stream with `io.LimitReader`, compute digest while writing into `os.MkdirTemp` private files, then call `Manager.Install` with exact absolute staging paths. Always remove temporary files.

Map failures to the spec's closed codes; never return wrapped remote errors. When update fails, call `Manager.Status` only to report last-known-good freshness and return `degraded` or `unavailable` without activating bytes.

- [x] **Step 4: Verify GREEN, race, and security mutations**

Run: `go test -race ./internal/bundle -run 'Test(Updater|Status)' -count=1`

Mutations: remove post-redirect host validation, remove bundle size limit, and activate before digest check one at a time; each corresponding test must fail. Restore after each and rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/bundle/update.go internal/bundle/update_http.go internal/bundle/update_test.go internal/bundle/status.go internal/bundle/status_test.go
git commit -m "feat: update TI from signed GitHub releases"
```

### Task 5: Explicit CLI Update and Same-Scan TI Evaluation

**Files:**
- Modify: `internal/cli/options.go`
- Modify: `internal/cli/options_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`
- Modify: `internal/audit/model.go`
- Modify: `internal/audit/model_test.go`
- Modify: `internal/audit/privacy.go`
- Modify: `internal/audit/privacy_test.go`

**Interfaces:**
- Adds `Options.UpdateTI bool` and accepts only `bundle update --family ti --json|--pretty` and baseline scan `--update-ti`.
- Adds narrow `TIUpdater` interface: `Update(context.Context) bundle.UpdateResult`.
- Scan orchestration runs update before collectors and evaluates findings with the same manager after activation.
- Audit record gains closed update receipt/freshness fields; no manifest bytes or URL.

- [x] **Step 1: Write failing parser and orchestration tests**

```go
func TestScanUpdateTIRunsBeforeCollectorsAndChangesSameScanFinding(t *testing.T) {
    order := []string{}
    app := App{TIUpdater: updaterFunc(func(context.Context) bundle.UpdateResult { order = append(order, "update"); return updated42 }), BaselineScanner: scannerFunc(func(context.Context) (...) { order = append(order, "scan"); return inventoryWithFixture, nil }), FindingService: activeTIFindingService}
    code := app.Run(context.Background(), []string{"scan", "--baseline", "--update-ti", "--pretty"}, &out, &errOut)
    if code != 4 || strings.Join(order, ",") != "update,scan" || !strings.Contains(out.String(), "ACTION REQUIRED") { t.Fatalf(...) }
}
```

Test that ordinary scan cannot invoke updater even if injected, update is rejected on hook/status/non-TI family, cancellation stops before scan, degraded update scans with last-known-good, unavailable update scans without TI, and JSON includes closed intelligence update state without ANSI/private values.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/cli ./cmd/ssc-init ./internal/audit -run 'Test(ParseOptions.*UpdateTI|ScanUpdateTI|DefaultScanNeverUpdates|Audit.*Intelligence)' -count=1 -v`

Expected: FAIL because option, updater seam, orchestration, and receipt fields do not exist.

- [x] **Step 3: Implement parser, wiring, and audit receipt**

In `cmd/ssc-init`, construct one verified TI manager, updater, and finding service for the scan branch. Call update only when `options.UpdateTI`; pass its closed result into `audit.Service.Complete`. Ensure update activation finishes before `BaselineScanner.Baseline`, and finding evaluation occurs after scan using the same manager.

`bundle update` calls only the updater. Pretty status/update uses a dedicated renderer; JSON uses `ssc-init.bundle-update.v1`. Preserve existing install/status/rollback JSON.

- [x] **Step 4: Verify GREEN and branch mutations**

Run: `go test -race ./internal/cli ./cmd/ssc-init ./internal/audit -count=1`

Mutations: call updater unconditionally and evaluate findings before update; confirm zero-network and same-scan tests fail, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/cli internal/audit cmd/ssc-init
git commit -m "feat: update TI before explicit baseline scans"
```

### Task 6: TI UX, Reasons, and Audit Evidence

**Files:**
- Modify: `internal/audit/render.go`
- Modify: `internal/audit/render_test.go`
- Modify: `internal/findingdisplay/reason.go`
- Create: `internal/findingdisplay/reason_test.go`
- Modify: `internal/report/findings.go`
- Modify: `internal/report/findings_test.go`
- Modify: `internal/acceptance/audit_evidence_test.go`

**Interfaces:**
- Pretty scan/status gains `INTELLIGENCE` immediately after `ASSESSMENT`.
- `findingdisplay.Reason` distinguishes verified malicious package and OSV affected-version records using closed source metadata encoded in intelligence IDs.
- Detailed findings show public advisory IDs, active bundle sequence, evidence count, and action without source URLs or opaque internal identities.

- [x] **Step 1: Write failing golden/privacy tests**

```go
func TestWritePrettyExplainsVerifiedMaliciousTIAndUpdateState(t *testing.T) {
    record := maliciousTIRecordFixture()
    var out bytes.Buffer
    if err := WritePrettyStyled(&out, record, storedFixture(), Style{Color: true}); err != nil { t.Fatal(err) }
    assertOrderedText(t, out.String(), "ASSESSMENT", "ACTION REQUIRED", "INTELLIGENCE", "updated", "PRIORITY FINDINGS")
    if !strings.Contains(out.String(), "verified malicious-package intelligence matched this exact package version") || !strings.Contains(out.String(), "\x1b[31m") { t.Fatal(out.String()) }
}
```

Add vulnerable OSV reason, stale/degraded update, no-TI state, ANSI-free `ReportText`, JSON byte-compatibility outside newly versioned audit receipt, and markers for paths, URLs, queries, hostnames, response bodies, keys, raw source text, and opaque evidence IDs.

- [x] **Step 2: Run RED tests**

Run: `go test ./internal/audit ./internal/findingdisplay ./internal/report ./internal/acceptance -run 'Test.*(Intelligence|MaliciousTI|OSVReason|AuditEvidence)' -count=1 -v`

Expected: FAIL because intelligence block and TI-specific reasons do not exist.

- [x] **Step 3: Implement action-first TI rendering**

Render only closed counts/status/sequence and approved public advisory IDs. Keep shortened digest display out of archived report if it would create a linkability concern; full digest remains in JSON bundle reference. Red applies only to malicious/action-required tokens; yellow to vulnerable/degraded/stale; green to verified fresh bundle/update, never to host safety.

- [x] **Step 4: Verify GREEN and privacy mutations**

Run: `go test -race ./internal/audit ./internal/findingdisplay ./internal/report ./internal/acceptance -count=1`

Mutations: print a source URL and an evidence ID; verify privacy tests fail independently, restore, rerun GREEN.

- [x] **Step 5: Commit**

```bash
git add internal/audit internal/findingdisplay internal/report internal/acceptance/audit_evidence_test.go
git commit -m "feat: explain TI update and match evidence"
```

### Task 7: Publication Workflow, Documentation, and End-to-End Acceptance

**Files:**
- Create: `.github/workflows/publish-ti.yml`
- Create: `scripts/generate-ti-key.sh`
- Create: `scripts/test-publish-ti.sh`
- Create: `docs/ti-publication-runbook.md`
- Modify: `README.md`
- Modify: `docs/release-runbook.md`
- Create: `internal/acceptance/ti_update_test.go`
- Modify: `scripts/build-darwin_test.go`

**Interfaces:**
- Workflow inputs: source revisions/digests, version, sequence, generated/valid times, and protected environment approval.
- Required secrets: `TI_ED25519_PRIVATE_KEY`; required repository variable: reviewed `TI_KEY_ID`.
- Acceptance uses a local TLS feed and injected test trust/base URL; production defaults remain fixed and fail closed.

- [x] **Step 1: Write failing workflow and isolated-HOME acceptance tests**

The acceptance test must build the real CLI, start a bounded TLS server, install a signed sequence 1 feed, run an explicit update scan against a fixture HOME containing one known-malicious and one vulnerable package, reload the audit ZIP, then publish sequence 2 and repeat. Assert:

```go
if before.Intelligence != "unavailable" || after.Intelligence != "fresh" { t.Fatalf(...) }
if malicious.Verdict != model.VerdictKnownMalicious || malicious.Level != 1 { t.Fatalf(...) }
if vulnerable.Verdict != model.VerdictNeedsReview { t.Fatalf(...) }
if archiveFinding.Bundles[0].Sequence != 2 { t.Fatalf(...) }
```

Also assert default scan causes zero server accepts, failed signature preserves sequence 1, lower sequence is refused, report/archive contain no fixture secrets, and repeated publisher output is byte-identical.

Script tests execute the workflow's local publisher/sign/verify commands with test secrets and reject a dirty tree, missing provenance, test key ID, nonmonotonic sequence, and overwritten release tag.

- [x] **Step 2: Run RED acceptance**

Run: `go test ./internal/acceptance ./scripts -run 'Test(TIUpdate|PublishTI)' -count=1 -v`

Expected: FAIL because workflow, scripts, runbook, and complete acceptance path do not exist.

- [x] **Step 3: Implement workflow and operator documentation**

Use pinned action SHAs, least-privilege permissions (`contents: write` only in publication job), protected environment approval, immutable `ti-%08d` tags, exact source digest verification, and post-signature verification with the compiled public key before upload. Never echo the private key; materialize it in a `mktemp -d` directory with mode 0700/0600 and delete it in an `always()` cleanup step.

The key script prints the public key and GitHub secret command guidance but never writes a private key unless an explicit private output path is supplied. The runbook documents dual-key rotation, emergency withdrawal with a higher sequence, rollback semantics, source licensing, and real-release smoke commands.

- [x] **Step 4: Verify all gates and real mutation battery**

Run:

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
go test ./scripts -count=1
```

Run the six acceptance mutations: default scan network call, manifest signature bypass, bundle digest bypass, rollback acceptance, malicious/vulnerability classifier merge, and pre-update finding evaluation. Each must make the exact acceptance test RED; restore after each and rerun full GREEN.

- [x] **Step 5: Commit implementation-complete state**

```bash
git add .github/workflows/publish-ti.yml scripts docs README.md internal/acceptance scripts/build-darwin_test.go
git commit -m "feat: publish and verify signed TI releases"
```

- [x] **Step 6: Provision production trust and run real-release acceptance**

This is the only externally blocked step. The repository owner generates the production key, configures the protected GitHub environment/secret, creates `s1ns3nz0/ssc-init-ti`, and supplies the public key for reviewed commit to `bundle.ProductionKeys()`.

After publication, run:

```bash
ssc-init bundle status --family ti --pretty
ssc-init bundle update --family ti --pretty
ssc-init bundle status --family ti --pretty
ssc-init scan --baseline --update-ti --pretty --label ti-release-smoke
ssc-init findings --json
ssc-init audit verify /absolute/path/to/the/new/archive.zip --pretty
```

Record release tag, sequence, manifest digest, bundle digest, update state, freshness, TI match count, analyzer-only match count, audit run ID, and archive digest. Do not call a synthetic match a real infection.

- [x] **Step 7: Commit the production public key and evidence documentation**

```bash
git add internal/bundle/trust.go internal/bundle/trust_test.go docs/ti-publication-runbook.md docs/release-runbook.md
git commit -m "chore: trust production TI signing key"
```

Re-run the full clean-tree gate after the commit and require `git status --short` to be empty.
