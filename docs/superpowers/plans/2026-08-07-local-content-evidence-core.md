# Local Content Evidence Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic, bounded, observation-scoped local content evidence for supported plugins, skills, IDE extensions, MCP declarations, and project manifest/lockfiles without adding malware verdicts or external execution.

**Architecture:** Existing collectors continue to discover assets and observations, and additionally issue sealed runtime-only evidence targets. A new `internal/evidence` engine validates those targets against the normalized graph, performs descriptor-anchored file or tree hashing, derives secret-free MCP semantic hashes, and returns first-class evidence plus explicit coverage. SQLite snapshot v3 persists the evidence ledger; a separate best-effort cache transaction accelerates unchanged local leaf files.

**Tech Stack:** Go 1.26, standard-library SHA-256 and JSON, `os.Root`, `golang.org/x/sys/unix`, modernc SQLite, existing table-driven Go tests.

## Global Constraints

- Runtime platform remains macOS Darwin; non-Darwin operational commands fail before state creation.
- Release binaries remain `CGO_ENABLED=0` for Darwin arm64 and amd64.
- Add no mandatory runtime, daemon, kernel component, network request, or command execution.
- Add no new Go module unless a standard-library or existing-module implementation is impossible and the plan is revised first.
- Default evidence collection is passive, offline, current-user-only, descriptor-anchored, and no-follow.
- Persist no source bytes, secret values, raw absolute paths, arbitrary tree leaf lists, symlink targets, or runtime provenance.
- File limits are 64 MiB for tree leaves and 32 MiB for project manifest/lockfiles.
- Tree limits are depth 32, 4,096 entries, 256 MiB total regular-file bytes, 64 errors, and 30 seconds per evidence target.
- Project discovery retains depth 12, 100,000 entries, and 4,096 recognized configuration files per configured root.
- Only `complete` evidence is eligible for content identity; every issued target receives a terminal result.
- `ssc-init.tree.v1`, `ssc-init.semantic-mcp.v1`, `ssc-init.evidence.id.v1`, and `ssc-init.content-cache.v1` are immutable format domains.
- Scan JSON becomes `ssc-init.scan.v3`; status JSON becomes `ssc-init.status.v3`; v1 and v2 snapshots remain readable without implied evidence coverage.
- Follow TDD for every task: observe the named test fail, add the minimum implementation, run the focused package, then run the stated regression set.

---

### Task 1: Evidence model, identity, normalization, and delta

**Files:**
- Create: `internal/model/evidence.go`
- Create: `internal/identity/evidence.go`
- Create: `internal/identity/evidence_test.go`
- Modify: `internal/model/observation.go`
- Modify: `internal/model/scan.go`
- Modify: `internal/model/scan_test.go`
- Modify: `internal/inventory/graph.go`
- Modify: `internal/inventory/graph_test.go`

**Interfaces:**
- Produces: `model.ContentEvidence`, `model.EvidenceKind`, `model.EvidenceStatus`, `model.EvidenceError`, `model.EvidenceCoverage`, `model.EvidenceTargetResult`, and `model.LocalEvidenceTarget`.
- Produces: `identity.FinalizeEvidence(model.ContentEvidence) (model.ContentEvidence, error)`.
- Changes: `model.Inventory.Evidence []model.ContentEvidence` and `model.ChangeEntityEvidence`.
- Consumes: existing `identity.FinalizeObservation` and deterministic graph/diff conventions.

- [ ] **Step 1: Write failing identity and model contract tests**

```go
func TestFinalizeEvidenceIDIsStableAcrossContentChanges(t *testing.T) {
    base := model.ContentEvidence{
        AssetID: "agent-skill:codex:fixture",
        ObservationID: "observation:sha256:" + strings.Repeat("a", 64),
        Kind: model.EvidenceFileSHA256,
        Subject: model.EvidenceSubjectSkillDocument,
        Status: model.EvidenceComplete,
        Algorithm: "sha256",
        Digest: strings.Repeat("b", 64),
    }
    first, err := FinalizeEvidence(base)
    if err != nil { t.Fatal(err) }
    base.Digest = strings.Repeat("c", 64)
    second, err := FinalizeEvidence(base)
    if err != nil { t.Fatal(err) }
    if first.ID == "" || first.ID != second.ID {
        t.Fatalf("ids differ: %q %q", first.ID, second.ID)
    }
}

func TestFinalizeEvidenceRejectsFreeFormSubject(t *testing.T) {
    _, err := FinalizeEvidence(model.ContentEvidence{
        AssetID: "a", ObservationID: "o", Kind: model.EvidenceFileSHA256,
        Subject: "../../private", Status: model.EvidenceUnavailable,
    })
    if err == nil { t.Fatal("free-form subject accepted") }
}
```

Add this JSON test:

```go
func TestScanV3MarshalsNonNilEmptyEvidenceContracts(t *testing.T) {
    value := struct {
        Scan model.ScanResult `json:"scan"`
        Inventory model.Inventory `json:"inventory"`
    }{
        Scan: model.ScanResult{SchemaVersion: "ssc-init.scan.v3", EvidenceCoverage: model.EvidenceCoverage{Targets: []model.EvidenceTargetResult{}}},
        Inventory: model.Inventory{Assets: []model.Asset{}, Evidence: []model.ContentEvidence{}, Relationships: []model.Relationship{}},
    }
    encoded, err := json.Marshal(value)
    if err != nil { t.Fatal(err) }
    for _, fragment := range []string{`"targets":[]`, `"evidence":[]`} {
        if !bytes.Contains(encoded, []byte(fragment)) { t.Fatalf("missing %s in %s", fragment, encoded) }
    }
}
```

- [ ] **Step 2: Run the new model and identity tests to verify failure**

Run: `go test ./internal/model ./internal/identity -run 'Evidence|ScanResult' -count=1`

Expected: compilation fails because the evidence types and finalizer do not exist.

- [ ] **Step 3: Implement the public evidence types and deterministic finalizer**

Define the constants exactly as follows:

```go
const (
    EvidenceFileSHA256     EvidenceKind = "file-sha256"
    EvidenceTreeSHA256     EvidenceKind = "tree-sha256"
    EvidenceSemanticSHA256 EvidenceKind = "semantic-sha256"
    EvidencePackageContent EvidenceKind = "package-content"
    EvidenceContainerIdentity EvidenceKind = "container-identity"

    EvidenceComplete    EvidenceStatus = "complete"
    EvidencePartial     EvidenceStatus = "partial"
    EvidenceOversize    EvidenceStatus = "oversize"
    EvidenceUnavailable EvidenceStatus = "unavailable"
    EvidenceUnsupported EvidenceStatus = "unsupported"
    EvidenceSkipped     EvidenceStatus = "skipped"

    EvidenceSubjectManifest          = "manifest"
    EvidenceSubjectSkillDocument     = "skill-document"
    EvidenceSubjectEntrypointMain    = "entrypoint-main"
    EvidenceSubjectEntrypointBrowser = "entrypoint-browser"
    EvidenceSubjectPayloadTree       = "payload-tree"
    EvidenceSubjectMCPDeclaration    = "mcp-declaration"
    EvidenceSubjectPackageContent    = "package-content"
    EvidenceSubjectContainerImage    = "container-image"
)
```

Implement the ID with the existing big-endian length-prefix convention and domain `ssc-init.evidence.id.v1`. Keep the project subject suffixes in the closed model catalog exposed through `model.ProjectEvidenceSubject`; Task 10 consumes that function rather than duplicating the list.

- [ ] **Step 4: Write failing graph and delta tests**

```go
func TestDiffReportsEvidenceDigestChange(t *testing.T) {
    before := model.Inventory{Evidence: []model.ContentEvidence{{ID: "e", Digest: strings.Repeat("a", 64)}}}
    after := model.Inventory{Evidence: []model.ContentEvidence{{ID: "e", Digest: strings.Repeat("b", 64)}}}
    got := Diff(before, after)
    want := model.Delta{Changes: []model.Change{{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: "e"}}}
    if !reflect.DeepEqual(got, want) { t.Fatalf("got=%+v want=%+v", got, want) }
}
```

Add `TestDiffOrdersAssetEvidenceObservationChanges` with one changed entity each for IDs `asset-a`, `evidence-a`, and `observation-a`; assert exact order `asset`, `evidence`, `observation`.

- [ ] **Step 5: Run the graph tests to verify failure**

Run: `go test ./internal/inventory -run 'Evidence|DiffOrders' -count=1`

Expected: the digest mutation produces no change before evidence-aware diffing is added.

- [ ] **Step 6: Add evidence normalization and diffing**

Sort evidence by ID, canonicalize every evidence record with JSON for diffing, and call:

```go
appendEntityChanges(&delta.Changes, model.ChangeEntityEvidence,
    canonicalEvidenceByID(previous.Evidence), canonicalEvidenceByID(current.Evidence))
```

Do not merge evidence in `inventory.Build`; the evidence engine appends it after discovery graph normalization.

- [ ] **Step 7: Run focused and regression tests**

Run: `go test ./internal/model ./internal/identity ./internal/inventory -count=1`

Expected: PASS.

- [ ] **Step 8: Commit Task 1**

```sh
git add internal/model internal/identity internal/inventory
git commit -m "feat: add content evidence contracts"
```

---

### Task 2: Rooted link reads and cache-safe file identity

**Files:**
- Modify: `internal/platform/fs.go`
- Modify: `internal/platform/fs_test.go`
- Modify: `internal/platform/rooted.go`
- Modify: `internal/platform/rooted_test.go`
- Create: `internal/platform/fingerprint.go`
- Create: `internal/platform/fingerprint_darwin.go`
- Create: `internal/platform/fingerprint_other.go`
- Create: `internal/platform/fingerprint_test.go`
- Modify: test fakes implementing `platform.RootedDirectory`

**Interfaces:**
- Produces: `RootedDirectory.Readlink(name string) (string, error)`.
- Produces: `platform.FileFingerprint` and `platform.Fingerprint(os.FileInfo) (FileFingerprint, bool)`.
- Produces: optional `platform.LocalRootedFile` with `LocalFilesystem() (local bool, known bool)`.
- Consumes: `os.Root.Readlink`, Darwin `syscall.Stat_t`, and `unix.Statfs_t`.

- [ ] **Step 1: Write failing rooted link and fingerprint tests**

```go
func TestOSRootedDirectoryReadlinkDoesNotResolveTarget(t *testing.T) {
    rootPath := t.TempDir()
    if err := os.WriteFile(filepath.Join(rootPath, "secret"), []byte("value"), 0o600); err != nil { t.Fatal(err) }
    if err := os.Symlink("secret", filepath.Join(rootPath, "link")); err != nil { t.Fatal(err) }
    root, err := (OSFileSystem{}).OpenRoot(rootPath)
    if err != nil { t.Fatal(err) }
    defer root.Close()
    got, err := root.Readlink("link")
    if err != nil { t.Fatal(err) }
    if got != "secret" { t.Fatalf("target=%q", got) }
}

func TestFingerprintChangesWhenCTimeChanges(t *testing.T) {
    path := filepath.Join(t.TempDir(), "file")
    if err := os.WriteFile(path, []byte("first"), 0o600); err != nil { t.Fatal(err) }
    beforeInfo, _ := os.Lstat(path)
    before, ok := Fingerprint(beforeInfo)
    if runtime.GOOS == "darwin" && !ok { t.Fatal("Darwin fingerprint unavailable") }
    if err := os.Chmod(path, 0o640); err != nil { t.Fatal(err) }
    afterInfo, _ := os.Lstat(path)
    after, _ := Fingerprint(afterInfo)
    if runtime.GOOS == "darwin" && before == after { t.Fatal("fingerprint did not change") }
}
```

- [ ] **Step 2: Run the platform tests to verify failure**

Run: `go test ./internal/platform -run 'Readlink|Fingerprint' -count=1`

Expected: compilation fails because both interfaces are absent.

- [ ] **Step 3: Implement no-follow link reads and fingerprints**

```go
type FileFingerprint struct {
    Device, Inode uint64
    Mode          uint32
    Size          int64
    ModTimeNS     int64
    ChangeTimeNS  int64
}
```

On Darwin, extract change time from `syscall.Stat_t.Ctimespec`. On other platforms, return `false` from `Fingerprint` so the cache is disabled while the package compiles. `Readlink` validates one root component and delegates to `os.Root.Readlink`; it never resolves the returned target.

- [ ] **Step 4: Update rooted test doubles and run the complete platform package**

Every fake `Readlink` returns either its explicit fixture target or `fs.ErrInvalid`. Run: `go test ./internal/platform -count=1`

Expected: PASS.

- [ ] **Step 5: Audit forbidden filesystem calls**

Run: `rg -n 'EvalSymlinks|filepath\.Walk|os\.ReadFile|os\.Open\(' internal/platform internal/collector internal/evidence`

Expected: no new evidence target-path reopen or `EvalSymlinks` call appears.

- [ ] **Step 6: Commit Task 2**

```sh
git add internal/platform internal/collector internal/scan internal/acceptance
git commit -m "feat: expose rooted evidence identity"
```

---

### Task 3: Descriptor-anchored file evidence hashing

**Files:**
- Create: `internal/evidence/file.go`
- Create: `internal/evidence/file_test.go`
- Modify: `internal/inventory/hash.go`
- Modify: `internal/inventory/hash_test.go`

**Interfaces:**
- Produces: `evidence.HashVerifiedFile(context.Context, platform.RootedDirectory, string, int64) (evidence.FileDigest, model.EvidenceStatus, []model.EvidenceError)`.
- Produces: `evidence.FileDigest{SHA256 string, Size int64, Fingerprint platform.FileFingerprint}`.
- Preserves: `inventory.HashFile` as a compatibility wrapper.

- [ ] **Step 1: Write failing boundary and race tests**

```go
func TestHashVerifiedFileHonorsExactLimit(t *testing.T) {
    rootPath := t.TempDir()
    if err := os.WriteFile(filepath.Join(rootPath, "payload"), []byte("abcd"), 0o600); err != nil { t.Fatal(err) }
    root, _ := (platform.OSFileSystem{}).OpenRoot(rootPath)
    defer root.Close()
    got, status, errs := HashVerifiedFile(context.Background(), root, "payload", 4)
    want := sha256.Sum256([]byte("abcd"))
    if status != model.EvidenceComplete || len(errs) != 0 || got.SHA256 != hex.EncodeToString(want[:]) || got.Size != 4 {
        t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
    }
}

func TestHashVerifiedFileRejectsFinalSymlink(t *testing.T) {
    rootPath := t.TempDir()
    if err := os.WriteFile(filepath.Join(rootPath, "target"), []byte("x"), 0o600); err != nil { t.Fatal(err) }
    if err := os.Symlink("target", filepath.Join(rootPath, "link")); err != nil { t.Fatal(err) }
    root, _ := (platform.OSFileSystem{}).OpenRoot(rootPath)
    defer root.Close()
    got, status, errs := HashVerifiedFile(context.Background(), root, "link", 4)
    if got.SHA256 != "" || status != model.EvidenceUnavailable || len(errs) != 1 || errs[0].Code != "symlink_rejected" {
        t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
    }
}
```

Also add a deterministic after-open seam that replaces, truncates, and appends to the file; every case must return no digest with `identity_changed`.

- [ ] **Step 2: Run the file evidence tests to verify failure**

Run: `go test ./internal/evidence -run HashVerifiedFile -count=1`

Expected: package or function does not exist.

- [ ] **Step 3: Implement bounded hashing over an opened root**

Split and validate the relative components, open parents with `OpenVerifiedRoot`, and open the final regular file with `OpenVerifiedFile`. Stream with `io.LimitedReader{N: maxBytes + 1}` so an exact-limit file is complete and a larger file is `oversize`. Compare opened and post-read fingerprints and sizes before returning a digest.

```go
var fixedFileErrors = map[string]model.EvidenceError{
    "identity": {Code: "identity_changed", Message: "evidence file identity changed"},
    "symlink":  {Code: "symlink_rejected", Message: "symbolic link was not followed"},
    "oversize": {Code: "byte_limit", Message: "evidence file exceeds the byte limit"},
    "read":     {Code: "read_unavailable", Message: "evidence file is unavailable"},
}
```

Never copy underlying OS error text into the model.

- [ ] **Step 4: Delegate the compatibility wrapper to the stronger primitive**

`inventory.HashFile` opens the volume root once, calls `HashVerifiedFile`, and maps complete, oversize, and all other statuses to existing `HashComplete`, `HashOversize`, and `HashUnavailable` values.

- [ ] **Step 5: Run focused and regression tests**

Run: `go test ./internal/evidence ./internal/inventory -count=1`

Run: `go test -race ./internal/evidence ./internal/inventory -count=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```sh
git add internal/evidence internal/inventory
git commit -m "feat: add verified file evidence hashing"
```

---

### Task 4: Bounded deterministic tree manifests

**Files:**
- Create: `internal/evidence/tree.go`
- Create: `internal/evidence/tree_test.go`

**Interfaces:**
- Produces: `evidence.HashTree(context.Context, platform.RootedDirectory, string, evidence.TreeLimits, evidence.LeafCache) (evidence.TreeDigest, model.EvidenceStatus, []model.EvidenceError, []evidence.CacheWrite)`.
- Produces: `evidence.TreeLimits` and `evidence.TreeDigest` aggregate counts.
- Produces: minimal `LeafCache`, `CacheKey`, `CacheEntry`, and `CacheWrite` types with a disabled implementation; Task 5 implements opaque keys and trusted hits.
- Consumes: `HashVerifiedFile` and `RootedDirectory.Readlink`.

- [ ] **Step 1: Write failing deterministic tree tests**

```go
func TestHashTreeChangesForByteMutation(t *testing.T) {
    rootPath := t.TempDir()
    path := filepath.Join(rootPath, "a", "main.js")
    if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, []byte("one"), 0o600); err != nil { t.Fatal(err) }
    first := hashTreeFixture(t, rootPath)
    if err := os.WriteFile(path, []byte("two"), 0o600); err != nil { t.Fatal(err) }
    second := hashTreeFixture(t, rootPath)
    if first.Digest == second.Digest { t.Fatal("byte mutation did not change tree") }
}

func TestHashTreeDoesNotFollowSymlink(t *testing.T) {
    outside := filepath.Join(t.TempDir(), "real-home-marker")
    if err := os.WriteFile(outside, []byte("must-not-read"), 0o600); err != nil { t.Fatal(err) }
    rootPath := t.TempDir()
    if err := os.Symlink(outside, filepath.Join(rootPath, "link")); err != nil { t.Fatal(err) }
    got, status, errs := hashTreeRaw(t, rootPath)
    if status != model.EvidencePartial || got.Symlinks != 1 || len(errs) != 1 || errs[0].Code != "symlink_rejected" {
        t.Fatalf("got=%+v status=%s errors=%+v", got, status, errs)
    }
}
```

Add exact tests for add, remove, rename, permission, link-target, special-file, depth, entry, total-byte, per-file, error-count, deadline, invalid UTF-8, decomposed Unicode, and reversed `ReadDir` order. Assert symlink/special cases are `partial`; numeric limits are `oversize`.

- [ ] **Step 2: Run tree tests to verify failure**

Run: `go test ./internal/evidence -run HashTree -count=1`

Expected: `HashTree` is undefined.

- [ ] **Step 3: Implement `ssc-init.tree.v1` manifest encoding**

```go
const (
    treeDomain          = "ssc-init.tree.v1"
    recordDirectory byte = 'd'
    recordFile      byte = 'f'
    recordSymlink   byte = 'l'
    recordSpecial   byte = 's'
)
```

Use big-endian uint32 length prefixes. Sort exact entry-name bytes before recursion. Hash relative paths only into the transient manifest. Hash link-target bytes into a symlink record without resolving them. Retain only the final digest and aggregate counts.

- [ ] **Step 4: Enforce all security limits and fixed errors**

```go
var DefaultTreeLimits = TreeLimits{
    MaxDepth: 32,
    MaxEntries: 4096,
    MaxFileBytes: 64 << 20,
    MaxTotalBytes: 256 << 20,
    MaxErrors: 64,
    Timeout: 30 * time.Second,
}
```

The first numeric bound stops that tree, preserves the observed-subset digest, and returns `oversize`. A path or identity error returns `partial` while continuing unrelated siblings within the error bound.

- [ ] **Step 5: Run focused race and regression tests**

Run: `go test ./internal/evidence -run 'HashTree|TreeLimit|TreeRace' -count=1`

Run: `go test -race ./internal/evidence -count=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```sh
git add internal/evidence
git commit -m "feat: add bounded tree evidence"
```

---

### Task 5: Opaque best-effort leaf cache

**Files:**
- Create: `internal/evidence/cache.go`
- Create: `internal/evidence/cache_test.go`
- Modify: `internal/evidence/file.go`
- Modify: `internal/evidence/tree.go`
- Modify: `internal/evidence/tree_test.go`

**Interfaces:**
- Produces: `evidence.LeafCache.Lookup(context.Context, evidence.CacheKey) (evidence.CacheEntry, bool, error)`.
- Produces: `evidence.CacheWriter.StoreContentCache(context.Context, []evidence.CacheWrite) error`.
- Produces: `evidence.NewCacheKey(model.LocalEvidenceTarget, string, platform.FileFingerprint) evidence.CacheKey`.
- Consumes: complete Darwin fingerprint and local-filesystem proof from Task 2.

- [ ] **Step 1: Write failing cache-key and trust tests**

```go
func TestCacheKeyContainsNoPathAndChangesWithFingerprint(t *testing.T) {
    target := model.LocalEvidenceTarget{
        AssetID: "a", ObservationID: "o", Kind: model.EvidenceTreeSHA256,
        Subject: model.EvidenceSubjectPayloadTree,
    }
    first := NewCacheKey(target, "src/private-name.js", platform.FileFingerprint{Device: 1, Inode: 2, Size: 3, ChangeTimeNS: 4})
    second := NewCacheKey(target, "src/private-name.js", platform.FileFingerprint{Device: 1, Inode: 2, Size: 3, ChangeTimeNS: 5})
    if first == second || strings.Contains(string(first[:]), "private-name") { t.Fatalf("keys=%x %x", first, second) }
}

func TestTreeCacheHitStillEnumeratesAndRebuildsRoot(t *testing.T) {
    rootPath := t.TempDir()
    if err := os.WriteFile(filepath.Join(rootPath, "first.js"), []byte("one"), 0o600); err != nil { t.Fatal(err) }
    cache := newRecordingLeafCache()
    first := hashTreeWithCache(t, rootPath, cache)
    cache.install(first.Writes)
    cache.resetCounters()
    if err := os.WriteFile(filepath.Join(rootPath, "second.js"), []byte("two"), 0o600); err != nil { t.Fatal(err) }
    second := hashTreeWithCache(t, rootPath, cache)
    if first.Digest == second.Digest || cache.Hits() != 1 || cache.Misses() != 1 || cache.ReadDirCalls() == 0 {
        t.Fatalf("first=%+v second=%+v hits=%d misses=%d reads=%d", first, second, cache.Hits(), cache.Misses(), cache.ReadDirCalls())
    }
}
```

Define `recordingLeafCache` in the same test file with a `map[CacheKey]CacheEntry`, integer hit/miss counters, and a wrapped rooted directory that increments `ReadDirCalls`; `install` accepts only complete writes.

Implement the second test with a recording fake cache and assert the engine calls `ReadDir` on the warm scan.

- [ ] **Step 2: Run cache tests to verify failure**

Run: `go test ./internal/evidence -run Cache -count=1`

Expected: cache contracts do not exist.

- [ ] **Step 3: Implement opaque v1 keys and strict cache reads**

Hash the length-prefixed domain `ssc-init.content-cache.v1`, observation ID, kind, subject, SHA-256 of runtime relative path, and every fingerprint field. A hit is usable only when the cached entry is `complete`, algorithm `sha256`, digest is lowercase 64-character hex, format matches, local-filesystem status is known true, and the before/after fingerprint is identical.

- [ ] **Step 4: Integrate leaf hits without skipping tree enumeration**

Return pending `CacheWrite` values only for freshly computed complete leaves. The tree always hashes directory records, entry types, names, modes, sizes, and the final root. A cache error sets cache metadata to `rejected` or `disabled` and falls back to `HashVerifiedFile`; it never changes evidence coverage.

- [ ] **Step 5: Run cache corruption and race tests**

Run: `go test ./internal/evidence -run 'Cache|HashTree' -count=1`

Run: `go test -race ./internal/evidence -count=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 5**

```sh
git add internal/evidence
git commit -m "feat: cache unchanged evidence leaves"
```

---

### Task 6: Sealed target issuer and local evidence engine

**Files:**
- Create: `internal/evidence/issuer.go`
- Create: `internal/evidence/issuer_test.go`
- Create: `internal/evidence/engine.go`
- Create: `internal/evidence/engine_test.go`
- Create: `internal/evidence/record.go`
- Create: `internal/evidence/record_test.go`
- Modify: `internal/model/scan.go`
- Modify: `internal/collector/collector.go`

**Interfaces:**
- Produces: `evidence.Issuer`, `evidence.Anchor`, and `Issuer.Issue(model.LocalEvidenceTarget, evidence.Anchor) model.LocalEvidenceTarget`.
- Produces: `evidence.Engine.Collect(context.Context, collector.Environment, model.Inventory, []model.CollectorResult) evidence.Collection`.
- Produces: `evidence.Collection{Coverage model.EvidenceCoverage, Evidence []model.ContentEvidence, CacheWrites []evidence.CacheWrite}`.
- Produces: optional `evidence.SemanticHasher`; a nil hasher yields terminal unsupported semantic evidence until Task 9 wires `HashMCPObservation`.
- Changes: `model.CollectorResult.LocalEvidenceTargets []model.LocalEvidenceTarget` with `json:"-"`.
- Consumes: Task 1 identities, Tasks 3–5 hashing/cache, and normalized assets/observations.

- [ ] **Step 1: Write failing issuer forgery tests**

```go
func TestIssuerRejectsEveryMutatedTargetField(t *testing.T) {
    issuer := NewIssuer()
    original := issuer.Issue(model.LocalEvidenceTarget{
        TargetID: "agents.codex.skills.content", AssetID: "asset", ObservationID: "observation",
        Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectSkillDocument,
        RootPath: "/runtime/root", RelativePath: "fixture/SKILL.md",
    }, Anchor{Root: platform.FileFingerprint{Device: 1, Inode: 2}})
    mutations := []func(*model.LocalEvidenceTarget){
        func(v *model.LocalEvidenceTarget) { v.AssetID = "other" },
        func(v *model.LocalEvidenceTarget) { v.ObservationID = "other" },
        func(v *model.LocalEvidenceTarget) { v.Subject = model.EvidenceSubjectManifest },
        func(v *model.LocalEvidenceTarget) { v.RelativePath = "../escape" },
    }
    for _, mutate := range mutations {
        candidate := original
        mutate(&candidate)
        if _, ok := verifyIssuedTarget(candidate); ok { t.Fatalf("mutation accepted: %+v", candidate) }
    }
}
```

Add a test that copies provenance from one issuer to a target created by another issuer; verification must fail.

- [ ] **Step 2: Run issuer tests to verify failure**

Run: `go test ./internal/evidence -run Issuer -count=1`

Expected: issuer types do not exist.

- [ ] **Step 3: Implement runtime-only sealed issuance**

`Issuer` owns an unexported random 32-byte nonce and pointer identity. The unexported proof stores the issuer pointer, canonical target SHA-256, root and asset-root fingerprints, optional anchor relative path/digest/size/mode/fingerprint, and no source bytes. `Issue` seals every target field including `PresetStatus`. `verifyIssuedTarget` returns a copy of the anchor only after constant-time seal comparison.

- [ ] **Step 4: Write failing engine terminal-state and graph-binding tests**

```go
func TestEngineReturnsOneTerminalResultPerTarget(t *testing.T) {
    inventory, results := issuedFileTreeSemanticUnsupportedFixtures(t)
    got := (Engine{Limits: TestLimits()}).Collect(context.Background(), testEnvironment(t), inventory, results)
    if len(got.Coverage.Targets) != 4 || len(got.Evidence) != 4 {
        t.Fatalf("coverage=%+v evidence=%+v", got.Coverage, got.Evidence)
    }
    for i := range got.Coverage.Targets {
        if got.Coverage.Targets[i].EvidenceID == "" || got.Coverage.Targets[i].Status == "" {
            t.Fatalf("non-terminal target: %+v", got.Coverage.Targets[i])
        }
    }
}

func TestEngineRejectsEvidenceForMismatchedObservationAsset(t *testing.T) {
    env, fs := recordingEvidenceEnvironment(t)
    issuer := NewIssuer()
    observation, err := identity.FinalizeObservation(model.Observation{
        AssetID: "asset-b", Collector: "fixture", Scope: model.ScopeUser, LocationRef: "$HOME/fixture",
    })
    if err != nil { t.Fatal(err) }
    target := issuer.Issue(model.LocalEvidenceTarget{
        TargetID: "fixture.manifest", AssetID: "asset-a", ObservationID: observation.ID,
        Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
        RootPath: filepath.Join(env.Home, "fixture"), RelativePath: "manifest.json",
    }, Anchor{})
    inventory := model.Inventory{
        Assets: []model.Asset{{ID: "asset-a"}, {ID: "asset-b"}},
        Observations: []model.Observation{observation},
    }
    got := (Engine{}).Collect(context.Background(), env, inventory, []model.CollectorResult{{Collector: "fixture", LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
    if len(got.Evidence) != 0 || len(got.Coverage.Errors) != 1 || got.Coverage.Errors[0].Code != "target_rejected" || fs.OpenRootCalls() != 0 {
        t.Fatalf("collection=%+v opens=%d", got, fs.OpenRootCalls())
    }
}
```

Use a recording filesystem in the second test and assert zero `OpenRoot` calls.

- [ ] **Step 5: Run engine tests to verify failure**

Run: `go test ./internal/evidence -run Engine -count=1`

Expected: engine is undefined.

- [ ] **Step 6: Implement validation, anchor checks, collection, and clearing**

Build asset and observation maps from the normalized inventory before examining paths. Reject duplicates, absent references, asset mismatch, invalid subjects, invalid presets, and forged seals. After a valid seal and graph binding, convert unsafe signed relative components to a terminal `unavailable/path_invalid` evidence record without an `OpenRoot` call. Process remaining targets in `TargetID`, `ObservationID`, evidence-ID order with a four-worker bound and a separate 30-second target context.

Preset `unsupported` and `skipped` targets create digest-free records without filesystem access. A semantic target calls the injected `SemanticHasher`; a nil hasher returns a digest-free unsupported record, and Task 9 installs the v1 MCP hasher. File/tree targets verify sealed root, asset directory, and content anchor before and after collection. On anchor mismatch, discard any computed digest and return `unavailable/identity_changed`.

Clear every `LocalEvidenceTarget` and its provenance in both the caller-visible result slices and temporary backing arrays before returning.

- [ ] **Step 7: Validate complete/non-complete record invariants**

`record.go` must enforce:

```go
func validTrustedDigest(v model.ContentEvidence) bool {
    return v.Status == model.EvidenceComplete && v.Algorithm == "sha256" && lowercaseSHA256(v.Digest)
}
```

Unsupported/skipped records may not carry algorithm, digest, sizes, counts, or anchor metadata. Partial/oversize records set `completeness=observed-subset`; complete records set `completeness=complete`.

- [ ] **Step 8: Run engine, model, and race tests**

Run: `go test ./internal/evidence ./internal/model ./internal/identity -count=1`

Run: `go test -race ./internal/evidence -count=1`

Expected: PASS.

- [ ] **Step 9: Commit Task 6**

```sh
git add internal/evidence internal/model internal/collector
git commit -m "feat: collect sealed local evidence targets"
```

---

### Task 7: Agent plugin and skill evidence targets

**Files:**
- Modify: `internal/collector/agents/collector.go`
- Modify: `internal/collector/agents/collector_test.go`
- Create: `internal/collector/agents/evidence.go`
- Create: `internal/collector/agents/evidence_test.go`
- Add fixtures under: `internal/collector/agents/testdata/content/`

**Interfaces:**
- Produces: sealed manifest, skill-document, and payload-tree targets from the agent collector.
- Consumes: `evidence.Issuer`, discovery-time manifest bytes, finalized observation IDs, and verified agent catalog roots.

- [ ] **Step 1: Write failing target matrix tests**

```go
func TestCollectorIssuesCodexSkillFileAndTreeTargets(t *testing.T) {
    home := fixtureHomeWithCodexSkill(t, "fixture", "---\nname: fixture\n---\nbody\n")
    got, err := New().Collect(context.Background(), testutil.Environment(t, home))
    if err != nil { t.Fatal(err) }
    subjects := evidenceSubjects(got.LocalEvidenceTargets)
    want := []string{model.EvidenceSubjectPayloadTree, model.EvidenceSubjectSkillDocument}
    if !reflect.DeepEqual(subjects, want) { t.Fatalf("subjects=%v want=%v", subjects, want) }
}

func TestAgentTargetAnchorMatchesBytesUsedForIdentity(t *testing.T) {
    home := fixtureHomeWithCodexSkill(t, "fixture", "---\nname: fixture\n---\nbody\n")
    collector := New().(*agentCollector)
    skillPath := filepath.Join(home, ".codex", "skills", "fixture", "SKILL.md")
    collector.afterManifestRead = func(relative string) {
        if strings.HasSuffix(relative, "fixture/SKILL.md") {
            if err := os.WriteFile(skillPath, []byte("---\nname: fixture\n---\nchanged\n"), 0o600); err != nil { t.Fatal(err) }
        }
    }
    result, err := collector.Collect(context.Background(), testutil.Environment(t, home))
    if err != nil { t.Fatal(err) }
    inventory := inventory.Build([]model.CollectorResult{result})
    got := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory, []model.CollectorResult{result})
    if !hasEvidenceError(got, "identity_changed") { t.Fatalf("collection=%+v", got) }
}
```

Add `afterManifestRead func(string)` as a test-only seam on `agentCollector`, invoked after verified bytes and anchor fingerprint are captured. Define `hasEvidenceError` in the test file as a bounded scan of evidence and target errors.

Add the same subject assertions for Claude/Codex plugins, Claude/Codex/Cursor skills, nested plugin-bundled skills, missing optional plugin manifest, and unsupported Cursor plugin roots.

- [ ] **Step 2: Run agent evidence tests to verify failure**

Run: `go test ./internal/collector/agents -run 'Evidence|TargetAnchor' -count=1`

Expected: no local evidence targets are emitted.

- [ ] **Step 3: Capture anchors during existing verified reads**

While `readManifest` already owns verified bytes, compute SHA-256, size, mode, file fingerprint, and catalog/asset-root fingerprints. Store them only in the candidate runtime struct. Do not add hashes or paths to asset metadata.

- [ ] **Step 4: Issue closed-catalog targets after observation finalization**

For a plugin, issue `manifest` only when the recognized `.claude-plugin/plugin.json` or `.codex-plugin/plugin.json` exists, plus `payload-tree` rooted at the plugin base. For a skill, issue `skill-document` for `SKILL.md` plus `payload-tree` rooted at the skill directory. Construct target IDs as `declaration.spec.ID + ".manifest"`, `declaration.spec.ID + ".skill-document"`, and `declaration.spec.ID + ".payload-tree"`.

- [ ] **Step 5: Run agent collector, engine integration, and privacy tests**

Run: `go test ./internal/collector/agents ./internal/evidence -count=1`

Run: `go test -race ./internal/collector/agents -count=1`

Expected: PASS; JSON marshaling of the collector result excludes raw target paths and anchor values.

- [ ] **Step 6: Commit Task 7**

```sh
git add internal/collector/agents
git commit -m "feat: plan agent content evidence"
```

---

### Task 8: VS Code-family and JetBrains evidence targets

**Files:**
- Modify: `internal/collector/ide/collector.go`
- Modify: `internal/collector/ide/collector_test.go`
- Modify: `internal/collector/ide/manifest.go`
- Modify: `internal/collector/ide/manifest_test.go`
- Create: `internal/collector/ide/evidence.go`
- Create: `internal/collector/ide/evidence_test.go`
- Add fixtures under: `internal/collector/ide/testdata/content/`

**Interfaces:**
- Produces: manifest, main/browser entry-point, and payload-tree targets for every supported IDE observation.
- Consumes: verified manifest bytes, parsed `main`/`browser` values, `evidence.Issuer`, and IDE root fingerprints.

- [ ] **Step 1: Write failing IDE target and escape tests**

```go
func TestVSCodeExtensionIssuesManifestEntrypointAndTreeTargets(t *testing.T) {
    home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/web.js"}`)
    got, err := New().Collect(context.Background(), testutil.Environment(t, home))
    if err != nil { t.Fatal(err) }
    want := []string{"entrypoint-browser", "entrypoint-main", "manifest", "payload-tree"}
    if subjects := evidenceSubjects(got.LocalEvidenceTargets); !reflect.DeepEqual(subjects, want) {
        t.Fatalf("subjects=%v want=%v", subjects, want)
    }
}

func TestIDEEntrypointCannotEscapeExtensionRoot(t *testing.T) {
    for index, entry := range []string{"../outside.js", "/private/outside.js", "dist/../../outside.js", "dist/\x00bad.js"} {
        t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
            result, collected, recorder := collectIDEWithEntrypoint(t, entry)
            if !collectionHasError(collected, model.EvidenceSubjectEntrypointMain, "path_invalid") {
                t.Fatalf("entry=%q targets=%+v collection=%+v", entry, result.LocalEvidenceTargets, collected)
            }
            if recorder.OutsideOpenCalls() != 0 { t.Fatalf("entry=%q outside opens=%d", entry, recorder.OutsideOpenCalls()) }
        })
    }
}
```

Define `collectIDEWithEntrypoint` in the same test file to create one VS Code fixture plus an outside marker, run its targets through the evidence engine, and return the collector result, collection, and existing recording rooted filesystem. Define `collectionHasError` as a bounded scan matching the controlled subject/error code.

Implement the table body with a recording rooted filesystem and assert the outside marker path is never opened.

- [ ] **Step 2: Run IDE evidence tests to verify failure**

Run: `go test ./internal/collector/ide -run 'Evidence|Entrypoint' -count=1`

Expected: local evidence targets are absent.

- [ ] **Step 3: Preserve both entry-point declarations in parsed evidence**

Replace the single fallback `entry_point` internal value with separate runtime `main` and `browser` fields while preserving the current public metadata behavior. Validate each evidence path independently as canonical, relative, below root, no NUL, and no symlink.

- [ ] **Step 4: Issue VS Code-family and JetBrains targets**

For every supported VS Code-family extension, issue `manifest`, each declared entry-point target, and `payload-tree`. For JetBrains, issue `manifest` for `META-INF/plugin.xml` and `payload-tree` for the plugin directory. Seal the manifest anchor bytes used to build the asset and observation.

- [ ] **Step 5: Prove mutation and JAR coverage through the engine**

Add a fixture with `lib/plugin.jar`, collect twice, mutate only JAR bytes, and assert only the JetBrains `payload-tree` evidence digest changes. Add the same body-only case for VS Code `dist/main.js`.

- [ ] **Step 6: Run IDE, evidence, race, and privacy tests**

Run: `go test ./internal/collector/ide ./internal/evidence -count=1`

Run: `go test -race ./internal/collector/ide -count=1`

Expected: PASS.

- [ ] **Step 7: Commit Task 8**

```sh
git add internal/collector/ide
git commit -m "feat: plan IDE content evidence"
```

---

### Task 9: Secret-free semantic MCP evidence

**Files:**
- Create: `internal/evidence/semantic.go`
- Create: `internal/evidence/semantic_test.go`
- Create: `internal/collector/mcp/evidence.go`
- Create: `internal/collector/mcp/evidence_test.go`
- Modify: `internal/collector/mcp/collector.go`
- Modify: `internal/collector/mcp/collector_test.go`

**Interfaces:**
- Produces: `evidence.HashMCPObservation(model.Observation) (string, error)`.
- Produces: one sealed semantic target per valid MCP observation.
- Changes: the default engine configuration to use `HashMCPObservation` as its `SemanticHasher`.
- Consumes: the existing sanitized MCP observation metadata; never consumes raw parser values or configuration bytes.

- [ ] **Step 1: Write failing canonical semantic tests**

```go
func TestHashMCPObservationIgnoresSecretAndUnknownValues(t *testing.T) {
    base := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
        "transport": "stdio", "command": "node", "args": "--mode\x1fsafe",
        "env_keys": "TOKEN", "unknown_fields": "future",
    }}
    first, err := HashMCPObservation(base)
    if err != nil { t.Fatal(err) }
    base.Metadata["unknown_fields"] = "another_future"
    second, err := HashMCPObservation(base)
    if err != nil { t.Fatal(err) }
    if first != second { t.Fatalf("unknown field names changed semantic digest: %q %q", first, second) }
}

func TestHashMCPObservationChangesForSupportedSemantics(t *testing.T) {
    base := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
        "transport": "stdio", "command": "node", "args": "--mode\x1fsafe", "enabled": "true", "env_keys": "TOKEN",
    }}
    first, err := HashMCPObservation(base)
    if err != nil { t.Fatal(err) }
    cases := []func(*model.Observation){
        func(v *model.Observation) { v.Host = "cursor" },
        func(v *model.Observation) { v.Metadata["transport"] = "http" },
        func(v *model.Observation) { v.Metadata["command"] = "python" },
        func(v *model.Observation) { v.Metadata["args"] = "--mode\x1fstrict" },
        func(v *model.Observation) { v.Metadata["enabled"] = "false" },
        func(v *model.Observation) { v.Metadata["env_keys"] = "OTHER_TOKEN" },
    }
    for index, mutate := range cases {
        candidate := cloneObservation(base)
        mutate(&candidate)
        got, err := HashMCPObservation(candidate)
        if err != nil { t.Fatal(err) }
        if got == first { t.Fatalf("case %d did not change digest", index) }
    }
}
```

Define `cloneObservation` in the same test file by copying the struct and cloning its metadata map.

Implement the second test as a table that clones a safe base observation and asserts every mutation changes the digest.

- [ ] **Step 2: Run semantic tests to verify failure**

Run: `go test ./internal/evidence -run MCP -count=1`

Expected: semantic hasher is undefined.

- [ ] **Step 3: Implement the immutable semantic encoding**

Encode domain `ssc-init.semantic-mcp.v1`, then fixed ordered fields `Host`, `Source`, and metadata keys:

```go
var semanticMCPKeys = []string{
    "transport", "command", "args", "url_shape", "cwd_ref", "enabled",
    "env_keys", "header_keys", "enabled_tools", "disabled_tools",
}
```

Length-prefix every value. Reject unknown required structure, raw absolute paths, credential shapes, and non-redacted values under secret-carrying keys. Do not include `unknown_fields`, target location, observation ID, project ID, or timestamps in the content digest.

- [ ] **Step 4: Issue semantic targets only after observation finalization**

The MCP collector owns an `evidence.Issuer`. After each successful `FinalizeObservation`, issue one target with kind `semantic-sha256`, subject `mcp-declaration`, empty paths, and no preset status. The issuer seal covers the exact observation ID and safe metadata fingerprint.

- [ ] **Step 5: Add end-to-end secret and semantic mutation tests**

Scan two fixtures differing only in env/header secret values and assert equal semantic evidence. Scan fixtures differing in sanitized command or endpoint shape and assert a changed evidence digest. Marshal collector, engine, report, and SQLite inputs and assert none contain the secret markers.

- [ ] **Step 6: Run MCP, evidence, privacy, and race tests**

Run: `go test ./internal/collector/mcp ./internal/evidence ./internal/privacy -count=1`

Run: `go test -race ./internal/collector/mcp ./internal/evidence -count=1`

Expected: PASS.

- [ ] **Step 7: Commit Task 9**

```sh
git add internal/evidence internal/collector/mcp
git commit -m "feat: hash secret-free MCP semantics"
```

---

### Task 10: Project manifest and lockfile evidence catalog

**Files:**
- Create: `internal/collector/projects/evidence_catalog.go`
- Create: `internal/collector/projects/evidence_catalog_test.go`
- Modify: `internal/collector/projects/walk.go`
- Modify: `internal/collector/projects/walk_test.go`
- Modify: `internal/collector/projects/collector.go`
- Modify: `internal/collector/projects/collector_test.go`
- Modify: `internal/model/evidence.go`
- Modify: `internal/model/scan_test.go`

**Interfaces:**
- Produces: exact project evidence catalog, project observations, and sealed 32 MiB file targets.
- Preserves: current sealed project-MCP `LocalTarget` handoff and relationships.
- Consumes: configured root seals, `identity.SafeLocationRef`, `identity.FinalizeObservation`, and `evidence.Issuer`.

- [ ] **Step 1: Write failing immutable catalog tests**

Use the exact table:

```go
var evidenceCatalog = map[string]projectEvidenceDefinition{
    "package.json":       {subject: "project-manifest:package.json", maxBytes: 32 << 20},
    "package-lock.json":  {subject: "project-lockfile:package-lock.json", maxBytes: 32 << 20},
    "npm-shrinkwrap.json": {subject: "project-lockfile:npm-shrinkwrap.json", maxBytes: 32 << 20},
    "pnpm-lock.yaml":     {subject: "project-lockfile:pnpm-lock.yaml", maxBytes: 32 << 20},
    "yarn.lock":          {subject: "project-lockfile:yarn.lock", maxBytes: 32 << 20},
    "bun.lock":           {subject: "project-lockfile:bun.lock", maxBytes: 32 << 20},
    "bun.lockb":          {subject: "project-lockfile:bun.lockb", maxBytes: 32 << 20},
    "pyproject.toml":     {subject: "project-manifest:pyproject.toml", maxBytes: 32 << 20},
    "Pipfile":            {subject: "project-manifest:Pipfile", maxBytes: 32 << 20},
    "requirements.txt":   {subject: "project-manifest:requirements.txt", maxBytes: 32 << 20},
    "poetry.lock":        {subject: "project-lockfile:poetry.lock", maxBytes: 32 << 20},
    "Pipfile.lock":       {subject: "project-lockfile:Pipfile.lock", maxBytes: 32 << 20},
    "uv.lock":            {subject: "project-lockfile:uv.lock", maxBytes: 32 << 20},
    "go.mod":             {subject: "project-manifest:go.mod", maxBytes: 32 << 20},
    "go.sum":             {subject: "project-lockfile:go.sum", maxBytes: 32 << 20},
    "Cargo.toml":         {subject: "project-manifest:Cargo.toml", maxBytes: 32 << 20},
    "Cargo.lock":         {subject: "project-lockfile:Cargo.lock", maxBytes: 32 << 20},
    "Brewfile":           {subject: "project-manifest:Brewfile", maxBytes: 32 << 20},
}
```

Assert `requirements-dev.txt`, different case, suffixes, and nested names not in this exact map are not recognized as evidence filenames.

- [ ] **Step 2: Run project catalog tests to verify failure**

Run: `go test ./internal/collector/projects -run 'EvidenceCatalog|Manifest|Lockfile' -count=1`

Expected: catalog and evidence discovery do not exist.

- [ ] **Step 3: Extend the existing bounded walker without broadening roots**

At each regular file, test project MCP definitions and exact evidence basenames separately. Preserve excluded directories and current root/depth/entry/config limits. Record a discovered project evidence file with its root-relative path, project-relative directory, definition, and verified file info; do not read bytes in the walk.

- [ ] **Step 4: Create one project asset and observation per discovered project**

Use existing `projectID := digestID("project", "ssc-init.project.v1", projectRef)`. Finalize a project observation with collector `projects`, scope `project`, safe project `LocationRef`, and metadata `root_ref`. Reuse it for all manifest/lockfile evidence in the project. Preserve current project-config assets, observations, and `contains` relationships.

- [ ] **Step 5: Issue sealed file targets and isolate hostile siblings**

Construct target IDs as `"projects.manifest." + definition.basename` and `"projects.lockfile." + definition.basename`. Seal the configured root, project directory, enumerated file identity, relative path, and 32 MiB limit. An oversized or identity-changing file gets its own non-complete target result and does not remove other project evidence.

- [ ] **Step 6: Add project mutation, exclusion, and privacy tests**

For every catalog name, scan a fixture, mutate only that file, and assert one evidence change. Add explicit tests for `.git`, `node_modules`, `.venv`, `vendor`, build output, symlinked roots/files, external configured roots, two projects with identical filenames, all walker limits, and no filename/path leakage beyond catalog subject values.

- [ ] **Step 7: Run project, model, evidence, and race tests**

Run: `go test ./internal/collector/projects ./internal/model ./internal/evidence -count=1`

Run: `go test -race ./internal/collector/projects -count=1`

Expected: PASS.

- [ ] **Step 8: Commit Task 10**

```sh
git add internal/collector/projects internal/model
git commit -m "feat: discover project content evidence"
```

---

### Task 11: Explicit unsupported package and container identities

**Files:**
- Create: `internal/collector/packages/evidence.go`
- Create: `internal/collector/packages/evidence_test.go`
- Modify: `internal/collector/packages/collector.go`
- Modify: `internal/collector/packages/collector_test.go`

**Interfaces:**
- Produces: one preset `unsupported` target for package content per package observation.
- Produces: one preset `unsupported` container-identity target per Docker observation.
- Consumes: `evidence.Issuer`, reserved model kinds/subjects, and existing package observations.

- [ ] **Step 1: Write failing unsupported-target tests**

```go
func TestPackageObservationsIssueVisibleUnsupportedEvidence(t *testing.T) {
    got := collectWithFakeProbes(t)
    assets := make(map[string]model.Asset, len(got.Assets))
    for _, asset := range got.Assets { assets[asset.ID] = asset }
    byObservation := make(map[string]model.LocalEvidenceTarget)
    for _, target := range got.LocalEvidenceTargets { byObservation[target.ObservationID] = target }
    for _, observation := range got.Observations {
        if assets[observation.AssetID].Type != model.AssetPackage { continue }
        target, ok := byObservation[observation.ID]
        if !ok || target.PresetStatus != model.EvidenceUnsupported || target.RootPath != "" || target.RelativePath != "" {
            t.Fatalf("observation=%+v target=%+v present=%v", observation, target, ok)
        }
    }
}
```

Assert Docker package assets use kind `container-identity`/subject `container-image`; all other `AssetPackage` observations use `package-content` for both kind and subject. Executable and other `AssetTool` observations receive no new preset target in this sub-project.

- [ ] **Step 2: Run package evidence tests to verify failure**

Run: `go test ./internal/collector/packages -run UnsupportedEvidence -count=1`

Expected: no targets are emitted.

- [ ] **Step 3: Issue sealed digest-free preset targets**

Issue targets only for observations whose referenced surviving asset has type `AssetPackage`. Preset targets carry no path, anchor, algorithm, digest, size, count, or arbitrary metadata. Construct non-Docker target IDs as `"packages." + asset.Source + ".content"`; Docker uses `packages.docker.container-identity`.

- [ ] **Step 4: Prove engine and report behavior**

Run these targets through the engine and assert every record is `unsupported`, overall evidence coverage is `partial` when packages exist, and no filesystem/runner call occurs during evidence collection.

- [ ] **Step 5: Run packages, evidence, and race tests**

Run: `go test ./internal/collector/packages ./internal/evidence -count=1`

Run: `go test -race ./internal/collector/packages -count=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 11**

```sh
git add internal/collector/packages
git commit -m "feat: report unsupported artifact evidence"
```

---

### Task 12: Snapshot v3 persistence, migration 5, and SQLite cache

**Files:**
- Modify: `internal/store/migrations.go`
- Modify: `internal/store/snapshots.go`
- Modify: `internal/store/snapshots_test.go`
- Modify: `internal/store/validation.go`
- Modify: `internal/store/sqlite.go`
- Create: `internal/store/evidence.go`
- Create: `internal/store/evidence_test.go`
- Create: `internal/store/content_cache.go`
- Create: `internal/store/content_cache_test.go`

**Interfaces:**
- Persists: evidence rows, evidence nil/order state, evidence coverage, and scan v3.
- Implements: `evidence.LeafCache` and `evidence.CacheWriter` on `*store.Store`.
- Preserves: v1/v2 snapshot reads, migration ordering, database guard, atomic snapshot rollback, and nil-shape contracts.

- [ ] **Step 1: Write failing migration 5 schema tests**

Add an exact migration-4 fixture, open it with `store.Open`, and assert version 5 plus these tables/columns:

```sql
CREATE TABLE evidence (
    scan_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    evidence_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, evidence_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id),
    FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id),
    FOREIGN KEY (scan_id, observation_id) REFERENCES observations(scan_id, observation_id)
);
CREATE TABLE evidence_state (
    scan_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    evidence_index INTEGER NOT NULL CHECK (evidence_index >= 0),
    metadata_nil INTEGER NOT NULL CHECK (metadata_nil IN (0, 1)),
    errors_nil INTEGER NOT NULL CHECK (errors_nil IN (0, 1)),
    PRIMARY KEY (scan_id, evidence_id),
    UNIQUE (scan_id, evidence_index),
    FOREIGN KEY (scan_id, evidence_id) REFERENCES evidence(scan_id, evidence_id)
);
CREATE TABLE evidence_coverage (
    scan_id TEXT PRIMARY KEY,
    result_json BLOB NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE content_cache (
    cache_key BLOB PRIMARY KEY CHECK (length(cache_key) = 32),
    algorithm TEXT NOT NULL,
    format TEXT NOT NULL,
    digest TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    last_used_at TEXT NOT NULL
);
```

Migration 5 also executes:

```sql
ALTER TABLE inventory_state ADD COLUMN evidence_nil INTEGER NOT NULL DEFAULT 1 CHECK (evidence_nil IN (0, 1));
ALTER TABLE inventory_state ADD COLUMN evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0);
```

- [ ] **Step 2: Run migration tests to verify failure**

Run: `go test ./internal/store -run 'Migration5|EvidenceSchema|ContentCacheSchema' -count=1`

Expected: migration 5 tables and columns are missing.

- [ ] **Step 3: Add migration SQL and schema verification contracts**

Extend `requiredColumns`, required primary keys, unique indexes, foreign keys, and table allowlists. Verify the two compound foreign keys from evidence point to the same scan. A future, missing, gapped, reordered, or shape-conflicting migration history must still fail open.

- [ ] **Step 4: Write failing v3 snapshot round-trip and corruption tests**

Construct a snapshot containing complete, partial, unsupported, empty-error, nil-error, empty-metadata, and nil-metadata evidence. Require exact order and nil shape after reopen. Add one corruption subtest for every validation rule: duplicate ID, malformed ID, absent asset, absent observation, asset mismatch, unknown kind/subject/status, uppercase digest, wrong digest length, complete without digest, preset with digest, negative count, unknown metadata, secret shape, absolute path, encoded path masking, bad error, bad coverage reference, row-count mismatch, and JSON/row ID mismatch.

- [ ] **Step 5: Run snapshot tests to verify failure**

Run: `go test ./internal/store -run 'Evidence|SnapshotV3|Corrupt' -count=1`

Expected: evidence is neither saved nor validated.

- [ ] **Step 6: Persist and load evidence atomically**

Save assets, observations, evidence, relationships, collector coverage, evidence coverage, inventory errors, and inventory state in that order. Add persisted structs that preserve nil maps/slices and exclude runtime target fields. On load, establish asset and observation maps before decoding evidence; validate every cross-reference and count before returning the snapshot.

- [ ] **Step 7: Write failing cache fallback, retention, and isolation tests**

```go
func TestCacheWriteFailureDoesNotRollbackCommittedSnapshot(t *testing.T) {
    store := openTestStore(t)
    saveValidV3Snapshot(t, store, "scan-one")
    if _, err := store.db.Exec(`DROP TABLE content_cache`); err != nil { t.Fatal(err) }
    err := store.StoreContentCache(context.Background(), []evidence.CacheWrite{validCacheWrite()})
    if err == nil { t.Fatal("cache failure not reported") }
    if _, ok, err := store.LatestSnapshot(context.Background()); err != nil || !ok {
        t.Fatalf("snapshot lost: ok=%v err=%v", ok, err)
    }
}
```

Add tests that corrupt a digest/format, insert an old row, and exceed 250,000 logical rows through a reduced test limit. Lookup must return miss/error without trusted content. Writes prune rows older than 90 days and oldest rows above the cap in the cache transaction only.

- [ ] **Step 8: Implement best-effort cache methods**

`Lookup` accepts only exact lowercase SHA-256 and expected format. `StoreContentCache` starts its own transaction after snapshot commit, upserts valid complete entries, touches hits, prunes retention/cap, and rolls back only itself on error. It never stores target paths, observation IDs, subjects, fingerprints, or source content outside the opaque 32-byte key.

- [ ] **Step 9: Run store, migration, race, and rollback tests**

Run: `go test ./internal/store -count=1`

Run: `go test -race ./internal/store -count=1`

Expected: PASS.

- [ ] **Step 10: Commit Task 12**

```sh
git add internal/store
git commit -m "feat: persist content evidence snapshots"
```

---

### Task 13: Baseline pipeline, report JSON, status v3, and cache handoff

**Files:**
- Modify: `internal/scan/service.go`
- Modify: `internal/scan/service_test.go`
- Modify: `internal/report/json.go`
- Modify: `internal/report/json_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Modify: `cmd/ssc-init/main_test.go`

**Interfaces:**
- Changes: `scan.schemaVersion` to `ssc-init.scan.v3`.
- Adds: evidence engine after discovery graph normalization and before diff/persistence.
- Adds: best-effort cache write after successful `SaveScan`.
- Changes: baseline/status public payloads to include evidence coverage and inventory evidence.

- [ ] **Step 1: Write failing pipeline-order and clearing tests**

```go
func TestBaselineCollectsEvidenceAfterGraphNormalization(t *testing.T) {
    snapshots := &memorySnapshots{}
    collector := issuedEvidenceCollector(t)
    service := NewService(collector.Orchestrator{Collectors: []collector.Collector{collector}}, snapshots, fixedTime, fixedUUID, testEnvironment(t))
    scan, inventory, delta, err := service.Baseline(context.Background())
    if err != nil { t.Fatal(err) }
    if scan.SchemaVersion != "ssc-init.scan.v3" || len(inventory.Evidence) != 1 || scan.EvidenceCoverage.Status != model.CoverageComplete {
        t.Fatalf("scan=%+v inventory=%+v delta=%+v", scan, inventory, delta)
    }
    for _, result := range scan.Coverage {
        if result.LocalEvidenceTargets != nil { t.Fatalf("runtime targets survived: %+v", result.LocalEvidenceTargets) }
    }
}
```

Add tests that graph-normalization orphan removal happens before evidence path access, project-MCP follow-up preserves both projects and MCP evidence targets, evidence change contributes to delta, partial evidence makes scan partial, and cache write failure still returns a successful persisted scan.

- [ ] **Step 2: Run scan tests to verify failure**

Run: `go test ./internal/scan -run 'Evidence|Cache|GraphNormalization' -count=1`

Expected: scan v2 has no evidence stage.

- [ ] **Step 3: Integrate the engine in the exact pipeline order**

Keep project MCP follow-up first. Build discovery inventory, call the evidence engine with normalized inventory and collector results, append sorted evidence, clear targets, load previous snapshot, compute delta, build v3 scan result, save snapshot, then best-effort write cache rows. When `snapshots` implements `evidence.LeafCache`/`CacheWriter`, wire it automatically; memory stores use the disabled cache.

Update `overallStatus` so evidence coverage must be `complete`. Zero accepted targets with complete discovery yields complete empty evidence coverage, not unknown coverage.

- [ ] **Step 4: Write failing baseline and status JSON golden tests**

Require this top-level order and exact schema values:

```json
{
  "schemaVersion": "ssc-init.scan.v3",
  "scanId": "00000000-0000-4000-8000-000000000001",
  "status": "complete",
  "startedAt": "2026-08-07T00:00:00Z",
  "finishedAt": "2026-08-07T00:00:01Z",
  "scope": {"platform":"darwin","catalogVersion":"ssc-init.catalog.v1","projectRoots":[],"externalProbes":false},
  "coverage": [],
  "evidenceCoverage": {"status":"complete","targets":[]},
  "inventory": {"assets":[],"observations":[],"evidence":[],"relationships":[]},
  "delta": {"changes":[]}
}
```

Use concrete fixed UUID/timestamps in the actual golden string. For status, require `ssc-init.status.v3`, inventory schema v3, and evidence coverage. A v1/v2 snapshot returns `legacyInventory=true`, nil evidence, and no claim of complete evidence coverage.

- [ ] **Step 5: Implement report and CLI v3 contracts**

Add `EvidenceCoverage` to `baselinePayload` after collector coverage. Update `statusPayload` and schema selection. Keep `version` and `doctor` contracts unchanged. Error messages remain fixed and path-free.

- [ ] **Step 6: Run scan/report/CLI/main regression tests**

Run: `go test ./internal/scan ./internal/report ./internal/cli ./cmd/ssc-init -count=1`

Run: `go test -race ./internal/scan ./internal/report ./internal/cli ./cmd/ssc-init -count=1`

Expected: PASS.

- [ ] **Step 7: Commit Task 13**

```sh
git add internal/scan internal/report internal/cli cmd/ssc-init
git commit -m "feat: expose content evidence in scan v3"
```

---

### Task 14: Isolated-home acceptance matrix, truthful docs, and release gates

**Files:**
- Modify: `internal/acceptance/baseline_test.go`
- Modify: `internal/acceptance/real_store_test.go`
- Modify: `internal/acceptance/usecase_matrix_test.go`
- Add fixtures under: `testdata/home/`
- Modify: `testdata/golden/baseline.json`
- Modify: `docs/testing/2026-08-06-use-case-validation.md`
- Modify: `README.md`
- Modify: `scripts/build-darwin_test.go`

**Interfaces:**
- Proves: every design acceptance criterion with isolated fixtures and release commands.
- Documents: exact supported content evidence and remaining non-goals.
- Preserves: no real home, network, daemon, package manager, Docker, or `codesign` contact in default acceptance.

- [ ] **Step 1: Write the failing isolated-home content mutation matrix**

Build a table with one baseline fixture and one mutation for each supported subject:

```go
type contentMutationCase struct {
    name, assetType, subject string
    mutate func(t *testing.T, home string)
    wantStatus model.EvidenceStatus
}
```

Populate concrete cases for Claude/Codex plugin manifests and payloads; Claude/Codex/Cursor skill bodies; VS Code, Insiders, OSS, Cursor, Windsurf manifests/main/browser/payloads; JetBrains plugin XML/JAR; supported-semantic MCP fields; every project catalog filename; unsupported package content; and unsupported Docker identity. For each case, save baseline, mutate one file or semantic field, rescan, reopen SQLite, and require the exact evidence `changed` delta or terminal unsupported status.

- [ ] **Step 2: Add adversarial coverage fixtures**

Add isolated cases for symlink root/intermediate/final/link swap, manifest anchor swap, entry-point escape, FIFO/socket/special file, exact/over byte bounds, tree depth/entry/total limits, cancellation, permission denial, hostile sibling isolation, invalid UTF-8/decomposed Unicode names, cache hit/miss/rejection, size/mtime-preserving replacement, external project root privacy, and real-home marker non-read.

- [ ] **Step 3: Run acceptance tests to verify at least one red case before final implementation fixes**

Run: `go test ./internal/acceptance -run 'ContentEvidence|EvidenceAdversarial' -count=1`

Expected before final fixture wiring: FAIL on missing v3 golden or evidence delta; after wiring: PASS.

- [ ] **Step 4: Update README and validation report with exact boundaries**

README must say that default scans hash supported plugin/skill manifests and bounded payload trees, supported IDE manifests/entry points/trees, secret-free MCP semantics, and exact project manifest/lockfile catalogs. It must also state that package payloads, immutable Docker identity, code signatures, TI, behavior analysis, policy, warnings, blocking, and host adapters remain unimplemented. Preserve “not an EDR,” “no malware verdict,” and “no safety guarantee.”

Append a dated v3 revalidation section to the use-case report with command outputs, fixture scope, false-negative boundaries, and no-contact proof. Do not rewrite the historical foundation results.

- [ ] **Step 5: Run the complete verification suite from a clean test cache**

Run:

```sh
go clean -testcache
go test -race -count=1 ./...
go vet ./...
go mod verify
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 6: Build and verify both Darwin release artifacts**

Run:

```sh
sh scripts/build-darwin.sh
file dist/ssc-init-darwin-arm64 dist/ssc-init-darwin-amd64
shasum -a 256 -c dist/checksums.txt
./dist/ssc-init-darwin-arm64 version --json
arch -x86_64 ./dist/ssc-init-darwin-amd64 version --json
```

Expected: arm64 and x86_64 Mach-O executables, valid checksums, and both version payloads reporting the committed HEAD.

- [ ] **Step 7: Perform privacy and filesystem static audits**

Run:

```sh
rg -n 'EvalSymlinks|filepath\.Walk|os\.ReadFile|os\.Open\(' internal/evidence internal/collector internal/scan
rg -n 'RootPath|RelativePath|Provenance|LocalEvidenceTargets' internal/store internal/report
rg -n 'malware|safe|full scan|block|signature|Docker' README.md docs/testing/2026-08-06-use-case-validation.md
```

Expected: no evidence target uses forbidden path reopen patterns; persistence/report references exist only in validators/tests proving runtime fields are rejected; public claims match implemented scope.

- [ ] **Step 8: Commit Task 14**

```sh
git add README.md docs/testing internal/acceptance testdata scripts/build-darwin_test.go
git commit -m "test: validate local content evidence scope"
```

- [ ] **Step 9: Request independent review and close every finding**

Review the complete implementation range against all 13 design acceptance criteria. For each finding, add a reproducing failing test before the fix, rerun the focused package, rerun the full verification suite, and commit the fix with a scoped `fix:` message. The branch is ready to merge only when review has no open correctness, privacy, race, scope, migration, or claim issue and `git status --short` is empty.

---

## Plan self-review

| Design acceptance criterion | Implemented and proved by |
|---|---|
| Supported content-only mutations produce deterministic deltas | Tasks 7–10 and 14 |
| Every issued target has a terminal result | Tasks 6, 11, and 14 |
| Only complete evidence is trusted | Tasks 1, 6, and 12 |
| Descriptor anchoring and no-follow trees | Tasks 2–4 and 14 |
| Discovery anchors match evidence revision | Tasks 6–10 and 14 |
| Hostile targets are isolated and previous snapshots survive | Tasks 6, 12, and 14 |
| Cache requires local ctime identity and safely falls back | Tasks 2, 5, 12, and 14 |
| No raw content, secrets, paths, leaf lists, or link targets persist | Tasks 6, 9, 10, 12, and 14 |
| Project scope is exact-catalog and configured-root only | Tasks 10 and 14 |
| Default scan executes no process or network access | Tasks 6, 13, and 14 |
| v3 determinism with v1/v2 read compatibility | Tasks 1, 12–14 |
| README claims match tested behavior | Task 14 |
| Race, vet, module, migration, build, checksum, smoke, and review gates pass | Task 14 |

Coverage review found no unassigned design requirement. Placeholder scan,
task-number order, interface names, schema versions, limits, subject/kind values,
and cache/persistence transaction boundaries must be rechecked after any plan
edit.

## Plan completion evidence

The implementing session records:

- the commit hash for every task;
- focused red/green command output for every task;
- final race, vet, module, diff, migration, acceptance, build, checksum, native, and Rosetta results;
- the independent review disposition;
- the exact clean worktree and integration state.
