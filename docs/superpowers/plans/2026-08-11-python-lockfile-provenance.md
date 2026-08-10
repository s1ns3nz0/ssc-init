# Python Lockfile Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse `requirements.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock` into privacy-safe PyPI package provenance and `declared-by` graph facts.

**Architecture:** Add four format-specific parsers behind `provenance.Parse`, with shared conservative Python coordinate and integrity classification helpers. Wire the already-discovered basenames through the existing descriptor-rooted project collector so bounds, cancellation, identity checks, evidence, persistence, and graph construction remain unchanged.

**Tech Stack:** Go 1.26, Go standard library, existing pinned `github.com/pelletier/go-toml/v2`; no new dependency, process, network access, CLI flag, or schema migration.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-11-python-lockfile-provenance-design.md` exactly.
- Only one exact version plus one distinct valid SHA-256 artifact digest is `immutable`; multiple hashes are `unknown` and retain no arbitrary digest.
- Never persist raw lines, URLs, paths, credentials, markers, filenames, or hash sets.
- Errors are fixed and value-free; hostile lockfiles remain isolated from safe siblings.
- Preserve descriptor-rooted reads, pre/post identity verification, cancellation, deterministic sorting, and the `ssc-init.scan.v7` contract.

---

## File responsibility map

- `internal/provenance/parser.go`: public formats, bounded dispatch, generic record conflict/sort behavior.
- `internal/provenance/python.go`: PyPI normalization, exact/mutable version classification, SHA-256 set classification.
- `internal/provenance/requirements.go`: bounded requirements logical-line grammar only.
- `internal/provenance/pipfile.go`: unique-key JSON lock parser only.
- `internal/provenance/poetry.go`: Poetry TOML lock parser only.
- `internal/provenance/uv.go`: uv TOML lock parser only.
- `internal/provenance/python_test.go`: shared and per-format parser contracts/adversarial cases.
- `internal/collector/projects/collector.go`: basename-to-format routing only.
- `internal/collector/projects/collector_test.go`: collector assets, relationships, identity and sibling isolation.
- `internal/acceptance/program_d_test.go`: isolated-home end-to-end and serialized privacy contract.
- `README.md`, `CLAUDE.md`, `docs/testing/2026-08-09-foundation-completion-audit.md`: current capability truth.

### Task 1: Shared Python provenance classification

**Files:**
- Create: `internal/provenance/python.go`
- Create: `internal/provenance/python_test.go`
- Modify: `internal/provenance/parser.go`

**Interfaces:**
- Produces: `pythonRecord(name, version string, mutable bool, hashes []string) (Record, bool)` and `normalizePyPIName(string) (string, bool)`.
- Consumes: existing `Record`, `packageRecord`, `lowercaseSHA256`, and `addRecord` contracts.

- [ ] **Step 1: Write failing shared-classification tests**

Add table tests that call `pythonRecord` directly:

```go
func TestPythonRecordClassifiesIntegrityConservatively(t *testing.T) {
    a := strings.Repeat("a", 64)
    b := strings.Repeat("b", 64)
    tests := []struct {
        name, version string
        mutable bool
        hashes []string
        wantName string
        wantStatus model.ProvenanceStatus
        wantIntegrity string
        ok bool
    }{
        {"Foo__..Bar", "1.2.3", false, []string{"sha256:" + a}, "foo-bar", model.ProvenanceImmutable, "sha256:" + a, true},
        {"demo", "1.2.3", false, nil, "demo", model.ProvenanceUnknown, "", true},
        {"demo", "1.2.3", false, []string{"sha256:" + a, "sha256:" + b}, "demo", model.ProvenanceUnknown, "", true},
        {"demo", "1.2.3", true, []string{"sha256:" + a}, "demo", model.ProvenanceMutable, "", true},
        {"/private/demo", "1.2.3", false, nil, "", "", "", false},
    }
    for _, testCase := range tests {
        got, ok := pythonRecord(testCase.name, testCase.version, testCase.mutable, testCase.hashes)
        if ok != testCase.ok {
            t.Fatalf("name=%q ok=%v want=%v record=%+v", testCase.name, ok, testCase.ok, got)
        }
        if !ok {
            continue
        }
        if got.Name != testCase.wantName || got.Version != testCase.version ||
            got.Ecosystem != "pypi" || got.Provenance.Ecosystem != "pypi" ||
            got.Provenance.Source != "lockfile" || got.Provenance.Status != testCase.wantStatus ||
            got.Provenance.Integrity != testCase.wantIntegrity {
            t.Fatalf("name=%q record=%+v", testCase.name, got)
        }
    }
}
```

Also assert deduplication of repeated identical hashes, rejection of malformed
declared SHA-256, lowercase normalized names, and exact-version detection for
`1.2.3`, `1.2.3.post1`, and `1!2.0`; reject/rank mutable `""`, `*`, `>=1`,
`~=1.2`, URL, Git, path, and workspace forms.

- [ ] **Step 2: Run RED**

Run: `go test ./internal/provenance -run 'TestPythonRecord|TestNormalizePyPI' -count=1`

Expected: FAIL because the Python helpers do not exist.

- [ ] **Step 3: Implement minimal shared helpers**

Implement ASCII PEP 503 normalization and a classifier with these invariants:

```go
func pythonRecord(name, version string, mutable bool, hashes []string) (Record, bool) {
    normalized, ok := normalizePyPIName(name)
    if !ok {
        return Record{}, false
    }
    record, ok := packageRecord("pypi", normalized, version)
    if !ok {
        return Record{}, false
    }
    if mutable || !exactPythonVersion(version) {
        record.Provenance.Status = model.ProvenanceMutable
        record.Provenance.Integrity = ""
        return record, true
    }
    unique, valid := distinctPythonSHA256(hashes)
    if !valid {
        return Record{}, false
    }
    if len(unique) == 1 {
        record.Provenance.Status = model.ProvenanceImmutable
        record.Provenance.Integrity = "sha256:" + unique[0]
    } else {
        record.Provenance.Status = model.ProvenanceUnknown
        record.Provenance.Integrity = ""
    }
    return record, true
}
```

`distinctPythonSHA256` ignores syntactically valid non-SHA-256 algorithms but
returns invalid when a value declares `sha256:` with anything other than 64
lowercase hex characters.

- [ ] **Step 4: Run GREEN and regression**

Run: `go test ./internal/provenance -count=1`

Expected: PASS, including the existing npm/Cargo/Go cases.

- [ ] **Step 5: Commit**

```sh
git add internal/provenance/parser.go internal/provenance/python.go internal/provenance/python_test.go
git commit -m "feat: classify python lockfile provenance"
```

### Task 2: Requirements and Pipfile lock parsers

**Files:**
- Create: `internal/provenance/requirements.go`
- Create: `internal/provenance/pipfile.go`
- Modify: `internal/provenance/parser.go`
- Modify: `internal/provenance/python_test.go`

**Interfaces:**
- Produces: `FormatRequirements`, `FormatPipfile`, `parseRequirements([]byte)`, and `parsePipfile([]byte)`.
- Consumes: Task 1's `pythonRecord`, existing `uniqueJSONKeys`, `addRecord`, and deterministic dispatch sorting.

- [ ] **Step 1: Write failing requirements tests**

Cover exact single-hash, hashless, multiple hashes, marker/comment removal,
backslash continuation, duplicate identical entries, conflicting duplicates,
mutable named direct reference/editable/range, ignored index/include options,
unnamed path skipping, malformed SHA-256, CRLF, oversize, and cancellation.
The principal fixture is:

```text
Foo_Bar==1.2.3 ; python_version >= "3.11" \
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
--index-url https://user:secret@example.invalid/simple
-r private-requirements.txt
```

Assert one immutable `pkg:pypi/foo-bar@1.2.3`-equivalent record and prove the
URL, credential, marker, and include name appear nowhere in formatted records
or errors.

- [ ] **Step 2: Write failing Pipfile tests**

Cover `default` plus `develop`, exact/hashless/multi-hash, path/git/editable,
duplicate normalized conflicts, duplicate JSON keys, wrong containers,
trailing JSON, malformed SHA-256, ignored `_meta` sources, and stable sorting.

- [ ] **Step 3: Run RED**

Run: `go test ./internal/provenance -run 'TestParseRequirements|TestParsePipfile' -count=1`

Expected: FAIL because the formats and parsers are undefined.

- [ ] **Step 4: Implement the requirements parser**

Build logical lines with an explicit maximum inherited from the already-bounded
input. Ignore only the closed option prefixes `-i`, `--index-url`,
`--extra-index-url`, `-f`, `--find-links`, `--trusted-host`, `-c`,
`--constraint`, `-r`, and `--requirement`. Parse hashes without opening any
referenced file. Use `addRecord` for deterministic conflict refusal.

- [ ] **Step 5: Implement the Pipfile parser**

Require unique JSON keys before decoding. Decode `default` and `develop` into
an explicit entry struct with `version`, `hashes`, `path`, `file`, `git`, and
`editable`; reject non-object dependency values and trailing data. Strip only
one leading `==` for an exact version.

- [ ] **Step 6: Wire dispatch and run GREEN**

Add both constants to `Format` and both cases to `Parse`.

Run: `go test ./internal/provenance -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```sh
git add internal/provenance/parser.go internal/provenance/requirements.go internal/provenance/pipfile.go internal/provenance/python_test.go
git commit -m "feat: parse python text and json locks"
```

### Task 3: Poetry and uv TOML parsers

**Files:**
- Create: `internal/provenance/poetry.go`
- Create: `internal/provenance/uv.go`
- Modify: `internal/provenance/parser.go`
- Modify: `internal/provenance/python_test.go`

**Interfaces:**
- Produces: `FormatPoetry`, `FormatUV`, `parsePoetry([]byte)`, and `parseUV([]byte)`.
- Consumes: Task 1 classification and the existing pinned TOML decoder.

- [ ] **Step 1: Write failing Poetry tests**

Use `[[package]]` fixtures for registry single/multiple/no hashes and
directory/file/url/git/develop sources. Assert groups, markers, extras,
filenames, and `[metadata].content-hash` do not enter records. Add wrong
container, missing name, conflicting duplicate, and malformed SHA-256 cases.

- [ ] **Step 2: Write failing uv tests**

Use `[[package]]` fixtures with `{ registry = ... }`, `{ git = ... }`,
`{ editable = ... }`, `{ virtual = ... }`, `{ path = ... }`, `sdist`, and
`wheels`. Assert all artifact hashes participate in conservative
classification, while filenames and URLs are discarded.

- [ ] **Step 3: Run RED**

Run: `go test ./internal/provenance -run 'TestParsePoetry|TestParseUV' -count=1`

Expected: FAIL because the TOML formats and parsers are undefined.

- [ ] **Step 4: Implement Poetry parser**

Decode only the closed fields needed for classification. Treat any source type
other than absent/`legacy` as mutable; also treat `develop = true` as mutable.
Collect only `files[].hash`, then immediately discard decoded filenames and
the input buffer after `Parse` returns.

- [ ] **Step 5: Implement uv parser**

Decode source as a typed map only long enough to classify registry versus
mutable source. Collect `sdist.hash` and every `wheels[].hash`; do not retain
URLs or filenames. Missing version is mutable.

- [ ] **Step 6: Wire dispatch and run GREEN**

Run: `go test ./internal/provenance -count=1`

Expected: PASS for all seven supported formats.

- [ ] **Step 7: Mutation-check the hash semantics**

Temporarily change the multi-hash branch to select the first hash and run:

`go test ./internal/provenance -run 'Multiple|MultiHash|Conservatively' -count=1`

Expected: FAIL. Restore the implementation and rerun the package to PASS.

- [ ] **Step 8: Commit**

```sh
git add internal/provenance/parser.go internal/provenance/poetry.go internal/provenance/uv.go internal/provenance/python_test.go
git commit -m "feat: parse poetry and uv locks"
```

### Task 4: Project collector wiring and isolation

**Files:**
- Modify: `internal/collector/projects/collector.go`
- Modify: `internal/collector/projects/collector_test.go`

**Interfaces:**
- Consumes: the four new `provenance.Format` constants.
- Produces: existing `model.Asset`, `model.Observation`, and `declared-by` relationships for all four basenames.

- [ ] **Step 1: Write failing routing and graph tests**

Create one project with valid minimal fixtures for all four formats. Assert
PyPI package IDs, provenance statuses, lockfile assets, and a `declared-by`
edge per package. Extend the exact-catalog test so valid Python fixtures no
longer expect the project to contain only its root asset.

- [ ] **Step 2: Write failing isolation tests**

Create a malformed `Pipfile.lock` beside a valid `uv.lock`; assert fixed
`provenance_malformed`, partial project coverage, valid uv package retention,
and complete content evidence for both files. Reuse the existing replacement
file hooks to prove identity drift emits no package from the changed file.

- [ ] **Step 3: Run RED**

Run: `go test ./internal/collector/projects -run 'Python|Pipfile|Poetry|UV|ExactCatalog' -count=1`

Expected: FAIL because `provenanceFormat` routes only npm, Cargo, and Go.

- [ ] **Step 4: Add exact basename routing**

Extend `provenanceFormat` with:

```go
case "requirements.txt": return provenance.FormatRequirements, true
case "Pipfile.lock": return provenance.FormatPipfile, true
case "poetry.lock": return provenance.FormatPoetry, true
case "uv.lock": return provenance.FormatUV, true
```

Do not change file discovery, open, fingerprint, error, asset, observation, or
relationship code.

- [ ] **Step 5: Run GREEN and race regression**

Run:

```sh
go test ./internal/collector/projects -count=1
go test -race ./internal/provenance ./internal/collector/projects -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add internal/collector/projects/collector.go internal/collector/projects/collector_test.go
git commit -m "feat: collect python lockfile provenance"
```

### Task 5: Acceptance, documentation, and full gates

**Files:**
- Modify: `internal/acceptance/program_d_test.go`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/testing/2026-08-09-foundation-completion-audit.md`

**Interfaces:**
- Consumes: complete parser and collector behavior from Tasks 1–4.
- Produces: end-to-end privacy/reproducibility evidence and current capability documentation.

- [ ] **Step 1: Write failing isolated-home acceptance**

Add `TestPythonLockfileProvenanceAcceptance`. Write four lockfiles under an
isolated `$HOME/Projects/app`, including marker, source URL, credential,
filename, local path, and two distinct hashes as privacy markers. Run the
default baseline with no external probes. Assert:

- expected `pkg:pypi/...` assets and `declared-by` edges exist;
- single-hash exact packages are immutable;
- multi-hash exact packages are unknown with empty integrity;
- mutable sources are mutable;
- serialized report and marshaled inventory contain none of the privacy
  markers or absolute home path;
- the runner call count remains zero.

- [ ] **Step 2: Prove acceptance sensitivity, then update capability docs**

Run: `go test ./internal/acceptance -run TestPythonLockfileProvenanceAcceptance -count=1`

Expected: PASS. Then temporarily remove the `requirements.txt` routing case,
rerun the same test, and observe FAIL on the missing requirements package and
relationship. Restore the routing case and rerun to PASS. This mutation proves
the end-to-end assertion is not decorative after the focused parser and
collector behavior was already built through RED→GREEN cycles. Update README,
CLAUDE, and the completion audit to name the four supported Python formats and
narrow the remaining provenance gap to other ecosystems and conditional
dependency-edge extraction.

- [ ] **Step 3: Run focused mutation battery**

Verify tests fail independently when temporarily applying each mutation, then
restore it:

1. route `uv.lock` to `FormatPoetry`;
2. classify multiple hashes as immutable;
3. remove the post-read fingerprint comparison;
4. serialize one source URL into observation metadata;
5. change PyPI normalization to preserve underscores.

Run the smallest focused test named by each mutation and record the expected
failure in the commit message body or task ledger.

- [ ] **Step 4: Run full release gates**

```sh
gofmt -w internal/provenance/*.go internal/collector/projects/*.go internal/acceptance/program_d_test.go
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
```

Expected: all PASS and `go.mod`/`go.sum` unchanged.

- [ ] **Step 5: Commit documentation and acceptance evidence**

```sh
git add internal/acceptance/program_d_test.go README.md CLAUDE.md docs/testing/2026-08-09-foundation-completion-audit.md
git commit -m "test: prove python lockfile provenance"
```

- [ ] **Step 6: Run the clean release-script gate**

After the commit leaves a clean tracked tree:

```sh
go test ./scripts -count=1
git status --short
```

Expected: PASS and no tracked or untracked changes.
