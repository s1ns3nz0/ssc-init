# Program A — Distribution and Lifecycle

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `scripts/build-darwin.sh` from "two unsigned per-arch binaries and a checksum file" into the §5.2/§14 release artifact set (Universal Binary, checksums, SBOM, build provenance, signature, notarization), and turn `~/Library/Application Support/SSC Init/` from "one directory containing `state.db`" into the §5.3 shared installation with versioned core binaries, a current-version pointer, and a §11 stage → verify → health check → atomic switch → rollback lifecycle.

**Architecture:** The release side stays in `scripts/`: `build-darwin.sh` gains a `lipo` step, a CycloneDX SBOM derived from `go version -m`, and an in-toto/SLSA provenance statement — all deterministic, all still produced with no network and no new module. Signing and notarization move to two *separate* scripts (`scripts/sign-darwin.sh`, `scripts/notarize-darwin.sh`) because a Developer ID signature carries an Apple secure timestamp and is therefore inherently non-reproducible: it must not run inside the reproducible build. The install side is a new `internal/install` package operating through `os.Root` on `DataDir`, with `internal/platform` owning the layout and the version-string trust boundary, `internal/cli` + `cmd/ssc-init` exposing `install`/`rollback`, and `internal/doctor` reporting install health.

**Tech Stack:** Go 1.26 standard library only (`os.Root`, `crypto/sha256`, `encoding/json`, `regexp`), POSIX `sh` + `awk` + `shasum`, Apple-provided `/usr/bin/lipo`, `/usr/bin/codesign`, `xcrun notarytool`. No new Go module.

## Blocked vs unblocked

Code signing and notarization require **an Apple Developer ID Application certificate in the login keychain and an Apple ID with an app-specific password stored as a `notarytool` keychain profile**. The user does not have these yet, and enrolment plus certificate issuance has real-world lead time (Apple Developer Program membership, identity verification, certificate request). Nothing else in this program depends on them.

| Task | Blocked on Developer ID? |
|---|---|
| 1 Universal binary via `lipo` | No |
| 2 CycloneDX SBOM | No |
| 3 Build provenance statement | No |
| 4 First CI workflow on macOS | No |
| 5 Versioned install layout and version trust boundary | No |
| 6 Stage and verify a core version | No |
| 7 Atomic switch, previous known-good, rollback | No |
| 8 `install` / `rollback` commands | No |
| 9 `doctor` install health (`ssc-init.doctor.v2`) | No |
| 10 `codesign` the Universal Binary | **Yes** — except its fail-closed path, which is tested now |
| 11 Notarization submission | **Yes** — except its fail-closed path, which is tested now |
| 12 Release runbook | No to write; the §10–11 sections cannot be *executed* until the certificate exists |

Execute 1 → 12 in order. Tasks 10 and 11 are written, committed, and their fail-closed behaviour tested without any credential; only their success paths wait. Do not reorder 10/11 ahead of 12 if the certificate has not arrived — Task 12 documents them as pending and is amended once they are exercised.

**How the signing tasks are verified.** `codesign` and `notarytool` cannot run in CI (no secrets, no keychain) and cannot run locally without the certificate. Both scripts are therefore split into a *testable* half and a *manual* half:

- Testable now, in CI, with no credential: the script must fail closed with an exact, value-free message naming the missing credential and must not produce, mutate, or truncate any artifact before failing. Task 10 and Task 11 each write a real Go test for this in `scripts/`.
- Manual, by the user, once the certificate exists: the exact commands and the exact expected output are recorded in the Task 12 runbook (`codesign --verify --strict --verbose=2`, `xcrun notarytool log`, `spctl -a -vvv -t open --context context:primary-signature`). The runbook is amended with the observed output the first time a real release is signed.

## Global constraints (release-blocking)

- `CGO_ENABLED=0`, Darwin arm64 + amd64, no mandatory external runtime. `lipo`, `codesign`, and `notarytool` are *build-host* tools, never runtime dependencies of `ssc-init`.
- No new Go module. `go.mod` must be unchanged by this program.
- The unsigned build is byte-for-byte reproducible: two consecutive `sh scripts/build-darwin.sh` runs on one machine must produce identical bytes for **every** file in `dist/`. Signing happens outside that boundary — verified below: two ad-hoc `codesign` runs over identical input produce different digests, so a signature in `build-darwin.sh` would break the reproducibility test permanently.
- The clean-tracked-worktree gate and its exact message `release build requires a clean worktree` stay. No new failure message may leak a filename or path.
- Version selection is unchanged: exact `v[0-9]*` tag with a safe character set wins, everything else is `dev+git.<40-hex>`.
- Every existing expectation in `scripts/build-darwin_test.go` keeps holding unless a task explicitly and minimally amends it; amendments are stated in full in the task.
- Install never touches `state.db`, TI/policy bundles, reports, or quarantine. §5.3: removing an adapter must not silently remove shared data.
- Persist no absolute path, no source path, no secret. The install manifest records version + digest only.

Conventions (every task): strict TDD; after GREEN run `go vet ./...`, `gofmt -l` on touched dirs, `git diff --check`; commit messages end with the trailer `Claude-Session: https://claude.ai/code/session_01YCnH78bwuqahh8qmL5wpu6`. `go test ./scripts` requires a clean tree — run it only after committing. Never `git add -A`; add the named paths.

---

### Task 1: Universal Binary via `lipo`

**Files:**
- Modify: `scripts/build-darwin.sh`
- Modify: `scripts/build-darwin_test.go`

§5.2 requires a Universal Binary; the script produces two thin ones. Keep both thin slices in `dist/` — the existing native smoke tests (`assertNativeVersion`, `assertNativeIsolatedStatusV3`) address `dist/ssc-init-darwin-<runtime.GOARCH>`, and `go version -m` on a thin slice is how `assertNoAutomaticVCSSettings` proves no VCS metadata leaked. The Universal Binary is a third artifact, not a replacement.

Verified facts this task depends on:
- `/usr/bin/lipo` ships with the Command Line Tools; no Xcode.app required.
- `lipo -create` is deterministic: two runs one second apart over identical inputs produced the same SHA-256.
- `go version -m` works on the fat Mach-O, so the version and VCS assertions extend to it.
- `lipo -create` **drops the ad-hoc linker signature** — `codesign -v` on the fat file reports `code object is not signed at all`, while `codesign -dv --arch arm64` still shows the arm64 slice's `adhoc,linker-signed` code directory. The universal artifact still executes and prints the correct version. Do **not** ad-hoc re-sign to "fix" this: ad-hoc `codesign` is non-deterministic (two runs produced digests `14415f75…` and `9b4efff2…`), which would break reproducibility. Task 10 gives it a real signature.

The fixtures build with a fake `go` that writes the text `fake-arm64` / `fake-amd64`. Real `lipo` rejects those, so `TestBuildScriptAllowsIgnoredEntries` and `TestBuildScriptVersionsFromExactTag` would fail. The fixture gets a fake `lipo` on the same `PATH` shim directory.

- [ ] **Step 1: Write the failing test**

In `scripts/build-darwin_test.go`, add `"lipo -create"` to the `want` list in `TestBuildScriptDeclaresStaticTargets`, and add:

```go
func TestBuildScriptProducesUniversalBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build smoke test")
	}
	repositoryRoot := repositoryRoot(t)
	command := exec.Command("sh", filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = environmentWith("SOURCE_DATE_EPOCH", "0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}
	universal := filepath.Join(repositoryRoot, "dist", "ssc-init-darwin-universal")
	info, err := exec.Command("lipo", "-info", universal).CombinedOutput()
	if err != nil {
		t.Fatalf("lipo -info failed: %v\n%s", err, info)
	}
	for _, architecture := range []string{"x86_64", "arm64"} {
		if !bytes.Contains(info, []byte(architecture)) {
			t.Fatalf("universal binary is missing %s: %s", architecture, info)
		}
	}
	assertNoAutomaticVCSSettings(t, universal)
	if content, err := os.ReadFile(universal); err != nil {
		t.Fatal(err)
	} else if !bytes.Contains(content, []byte(expectedReleaseVersion(t, repositoryRoot))) {
		t.Fatal("universal binary does not carry the release version")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run 'TestBuildScriptDeclaresStaticTargets|TestBuildScriptProducesUniversalBinary' -count=1`

Expected: FAIL — `build script missing "lipo -create"`, and `lipo -info failed: exit status 1 … can't open input file: …/dist/ssc-init-darwin-universal`.

- [ ] **Step 3: Implement**

In `scripts/build-darwin.sh`, after the two `go build` lines and before the `shasum` line:

```sh
lipo -create -output "$DIST_DIR/ssc-init-darwin-universal" \
	"$DIST_DIR/ssc-init-darwin-arm64" \
	"$DIST_DIR/ssc-init-darwin-amd64"
```

Extend the checksum line to cover it:

```sh
shasum -a 256 \
	dist/ssc-init-darwin-amd64 \
	dist/ssc-init-darwin-arm64 \
	dist/ssc-init-darwin-universal | sort -k 2 > "$DIST_DIR/checksums.txt"
```

`sort -k 2` puts `…-universal` last, so the file stays deterministically ordered.

In `scripts/build-darwin_test.go`, three existing expectations move:

1. `TestBuildScriptWorksOutsideRepositoryAndIsReproducible` — add `"ssc-init-darwin-universal"` to the artifact name slice, and change the checksum tail assertion from two lines to three:

```go
	if len(lines) != 3 ||
		!strings.HasSuffix(lines[0], "  dist/ssc-init-darwin-amd64") ||
		!strings.HasSuffix(lines[1], "  dist/ssc-init-darwin-arm64") ||
		!strings.HasSuffix(lines[2], "  dist/ssc-init-darwin-universal") {
		t.Fatalf("checksums are not deterministically sorted:\n%s", checksums)
	}
```

2. `TestBuildScriptAllowsIgnoredEntries` — add `"ssc-init-darwin-universal"` to its expected-name slice.

3. `newIsolatedReleaseRepository` — write a fake `lipo` into the same `binDirectory` as the fake `go`, so the fixture never invokes the real one:

```go
	fakeLipo := filepath.Join(binDirectory, "lipo")
	fakeLipoSource := "#!/bin/sh\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -output ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf 'fake-universal\\n' > \"$output\"\n"
	if err := os.WriteFile(fakeLipo, []byte(fakeLipoSource), 0o755); err != nil {
		t.Fatal(err)
	}
```

`newVersionRecordingReleaseRepository` builds on `newIsolatedReleaseRepository` but replaces `binDirectory`; give it the same fake `lipo` so its build also completes.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -count=1`

Expected: PASS, including the reproducibility comparison — the universal binary must have the same digest across both runs.

Also confirm by hand that the artifact is real and runnable:

```sh
lipo -info dist/ssc-init-darwin-universal
dist/ssc-init-darwin-universal version --json
```

Expected: `Architectures in the fat file: dist/ssc-init-darwin-universal are: x86_64 arm64` and the same `version` value the thin slices report.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-darwin.sh scripts/build-darwin_test.go
git commit -m "feat: build a darwin universal binary"
```

---

### Task 2: CycloneDX SBOM from the built binary

**Files:**
- Modify: `scripts/build-darwin.sh`
- Modify: `scripts/build-darwin_test.go`

§14 requires an SBOM in every release. The dependency set is already embedded in the binary — `go version -m dist/ssc-init-darwin-universal` lists every `dep` with its version and its `h1:` module hash. Deriving the SBOM from the *artifact* rather than from `go.mod` is the point: it describes what actually shipped. No SBOM tool is installed and none may be added (`GOPROXY=off`, and a new module is release-blocking), so the script emits CycloneDX 1.5 JSON with `awk`.

The `h1:` value is a base64 module dirhash, **not** a hex SHA-256. Emitting it as a CycloneDX `hashes[].content` would be a false statement in a supply-chain document. It goes in a `properties` entry instead. The document carries no timestamp, which keeps it deterministic (CycloneDX `metadata.timestamp` is optional).

- [ ] **Step 1: Write the failing test**

Add `"go version -m"` and `"bomFormat"` to the `want` list in `TestBuildScriptDeclaresStaticTargets`, and add:

```go
func TestBuildScriptEmitsCycloneDXSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build smoke test")
	}
	repositoryRoot := repositoryRoot(t)
	command := exec.Command("sh", filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = environmentWith("SOURCE_DATE_EPOCH", "0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, "dist", "sbom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, raw)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.5" {
		t.Fatalf("unexpected sbom envelope: %+v", document)
	}
	if document.Metadata.Component.Name != "ssc-init" ||
		document.Metadata.Component.Version != expectedReleaseVersion(t, repositoryRoot) {
		t.Fatalf("sbom does not describe this release: %+v", document.Metadata.Component)
	}
	if len(document.Components) == 0 {
		t.Fatal("sbom lists no dependencies")
	}
	for _, component := range document.Components {
		if component.PURL != "pkg:golang/"+component.Name+"@"+component.Version {
			t.Fatalf("malformed purl for %s: %q", component.Name, component.PURL)
		}
	}
	if bytes.Contains(raw, []byte(repositoryRoot)) {
		t.Fatal("sbom contains an absolute repository path")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run 'TestBuildScriptDeclaresStaticTargets|TestBuildScriptEmitsCycloneDXSBOM' -count=1`

Expected: FAIL — `build script missing "bomFormat"`, and `open …/dist/sbom.cdx.json: no such file or directory`.

- [ ] **Step 3: Implement**

In `scripts/build-darwin.sh`, after the `shasum` line:

```sh
go version -m "$DIST_DIR/ssc-init-darwin-universal" |
	awk -v version="$VERSION" -v revision="$REVISION" '
		BEGIN {
			printf "{\n"
			printf "  \"bomFormat\": \"CycloneDX\",\n"
			printf "  \"specVersion\": \"1.5\",\n"
			printf "  \"version\": 1,\n"
			printf "  \"metadata\": {\n"
			printf "    \"component\": {\n"
			printf "      \"type\": \"application\",\n"
			printf "      \"bom-ref\": \"pkg:golang/github.com/s1ns3nz0/ssc-init@%s\",\n", version
			printf "      \"name\": \"ssc-init\",\n"
			printf "      \"version\": \"%s\",\n", version
			printf "      \"purl\": \"pkg:golang/github.com/s1ns3nz0/ssc-init@%s\",\n", version
			printf "      \"licenses\": [{\"license\": {\"id\": \"Apache-2.0\"}}],\n"
			printf "      \"properties\": [{\"name\": \"ssc-init:revision\", \"value\": \"%s\"}]\n", revision
			printf "    }\n"
			printf "  },\n"
			printf "  \"components\": ["
		}
		$1 == "dep" {
			if (count++) printf ","
			printf "\n    {"
			printf "\"type\": \"library\", "
			printf "\"bom-ref\": \"pkg:golang/%s@%s\", ", $2, $3
			printf "\"name\": \"%s\", ", $2
			printf "\"version\": \"%s\", ", $3
			printf "\"purl\": \"pkg:golang/%s@%s\"", $2, $3
			if ($4 != "") {
				printf ", \"properties\": [{\"name\": \"go:mod:h1\", \"value\": \"%s\"}]", $4
			}
			printf "}"
		}
		END {
			if (count) printf "\n  "
			printf "]\n}\n"
		}' > "$DIST_DIR/sbom.cdx.json"
```

`go version -m` prints tab-separated fields, so default `awk` field splitting gives `$1="dep"`, `$2=path`, `$3=version`, `$4=h1 hash`. Module paths and versions come from `go.sum`-verified module data and contain no character needing JSON escaping; if that ever stops being true the test's `json.Unmarshal` fails loudly.

Extend the fixture's fake `go` (in `newIsolatedReleaseRepository` and `newVersionRecordingReleaseRepository`) to answer `version -m`, since it currently exits 2 when no `-o` is present and would abort the build under `set -eu`:

```go
	fakeGoSource := "#!/bin/sh\nif [ \"$1\" = version ]; then\n  printf '%s: go1.26.5\\n\\tpath\\tfixture\\n\\tdep\\texample.com/fixture\\tv1.0.0\\th1:fixture=\\n' \"$3\"\n  exit 0\nfi\noutput=\n…"
```

Keep the existing `-o` scanning branch after the `version` branch.

Add `"sbom.cdx.json"` to the artifact-name slices in `TestBuildScriptWorksOutsideRepositoryAndIsReproducible` and `TestBuildScriptAllowsIgnoredEntries`. In the reproducibility loop, the version/VCS assertions apply to binaries only — restructure the loop body so the `assertNoAutomaticVCSSettings` and release-version checks run for the three binaries, while the absolute-path check runs for every artifact except `checksums.txt`:

```go
		binary := strings.HasPrefix(name, "ssc-init-darwin-")
		if name != "checksums.txt" && bytes.Contains(content, []byte(repositoryRoot)) {
			t.Fatalf("%s contains absolute repository path %q", name, repositoryRoot)
		}
		if binary {
			if !bytes.Contains(content, []byte(wantVersion)) {
				t.Fatalf("%s does not contain release version %q", name, wantVersion)
			}
			assertNoAutomaticVCSSettings(t, path)
		}
```

`checksums.txt` still covers only the three binaries — do not add `sbom.cdx.json` to it, or Task 3's provenance would have to hash a file that hashes itself.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -count=1`

Expected: PASS, and the reproducibility comparison must show an identical `sbom.cdx.json` digest across the two runs.

Sanity-check the real document: `python3 -m json.tool dist/sbom.cdx.json | head -30`.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-darwin.sh scripts/build-darwin_test.go
git commit -m "feat: emit a cyclonedx sbom for the release build"
```

---

### Task 3: Build provenance statement

**Files:**
- Modify: `scripts/build-darwin.sh`
- Modify: `scripts/build-darwin_test.go`

§14 requires build provenance. There is no remote, no CI identity, and no signing key yet, so this is an *unsigned, locally reproducible* in-toto Statement wrapping a SLSA v1 provenance predicate: it records exactly which commit, which toolchain, which flags, and which artifact digests produced this build, so a third party who clones the tag and re-runs the script can confirm they get the same digests. It carries no wall-clock time and no invocation ID — both would destroy reproducibility, and neither is verifiable without a hosted builder.

The subjects are the three binaries, read out of the `checksums.txt` the previous step already wrote.

- [ ] **Step 1: Write the failing test**

Add `"in-toto.io/Statement/v1"` to the `want` list in `TestBuildScriptDeclaresStaticTargets`, and add:

```go
func TestBuildScriptEmitsProvenanceMatchingChecksums(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build smoke test")
	}
	repositoryRoot := repositoryRoot(t)
	command := exec.Command("sh", filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = environmentWith("SOURCE_DATE_EPOCH", "0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, "dist", "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			BuildDefinition struct {
				BuildType          string            `json:"buildType"`
				ExternalParameters map[string]string `json:"externalParameters"`
				InternalParameters map[string]string `json:"internalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &statement); err != nil {
		t.Fatalf("provenance is not valid JSON: %v\n%s", err, raw)
	}
	if statement.Type != "https://in-toto.io/Statement/v1" ||
		statement.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("unexpected provenance envelope: %+v", statement)
	}
	if statement.Predicate.BuildDefinition.ExternalParameters["version"] != expectedReleaseVersion(t, repositoryRoot) {
		t.Fatalf("provenance version mismatch: %+v", statement.Predicate.BuildDefinition.ExternalParameters)
	}
	if statement.Predicate.BuildDefinition.ExternalParameters["revision"] != worktreeRevision(t, repositoryRoot) {
		t.Fatal("provenance revision does not match the committed HEAD")
	}
	if statement.Predicate.BuildDefinition.InternalParameters["cgoEnabled"] != "0" {
		t.Fatal("provenance does not record a CGO-free build")
	}

	checksums, err := os.ReadFile(filepath.Join(repositoryRoot, "dist", "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	recorded := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(checksums)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("unexpected checksum line %q", line)
		}
		recorded[filepath.Base(fields[1])] = fields[0]
	}
	if len(statement.Subject) != len(recorded) {
		t.Fatalf("provenance covers %d subjects, checksums cover %d", len(statement.Subject), len(recorded))
	}
	for _, subject := range statement.Subject {
		if subject.Digest["sha256"] != recorded[subject.Name] {
			t.Fatalf("provenance digest for %s does not match checksums.txt", subject.Name)
		}
	}
	if bytes.Contains(raw, []byte(repositoryRoot)) {
		t.Fatal("provenance contains an absolute repository path")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run 'TestBuildScriptDeclaresStaticTargets|TestBuildScriptEmitsProvenanceMatchingChecksums' -count=1`

Expected: FAIL — `build script missing "in-toto.io/Statement/v1"`, and `open …/dist/provenance.json: no such file or directory`.

- [ ] **Step 3: Implement**

In `scripts/build-darwin.sh`, after the SBOM step:

```sh
GO_VERSION=$(go env GOVERSION)

awk -v version="$VERSION" \
	-v revision="$REVISION" \
	-v epoch="$SOURCE_DATE_EPOCH" \
	-v goversion="$GO_VERSION" \
	-v ldflags="$LINKER_FLAGS" '
	BEGIN {
		printf "{\n"
		printf "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
		printf "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n"
		printf "  \"subject\": ["
	}
	NF == 2 {
		name = $2
		sub(/^.*\//, "", name)
		if (count++) printf ","
		printf "\n    {\"name\": \"%s\", \"digest\": {\"sha256\": \"%s\"}}", name, $1
	}
	END {
		if (count) printf "\n  "
		printf "],\n"
		printf "  \"predicate\": {\n"
		printf "    \"buildDefinition\": {\n"
		printf "      \"buildType\": \"https://github.com/s1ns3nz0/ssc-init/scripts/build-darwin.sh@v1\",\n"
		printf "      \"externalParameters\": {\"version\": \"%s\", \"revision\": \"%s\", \"sourceDateEpoch\": \"%s\"},\n", version, revision, epoch
		printf "      \"internalParameters\": {\"goVersion\": \"%s\", \"cgoEnabled\": \"0\", \"goos\": \"darwin\", \"goarch\": \"arm64 amd64\", \"buildFlags\": \"-mod=readonly -trimpath -buildvcs=false\", \"ldflags\": \"%s\"},\n", goversion, ldflags
		printf "      \"resolvedDependencies\": [{\"uri\": \"git+https://github.com/s1ns3nz0/ssc-init\", \"digest\": {\"gitCommit\": \"%s\"}}]\n", revision
		printf "    },\n"
		printf "    \"runDetails\": {\n"
		printf "      \"builder\": {\"id\": \"https://github.com/s1ns3nz0/ssc-init/scripts/build-darwin.sh\"}\n"
		printf "    }\n"
		printf "  }\n"
		printf "}\n"
	}' "$DIST_DIR/checksums.txt" > "$DIST_DIR/provenance.json"
```

`go env GOVERSION` is not intercepted by the fixture's fake `go` unless it is taught to — extend the fake `go`'s `version` branch guard so `go env GOVERSION` prints `go1.26.5` and exits 0. Note `LINKER_FLAGS` contains `-X main.version=dev+git.<sha>`, which has no JSON-hostile character.

Add `"provenance.json"` to the artifact slices in `TestBuildScriptWorksOutsideRepositoryAndIsReproducible` and `TestBuildScriptAllowsIgnoredEntries`. The Task 2 loop restructure already treats it as a non-binary artifact.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -count=1`

Expected: PASS, `provenance.json` identical across the two runs.

- [ ] **Step 5: Commit**

```bash
git add scripts/build-darwin.sh scripts/build-darwin_test.go
git commit -m "feat: emit slsa build provenance for the release build"
```

---

### Task 4: First CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `scripts/workflow_test.go`

There is no `.github/` directory and no git remote, so this workflow cannot execute until a remote exists — say so in the commit body, and treat the local test as the gate in the meantime. The workflow must run on macOS: the whole product is Darwin-only, `internal/store` enforces a no-symlink database parent, and the release smoke tests exec real Darwin binaries.

The workflow is itself a supply-chain surface. Every `uses:` must be pinned to a 40-hex commit SHA, and the test enforces that — an unpinned action tag is exactly the mutable-dependency class this product exists to flag (§6.3).

- [ ] **Step 1: Write the failing test**

Create `scripts/workflow_test.go`:

```go
package scripts_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCIWorkflowRunsTheReleaseGatesOnMacOS(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	for _, want := range []string{
		"runs-on: macos-15",
		"fetch-depth: 0",
		"go-version-file: go.mod",
		"go mod verify",
		"go mod download",
		"go vet ./...",
		"gofmt -l",
		"git diff --check",
		"go test -race -count=1 ./internal/... ./cmd/...",
		"go test -count=1 ./scripts",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("ci workflow missing %q", want)
		}
	}
	uses := regexp.MustCompile(`(?m)uses:\s*(\S+)`)
	pinned := regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)
	matches := uses.FindAllStringSubmatch(workflow, -1)
	if len(matches) == 0 {
		t.Fatal("ci workflow declares no actions to pin")
	}
	for _, match := range matches {
		if !pinned.MatchString(match[1]) {
			t.Fatalf("action %q is not pinned to a commit sha", match[1])
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run TestCIWorkflowRunsTheReleaseGatesOnMacOS -count=1`

Expected: FAIL — `open …/.github/workflows/ci.yml: no such file or directory`.

- [ ] **Step 3: Implement**

Resolve the two action SHAs first (requires network and `gh auth`; if `gh` is unavailable, use the `curl` form shown second):

```sh
gh api repos/actions/checkout/commits/v5 --jq .sha
gh api repos/actions/setup-go/commits/v6 --jq .sha
# without gh:
curl -sS https://api.github.com/repos/actions/checkout/commits/v5 | awk -F'"' '/"sha"/{print $4; exit}'
curl -sS https://api.github.com/repos/actions/setup-go/commits/v6 | awk -F'"' '/"sha"/{print $4; exit}'
```

Create `.github/workflows/ci.yml`, substituting the two resolved SHAs (the trailing comment records which tag the SHA came from):

```yaml
name: CI

on:
  push:
    branches: ["**"]
    tags: ["v*"]
  pull_request:

permissions:
  contents: read

jobs:
  gates:
    runs-on: macos-15
    steps:
      - uses: actions/checkout@<resolved-checkout-sha> # v5
        with:
          fetch-depth: 0

      - uses: actions/setup-go@<resolved-setup-go-sha> # v6
        with:
          go-version-file: go.mod
          check-latest: true

      - name: Verify and download modules
        run: |
          go mod verify
          go mod download

      - name: Static gates
        run: |
          go vet ./...
          test -z "$(gofmt -l ./cmd ./internal ./scripts)"
          git diff --check

      - name: Unit and race gates
        run: go test -race -count=1 ./internal/... ./cmd/...

      - name: Release build gates
        run: |
          git status --porcelain
          go test -count=1 ./scripts
```

Notes that make this work rather than merely look right:

- `fetch-depth: 0` is required: `build-darwin.sh` calls `git describe --tags --exact-match`, and a shallow checkout has no tags, which would silently version every tagged release as `dev+git.<sha>`.
- `go mod download` before `go test ./scripts` is required: the build script sets `GOPROXY=off`, so the module cache must already be warm.
- `git status --porcelain` before the release gate makes a dirty tree visible in the log instead of surfacing as the opaque `release build requires a clean worktree`.
- `dist/` is gitignored, so the build test does not dirty the tree it just gated.
- `gofmt -l` returning names must fail the step, hence the `test -z "$(…)"` form.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -run TestCIWorkflowRunsTheReleaseGatesOnMacOS -count=1`

Expected: PASS. Then confirm locally that the workflow's own gate list actually passes on this machine, since no runner will do it yet:

```sh
go mod verify && go vet ./... && test -z "$(gofmt -l ./cmd ./internal ./scripts)" && git diff --check && go test -race -count=1 ./internal/... ./cmd/...
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml scripts/workflow_test.go
git commit -m "ci: run the release gates on macos

The repository has no git remote yet, so this workflow is gated locally by
scripts/workflow_test.go until one exists."
```

---

### Task 5: Versioned install layout and the version trust boundary

**Files:**
- Modify: `internal/platform/paths.go`
- Modify: `internal/platform/paths_test.go`

`PathsForHome` yields one directory and the only file ever written under it is `state.db`. §5.3 requires versioned core binaries, a current-version pointer, a single state database, TI and policy bundles, local reports, and quarantine — all in that one shared directory. This task adds the layout and, more importantly, the trust boundary: a version string arriving from an adapter becomes a **path element**, so it must be validated before it is ever joined.

Layout decision (see the ambiguity note at the end of this plan): the current-version pointer is a **file containing the version string**, not a symlink. Every other part of this codebase refuses to follow symlinks — `internal/platform/rooted.go`, the evidence engine, and the store's no-symlink database parent — and introducing one at the heart of the install would make the install the softest target in the product.

- [ ] **Step 1: Write the failing test**

Add to `internal/platform/paths_test.go`:

```go
func TestInstallLayoutIsRootedInTheDataDirectory(t *testing.T) {
	paths := platform.PathsForHome("/Users/example")
	layout := paths.Install()
	for name, got := range map[string]string{
		"root":     layout.Root,
		"versions": layout.VersionsDir,
		"current":  layout.CurrentFile,
		"previous": layout.PreviousFile,
	} {
		if !strings.HasPrefix(got, paths.DataDir+string(filepath.Separator)) {
			t.Fatalf("%s escapes the data directory: %q", name, got)
		}
	}
	if layout.CurrentFile == layout.PreviousFile {
		t.Fatal("current and previous pointers share a path")
	}
}

func TestInstallVersionRejectsAnythingTheBuildCannotProduce(t *testing.T) {
	for _, valid := range []string{
		"v0.1.0",
		"v1.2.3-rc.1",
		"v1.2.3+build.4",
		"dev+git.0123456789abcdef0123456789abcdef01234567",
	} {
		if !platform.ValidInstallVersion(valid) {
			t.Fatalf("release version %q rejected", valid)
		}
	}
	for _, invalid := range []string{
		"",
		".",
		"..",
		"../../../../etc",
		"v1/../../escape",
		"v1.0.0/nested",
		"dev+git.NOTHEX0000000000000000000000000000000000",
		"latest",
		"v1.0.0\n",
		"v1.0.0 ",
		strings.Repeat("v1.0.0", 32),
	} {
		if platform.ValidInstallVersion(invalid) {
			t.Fatalf("unsafe version %q accepted", invalid)
		}
	}
}

func TestVersionDirRejectsUnsafeVersions(t *testing.T) {
	layout := platform.PathsForHome("/Users/example").Install()
	if _, err := layout.VersionDir("../escape"); err == nil {
		t.Fatal("VersionDir accepted a traversing version")
	}
	directory, err := layout.VersionDir("v0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(directory) != layout.VersionsDir {
		t.Fatalf("version directory is not a direct child of versions: %q", directory)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/platform -run 'Install|VersionDir' -count=1`

Expected: FAIL — `paths.Install undefined (type platform.Paths has no field or method Install)`.

- [ ] **Step 3: Implement**

In `internal/platform/paths.go`:

```go
// InstallLayout is the §5.3 shared installation layout beneath DataDir. All
// members are absolute host paths; nothing here is ever persisted or reported.
type InstallLayout struct {
	Root         string // <DataDir>/core
	VersionsDir  string // <DataDir>/core/versions
	CurrentFile  string // <DataDir>/core/current
	PreviousFile string // <DataDir>/core/previous
	StagingDir   string // <DataDir>/core/staging
}

// CoreExecutableName is the file name of an installed core binary inside a
// version directory.
const CoreExecutableName = "ssc-init"

// Install returns the versioned core layout for these paths.
func (p Paths) Install() InstallLayout {
	root := filepath.Join(p.DataDir, "core")
	return InstallLayout{
		Root:         root,
		VersionsDir:  filepath.Join(root, "versions"),
		CurrentFile:  filepath.Join(root, "current"),
		PreviousFile: filepath.Join(root, "previous"),
		StagingDir:   filepath.Join(root, "staging"),
	}
}

// installVersionPattern mirrors scripts/build-darwin.sh exactly: an exact
// v-prefixed tag with a safe character set, or the committed-revision fallback.
// Nothing else can name a version directory, so no supplied version can
// traverse, hide, or collide.
var installVersionPattern = regexp.MustCompile(`^(v[0-9][0-9A-Za-z.+-]*|dev\+git\.[0-9a-f]{40})$`)

// ValidInstallVersion reports whether version is a version string the release
// build can produce and is safe to use as a single path element.
func ValidInstallVersion(version string) bool {
	return len(version) <= 64 && installVersionPattern.MatchString(version)
}

// VersionDir returns the directory holding one installed core version.
func (l InstallLayout) VersionDir(version string) (string, error) {
	if !ValidInstallVersion(version) {
		return "", errors.New("unsupported core version")
	}
	return filepath.Join(l.VersionsDir, version), nil
}
```

`v1.2.3+build.4` matches because `+` is in the character class; `..` fails the leading `v[0-9]` requirement; a trailing newline fails because `regexp` `$` in non-multiline mode still permits a final `\n` — guard it by using `\A…\z` semantics via `regexp.MustCompile` with `(?s)\A(?:…)\z`. Write the pattern as:

```go
var installVersionPattern = regexp.MustCompile(`\A(v[0-9][0-9A-Za-z.+-]*|dev\+git\.[0-9a-f]{40})\z`)
```

The `"v1.0.0\n"` case in the test exists precisely to catch the `$` mistake.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/platform -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform
git commit -m "feat: define the versioned core installation layout"
```

---

### Task 6: Stage and verify a core version

**Files:**
- Create: `internal/install/install.go`
- Create: `internal/install/install_test.go`

§5.3/§11: a new version is staged, then verified, and only then switched to. This task is stage + verify; Task 7 is switch + rollback. Verification here is the integrity half: the caller supplies the expected SHA-256 (the adapter reads it from the release `checksums.txt`), and the staged file is hashed *while being copied* so the bytes that were hashed are the bytes that were written.

Everything happens through `os.Root` opened on `DataDir`. A local process can pre-create `core/versions/v9.9.9` as a symlink pointing anywhere; `os.Root` refuses to leave the root, which turns that from an arbitrary-write primitive into an error.

- [ ] **Step 1: Write the failing test**

Create `internal/install/install_test.go` with, at minimum:

```go
func TestStageRejectsADigestMismatchAndLeavesNothingBehind(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := writeFakeCore(t, "core-bytes")

	err := manager.Stage(context.Background(), source, "v0.1.0", strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("Stage accepted a binary whose digest does not match")
	}
	if strings.Contains(err.Error(), source) {
		t.Fatal("Stage error leaks the source path")
	}
	layout := platform.PathsForHome(home).Install()
	if _, err := os.Stat(filepath.Join(layout.VersionsDir, "v0.1.0")); !os.IsNotExist(err) {
		t.Fatalf("failed stage left a version directory behind: %v", err)
	}
	entries, err := os.ReadDir(layout.StagingDir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("failed stage left %d staging entries behind", len(entries))
	}
}

func TestStageInstallsAVerifiedVersionWithoutActivatingIt(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := writeFakeCore(t, "core-bytes")
	digest := sha256.Sum256([]byte("core-bytes"))

	if err := manager.Stage(context.Background(), source, "v0.1.0", hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	layout := platform.PathsForHome(home).Install()
	info, err := os.Lstat(filepath.Join(layout.VersionsDir, "v0.1.0", platform.CoreExecutableName))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("staged core is not a regular file: %v", info.Mode())
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("staged core is not executable: %v", info.Mode().Perm())
	}
	if _, err := os.Stat(layout.CurrentFile); !os.IsNotExist(err) {
		t.Fatal("Stage activated the version instead of only staging it")
	}
}

func TestStageRejectsAVersionItCannotName(t *testing.T) {
	home := isolatedHome(t)
	manager := newManager(t, home)
	source := writeFakeCore(t, "core-bytes")
	digest := sha256.Sum256([]byte("core-bytes"))
	if err := manager.Stage(context.Background(), source, "../escape", hex.EncodeToString(digest[:])); err == nil {
		t.Fatal("Stage accepted a traversing version")
	}
}

func TestStageNeverTouchesSharedState(t *testing.T) {
	home := isolatedHome(t)
	statePath := filepath.Join(platform.PathsForHome(home).DataDir, "state.db")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := newManager(t, home)
	source := writeFakeCore(t, "core-bytes")
	digest := sha256.Sum256([]byte("core-bytes"))
	if err := manager.Stage(context.Background(), source, "v0.1.0", hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(statePath)
	if err != nil || string(content) != "state" {
		t.Fatalf("Stage disturbed the shared state database: %q %v", content, err)
	}
}
```

`isolatedHome` must return `filepath.EvalSymlinks(t.TempDir())` — macOS temp directories live under the `/var` → `/private/var` symlink, and the existing suites already handle it that way (`scripts/build-darwin_test.go` `assertNativeIsolatedStatusV3`).

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/install -count=1`

Expected: FAIL — `no required module provides package github.com/s1ns3nz0/ssc-init/internal/install`, then `undefined: Manager` once the file exists.

- [ ] **Step 3: Implement**

`internal/install/install.go`:

```go
// Package install performs staged, digest-verified, health-checked, atomically
// switched core installations under the shared SSC Init data directory
// (design §5.3, §11). It never reads, writes, or removes the state database,
// intelligence bundles, reports, or quarantine.
package install

// Manager owns one shared installation.
type Manager struct {
	Home   string
	Layout platform.InstallLayout
}

// Stage copies the core binary at sourcePath into a private staging directory,
// verifies its SHA-256 against wantDigest while copying, and promotes it to
// versions/<version> only on a match. A failed stage promotes nothing and
// leaves no staging remnant. Errors are value-free: they never echo the source
// path, the digest, or the version.
func (m Manager) Stage(ctx context.Context, sourcePath, version, wantDigest string) error
```

Implementation shape:

1. Reject `wantDigest` that is not 64 lowercase hex characters before touching the filesystem.
2. `platform.ValidInstallVersion(version)` or return `errors.New("unsupported core version")`.
3. `os.MkdirAll(m.Layout.Root, 0o755)`, then `root, err := os.OpenRoot(m.Layout.Root)`; `defer root.Close()`. Every subsequent path is relative to that root — `versions/<version>`, `staging/<version>`.
4. `root.RemoveAll("staging/" + version)` then `root.MkdirAll("staging/"+version, 0o755)` so a previous crash cannot poison this stage.
5. Open the source with plain `os.Open` (it is an adapter-supplied path outside our tree, deliberately not root-scoped), `Lstat` it and require `Mode().IsRegular()`.
6. `destination, err := root.OpenFile("staging/"+version+"/"+platform.CoreExecutableName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)`; copy through `io.MultiWriter(destination, hasher)` with a context check on each chunk so cancellation propagates; `destination.Sync()` before close.
7. Compare `hex.EncodeToString(hasher.Sum(nil))` with `wantDigest` using `subtle.ConstantTimeCompare` (cheap, and this is an integrity boundary).
8. On mismatch or any error: `root.RemoveAll("staging/" + version)` and return.
9. On match: `root.RemoveAll("versions/" + version)`, `root.MkdirAll("versions", 0o755)`, `root.Rename("staging/"+version, "versions/"+version)`. Rename within one directory tree on APFS is atomic.
10. Write `versions/<version>/manifest.json` containing `{"schemaVersion":"ssc-init.install.manifest.v1","version":"…","sha256":"…"}` — version and digest only. No source path, no timestamp, no host name.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/install -count=1 && go test -race ./internal/install -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/install
git commit -m "feat: stage and verify a core version"
```

---

### Task 7: Atomic switch, previous known-good, and rollback

**Files:**
- Modify: `internal/install/install.go`
- Modify: `internal/install/install_test.go`

§11: "Core, TI, and policy updates use stage, verify, health check, atomic switch, and rollback. The last known-good state remains active on any checksum, signature, schema, migration, or doctor failure." This task adds the health check, the switch, the previous-known-good pointer, the rollback, and the pruning that keeps at least one previous version.

The health check executes the *staged* binary's `doctor --json`. That does not violate the "default scans execute no process" invariant: this is not a discovered asset, it is the tool we just verified by digest, it runs only on an explicit `install`/`rollback`, and it never runs on a scan path. Say so in the doc comment so no future reviewer has to re-derive it.

- [ ] **Step 1: Write the failing test**

```go
func TestActivateSwitchesOnlyAfterAPassingHealthCheck(t *testing.T)
func TestActivateKeepsTheLastKnownGoodWhenHealthFails(t *testing.T)
func TestActivateRecordsThePreviousVersionForRollback(t *testing.T)
func TestRollbackRestoresThePreviousKnownGood(t *testing.T)
func TestRollbackFailsWhenThereIsNoPreviousVersion(t *testing.T)
func TestPruneKeepsCurrentAndPreviousOnly(t *testing.T)
```

Write them concretely against the same `isolatedHome` fixture. The health check is injected as `Health func(ctx context.Context, executablePath string) error` on `Manager` so the tests never exec anything; the production wiring in Task 8 supplies the real exec. The load-bearing assertions:

- `TestActivateKeepsTheLastKnownGoodWhenHealthFails`: stage `v0.1.0`, activate it with a passing health func, stage `v0.2.0`, activate it with a health func returning an error; `Activate` must return an error, `CurrentFile` must still read `v0.1.0`, and `versions/v0.2.0` must still exist (staged but not active) so the operator can retry rather than re-download.
- `TestRollbackRestoresThePreviousKnownGood`: after two successful activations, `Rollback` makes `current` read `v0.1.0` and `previous` read `v0.2.0`, and a second `Rollback` returns to `v0.2.0` — rollback is an exchange, not a stack pop, so a bad rollback is itself reversible.
- `TestPruneKeepsCurrentAndPreviousOnly`: with three activated versions, exactly the current and previous version directories survive.
- Every one of these must also assert `state.db` is untouched, as in Task 6.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/install -count=1`

Expected: FAIL — `manager.Activate undefined`.

- [ ] **Step 3: Implement**

```go
// Activate runs the staged version's health check and, only if it passes,
// atomically switches the current-version pointer, demoting the outgoing
// version to previous. Any failure leaves the last known-good version active
// (design §11). The health check executes the freshly digest-verified core
// binary; this is the only place SSC Init executes anything by default, and it
// is never reached from a scan.
func (m Manager) Activate(ctx context.Context, version string) error

// Rollback exchanges the current and previous pointers, restoring the last
// known-good version. It is itself reversible.
func (m Manager) Rollback(ctx context.Context) error

// Current reads the current-version pointer. The bool is false when nothing is
// installed yet.
func (m Manager) Current() (string, bool, error)

// Prune removes installed versions other than current and previous.
func (m Manager) Prune() error
```

Pointer write must be atomic: `root.WriteFile("current.tmp", []byte(version+"\n"), 0o644)` followed by `root.Rename("current.tmp", "current")`. Never `WriteFile` directly onto `current` — a crash mid-write would leave an unparseable pointer and no way to find the binary.

Pointer read must re-validate: `ValidInstallVersion(strings.TrimSpace(string(content)))` before the value is joined into a path. A pointer file is on-disk state that another local process can rewrite; treat it as untrusted input on every read, not only on write.

Ordering inside `Activate`:
1. Validate the version; `Lstat` `versions/<version>/ssc-init`, require a regular executable file.
2. Re-verify the digest against `manifest.json` — this is the §11 "checksum failure keeps last known-good" path, and it catches a version that was tampered with between staging and activation.
3. Run `m.Health(ctx, executablePath)`; on error return without touching any pointer.
4. Read the existing `current` (if any) into `previousVersion`.
5. Write `current` atomically, then write `previous` atomically. If `previous` fails to write, the install is still coherent — `current` is correct and rollback is merely unavailable, which `doctor` will report in Task 9.
6. `Prune()`.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/install -count=1 && go test -race ./internal/install -count=50`

`-count=50` because the pointer exchange is the race-prone part and the house convention re-verifies such suites at 50.

- [ ] **Step 5: Commit**

```bash
git add internal/install
git commit -m "feat: switch core versions atomically with rollback"
```

---

### Task 8: `ssc-init install` and `ssc-init rollback`

**Files:**
- Modify: `internal/cli/options.go`, `internal/cli/options_test.go`
- Modify: `internal/cli/run.go`, `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`, `cmd/ssc-init/main_test.go`

Without a command surface `internal/install` is unreachable code. Adapters (which do not exist yet) will call these; the commands are the contract they will be written against.

`ParseOptions` accepts only documented, command-aware forms and returns the value-free `ErrInvalidOptions` — follow that exactly.

- [ ] **Step 1: Write the failing test**

In `internal/cli/options_test.go`:

```go
func TestParseOptionsAcceptsInstallAndRollback(t *testing.T) {
	options, err := cli.ParseOptions([]string{
		"install", "--from", "/tmp/ssc-init", "--version", "v0.2.0",
		"--sha256", strings.Repeat("a", 64), "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Command != "install" || options.InstallSource != "/tmp/ssc-init" ||
		options.InstallVersion != "v0.2.0" || !options.JSON {
		t.Fatalf("unexpected options: %+v", options)
	}
	if _, err := cli.ParseOptions([]string{"rollback", "--json"}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]string{
		{"install"},
		{"install", "--json"},
		{"install", "--from", "relative/path", "--version", "v0.2.0", "--sha256", strings.Repeat("a", 64), "--json"},
		{"install", "--from", "/tmp/x", "--version", "latest", "--sha256", strings.Repeat("a", 64), "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", "short", "--json"},
		{"install", "--from", "/tmp/x", "--from", "/tmp/y", "--version", "v0.2.0", "--sha256", strings.Repeat("a", 64), "--json"},
		{"rollback"},
		{"rollback", "--json", "--pretty"},
	} {
		if _, err := cli.ParseOptions(invalid); err == nil {
			t.Fatalf("accepted %v", invalid)
		}
	}
}
```

In `internal/cli/run_test.go`, assert the JSON contract: `install` emits `{"schemaVersion":"ssc-init.install.v1","command":"install","version":"v0.2.0","previousVersion":"v0.1.0","rollbackAvailable":true}`, with no path anywhere in the payload, and a non-zero exit with the value-free `stderr` line on failure.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli -count=1`

Expected: FAIL — `options.InstallSource undefined`.

- [ ] **Step 3: Implement**

Add `InstallSource`, `InstallVersion`, `InstallDigest` to `Options`. Parse `install` with the same duplicate-flag rejection style `parseScanOptions` already uses; require `--from` to be absolute (`filepath.IsAbs`), require `platform.ValidInstallVersion`, require 64 lowercase hex for `--sha256`, and require `--json`. `rollback` takes exactly `--json`.

Add an `Installer` interface to `cli.App` mirroring the existing `BaselineScanner`/`Doctor` seams:

```go
// Installer stages, verifies, and activates core versions.
type Installer interface {
	Install(ctx context.Context, sourcePath, version, digest string) (InstallOutcome, error)
	Rollback(ctx context.Context) (InstallOutcome, error)
}
```

Wire it in `cmd/ssc-init/main.go` under `case "install":` and `case "rollback":`, both added to `operationalCommand` so they still refuse to run off Darwin before creating state. The concrete implementation composes `install.Manager.Stage` then `install.Manager.Activate`, with `Health` running:

```go
	Health: func(ctx context.Context, executablePath string) error {
		command := exec.CommandContext(ctx, executablePath, "doctor", "--json")
		output, err := command.Output()
		if err != nil {
			return errors.New("staged core failed its health check")
		}
		var result struct {
			SchemaVersion string `json:"schemaVersion"`
			Status        string `json:"status"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			return errors.New("staged core produced an unreadable health report")
		}
		if !strings.HasPrefix(result.SchemaVersion, "ssc-init.doctor.") || result.Status != "ready" {
			return errors.New("staged core reported a degraded installation")
		}
		return nil
	},
```

Give the health exec its own timeout via `context.WithTimeout(ctx, 30*time.Second)` so a wedged staged binary cannot hang the install.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/cli ./cmd/ssc-init ./internal/install -count=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cli cmd/ssc-init
git commit -m "feat: add the install and rollback commands"
```

---

### Task 9: `doctor` reports installation health

**Files:**
- Modify: `internal/doctor/doctor.go`, `internal/doctor/doctor_test.go`
- Modify: `cmd/ssc-init/main.go`

`doctor` is the health check §11 names, and Task 8 already calls it — but it currently knows nothing about the install, so it would pass on a machine whose current pointer names a version whose binary is missing or corrupt. That is the exact failure §11 exists to catch.

This changes a public JSON contract, so the schema version goes to `ssc-init.doctor.v2`.

- [ ] **Step 1: Write the failing test**

```go
func TestCheckReportsInstallHealth(t *testing.T)          // current, previous, rollbackAvailable, versionsInstalled
func TestCheckDegradesWhenTheCurrentVersionIsMissing(t *testing.T)
func TestCheckDegradesWhenTheCurrentBinaryDigestDoesNotMatch(t *testing.T)
func TestCheckReportsNoInstallWithoutDegrading(t *testing.T) // a source build with no managed install is "ready"
func TestInstallReportCarriesNoAbsolutePath(t *testing.T)
```

The last one matters: `CorePaths` already redacts through `platform.RedactHome`, and the install report must not reintroduce a raw path. It reports version strings and booleans only.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/doctor -count=1`

Expected: FAIL — `result.Install undefined`.

- [ ] **Step 3: Implement**

```go
const schemaVersion = "ssc-init.doctor.v2"

// Install summarises the §5.3 shared installation. It carries version strings
// and booleans only — never a path.
type Install struct {
	Managed           bool   `json:"managed"`
	CurrentVersion    string `json:"currentVersion"`
	PreviousVersion   string `json:"previousVersion"`
	RollbackAvailable bool   `json:"rollbackAvailable"`
	VersionsInstalled int    `json:"versionsInstalled"`
	IntegrityVerified bool   `json:"integrityVerified"`
}
```

Add `Install Install \`json:"install"\`` to `Result` and an `InstallReporter func() (Install, error)` to `Config` so `doctor` keeps its "no filesystem knowledge of its own" shape and the tests stay hermetic. `Managed=false` (no `core/current`) is `ready`, not `degraded` — a developer running a source build has no managed install and is not broken. `Managed=true` with a missing binary or a digest mismatch is `degraded`.

Wire the real reporter in `cmd/ssc-init/main.go` from `install.Manager`.

Check for any golden or fixture that pins `ssc-init.doctor.v1` before committing:

```sh
grep -rn "ssc-init.doctor.v1" --include='*.go' --include='*.json' --include='*.md' .
```

Update every hit, including `internal/acceptance` and `README.md` if it documents the doctor payload. Coordinate on `README.md` — another program is editing it concurrently; if it is dirty, leave the README hit for Task 12 and note it.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/doctor ./cmd/ssc-init ./internal/acceptance ./internal/cli -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/doctor cmd/ssc-init
git commit -m "feat: report installation health in doctor"
```

---

### Task 10 (BLOCKED on Developer ID): sign the Universal Binary

**Files:**
- Create: `scripts/sign-darwin.sh`
- Create: `scripts/sign-darwin_test.go`

**Blocked on:** a `Developer ID Application: <name> (<team id>)` certificate and private key in the login keychain, from an active Apple Developer Program membership.

**Why this is a separate script and not part of `build-darwin.sh`:** measured on this machine, two ad-hoc `codesign` runs over byte-identical input produced different digests (`14415f75…` vs `9b4efff2…`). A real Developer ID signature is worse — `--timestamp` embeds an Apple-issued RFC 3161 timestamp, so the signed artifact is non-reproducible **by design**. Putting `codesign` inside `build-darwin.sh` would make `TestBuildScriptWorksOutsideRepositoryAndIsReproducible` fail forever. The reproducible build and the signature are two separate, independently verifiable facts: `checksums.txt` + `provenance.json` attest to the reproducible bytes, `checksums-signed.txt` attests to what users download.

- [ ] **Step 1: Write the failing test**

Create `scripts/sign-darwin_test.go`:

```go
func TestSignScriptFailsClosedWithoutAnIdentity(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	script := filepath.Join(repositoryRoot, "scripts", "sign-darwin.sh")
	distribution := t.TempDir()
	artifact := filepath.Join(distribution, "ssc-init-darwin-universal")
	if err := os.WriteFile(artifact, []byte("not-really-a-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command("sh", script)
	command.Dir = t.TempDir()
	command.Env = append(environmentWith("SSC_INIT_DIST_DIR", distribution), "SSC_INIT_SIGNING_IDENTITY=")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("sign script ran without an identity:\n%s", output)
	}
	if got := strings.TrimSpace(string(output)); got != "SSC_INIT_SIGNING_IDENTITY is not set; a Developer ID Application identity is required to sign" {
		t.Fatalf("unexpected or leaking error %q", got)
	}
	after, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("sign script modified the artifact before failing closed")
	}
	if _, err := os.Stat(filepath.Join(distribution, "checksums-signed.txt")); !os.IsNotExist(err) {
		t.Fatal("sign script produced a signed checksum file without signing")
	}
}

func TestSignScriptFailsClosedWithoutAnArtifact(t *testing.T) {
	// Same shape, with SSC_INIT_SIGNING_IDENTITY set to a value and an empty
	// dist directory: expect exactly
	// "universal binary not found; run scripts/build-darwin.sh first".
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run TestSignScript -count=1`

Expected: FAIL — `fork/exec …/scripts/sign-darwin.sh: no such file or directory`.

- [ ] **Step 3: Implement**

Create `scripts/sign-darwin.sh`:

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${SSC_INIT_DIST_DIR:-$REPOSITORY_ROOT/dist}
UNIVERSAL="$DIST_DIR/ssc-init-darwin-universal"
BUNDLE_IDENTIFIER=${SSC_INIT_BUNDLE_IDENTIFIER:-dev.sscinit.core}

if [ -z "${SSC_INIT_SIGNING_IDENTITY:-}" ]; then
	echo "SSC_INIT_SIGNING_IDENTITY is not set; a Developer ID Application identity is required to sign" >&2
	exit 1
fi

if [ ! -f "$UNIVERSAL" ]; then
	echo "universal binary not found; run scripts/build-darwin.sh first" >&2
	exit 1
fi

codesign \
	--sign "$SSC_INIT_SIGNING_IDENTITY" \
	--identifier "$BUNDLE_IDENTIFIER" \
	--options runtime \
	--timestamp \
	--force \
	"$UNIVERSAL"

codesign --verify --strict --verbose=2 "$UNIVERSAL"

cd "$REPOSITORY_ROOT"
shasum -a 256 "$UNIVERSAL" | sed "s|$DIST_DIR/|dist/|" > "$DIST_DIR/checksums-signed.txt"
```

Flag notes that are load-bearing rather than decorative:
- `--options runtime` enables the hardened runtime. Notarization (Task 11) **rejects** submissions without it, so omitting it here fails a step later with a much worse error message.
- `--timestamp` requests Apple's secure timestamp. Without it, the signature stops validating when the certificate expires. It requires network access at signing time.
- `--identifier` pins the signing identifier; without it `codesign` derives one from the file name (the existing ad-hoc signature shows `Identifier=a.out`).
- The `sed` keeps `checksums-signed.txt` in the same repository-relative form as `checksums.txt` and, more importantly, keeps the build host's absolute path out of a published file.

Add `scripts/sign-darwin.sh` to the CI workflow's static gates in `.github/workflows/ci.yml` only via `go test ./scripts` — do not add a CI step that invokes it.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -run TestSignScript -count=1`

Expected: PASS. This exercises only the fail-closed path — which is the whole point of the test.

**Manual verification, once the certificate exists** (record the output in the Task 12 runbook):

```sh
security find-identity -v -p codesigning        # must list a "Developer ID Application" identity
SSC_INIT_SIGNING_IDENTITY="Developer ID Application: <name> (<team>)" sh scripts/sign-darwin.sh
codesign --verify --strict --verbose=2 dist/ssc-init-darwin-universal
codesign -dv --verbose=4 dist/ssc-init-darwin-universal 2>&1 | grep -E 'Authority|TeamIdentifier|Timestamp|flags'
```

Expected: `valid on disk`, `satisfies its Designated Requirement`, an `Authority=Developer ID Certification Authority` chain, a non-empty `Timestamp=`, and `flags=0x10000(runtime)`.

- [ ] **Step 5: Commit**

```bash
git add scripts/sign-darwin.sh scripts/sign-darwin_test.go
git commit -m "feat: sign the universal binary with a developer id identity

The success path cannot run until an Apple Developer ID Application
certificate exists; the fail-closed path is tested."
```

---

### Task 11 (BLOCKED on Developer ID): notarization submission

**Files:**
- Create: `scripts/notarize-darwin.sh`
- Create: `scripts/notarize-darwin_test.go`

**Blocked on:** Task 10's signature plus an Apple ID with an app-specific password stored as a `notarytool` keychain profile:

```sh
xcrun notarytool store-credentials ssc-init-notary \
	--apple-id <apple-id> --team-id <team-id> --password <app-specific-password>
```

**A hard Apple constraint to design around:** `xcrun stapler staple` works on `.app` bundles, `.dmg`, `.pkg`, and `.kext` — **not** on a bare Mach-O executable and not on a `.zip`. There is therefore no way to attach an offline notarization ticket to `ssc-init-darwin-universal` as a bare binary. Two consequences, both of which the runbook must state plainly rather than paper over:

1. Notarization still happens, and Gatekeeper still finds the ticket — by online lookup against Apple's service, keyed on the signature's CDHash.
2. Offline first-run verification is only possible if the binary ships inside a stapled container. Whether to build one is the open decision recorded at the end of this plan.

- [ ] **Step 1: Write the failing test**

`scripts/notarize-darwin_test.go`, same shape as Task 10:

```go
func TestNotarizeScriptFailsClosedWithoutAKeychainProfile(t *testing.T)
// Expect exactly:
// "SSC_INIT_NOTARY_PROFILE is not set; run xcrun notarytool store-credentials first"
// and assert no .zip was produced.

func TestNotarizeScriptFailsClosedOnAnUnsignedArtifact(t *testing.T)
// With the profile variable set and an unsigned artifact present, expect exactly:
// "universal binary is not signed; run scripts/sign-darwin.sh first"
```

The second test is runnable now and is worth having: it exercises the real `codesign --verify` on an unsigned file, which is precisely the state of `dist/ssc-init-darwin-universal` after Task 1.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./scripts -run TestNotarizeScript -count=1`

Expected: FAIL — `no such file or directory`.

- [ ] **Step 3: Implement**

```sh
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${SSC_INIT_DIST_DIR:-$REPOSITORY_ROOT/dist}
UNIVERSAL="$DIST_DIR/ssc-init-darwin-universal"
ARCHIVE="$DIST_DIR/ssc-init-darwin-universal.zip"

if [ -z "${SSC_INIT_NOTARY_PROFILE:-}" ]; then
	echo "SSC_INIT_NOTARY_PROFILE is not set; run xcrun notarytool store-credentials first" >&2
	exit 1
fi

if [ ! -f "$UNIVERSAL" ]; then
	echo "universal binary not found; run scripts/build-darwin.sh first" >&2
	exit 1
fi

if ! codesign --verify --strict "$UNIVERSAL" >/dev/null 2>&1; then
	echo "universal binary is not signed; run scripts/sign-darwin.sh first" >&2
	exit 1
fi

rm -f "$ARCHIVE"
ditto -c -k --keepParent "$UNIVERSAL" "$ARCHIVE"

xcrun notarytool submit "$ARCHIVE" \
	--keychain-profile "$SSC_INIT_NOTARY_PROFILE" \
	--wait

# A bare Mach-O executable cannot be stapled (stapler supports .app, .dmg,
# .pkg, .kext only). Gatekeeper resolves the ticket online instead; this
# assessment is the closest local confirmation available.
spctl --assess -vvv --type open --context context:primary-signature "$UNIVERSAL"
```

`ditto -c -k --keepParent` is the archive form Apple documents for notarizing standalone executables; a `zip(1)` archive does not reliably preserve the metadata `notarytool` expects.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./scripts -run TestNotarizeScript -count=1`

Expected: PASS (fail-closed paths only).

**Manual verification, once credentials exist:**

```sh
SSC_INIT_NOTARY_PROFILE=ssc-init-notary sh scripts/notarize-darwin.sh
xcrun notarytool history --keychain-profile ssc-init-notary | head
xcrun notarytool log <submission-id> --keychain-profile ssc-init-notary
```

Expected: `status: Accepted`, an empty `issues` array in the log, and `spctl` reporting `accepted` with `source=Notarized Developer ID`. If `notarytool` reports `Invalid`, the log's `issues[].message` names the cause; the two likely ones for this artifact are a missing hardened runtime (Task 10's `--options runtime`) and a missing secure timestamp (`--timestamp`).

- [ ] **Step 5: Commit**

```bash
git add scripts/notarize-darwin.sh scripts/notarize-darwin_test.go
git commit -m "feat: notarize the signed universal binary

Stapling is not possible for a bare Mach-O executable; Gatekeeper resolves
the ticket online. The success path awaits Apple credentials."
```

---

### Task 12: Release runbook

**Files:**
- Create: `docs/release-runbook.md`
- Modify: `README.md` (installation section only, and only if it is not concurrently held by another program)
- Modify: `CLAUDE.md`

The program is not done when the scripts exist; it is done when a person can cut a release without rediscovering the ordering, and when the parts that are still blocked say so out loud instead of looking finished.

- [ ] **Step 1: Write `docs/release-runbook.md`**

It must contain, in this order, with the exact commands:

1. **Preconditions.** Clean tracked worktree; `go mod verify`; full gate `go test -race -count=1 ./...`; the annotated tag `git tag -a vX.Y.Z -m vX.Y.Z` created *before* building, because the build script versions from the exact tag and an untagged build silently produces `dev+git.<sha>`.
2. **Reproducible build.** `go mod download && sh scripts/build-darwin.sh`, producing `dist/ssc-init-darwin-{amd64,arm64,universal}`, `checksums.txt`, `sbom.cdx.json`, `provenance.json`. Note that a second run must yield identical bytes and that `go test ./scripts -count=1` proves it.
3. **Signing (blocked until the Developer ID certificate exists).** Task 10's commands and expected `codesign` output. State clearly that the signed artifact is *not* byte-reproducible and that `checksums.txt` describes the pre-signature build while `checksums-signed.txt` describes what users verify.
4. **Notarization (blocked).** Task 11's commands, expected `Accepted` status, and the explicit statement that no ticket is stapled to the bare binary.
5. **Publish.** Which files ship: the universal binary, `checksums.txt`, `checksums-signed.txt`, `sbom.cdx.json`, `provenance.json`. The thin per-arch slices are build intermediates and diagnostic aids, not the shipping artifact.
6. **Consumer verification.** What an adapter or a user runs before trusting a download: `shasum -a 256 -c checksums-signed.txt`, `codesign --verify --strict --verbose=2`, `spctl --assess -vvv --type open --context context:primary-signature`.
7. **Install and rollback.** `ssc-init install --from <path> --version vX.Y.Z --sha256 <digest> --json`, `ssc-init doctor --json` to read install health, `ssc-init rollback --json` to return to the last known-good. State §5.3's rule explicitly: uninstalling an adapter must never remove `state.db`, bundles, reports, or quarantine, and neither `install` nor `rollback` touches them.
8. **Known gaps.** No git remote, so `.github/workflows/ci.yml` has never executed. No Developer ID, so steps 3 and 4 have never executed. No stapled container. Each gap names what unblocks it.

- [ ] **Step 2: Verify every unblocked command in the runbook by running it**

Cut a throwaway tag, run the full sequence through step 2 and step 7, then delete the tag:

```sh
git tag -a v0.0.0-runbook-check -m runbook-check
go mod download && sh scripts/build-darwin.sh
shasum -a 256 -c dist/checksums.txt
go test ./scripts -count=1
git tag -d v0.0.0-runbook-check
```

Then exercise install/rollback against an isolated home so the real one is untouched:

```sh
HOME=$(mktemp -d) dist/ssc-init-darwin-universal install \
	--from "$PWD/dist/ssc-init-darwin-universal" \
	--version v0.0.0-runbook-check \
	--sha256 "$(shasum -a 256 dist/ssc-init-darwin-universal | cut -d' ' -f1)" --json
```

Note that `v0.0.0-runbook-check` is accepted by `ValidInstallVersion` (v-prefixed, safe characters). Correct any command in the runbook that did not behave as written — the runbook's value is that it was executed, not that it was drafted.

- [ ] **Step 3: Update `CLAUDE.md`**

Record: the release artifact set and that signing/notarization live outside the reproducible build and why; that the doctor contract is now `ssc-init.doctor.v2`; that `internal/install` is the only place SSC Init executes a binary by default and that it is never on a scan path; that the current-version pointer is a file, not a symlink, and is re-validated on every read.

- [ ] **Step 4: Full gate**

```sh
go clean -testcache && go test -race -count=1 ./internal/... ./cmd/...
go vet ./...
gofmt -l ./cmd ./internal ./scripts
git diff --check
go mod verify
```

Then commit, and only then run `go test ./scripts -count=1` on the clean tree.

- [ ] **Step 5: Commit**

```bash
git add docs/release-runbook.md CLAUDE.md
git commit -m "docs: add the release runbook"
```

---

## Decisions the controller should confirm before implementation starts

1. **Stapling and the shipping container.** §5.3 says adapters may bundle the executable in a plugin `bin/` directory, which implies a bare Mach-O. A notarization ticket cannot be stapled to a bare Mach-O, so a machine with no network cannot verify notarization on first run. Options: (a) accept online-only ticket resolution, which this plan assumes; (b) additionally build, sign, notarize, and staple a `.dmg` or `.pkg`, adding a task after 11. The design does not say which, and (b) is a real amount of extra work.

2. **Current-version pointer: file vs symlink.** §5.3 says "a current-version pointer" without specifying the mechanism. This plan uses a pointer *file* because every other subsystem refuses to follow symlinks, but a symlink would give adapters a stable executable path (`core/current/ssc-init`) instead of requiring them to read a file and then build a path. If adapter ergonomics outrank the no-symlink consistency, Task 5 and Task 7 change shape.

3. **Which artifact `checksums.txt` describes after signing.** This plan keeps `checksums.txt` as the record of the *reproducible, unsigned* build and adds `checksums-signed.txt` for the shipped artifact, because signing mutates the universal binary in place. The alternative is signing a copy under a distinct name. The design says a release produces "checksums, signatures, SBOM, and build provenance" without resolving this.

4. **Provenance subject scope.** This plan's `provenance.json` attests to the unsigned build outputs, so a third party can reproduce and confirm the digests. It therefore does *not* cover the signed artifact. If provenance is expected to describe what users actually download, it must be regenerated after signing — at which point it is no longer independently reproducible.

5. **`install --from` accepts an absolute path from the caller.** No adapters exist yet, so nothing constrains where a staged binary comes from. The plan validates that the path is absolute and a regular file, hashes it against a caller-supplied digest, and never persists or echoes it. If the intended model is instead "the adapter hands over an already-verified file descriptor" or "the core downloads a pinned release itself" (§5.3 mentions bootstrap after checksum, project-signature, and code-signing verification), Task 6 and Task 8 change shape — and the download path would add the first network access in the product, which needs its own decision.

6. **`ssc-init.doctor.v2`.** Task 9 adds an `install` object to the doctor payload and bumps the schema version. If any adapter contract or fixture is expected to pin `v1`, that must be resolved first; `grep -rn "ssc-init.doctor.v1"` is the check.
