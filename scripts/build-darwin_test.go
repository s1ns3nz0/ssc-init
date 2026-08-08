package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestBuildScriptDeclaresStaticTargets(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"#!/bin/sh",
		"set -eu",
		"CGO_ENABLED=0",
		"GOOS=darwin",
		"GOARCH=arm64",
		"GOARCH=amd64",
		"-trimpath",
		"-buildvcs=false",
		"git -C \"$REPOSITORY_ROOT\" rev-parse",
		"-X main.version=",
		"SOURCE_DATE_EPOCH",
		"lipo -create",
		"shasum -a 256",
		"go version -m",
		"bomFormat",
		"in-toto.io/Statement/v1",
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("build script missing %q", want)
		}
	}
}

func TestBuildScriptWorksOutsideRepositoryAndIsReproducible(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build smoke test")
	}
	repositoryRoot := repositoryRoot(t)
	script := filepath.Join(repositoryRoot, "scripts", "build-darwin.sh")
	wantVersion := expectedReleaseVersion(t, repositoryRoot)
	runBuild := func() map[string][32]byte {
		t.Helper()
		command := exec.Command("sh", script)
		command.Dir = t.TempDir()
		command.Env = environmentWith("SOURCE_DATE_EPOCH", "0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build failed: %v\n%s", err, output)
		}
		digests := make(map[string][32]byte, 5)
		for _, name := range releaseArtifactNames {
			path := filepath.Join(repositoryRoot, "dist", name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if name != "checksums.txt" && bytes.Contains(content, []byte(repositoryRoot)) {
				t.Fatalf("%s contains absolute repository path %q", name, repositoryRoot)
			}
			if strings.HasPrefix(name, "ssc-init-darwin-") {
				if !bytes.Contains(content, []byte(wantVersion)) {
					t.Fatalf("%s does not contain release version %q", name, wantVersion)
				}
				assertNoAutomaticVCSSettings(t, path)
			}
			digests[name] = sha256.Sum256(content)
		}
		assertNativeVersion(t, repositoryRoot, wantVersion)
		assertNativeIsolatedStatusV3(t, repositoryRoot)
		return digests
	}

	first := runBuild()
	second := runBuild()
	for name, firstDigest := range first {
		if second[name] != firstDigest {
			t.Errorf("%s changed between identical builds: %x != %x", name, firstDigest, second[name])
		}
	}

	checksums, err := os.ReadFile(filepath.Join(repositoryRoot, "dist", "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(checksums)), "\n")
	if len(lines) != 4 ||
		!strings.HasSuffix(lines[0], "  dist/sbom.cdx.json") ||
		!strings.HasSuffix(lines[1], "  dist/ssc-init-darwin-amd64") ||
		!strings.HasSuffix(lines[2], "  dist/ssc-init-darwin-arm64") ||
		!strings.HasSuffix(lines[3], "  dist/ssc-init-darwin-universal") {
		t.Fatalf("checksums are not deterministically sorted:\n%s", checksums)
	}
}

// releaseArtifactNames is every file a release build writes into dist/.
var releaseArtifactNames = []string{
	"ssc-init-darwin-amd64",
	"ssc-init-darwin-arm64",
	"ssc-init-darwin-universal",
	"sbom.cdx.json",
	"checksums.txt",
	"provenance.json",
}

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
			Name       string `json:"name"`
			Version    string `json:"version"`
			PURL       string `json:"purl"`
			Hashes     []any  `json:"hashes"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
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
		// The go.sum h1: value is a base64 module dirhash, not a hex
		// SHA-256, so it may never be stated as a CycloneDX hash.
		if len(component.Hashes) != 0 {
			t.Fatalf("%s states a hash the build cannot verify: %v", component.Name, component.Hashes)
		}
		var recorded string
		for _, property := range component.Properties {
			if property.Name == "go:mod:h1" {
				recorded = property.Value
			}
		}
		if !strings.HasPrefix(recorded, "h1:") {
			t.Fatalf("%s does not carry its module dirhash as a property: %+v", component.Name, component.Properties)
		}
	}
	if bytes.Contains(raw, []byte(repositoryRoot)) {
		t.Fatal("sbom contains an absolute repository path")
	}
}

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

func TestBuildScriptRejectsDirtySourcesBeforeCreatingDist(t *testing.T) {
	tests := []struct {
		name  string
		dirty func(*testing.T, string)
	}{
		{
			name: "unstaged tracked change",
			dirty: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "staged change",
			dirty: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("staged\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				runGit(t, root, "add", "tracked.txt")
			},
		},
		{
			name: "untracked entry",
			dirty: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "untracked-secret-name.txt"), []byte("new\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, script, environment := newIsolatedReleaseRepository(t)
			test.dirty(t, root)

			command := exec.Command("sh", script)
			command.Dir = t.TempDir()
			command.Env = environment
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("build accepted dirty sources:\n%s", output)
			}
			if got := strings.TrimSpace(string(output)); got != "release build requires a clean worktree" {
				t.Fatalf("unexpected or filename-leaking error %q", got)
			}
			if _, err := os.Stat(filepath.Join(root, "dist")); !os.IsNotExist(err) {
				t.Fatalf("dist was created before clean-worktree rejection: %v", err)
			}
		})
	}
}

func TestBuildScriptAllowsIgnoredEntries(t *testing.T) {
	root, script, environment := newIsolatedReleaseRepository(t)
	for _, path := range []string{
		filepath.Join(root, ".superpowers", "local-note"),
		filepath.Join(root, "dist", "ignored-cache"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("ignored\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	command := exec.Command("sh", script)
	command.Dir = t.TempDir()
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ignored entries blocked build: %v\n%s", err, output)
	}
	for _, name := range releaseArtifactNames {
		if _, err := os.Stat(filepath.Join(root, "dist", name)); err != nil {
			t.Fatalf("missing %s after ignored-entry build: %v", name, err)
		}
	}
}

func TestBuildScriptRejectsInvalidRevision(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	binDirectory := t.TempDir()
	fakeGit := filepath.Join(binDirectory, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\ncase \" $* \" in\n  *\" diff \"*) exit 0 ;;\n  *\" ls-files \"*) exit 0 ;;\n  *\" rev-parse \"*) printf '%s\\n' not-a-commit; exit 0 ;;\nesac\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", filepath.Join(repositoryRoot, "scripts", "build-darwin.sh"))
	command.Dir = t.TempDir()
	command.Env = environmentWith("PATH", binDirectory+":/usr/bin:/bin")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("build accepted invalid revision:\n%s", output)
	}
	if !bytes.Contains(output, []byte("revision is not a 40-character lowercase hexadecimal commit")) {
		t.Fatalf("unexpected failure for invalid revision: %v\n%s", err, output)
	}
}

func TestBuildScriptVersionsFromExactTag(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want func(revision string) string
	}{
		{
			name: "release tag versions the binary",
			tag:  "v9.9.9",
			want: func(string) string { return "v9.9.9" },
		},
		{
			name: "non-release tag falls back to commit version",
			tag:  "experiment",
			want: func(revision string) string { return "dev+git." + revision },
		},
		{
			name: "untagged commit keeps commit version",
			tag:  "",
			want: func(revision string) string { return "dev+git." + revision },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, script, environment := newVersionRecordingReleaseRepository(t)
			if test.tag != "" {
				runGit(t, root, "tag", "-a", test.tag, "-m", test.tag)
			}
			command := exec.Command("sh", script)
			command.Dir = t.TempDir()
			command.Env = environment
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("build failed: %v\n%s", err, output)
			}
			recorded, err := os.ReadFile(filepath.Join(root, "dist", "ssc-init-darwin-arm64"))
			if err != nil {
				t.Fatal(err)
			}
			want := "-X main.version=" + test.want(worktreeRevision(t, root))
			if !strings.Contains(string(recorded), want) {
				t.Fatalf("linker flags missing %q:\n%s", want, recorded)
			}
		})
	}
}

// newVersionRecordingReleaseRepository builds the isolated fixture with a fake
// go binary that records its full argument list into the output artifact, so
// tests can assert the exact linker version flag the script passed.
func newVersionRecordingReleaseRepository(t *testing.T) (string, string, []string) {
	t.Helper()
	root, script, _ := newIsolatedReleaseRepository(t)
	binDirectory := t.TempDir()
	fakeGo := filepath.Join(binDirectory, "go")
	fakeGoSource := fakeGoVersionBranch + "output=\nall=\"$*\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -o ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf '%s\\n' \"$all\" > \"$output\"\n"
	if err := os.WriteFile(fakeGo, []byte(fakeGoSource), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeLipo(t, binDirectory)
	return root, script, environmentWith("PATH", binDirectory+":/usr/bin:/bin")
}

// fakeGoVersionBranch answers `go version -m` and `go env GOVERSION` for the
// isolated fixtures, whose fake go writes text the real toolchain cannot read
// module metadata out of. It prefixes the fixtures' argument-scanning bodies,
// which exit 2 without -o.
const fakeGoVersionBranch = `#!/bin/sh
if [ "$1" = version ]; then
  printf '%s: go1.26.5\n\tpath\tfixture\n\tdep\texample.com/fixture\tv1.0.0\th1:fixture=\n' "$3"
  exit 0
fi
if [ "$1" = env ] && [ "$2" = GOVERSION ]; then
  printf 'go1.26.5\n'
  exit 0
fi
`

// writeFakeLipo shadows /usr/bin/lipo for the isolated fixtures, whose fake go
// writes text rather than Mach-O objects that the real lipo would accept.
func writeFakeLipo(t *testing.T, binDirectory string) {
	t.Helper()
	fakeLipo := filepath.Join(binDirectory, "lipo")
	fakeLipoSource := "#!/bin/sh\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -output ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf 'fake-universal\\n' > \"$output\"\n"
	if err := os.WriteFile(fakeLipo, []byte(fakeLipoSource), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newIsolatedReleaseRepository(t *testing.T) (string, string, []string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "build-darwin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "build-darwin.sh")
	if err := os.WriteFile(script, source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("/dist/\n/.superpowers/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "-q")
	runGit(t, root, "config", "user.email", "ssc-init-tests@example.invalid")
	runGit(t, root, "config", "user.name", "SSC Init Tests")
	runGit(t, root, "add", ".gitignore", "scripts/build-darwin.sh", "tracked.txt")
	runGit(t, root, "commit", "-q", "-m", "fixture")

	binDirectory := t.TempDir()
	fakeGo := filepath.Join(binDirectory, "go")
	fakeGoSource := fakeGoVersionBranch + "output=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -o ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf 'fake-%s\\n' \"$GOARCH\" > \"$output\"\n"
	if err := os.WriteFile(fakeGo, []byte(fakeGoSource), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeLipo(t, binDirectory)
	return root, script, environmentWith("PATH", binDirectory+":/usr/bin:/bin")
}

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func environmentWith(name, value string) []string {
	prefix := name + "="
	environment := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, prefix) {
			environment = append(environment, entry)
		}
	}
	return append(environment, prefix+value)
}

// expectedReleaseVersion mirrors the build script's version selection: an
// exact v-prefixed tag with a safe character set versions the binary, anything
// else falls back to the committed revision.
func expectedReleaseVersion(t *testing.T, repositoryRoot string) string {
	t.Helper()
	command := exec.Command("git", "-C", repositoryRoot, "describe", "--tags", "--exact-match")
	output, err := command.Output()
	if err == nil {
		tag := strings.TrimSpace(string(output))
		if regexp.MustCompile(`^v[0-9][0-9A-Za-z.+-]*$`).MatchString(tag) {
			return tag
		}
	}
	return "dev+git." + worktreeRevision(t, repositoryRoot)
}

func worktreeRevision(t *testing.T, repositoryRoot string) string {
	t.Helper()
	command := exec.Command("git", "-C", repositoryRoot, "rev-parse", "--verify", "HEAD^{commit}")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(output))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(revision) {
		t.Fatalf("invalid worktree revision %q", revision)
	}
	return revision
}

func assertNoAutomaticVCSSettings(t *testing.T, binary string) {
	t.Helper()
	command := exec.Command("go", "version", "-m", binary)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect build metadata: %v\n%s", err, output)
	}
	for _, forbidden := range []string{"\tbuild\tvcs=", "\tbuild\tvcs.revision=", "\tbuild\tvcs.time=", "\tbuild\tvcs.modified="} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Fatalf("%s contains automatic VCS metadata %q:\n%s", filepath.Base(binary), forbidden, output)
		}
	}
}

func assertNativeVersion(t *testing.T, repositoryRoot, want string) {
	t.Helper()
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("native Darwin provenance smoke test")
	}
	binary := filepath.Join(repositoryRoot, "dist", "ssc-init-darwin-"+runtime.GOARCH)
	command := exec.Command(binary, "version", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native version smoke failed: %v\n%s", err, output)
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode native version output: %v\n%s", err, output)
	}
	if result.Version != want {
		t.Fatalf("native version=%q, want %q", result.Version, want)
	}
}

// assertNativeIsolatedStatusV3 smokes the release binary's status contract
// against an isolated HOME: the v3 schema version must be reported, no
// baseline may be claimed, and state must be created only inside that home.
func assertNativeIsolatedStatusV3(t *testing.T, repositoryRoot string) {
	t.Helper()
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("native Darwin status smoke test")
	}
	binary := filepath.Join(repositoryRoot, "dist", "ssc-init-darwin-"+runtime.GOARCH)
	// The store enforces a no-symlink database parent; macOS temporary
	// directories live under the /var -> /private/var symlink, so the
	// isolated home must be the physical path.
	isolatedHome, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "status", "--json")
	command.Env = environmentWith("HOME", isolatedHome)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native isolated status smoke failed: %v\n%s", err, output)
	}
	var result struct {
		SchemaVersion string `json:"schemaVersion"`
		Initialized   bool   `json:"initialized"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode native status output: %v\n%s", err, output)
	}
	if result.SchemaVersion != "ssc-init.status.v3" || result.Initialized {
		t.Fatalf("native isolated status=%+v", result)
	}
	if _, err := os.Stat(filepath.Join(isolatedHome, "Library", "Application Support", "SSC Init", "state.db")); err != nil {
		t.Fatalf("release binary did not create state inside the isolated home: %v", err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(filename), ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(fmt.Errorf("locate repository root: %w", err))
	}
	return root
}
