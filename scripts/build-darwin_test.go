package scripts_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPublishTIWorkflowIsPinnedLeastPrivilegeAndFailClosed(t *testing.T) {
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(mustRead(t, filepath.Join(repositoryRoot, ".github", "workflows", "publish-ti.yml")))
	for _, required := range []string{
		"workflow_dispatch:", "environment: ti-production", "permissions:\n  contents: read", "contents: write",
		"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "actions/setup-go@0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32",
		"secrets.TI_ED25519_PRIVATE_KEY", "secrets.TI_FEED_TOKEN", "vars.TI_KEY_ID", "persist-credentials: false", "base64 --decode",
		"scripts/test-publish-ti.sh", "ssc-init-ti-publisher verify", "--clobber=false", "if: always()", "rm -rf -- \"$TI_KEY_DIR\"",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow missing %q", required)
		}
	}
	if strings.Contains(workflow, "echo $PRIVATE_KEY") || strings.Contains(workflow, "set -x") {
		t.Fatal("workflow risks printing private key")
	}
	for _, line := range strings.Split(workflow, "\n") {
		if strings.Contains(line, "uses:") && !regexp.MustCompile(`@[0-9a-f]{40}(?:\s|$)`).MatchString(line) {
			t.Fatalf("action is not pinned by full commit SHA: %q", line)
		}
	}
}

func TestPublishTIScriptsRequireExplicitPrivateOutputAndProvenance(t *testing.T) {
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	keyScript := string(mustRead(t, filepath.Join(repositoryRoot, "scripts", "generate-ti-key.sh")))
	publishScript := string(mustRead(t, filepath.Join(repositoryRoot, "scripts", "test-publish-ti.sh")))
	for _, required := range []string{"--private-output", "tail -c 32 | go run", "never paste it into logs"} {
		if !strings.Contains(keyScript, required) {
			t.Fatalf("key script missing %q", required)
		}
	}
	for _, required := range []string{"git diff --quiet HEAD", "TI_OSV_SHA256", "TI_OPENSSF_SHA256", "TI_OSV_REVISION", "TI_OSV_LICENSE", "TI_SOURCE_RETRIEVED_AT", "TI_LAST_SEQUENCE", "TI_RELEASE_TAG_EXISTS", "test or placeholder key ID refused", "source-provenance.json"} {
		if !strings.Contains(publishScript, required) {
			t.Fatalf("publication script missing %q", required)
		}
	}
}

func TestGenerateTIKeyKeepsSeedOffArgvAndRejectsUnsafeTargets(t *testing.T) {
	repo := repositoryRoot(t)
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(userHome, ".ssc-ti-key-script-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	wrapperDir := filepath.Join(root, "bin")
	if err := os.Mkdir(wrapperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	argvLog := filepath.Join(root, "argv.log")
	wrapper := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TI_ARGV_LOG\"\nexec \"$TI_REAL_GO\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(wrapperDir, "go"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(output string) ([]byte, error) {
		command := exec.Command("sh", filepath.Join(repo, "scripts/generate-ti-key.sh"), "--private-output", output)
		command.Dir = repo
		command.Env = append(os.Environ(), "PATH="+wrapperDir+":"+os.Getenv("PATH"), "TI_ARGV_LOG="+argvLog, "TI_REAL_GO="+realGo)
		return command.CombinedOutput()
	}
	privatePath := filepath.Join(root, "private.key")
	output, err := run(privatePath)
	if err != nil {
		t.Fatalf("generate: %v: %s", err, output)
	}
	key := mustRead(t, privatePath)
	if len(key) != ed25519.PrivateKeySize {
		t.Fatalf("private size=%d", len(key))
	}
	argv := string(mustRead(t, argvLog))
	if strings.Contains(argv, string(key[:16])) || strings.Contains(argv, "=") || !strings.Contains(argv, privatePath) {
		t.Fatalf("unsafe helper argv=%q", argv)
	}
	if info, err := os.Stat(privatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}

	for name, prepare := range map[string]func(string){
		"existing":         func(path string) { _ = os.WriteFile(path, []byte("preserve"), 0o600) },
		"dangling symlink": func(path string) { _ = os.Symlink(filepath.Join(root, "victim"), path) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(name, " ", "-"))
			prepare(path)
			if out, err := run(path); err == nil {
				t.Fatalf("unsafe target accepted: %s", out)
			}
			if name == "dangling symlink" {
				if _, err := os.Stat(filepath.Join(root, "victim")); !os.IsNotExist(err) {
					t.Fatal("dangling symlink target was written")
				}
			}
		})
	}
	actual := filepath.Join(root, "actual")
	if err := os.Mkdir(actual, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(actual, linked); err != nil {
		t.Fatal(err)
	}
	if out, err := run(filepath.Join(linked, "private.key")); err == nil {
		t.Fatalf("intermediate symlink accepted: %s", out)
	}
}

func TestPublishTIScriptExecutableFailureGatesAndReproducibility(t *testing.T) {
	repo := publicationSandbox(t)
	osv := filepath.Join(repo, "internal/tipublish/testdata/osv-vulnerable.json")
	openssf := filepath.Join(repo, "internal/tipublish/testdata/openssf-malicious.json")
	osvDigest := fmt.Sprintf("%x", sha256.Sum256(mustRead(t, osv)))
	openssfDigest := fmt.Sprintf("%x", sha256.Sum256(mustRead(t, openssf)))
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(repo, "private.key")
	if err := os.WriteFile(keyPath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := map[string]string{
		"TI_OSV_SOURCE": osv, "TI_OPENSSF_SOURCE": openssf, "TI_OSV_SHA256": osvDigest, "TI_OPENSSF_SHA256": openssfDigest,
		"TI_OSV_REVISION": "osv-commit-0123456789abcdef", "TI_OPENSSF_REVISION": "openssf-commit-fedcba9876543210",
		"TI_OSV_LICENSE": "CC-BY-4.0", "TI_OPENSSF_LICENSE": "Apache-2.0", "TI_SOURCE_RETRIEVED_AT": now.Format(time.RFC3339),
		"TI_OSV_PUBLIC_URL": "https://example.test/osv.json", "TI_OPENSSF_PUBLIC_URL": "https://example.test/openssf.json",
		"TI_VERSION": "acceptance", "TI_SEQUENCE": "42", "TI_KEY_ID": "ti-fixture-2026", "TI_GENERATED_AT": now.Format(time.RFC3339),
		"TI_VALID_FROM": now.Add(-time.Hour).Format(time.RFC3339), "TI_VALID_UNTIL": now.Add(time.Hour).Format(time.RFC3339), "TI_PRIVATE_KEY_FILE": keyPath,
	}
	run := func(overrides map[string]string, unset string, output string) ([]byte, error) {
		values := map[string]string{}
		for _, entry := range os.Environ() {
			parts := strings.SplitN(entry, "=", 2)
			values[parts[0]] = parts[1]
		}
		for k, v := range base {
			values[k] = v
		}
		for k, v := range overrides {
			values[k] = v
		}
		delete(values, unset)
		values["TI_OUTPUT_DIR"] = output
		env := make([]string, 0, len(values))
		for k, v := range values {
			env = append(env, k+"="+v)
		}
		command := exec.Command("sh", "scripts/test-publish-ti.sh")
		command.Dir = repo
		command.Env = env
		return command.CombinedOutput()
	}
	for name, tc := range map[string]struct {
		over  map[string]string
		unset string
		dirty bool
	}{
		"missing provenance": {unset: "TI_OSV_REVISION"}, "test key": {over: map[string]string{"TI_KEY_ID": "test-fixture"}},
		"nonmonotonic": {over: map[string]string{"TI_LAST_SEQUENCE": "42"}}, "existing tag": {over: map[string]string{"TI_RELEASE_TAG_EXISTS": "1"}},
		"dirty tree": {dirty: true},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.dirty {
				path := filepath.Join(repo, "README.md")
				raw := mustRead(t, path)
				if err := os.WriteFile(path, append(raw, []byte("\ndirty\n")...), 0o644); err != nil {
					t.Fatal(err)
				}
				defer os.WriteFile(path, raw, 0o644)
			}
			output := filepath.Join(repo, "out-"+strings.ReplaceAll(name, " ", "-"))
			if err := os.Mkdir(output, 0o700); err != nil {
				t.Fatal(err)
			}
			if got, err := run(tc.over, tc.unset, output); err == nil {
				t.Fatalf("gate accepted invalid publication: %s", got)
			}
		})
	}

	outputs := []string{filepath.Join(repo, "repro-one"), filepath.Join(repo, "repro-two")}
	for _, output := range outputs {
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		if got, err := run(nil, "", output); err != nil {
			t.Fatalf("publication: %v: %s", err, got)
		}
	}
	for _, name := range []string{"ti-manifest.json", "ti-manifest.sig", "ti-bundle.json", "ti-bundle.sig", "attribution-report.json", "source-provenance.json", "checksums.txt"} {
		a, b := mustRead(t, filepath.Join(outputs[0], name)), mustRead(t, filepath.Join(outputs[1], name))
		if !bytes.Equal(a, b) {
			t.Fatalf("real publisher is not reproducible: %s", name)
		}
	}
}

func publicationSandbox(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	target := filepath.Join(t.TempDir(), "repo")
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.Mkdir(target, 0o700)
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".worktrees" || entry.Name() == "dist") {
			return filepath.SkipDir
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.Mkdir(destination, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		inputErr := input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputErr != nil {
			return inputErr
		}
		return closeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = target
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	return target
}

func TestProductionBuildExcludesTIAcceptanceInjection(t *testing.T) {
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	list := func(tags string) string {
		t.Helper()
		args := []string{"list", "-f", `{{join .GoFiles " "}}`}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		args = append(args, "./cmd/ssc-init")
		command := exec.Command("go", args...)
		command.Dir = repositoryRoot
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			t.Fatalf("go list: %v: %s", runErr, output)
		}
		return string(output)
	}
	if strings.Contains(list(""), "ti_acceptance.go") {
		t.Fatal("normal build includes TI acceptance injection")
	}
	if !strings.Contains(list("ti_acceptance"), "ti_acceptance.go") {
		t.Fatal("acceptance tag does not include its isolated seam")
	}
	raw := string(mustRead(t, filepath.Join(repositoryRoot, "cmd", "ssc-init", "ti_acceptance.go")))
	if !strings.HasPrefix(raw, "//go:build ti_acceptance\n") {
		t.Fatal("TI acceptance seam lacks an exclusive build constraint")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

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
		assertNativeIsolatedStatusV7(t, repositoryRoot)
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
	wantChecksumFiles := []string{
		"sbom.cdx.json",
		"ssc-init-adapter-claude.zip",
		"ssc-init-adapter-codex.zip",
		"ssc-init-adapter-cursor.zip",
		"ssc-init-darwin-universal",
	}
	if len(lines) != len(wantChecksumFiles) {
		t.Fatalf("checksums are not deterministically sorted:\n%s", checksums)
	}
	for index, name := range wantChecksumFiles {
		if !strings.HasSuffix(lines[index], "  "+name) {
			t.Fatalf("checksums are not deterministically sorted:\n%s", checksums)
		}
	}
}

func TestBuildScriptPublishesConsumerVerifiableBasenameSubjects(t *testing.T) {
	root, script, environment := newIsolatedReleaseRepository(t)
	command := exec.Command("sh", script)
	command.Dir = t.TempDir()
	command.Env = environment
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, output)
	}

	distribution := filepath.Join(root, "dist")
	checksums, err := os.ReadFile(filepath.Join(distribution, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"sbom.cdx.json",
		"ssc-init-adapter-claude.zip",
		"ssc-init-adapter-codex.zip",
		"ssc-init-adapter-cursor.zip",
		"ssc-init-darwin-universal",
	}
	gotNames := make([]string, 0, len(wantNames))
	for _, line := range strings.Split(strings.TrimSpace(string(checksums)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("unexpected checksum line %q", line)
		}
		gotNames = append(gotNames, fields[1])
	}
	if fmt.Sprint(gotNames) != fmt.Sprint(wantNames) {
		t.Fatalf("checksum subjects=%v, want published basenames %v", gotNames, wantNames)
	}

	verify := exec.Command("shasum", "-a", "256", "-c", "checksums.txt")
	verify.Dir = distribution
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("consumer checksum verification failed: %v\n%s", err, output)
	}

	provenance, err := os.ReadFile(filepath.Join(distribution, "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var statement struct {
		Subject []struct {
			Name string `json:"name"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(provenance, &statement); err != nil {
		t.Fatalf("decode provenance: %v", err)
	}
	gotNames = gotNames[:0]
	for _, subject := range statement.Subject {
		gotNames = append(gotNames, subject.Name)
	}
	if fmt.Sprint(gotNames) != fmt.Sprint(wantNames) {
		t.Fatalf("provenance subjects=%v, want checksum basenames %v", gotNames, wantNames)
	}
}

func TestAdapterPackagerEmitsNativePackagesWithoutExecutables(t *testing.T) {
	repositoryRoot := repositoryRoot(t)
	distribution := t.TempDir()
	command := exec.Command("go", "run", filepath.Join(repositoryRoot, "scripts", "package-adapters.go"), filepath.Join(repositoryRoot, "adapters"), distribution)
	command.Env = environmentWith("SOURCE_DATE_EPOCH", "0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("package failed: %v\n%s", err, output)
	}
	for _, host := range []string{"claude", "codex", "cursor"} {
		archive, err := zip.OpenReader(filepath.Join(distribution, "ssc-init-adapter-"+host+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		foundManifest, foundCapabilities := false, false
		for _, entry := range archive.File {
			if filepath.IsAbs(entry.Name) || strings.Contains(entry.Name, "..") || entry.Mode()&0o111 != 0 {
				archive.Close()
				t.Fatalf("unsafe %s entry %q mode=%v", host, entry.Name, entry.Mode())
			}
			foundManifest = foundManifest || strings.HasSuffix(entry.Name, "-plugin/plugin.json")
			foundCapabilities = foundCapabilities || strings.HasSuffix(entry.Name, "/ssc-init-capabilities.json")
		}
		archive.Close()
		if !foundManifest || !foundCapabilities {
			t.Fatalf("host=%s manifest=%v capabilities=%v", host, foundManifest, foundCapabilities)
		}
	}
}

// releaseArtifactNames is every file a release build writes into dist/.
var releaseArtifactNames = []string{
	"ssc-init-adapter-claude.zip",
	"ssc-init-adapter-codex.zip",
	"ssc-init-adapter-cursor.zip",
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
		recorded[fields[1]] = fields[0]
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

func TestReleaseModeRejectsAnythingButAnExactAnnotatedVersionTag(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name:  "untagged commit",
			setup: func(*testing.T, string) {},
		},
		{
			name: "lightweight version tag",
			setup: func(t *testing.T, root string) {
				runGit(t, root, "tag", "v9.9.9")
			},
		},
		{
			name: "annotated non-version tag",
			setup: func(t *testing.T, root string) {
				runGit(t, root, "tag", "-a", "experiment", "-m", "experiment")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, script, environment := newIsolatedReleaseRepository(t)
			test.setup(t, root)
			command := exec.Command("sh", script)
			command.Dir = t.TempDir()
			command.Env = environmentWithValue(environment, "SSC_INIT_RELEASE", "1")
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("release mode accepted %s:\n%s", test.name, output)
			}
			if got := strings.TrimSpace(string(output)); got != "release build requires an exact annotated v* tag" {
				t.Fatalf("unexpected release-mode rejection %q", got)
			}
			if _, err := os.Stat(filepath.Join(root, "dist")); !os.IsNotExist(err) {
				t.Fatalf("dist was created before tag rejection: %v", err)
			}
		})
	}
}

func TestReleaseModeReproducesFromExactAnnotatedVersionTag(t *testing.T) {
	root, script, environment := newVersionRecordingReleaseRepository(t)
	runGit(t, root, "tag", "-a", "v9.9.9", "-m", "v9.9.9")
	environment = environmentWithValue(environment, "SSC_INIT_RELEASE", "1")

	runBuild := func() map[string][32]byte {
		t.Helper()
		command := exec.Command("sh", script)
		command.Dir = t.TempDir()
		command.Env = environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("release build failed: %v\n%s", err, output)
		}
		digests := make(map[string][32]byte, len(releaseArtifactNames))
		for _, name := range releaseArtifactNames {
			content, err := os.ReadFile(filepath.Join(root, "dist", name))
			if err != nil {
				t.Fatal(err)
			}
			digests[name] = sha256.Sum256(content)
		}
		return digests
	}

	first := runBuild()
	second := runBuild()
	for name, firstDigest := range first {
		if second[name] != firstDigest {
			t.Errorf("%s changed between release builds: %x != %x", name, firstDigest, second[name])
		}
	}
	recorded, err := os.ReadFile(filepath.Join(root, "dist", "ssc-init-darwin-arm64"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recorded), "-X main.version=v9.9.9") {
		t.Fatalf("release binary does not carry annotated tag version:\n%s", recorded)
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
	fakeGoSource := fakeGoRunBranch(t) + fakeGoVersionBranch + "output=\nall=\"$*\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -o ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf '%s\\n' \"$all\" > \"$output\"\n"
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
	packager, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "package-adapters.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "package-adapters.go"), packager, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(root, "adapters"), os.DirFS(filepath.Join(repositoryRoot(t), "adapters"))); err != nil {
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
	runGit(t, root, "add", ".gitignore", "scripts", "adapters", "tracked.txt")
	runGit(t, root, "commit", "-q", "-m", "fixture")

	binDirectory := t.TempDir()
	fakeGo := filepath.Join(binDirectory, "go")
	fakeGoSource := fakeGoRunBranch(t) + fakeGoVersionBranch + "output=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = -o ]; then\n    shift\n    output=$1\n  fi\n  shift\ndone\n[ -n \"$output\" ] || exit 2\nprintf 'fake-%s\\n' \"$GOARCH\" > \"$output\"\n"
	if err := os.WriteFile(fakeGo, []byte(fakeGoSource), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeLipo(t, binDirectory)
	return root, script, environmentWith("PATH", binDirectory+":/usr/bin:/bin")
}

func fakeGoRunBranch(t *testing.T) string {
	t.Helper()
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = run ]; then exec %q \"$@\"; fi\n", realGo)
}

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func environmentWith(name, value string) []string {
	return environmentWithValue(os.Environ(), name, value)
}

func environmentWithValue(base []string, name, value string) []string {
	prefix := name + "="
	environment := make([]string, 0, len(base)+1)
	for _, entry := range base {
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

// assertNativeIsolatedStatusV7 smokes the release binary's status contract
// against an isolated HOME: the v7 schema version must be reported, no
// baseline may be claimed, and state must be created only inside that home.
func assertNativeIsolatedStatusV7(t *testing.T, repositoryRoot string) {
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
	if result.SchemaVersion != "ssc-init.status.v7" || result.Initialized {
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
