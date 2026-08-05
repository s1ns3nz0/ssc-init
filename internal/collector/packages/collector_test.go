package packages_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector/packages"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestPackagesCollectorUsesFixedProbesAndEmitsPackageURLs(t *testing.T) {
	home := t.TempDir()
	npmRoot := filepath.Join(home, ".npm-global", "lib", "node_modules")
	goPath := filepath.Join(home, "go")
	writeFile(t, filepath.Join(npmRoot, "eslint", "package.json"), `{"name":"eslint","version":"9.1.0"}`)
	writeFile(t, filepath.Join(npmRoot, "@scope", "tool", "package.json"), `{"name":"@scope/tool","version":"2.0.0"}`)
	writeFile(t, filepath.Join(goPath, "bin", "gopls"), "binary")

	runner := &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		commandKey("npm", "root", "-g"):                               {Stdout: npmRoot + "\n"},
		commandKey("python3", "-m", "pip", "list", "--format=json"):   {Stdout: `[{"name":"requests","version":"2.32.3"}]`},
		commandKey("pipx", "list", "--json"):                          {Stdout: `{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"24.4.2"},"injected_packages":{"isort":{"package":"isort","package_version":"5.13.2"}}}}}}`},
		commandKey("uv", "tool", "list"):                              {Stdout: "ruff v0.5.0\n- ruff\n"},
		commandKey("cargo", "install", "--list"):                      {Stdout: "ripgrep v14.1.0:\n    rg\n"},
		commandKey("go", "env", "GOPATH"):                             {Stdout: goPath + "\n"},
		commandKey("brew", "list", "--versions"):                      {Stdout: "jq 1.7.1\nopenssl@3 3.3.1 3.3.2\n"},
		commandKey("docker", "image", "ls", "--format", "{{json .}}"): {Stdout: `{"Repository":"alpine","Tag":"3.20","ID":"sha256:abc"}` + "\n"},
	}}
	env := testutil.Environment(t, home)
	env.Runner = runner

	got, err := packages.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"pkg:npm/eslint@9.1.0", "pkg:npm/%40scope/tool@2.0.0", "pkg:pypi/requests@2.32.3",
		"pkg:pypi/black@24.4.2", "pkg:pypi/isort@5.13.2", "pkg:pypi/ruff@0.5.0",
		"pkg:cargo/ripgrep@14.1.0", "pkg:brew/jq@1.7.1", "pkg:brew/openssl%403@3.3.2",
		"pkg:docker/alpine@3.20", "tool:go:gopls",
	} {
		testutil.AssertAsset(t, got.Assets, id)
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("status=%s errors=%+v", got.Status, got.Errors)
	}
	wantCalls := []string{
		commandKey("npm", "root", "-g"),
		commandKey("python3", "-m", "pip", "list", "--format=json"),
		commandKey("pipx", "list", "--json"),
		commandKey("uv", "tool", "list"),
		commandKey("cargo", "install", "--list"),
		commandKey("go", "env", "GOPATH"),
		commandKey("brew", "list", "--versions"),
		commandKey("docker", "image", "ls", "--format", "{{json .}}"),
	}
	if !reflect.DeepEqual(runner.Calls, wantCalls) {
		t.Fatalf("calls=%q want=%q", runner.Calls, wantCalls)
	}
	for _, call := range runner.Calls {
		if strings.Contains(call, "sh\x1f-c") || strings.HasPrefix(call, "sh\x1f") {
			t.Fatalf("shell invocation: %q", call)
		}
	}
}

func TestPackagesCollectorMarksAllMissingExecutablesSkipped(t *testing.T) {
	runner := missingRunner()
	env := testutil.Environment(t, t.TempDir())
	env.Runner = runner

	got, err := packages.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageSkipped || len(got.Assets) != 0 {
		t.Fatalf("result=%+v", got)
	}
	if len(got.Errors) != 8 {
		t.Fatalf("errors=%+v", got.Errors)
	}
	for _, coverageErr := range got.Errors {
		if coverageErr.Code != "executable_missing" || coverageErr.Path != "" {
			t.Fatalf("error=%+v", coverageErr)
		}
	}
}

func TestPackagesCollectorMarksStoppedDockerUnavailableWithoutStderr(t *testing.T) {
	secret := "registry-token-do-not-persist"
	runner := missingRunner()
	dockerKey := commandKey("docker", "image", "ls", "--format", "{{json .}}")
	delete(runner.Errors, dockerKey)
	runner.Results = map[string]platform.CommandResult{
		dockerKey: {Stderr: "Cannot connect to daemon: " + secret, ExitCode: 1},
	}
	runner.Errors[dockerKey] = errors.New("exit status 1")
	env := testutil.Environment(t, t.TempDir())
	env.Runner = runner

	got, err := packages.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageUnavailable {
		t.Fatalf("result=%+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "Cannot connect") {
		t.Fatalf("stderr persisted: %s", encoded)
	}
}

func TestPackagesCollectorKeepsValidSiblingsWhenOneProbeIsMalformed(t *testing.T) {
	runner := missingRunner()
	pythonKey := commandKey("python3", "-m", "pip", "list", "--format=json")
	brewKey := commandKey("brew", "list", "--versions")
	delete(runner.Errors, pythonKey)
	delete(runner.Errors, brewKey)
	runner.Results = map[string]platform.CommandResult{
		pythonKey: {Stdout: "not-json"},
		brewKey:   {Stdout: "jq 1.7.1\n"},
	}
	env := testutil.Environment(t, t.TempDir())
	env.Runner = runner

	got, err := packages.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "pkg:brew/jq@1.7.1")
	if got.Status != model.CoveragePartial {
		t.Fatalf("result=%+v", got)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commandKey(command string, args ...string) string {
	return strings.Join(append([]string{command}, args...), "\x1f")
}

func missingRunner() *testutil.FakeRunner {
	errorsByCommand := make(map[string]error)
	for _, command := range [][]string{
		{"npm", "root", "-g"},
		{"python3", "-m", "pip", "list", "--format=json"},
		{"pipx", "list", "--json"},
		{"uv", "tool", "list"},
		{"cargo", "install", "--list"},
		{"go", "env", "GOPATH"},
		{"brew", "list", "--versions"},
		{"docker", "image", "ls", "--format", "{{json .}}"},
	} {
		errorsByCommand[commandKey(command[0], command[1:]...)] = exec.ErrNotFound
	}
	return &testutil.FakeRunner{Errors: errorsByCommand}
}
