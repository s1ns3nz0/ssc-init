package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/store"
	"github.com/ssc-init/ssc-init/internal/testutil"
	"golang.org/x/sys/unix"
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
		commandKey("python3", "-m", "pip", "list", "--format=json"):   {Stdout: `[{"name":"requests","version":"2.32.3"},{"name":"Foo__..Bar","version":"1.0.0"}]`},
		commandKey("pipx", "list", "--json"):                          {Stdout: `{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"24.4.2"},"injected_packages":{"isort":{"package":"isort","package_version":"5.13.2"}}}}}}`},
		commandKey("uv", "tool", "list"):                              {Stdout: "ruff v0.5.0\n- ruff\n"},
		commandKey("cargo", "install", "--list"):                      {Stdout: "ripgrep v14.1.0:\n    rg\n"},
		commandKey("go", "env", "GOPATH"):                             {Stdout: goPath + "\n"},
		commandKey("brew", "list", "--versions"):                      {Stdout: "jq 1.7.1\nopenssl@3 3.3.1 3.3.2\n"},
		commandKey("docker", "image", "ls", "--format", "{{json .}}"): {Stdout: `{"Repository":"alpine","Tag":"3.20","ID":"sha256:abc"}` + "\n"},
	}}
	env := optInEnvironment(t, home, runner)

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"pkg:npm/eslint@9.1.0", "pkg:npm/%40scope/tool@2.0.0", "pkg:pypi/requests@2.32.3",
		"pkg:pypi/foo-bar@1.0.0",
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

func TestPackageProbesAreSkippedByDefault(t *testing.T) {
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = false
	env.Inspector = &fakeInspector{failOnCall: true}
	env.Runner = failRunner{}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 8 {
		t.Fatalf("targets=%+v", got.Targets)
	}
	for _, target := range got.Targets {
		if target.Status != model.TargetSkipped || target.Assets != 0 || target.Observations != 0 || len(target.Errors) != 0 {
			t.Fatalf("target=%+v", target)
		}
	}
	if got.Status != model.CoverageSkipped || len(got.Assets) != 0 || len(got.Observations) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestOptInPackageProbeInspectsRunsAbsoluteAndVerifiesWithLinkedEvidence(t *testing.T) {
	home := t.TempDir()
	npmRoot := filepath.Join(home, ".npm-global", "lib", "node_modules")
	writeFile(t, filepath.Join(npmRoot, "eslint", "package.json"), `{"name":"eslint","version":"9.1.0"}`)
	executablePath := filepath.Join(home, "bin", "npm")
	events := []string{}
	inspector := &fakeInspector{
		events: &events,
		evidence: map[string]platform.ExecutableEvidence{
			"npm": {
				Command: "npm", Path: executablePath, LocationRef: "$HOME/bin/npm",
				SHA256: strings.Repeat("a", 64), Mode: 0o755,
			},
		},
		errors: missingInspectorErrors("npm"),
	}
	runner := &recordingRunner{events: &events, results: map[string]platform.CommandResult{
		commandKey(executablePath, "root", "-g"): {Stdout: npmRoot + "\n"},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector = inspector
	env.Runner = runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []string{
		"inspect:npm", "run:" + commandKey(executablePath, "root", "-g"), "verify:npm", "inspect:python3",
	}
	if len(events) < len(wantPrefix) || !reflect.DeepEqual(events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("events=%q wantPrefix=%q", events, wantPrefix)
	}
	executableID := "tool-executable:sha256:" + strings.Repeat("a", 64)
	testutil.AssertAsset(t, got.Assets, executableID)
	packageAsset := testutil.AssertAsset(t, got.Assets, "pkg:npm/eslint@9.1.0")
	if packageAsset.Path != "" || packageAsset.Source != "" || len(packageAsset.Metadata) != 0 {
		t.Fatalf("canonical package carries occurrence facts: %+v", packageAsset)
	}
	var executableObservation, packageObservation model.Observation
	for _, observation := range got.Observations {
		switch observation.AssetID {
		case executableID:
			executableObservation = observation
		case packageAsset.ID:
			packageObservation = observation
		}
	}
	if executableObservation.ID == "" || executableObservation.LocationRef != "$HOME/bin/npm" {
		t.Fatalf("executable observation=%+v", executableObservation)
	}
	if packageObservation.ID == "" || packageObservation.Metadata["probe_target_id"] != "packages.npm" || packageObservation.Metadata["executable_observation_id"] != executableObservation.ID || packageObservation.Metadata["manager"] != "npm" {
		t.Fatalf("package observation=%+v executable=%+v", packageObservation, executableObservation)
	}
	assertPackageTarget(t, got, "packages.npm", model.TargetComplete, 2, 2)
}

func TestAllOptInPackageProbesUseInspectedAbsolutePathsAndExactFixedArgv(t *testing.T) {
	events := []string{}
	inspector := &fakeInspector{events: &events, evidence: make(map[string]platform.ExecutableEvidence), errors: make(map[string]error)}
	runner := &recordingRunner{events: &events, results: make(map[string]platform.CommandResult)}
	missingRoot := filepath.Join(t.TempDir(), "missing-package-root")
	for _, probe := range probes() {
		path := filepath.Join("/inspected-bin", probe.command)
		digest := sha256.Sum256([]byte(probe.command))
		inspector.evidence[probe.command] = platform.ExecutableEvidence{
			Command: probe.command, Path: path, LocationRef: "external-executable:1/path-sha256:" + fmt.Sprintf("%x", digest),
			SHA256: fmt.Sprintf("%x", digest), Mode: 0o755,
		}
		result := platform.CommandResult{}
		switch probe.targetID {
		case "packages.npm", "packages.go":
			result.Stdout = missingRoot + "\n"
		case "packages.pip":
			result.Stdout = `[{"name":"probe-package","version":"1.0.0"}]`
		case "packages.pipx":
			result.Stdout = `{"venvs":{"probe-package":{"metadata":{"main_package":{"package":"probe-package","package_version":"1.0.0"}}}}}`
		}
		runner.results[commandKey(path, probe.args...)] = result
	}
	env := testutil.Environment(t, t.TempDir())
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("result=%+v", got)
	}
	want := make([]string, 0, len(probes())*3)
	for _, probe := range probes() {
		want = append(want,
			"inspect:"+probe.command,
			"run:"+commandKey(filepath.Join("/inspected-bin", probe.command), probe.args...),
			"verify:"+probe.command,
		)
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events=%q want=%q", events, want)
	}
	assertPackageCountsMatchEmitted(t, got)
}

func TestPackageProbeMarksParserLossPartialWhileKeepingValidPackages(t *testing.T) {
	home := t.TempDir()
	pythonPath := filepath.Join(home, "bin", "python3")
	inspector := &fakeInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {Command: "python3", Path: pythonPath, LocationRef: "$HOME/bin/python3", SHA256: strings.Repeat("b", 64), Mode: 0o755},
		},
		errors: missingInspectorErrors("python3"),
	}
	runner := &recordingRunner{results: map[string]platform.CommandResult{
		commandKey(pythonPath, "-m", "pip", "list", "--format=json"): {
			Stdout: `[{"name":"requests","version":"2.32.3"},{"name":"missing-version"}]`,
		},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "pkg:pypi/requests@2.32.3")
	assertPackageTarget(t, got, "packages.pip", model.TargetPartial, 2, 2)
	if !hasPackageError(got, "probe_output_invalid") {
		t.Fatalf("errors=%+v", got.Errors)
	}
}

func TestPackageProbeVerifiesAfterEveryAttemptAndReportsLossTruthfully(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		result    platform.CommandResult
		runErr    error
		verifyErr error
		wantCode  string
	}{
		{name: "timeout", result: platform.CommandResult{ExitCode: -1}, runErr: &platform.TimeoutError{Command: "/fake/python3"}, wantCode: "probe_failed"},
		{name: "nonzero", result: platform.CommandResult{ExitCode: 2}, runErr: errors.New("exit status 2"), wantCode: "probe_failed"},
		{name: "truncated", result: platform.CommandResult{Stdout: `[]`, Truncated: true}, wantCode: "probe_output_truncated"},
		{name: "replacement", result: platform.CommandResult{Stdout: `[]`}, verifyErr: errors.New("changed"), wantCode: "executable_replaced"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "bin", "python3")
			events := []string{}
			inspector := &fakeInspector{
				events: &events,
				evidence: map[string]platform.ExecutableEvidence{
					"python3": {Command: "python3", Path: path, LocationRef: "$HOME/bin/python3", SHA256: strings.Repeat("c", 64), Mode: 0o755},
				},
				errors:    missingInspectorErrors("python3"),
				verifyErr: map[string]error{"python3": testCase.verifyErr},
			}
			key := commandKey(path, "-m", "pip", "list", "--format=json")
			runner := &recordingRunner{
				events: &events, results: map[string]platform.CommandResult{key: testCase.result}, errors: map[string]error{key: testCase.runErr},
			}
			env := testutil.Environment(t, home)
			env.Scope.ExternalProbes = true
			env.Inspector, env.Runner = inspector, runner

			got, err := New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			wantEvents := []string{"inspect:python3", "run:" + key, "verify:python3"}
			if !containsEventSequence(events, wantEvents) {
				t.Fatalf("events=%q wantSequence=%q", events, wantEvents)
			}
			assertPackageTarget(t, got, "packages.pip", model.TargetPartial, 1, 1)
			if !hasPackageError(got, testCase.wantCode) {
				t.Fatalf("errors=%+v", got.Errors)
			}
		})
	}
}

func TestCapabilitiesMatchFixedProbesAndReturnIndependentSlices(t *testing.T) {
	want := []Capability{
		{Ecosystem: "npm", Executable: "npm"},
		{Ecosystem: "pip", Executable: "python3"},
		{Ecosystem: "pipx", Executable: "pipx"},
		{Ecosystem: "uv", Executable: "uv"},
		{Ecosystem: "cargo", Executable: "cargo"},
		{Ecosystem: "go", Executable: "go"},
		{Ecosystem: "homebrew", Executable: "brew"},
		{Ecosystem: "docker", Executable: "docker"},
	}
	got := Capabilities()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities=%+v want=%+v", got, want)
	}
	got[0] = Capability{Ecosystem: "mutated", Executable: "mutated"}
	if next := Capabilities(); !reflect.DeepEqual(next, want) {
		t.Fatalf("shared mutable capabilities=%+v", next)
	}
}

func TestPackageTargetCatalogIsExactAndIndependent(t *testing.T) {
	targeted, ok := New().(collector.TargetedCollector)
	if !ok {
		t.Fatalf("collector=%T does not implement TargetedCollector", New())
	}
	wantIDs := []string{
		"packages.cargo", "packages.docker", "packages.go", "packages.homebrew",
		"packages.npm", "packages.pip", "packages.pipx", "packages.uv",
	}
	got := targeted.Targets()
	if len(got) != len(wantIDs) {
		t.Fatalf("targets=%+v", got)
	}
	for index, target := range got {
		if target.ID != wantIDs[index] || target.Collector != "packages" || target.Platform != "darwin" || target.Scope != model.ScopeToolEnvironment || target.Method != model.TargetCommand {
			t.Fatalf("target[%d]=%+v", index, target)
		}
	}
	got[0].ID = "mutated"
	if next := targeted.Targets(); next[0].ID != wantIDs[0] {
		t.Fatalf("shared target catalog=%+v", next)
	}
}

func TestPackageManagerCollisionsRemainCandidatesAndDistinctObservations(t *testing.T) {
	home := t.TempDir()
	pythonPath := filepath.Join(home, "bin", "python3")
	pipxPath := filepath.Join(home, "bin", "pipx")
	inspector := &fakeInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {Command: "python3", Path: pythonPath, LocationRef: "$HOME/bin/python3", SHA256: strings.Repeat("d", 64), Mode: 0o755},
			"pipx":    {Command: "pipx", Path: pipxPath, LocationRef: "$HOME/bin/pipx", SHA256: strings.Repeat("e", 64), Mode: 0o755},
		},
		errors: missingInspectorErrors("python3", "pipx"),
	}
	runner := &recordingRunner{results: map[string]platform.CommandResult{
		commandKey(pythonPath, "-m", "pip", "list", "--format=json"): {Stdout: `[{"name":"black","version":"24.4.2"}]`},
		commandKey(pipxPath, "list", "--json"):                       {Stdout: `{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"24.4.2"}}}}}`},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	assetID := "pkg:pypi/black@24.4.2"
	candidates := 0
	managers := map[string]bool{}
	for _, asset := range got.Assets {
		if asset.ID == assetID {
			candidates++
		}
	}
	for _, observation := range got.Observations {
		if observation.AssetID == assetID {
			managers[observation.Metadata["manager"]] = true
		}
	}
	if candidates != 2 || !managers["pip"] || !managers["pipx"] || len(managers) != 2 {
		t.Fatalf("candidates=%d managers=%v result=%+v", candidates, managers, got)
	}
}

func TestRealPATHSpoofIsRecordedByActualHashAndSafeLocation(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	pythonPath := filepath.Join(bin, "python3")
	contents := []byte("#!/bin/sh\nprintf '[{\"name\":\"spoofed-package\",\"version\":\"1.2.3\"}]'\n")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pythonPath, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	digest := sha256.Sum256(contents)
	digestText := fmt.Sprintf("%x", digest)
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector = platform.NewExecutableInspector(16, 64<<20)
	env.Runner = platform.ExecRunner{Timeout: 5 * time.Second, MaxOutputBytes: 1 << 20}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	executable := testutil.AssertAsset(t, got.Assets, "tool-executable:sha256:"+digestText)
	if executable.Name != "executable" || executable.SHA256 != digestText || executable.Path != "" || executable.Source != "" {
		t.Fatalf("executable=%+v", executable)
	}
	testutil.AssertAsset(t, got.Assets, "pkg:pypi/spoofed-package@1.2.3")
	for _, observation := range got.Observations {
		if observation.AssetID == executable.ID && observation.LocationRef != "$HOME/bin/python3" {
			t.Fatalf("observation=%+v", observation)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(pythonPath)) {
		t.Fatalf("absolute spoof path leaked: %s", encoded)
	}
}

func TestDockerEvidenceKeepsReportedReferenceWithUnknownLocality(t *testing.T) {
	home := t.TempDir()
	dockerPath := filepath.Join(home, "bin", "docker")
	inspector := &fakeInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"docker": {Command: "docker", Path: dockerPath, LocationRef: "$HOME/bin/docker", SHA256: strings.Repeat("f", 64), Mode: 0o755},
		},
		errors: missingInspectorErrors("docker"),
	}
	runner := &recordingRunner{results: map[string]platform.CommandResult{
		commandKey(dockerPath, "image", "ls", "--format", "{{json .}}"): {Stdout: `{"Repository":"alpine","Tag":"3.20","ID":"sha256:local-only"}` + "\n"},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "pkg:docker/alpine@3.20")
	if asset.Source != "" || asset.Path != "" || len(asset.Metadata) != 0 {
		t.Fatalf("asset=%+v", asset)
	}
	for _, observation := range got.Observations {
		if observation.AssetID == asset.ID {
			if observation.Metadata["locality"] != "unknown" || strings.Contains(fmt.Sprint(observation.Metadata), "local-only") {
				t.Fatalf("observation=%+v", observation)
			}
			return
		}
	}
	t.Fatal("missing Docker observation")
}

func TestPackageProbeQuarantinesUnsafePackageIdentityWithoutEcho(t *testing.T) {
	home := t.TempDir()
	privateName := "/Volumes/private-client/package"
	pythonPath := filepath.Join(home, "bin", "python3")
	inspector := &fakeInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {Command: "python3", Path: pythonPath, LocationRef: "$HOME/bin/python3", SHA256: strings.Repeat("1", 64), Mode: 0o755},
		},
		errors: missingInspectorErrors("python3"),
	}
	runner := &recordingRunner{results: map[string]platform.CommandResult{
		commandKey(pythonPath, "-m", "pip", "list", "--format=json"): {Stdout: `[{"name":"` + privateName + `","version":"1.0.0"}]`},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	assertPackageTarget(t, got, "packages.pip", model.TargetPartial, 1, 1)
	if !hasPackageError(got, "identity_rejected") {
		t.Fatalf("errors=%+v", got.Errors)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(privateName)) || bytes.Contains(encoded, []byte("/Volumes/private-client")) {
		t.Fatalf("unsafe identity leaked: %s", encoded)
	}
}

func TestPackageExecutableAndManagerEvidencePassPersistencePrivacyBackstop(t *testing.T) {
	home := t.TempDir()
	pythonPath := filepath.Join(home, "bin", "python3")
	inspector := &fakeInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {
				Command: "python3", Path: pythonPath, LocationRef: "$HOME/bin/python3",
				SymlinkRefs: []string{"$HOME/bin/python"}, SHA256: strings.Repeat("2", 64), Mode: 0o755,
			},
		},
		errors: missingInspectorErrors("python3"),
	}
	runner := &recordingRunner{results: map[string]platform.CommandResult{
		commandKey(pythonPath, "-m", "pip", "list", "--format=json"): {Stdout: `[{"name":"requests","version":"2.32.3"}]`},
	}}
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	env.Inspector, env.Runner = inspector, runner
	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	databaseDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(filepath.Join(databaseDirectory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v2", ScanID: "packages-privacy-backstop", Status: "partial",
		StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC(),
		Coverage: []model.CollectorResult{got},
		Scope: model.ScanScope{
			Platform: "darwin", CatalogVersion: collector.CatalogVersion, ExternalProbes: true,
		},
	}
	if err := state.SaveScan(context.Background(), scan, inventory.Build(scan.Coverage)); err != nil {
		t.Fatalf("persist package evidence: %v", err)
	}
}

func TestPackagesCollectorMarksAllMissingExecutablesSkipped(t *testing.T) {
	runner := missingRunner()
	env := optInEnvironment(t, t.TempDir(), runner)

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete || len(got.Assets) != 0 {
		t.Fatalf("result=%+v", got)
	}
	if len(got.Errors) != 0 || len(got.Targets) != 8 {
		t.Fatalf("result=%+v", got)
	}
	for _, target := range got.Targets {
		if target.Status != model.TargetNotPresent {
			t.Fatalf("target=%+v", target)
		}
	}
}

func TestDockerFailureClassificationIsBoundedEphemeralAndAlwaysVerified(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		result     platform.CommandResult
		runErr     error
		wantStatus model.TargetStatus
	}{
		{
			name:   "identified daemon failure",
			result: platform.CommandResult{ExitCode: 1, Stderr: "Cannot connect to the Docker daemon at unix:///private.sock. Is the docker daemon running? registry-token-do-not-persist"},
			runErr: errors.New("exit status 1"), wantStatus: model.TargetUnavailable,
		},
		{
			name:   "timeout",
			result: platform.CommandResult{ExitCode: -1, Stderr: "Cannot connect to the Docker daemon"},
			runErr: &platform.TimeoutError{Command: "/private/docker"}, wantStatus: model.TargetPartial,
		},
		{
			name:   "generic nonzero",
			result: platform.CommandResult{ExitCode: 125, Stderr: "generic private failure detail"},
			runErr: errors.New("exit status 125"), wantStatus: model.TargetPartial,
		},
		{
			name:   "invalid invocation",
			result: platform.CommandResult{ExitCode: 125, Stderr: "unknown flag: --private-invalid"},
			runErr: errors.New("exit status 125"), wantStatus: model.TargetPartial,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			dockerPath := filepath.Join(home, "bin", "docker")
			events := []string{}
			inspector := &fakeInspector{
				events: &events,
				evidence: map[string]platform.ExecutableEvidence{
					"docker": {Command: "docker", Path: dockerPath, LocationRef: "$HOME/bin/docker", SHA256: strings.Repeat("3", 64), Mode: 0o755},
				},
				errors: missingInspectorErrors("docker"),
			}
			key := commandKey(dockerPath, "image", "ls", "--format", "{{json .}}")
			runner := &recordingRunner{
				events: &events, results: map[string]platform.CommandResult{key: testCase.result}, errors: map[string]error{key: testCase.runErr},
			}
			env := testutil.Environment(t, home)
			env.Scope.ExternalProbes = true
			env.Inspector, env.Runner = inspector, runner

			got, err := New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			assertPackageTarget(t, got, "packages.docker", testCase.wantStatus, 1, 1)
			if !containsEventSequence(events, []string{"inspect:docker", "run:" + key, "verify:docker"}) {
				t.Fatalf("events=%q", events)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(testCase.result.Stderr)) || bytes.Contains(encoded, []byte("registry-token-do-not-persist")) {
				t.Fatalf("stderr persisted: %s", encoded)
			}
		})
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
	env := optInEnvironment(t, t.TempDir(), runner)

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "pkg:brew/jq@1.7.1")
	if got.Status != model.CoveragePartial {
		t.Fatalf("result=%+v", got)
	}
}

func TestPackagesCollectorTreatsMissingPackageDirectoriesAsBenign(t *testing.T) {
	home := t.TempDir()
	runner := successfulRunner(t)
	runner.Results[commandKey("npm", "root", "-g")] = platform.CommandResult{Stdout: filepath.Join(home, "missing-npm") + "\n"}
	runner.Results[commandKey("go", "env", "GOPATH")] = platform.CommandResult{Stdout: filepath.Join(home, "missing-go") + "\n"}
	env := optInEnvironment(t, home, runner)

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete || len(got.Errors) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestPackagesCollectorReportsFilesystemAccessWithoutPersistingDetails(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(*testing.T, string, *testutil.FakeRunner) platform.FileSystem
		want  string
	}{
		{
			name: "scoped npm directory",
			setup: func(t *testing.T, home string, runner *testutil.FakeRunner) platform.FileSystem {
				root := filepath.Join(home, "npm-root")
				writeFile(t, filepath.Join(root, "good", "package.json"), `{"name":"good","version":"1.0.0"}`)
				scope := filepath.Join(root, "@private")
				if err := os.MkdirAll(scope, 0o755); err != nil {
					t.Fatal(err)
				}
				runner.Results[commandKey("npm", "root", "-g")] = platform.CommandResult{Stdout: root + "\n"}
				return faultFS{
					FileSystem:    platform.OSFileSystem{},
					readDirErrors: map[string]error{scope: fmt.Errorf("private-scope-marker: %w", fs.ErrPermission)},
				}
			},
			want: "pkg:npm/good@1.0.0",
		},
		{
			name: "npm manifest",
			setup: func(t *testing.T, home string, runner *testutil.FakeRunner) platform.FileSystem {
				root := filepath.Join(home, "npm-root")
				writeFile(t, filepath.Join(root, "good", "package.json"), `{"name":"good","version":"1.0.0"}`)
				blocked := filepath.Join(root, "blocked", "package.json")
				writeFile(t, blocked, `{"name":"blocked","version":"9.9.9"}`)
				runner.Results[commandKey("npm", "root", "-g")] = platform.CommandResult{Stdout: root + "\n"}
				return faultFS{
					FileSystem:     platform.OSFileSystem{},
					readFileErrors: map[string]error{blocked: fmt.Errorf("manifest-secret-marker: %w", fs.ErrPermission)},
				}
			},
			want: "pkg:npm/good@1.0.0",
		},
		{
			name: "Go bin directory",
			setup: func(t *testing.T, home string, runner *testutil.FakeRunner) platform.FileSystem {
				goPath := filepath.Join(home, "private-go")
				binPath := filepath.Join(goPath, "bin")
				runner.Results[commandKey("go", "env", "GOPATH")] = platform.CommandResult{Stdout: goPath + "\n"}
				return faultFS{
					FileSystem:    platform.OSFileSystem{},
					readDirErrors: map[string]error{binPath: fmt.Errorf("go-bin-secret-marker: %w", fs.ErrPermission)},
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			runner := successfulRunner(t)
			env := optInEnvironment(t, home, runner)
			env.FS = testCase.setup(t, home, runner)

			got, err := New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.want != "" {
				testutil.AssertAsset(t, got.Assets, testCase.want)
			}
			if got.Status != model.CoveragePartial || len(got.Errors) != 1 {
				t.Fatalf("result=%+v", got)
			}
			coverageErr := got.Errors[0]
			if coverageErr.Code != "filesystem_unavailable" || coverageErr.Path != "" {
				t.Fatalf("error=%+v", coverageErr)
			}
			encoded, marshalErr := json.Marshal(got)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			for _, marker := range []string{"private-scope-marker", "manifest-secret-marker", "go-bin-secret-marker", home} {
				if strings.Contains(string(encoded), marker) {
					t.Fatalf("sensitive detail persisted: %s", encoded)
				}
			}
		})
	}
}

func TestPackageParsersHonorCanceledContext(t *testing.T) {
	home := t.TempDir()
	npmRoot := filepath.Join(home, "npm-root")
	goPath := filepath.Join(home, "go")
	writeFile(t, filepath.Join(npmRoot, "tool", "package.json"), `{"name":"tool","version":"1.0.0"}`)
	writeFile(t, filepath.Join(goPath, "bin", "gopls"), "binary")
	env := testutil.Environment(t, home)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, testCase := range []struct {
		name   string
		parse  func(context.Context, collector.Environment, string) ([]model.Asset, error)
		stdout string
	}{
		{name: "npm", parse: parseNPM, stdout: npmRoot + "\n"},
		{name: "pip", parse: parsePip, stdout: `[{"name":"requests","version":"2.32.3"}]`},
		{name: "pipx", parse: parsePipx, stdout: `{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"24.4.2"}}}}}`},
		{name: "uv", parse: parseUV, stdout: "ruff v0.5.0\n"},
		{name: "cargo", parse: parseCargo, stdout: "ripgrep v14.1.0:\n"},
		{name: "go", parse: parseGoPath, stdout: goPath + "\n"},
		{name: "brew", parse: parseBrew, stdout: "jq 1.7.1\n"},
		{name: "docker", parse: parseDocker, stdout: `{"Repository":"alpine","Tag":"3.20"}` + "\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := testCase.parse(ctx, env, testCase.stdout)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPackageParsersReportLossInsteadOfSilentlyDroppingRecords(t *testing.T) {
	home := t.TempDir()
	npmRoot := filepath.Join(home, "npm-root")
	writeFile(t, filepath.Join(npmRoot, "valid", "package.json"), `{"name":"valid","version":"1.0.0"}`)
	writeFile(t, filepath.Join(npmRoot, "invalid", "package.json"), `{"name":"missing-version"}`)
	env := testutil.Environment(t, home)

	for _, testCase := range []struct {
		name   string
		parse  func(context.Context, collector.Environment, string) ([]model.Asset, error)
		stdout string
	}{
		{name: "npm", parse: parseNPM, stdout: npmRoot + "\n"},
		{name: "pipx", parse: parsePipx, stdout: `{"venvs":{"bad":{"metadata":{"main_package":{"package":"bad"}}}}}`},
		{name: "pipx shape-less", parse: parsePipx, stdout: `{}`},
		{name: "uv", parse: parseUV, stdout: "broken output\n"},
		{name: "cargo", parse: parseCargo, stdout: "broken output\n"},
		{name: "homebrew", parse: parseBrew, stdout: "missing-version\n"},
		{name: "docker", parse: parseDocker, stdout: `{"Repository":"alpine","Tag":"<none>","Digest":"<none>","ID":"sha256:local-only"}` + "\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := testCase.parse(context.Background(), env, testCase.stdout)
			if !errors.Is(err, errParserLoss) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSuccessfulEmptyDiscoveryOutputsAreParserLoss(t *testing.T) {
	env := testutil.Environment(t, t.TempDir())
	for _, testCase := range []struct {
		name, stdout string
		parse        func(context.Context, collector.Environment, string) ([]model.Asset, error)
	}{
		{name: "npm", stdout: " \n", parse: parseNPM},
		{name: "pip", stdout: `[]`, parse: parsePip},
		{name: "pipx", stdout: `{"venvs":{}}`, parse: parsePipx},
		{name: "go", stdout: " \n", parse: parseGoPath},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assets, err := testCase.parse(context.Background(), env, testCase.stdout)
			if len(assets) != 0 || !errors.Is(err, errParserLoss) {
				t.Fatalf("assets=%+v error=%v", assets, err)
			}
		})
	}
}

func TestDockerMalformedNDJSONLinePreservesValidSiblingsAndReportsLoss(t *testing.T) {
	stdout := strings.Join([]string{
		`{"Repository":"alpine","Tag":"3.20"}`,
		`{"Repository":`,
		`{"Repository":"ubuntu","Tag":"24.04"}`,
	}, "\n")
	assets, err := parseDocker(context.Background(), testutil.Environment(t, t.TempDir()), stdout)
	if !errors.Is(err, errParserLoss) {
		t.Fatalf("error=%v", err)
	}
	want := []string{"pkg:docker/alpine@3.20", "pkg:docker/ubuntu@24.04"}
	got := make([]string, len(assets))
	for index, asset := range assets {
		got[index] = asset.ID
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assets=%q want=%q", got, want)
	}
}

func TestNPMManifestFIFOIsRejectedWithoutBlockingAndValidSiblingSurvives(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "node_modules")
	writeFile(t, filepath.Join(root, "valid", "package.json"), `{"name":"valid","version":"1.0.0"}`)
	fifoPath := filepath.Join(root, "hostile", "package.json")
	if err := os.MkdirAll(filepath.Dir(fifoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		assets []model.Asset
		err    error
	}
	done := make(chan outcome, 1)
	env := testutil.Environment(t, home)
	go func() {
		assets, err := parseNPM(context.Background(), env, root+"\n")
		done <- outcome{assets: assets, err: err}
	}()
	select {
	case got := <-done:
		if !errors.Is(got.err, errParserLoss) {
			t.Fatalf("error=%v", got.err)
		}
		testutil.AssertAsset(t, got.assets, "pkg:npm/valid@1.0.0")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("FIFO manifest read blocked")
	}
}

func TestNPMEntryBudgetExactLimitAndPlusOne(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		entries    int
		wantLoss   bool
		wantAssets int
	}{
		{name: "exact limit", entries: 2, wantAssets: 2},
		{name: "limit plus one", entries: 3, wantLoss: true, wantAssets: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, "node_modules")
			for index := 0; index < testCase.entries; index++ {
				name := fmt.Sprintf("package-%02d", index)
				writeFile(t, filepath.Join(root, name, "package.json"), fmt.Sprintf(`{"name":%q,"version":"1.0.0"}`, name))
			}
			assets, err := parseNPMWithEntryLimit(context.Background(), testutil.Environment(t, home), root+"\n", 2)
			if len(assets) != testCase.wantAssets || errors.Is(err, errParserLoss) != testCase.wantLoss {
				t.Fatalf("assets=%+v error=%v", assets, err)
			}
		})
	}
}

func TestNPMEntryBudgetIsSharedWithScopedPackages(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "node_modules")
	writeFile(t, filepath.Join(root, "direct", "package.json"), `{"name":"direct","version":"1.0.0"}`)
	writeFile(t, filepath.Join(root, "@scope", "first", "package.json"), `{"name":"@scope/first","version":"1.0.0"}`)
	writeFile(t, filepath.Join(root, "@scope", "second", "package.json"), `{"name":"@scope/second","version":"1.0.0"}`)

	assets, err := parseNPMWithEntryLimit(context.Background(), testutil.Environment(t, home), root+"\n", 3)
	if len(assets) != 2 || !errors.Is(err, errParserLoss) {
		t.Fatalf("assets=%+v error=%v", assets, err)
	}
	testutil.AssertAsset(t, assets, "pkg:npm/direct@1.0.0")
}

func TestGoEntryBudgetIsSharedAcrossGOPATHDirectories(t *testing.T) {
	home := t.TempDir()
	first, second := filepath.Join(home, "go-one"), filepath.Join(home, "go-two")
	writeFile(t, filepath.Join(first, "bin", "first-tool"), "binary")
	writeFile(t, filepath.Join(second, "bin", "second-tool"), "binary")
	writeFile(t, filepath.Join(second, "bin", "third-tool"), "binary")
	assets, err := parseGoPathWithEntryLimit(context.Background(), testutil.Environment(t, home), strings.Join([]string{first, second}, string(os.PathListSeparator)), 2)
	if len(assets) != 2 || !errors.Is(err, errParserLoss) {
		t.Fatalf("assets=%+v error=%v", assets, err)
	}
}

func TestNPMManifestBoundAcceptsExactLimitRejectsPlusOneAndPreservesSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "node_modules")
	exact := paddedNPMManifest(t, "exact", maxPackageManifestBytes)
	oversized := paddedNPMManifest(t, "oversized", maxPackageManifestBytes+1)
	writeFile(t, filepath.Join(root, "exact", "package.json"), exact)
	writeFile(t, filepath.Join(root, "oversized", "package.json"), oversized)
	assets, err := parseNPM(context.Background(), testutil.Environment(t, home), root+"\n")
	if !errors.Is(err, errParserLoss) {
		t.Fatalf("error=%v", err)
	}
	testutil.AssertAsset(t, assets, "pkg:npm/exact@1.0.0")
	for _, asset := range assets {
		if asset.ID == "pkg:npm/oversized@1.0.0" {
			t.Fatalf("oversized manifest accepted: %+v", asset)
		}
	}
}

func TestNPMSymlinkManifestIsRejectedWithoutReadingOutsideAndValidSiblingSurvives(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "node_modules")
	writeFile(t, filepath.Join(root, "valid", "package.json"), `{"name":"valid","version":"1.0.0"}`)
	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, outside, `{"name":"outside-marker","version":"9.9.9"}`)
	linkedManifest := filepath.Join(root, "linked", "package.json")
	if err := os.MkdirAll(filepath.Dir(linkedManifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, linkedManifest); err != nil {
		t.Fatal(err)
	}
	assets, err := parseNPM(context.Background(), testutil.Environment(t, home), root+"\n")
	if !errors.Is(err, errParserLoss) {
		t.Fatalf("error=%v", err)
	}
	testutil.AssertAsset(t, assets, "pkg:npm/valid@1.0.0")
	for _, asset := range assets {
		if strings.Contains(asset.ID, "outside-marker") {
			t.Fatalf("outside manifest followed: %+v", asset)
		}
	}
}

func TestNPMManifestReplacementBetweenLstatAndOpenIsRejectedAndValidSiblingSurvives(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "node_modules")
	replacedDir := filepath.Join(root, "replaced")
	writeFile(t, filepath.Join(root, "valid", "package.json"), `{"name":"valid","version":"1.0.0"}`)
	writeFile(t, filepath.Join(replacedDir, "package.json"), `{"name":"original","version":"1.0.0"}`)
	replacement := filepath.Join(home, "replacement.json")
	writeFile(t, replacement, `{"name":"replacement-marker","version":"9.9.9"}`)
	env := testutil.Environment(t, home)
	env.FS = &replacingRootedFS{OSFileSystem: platform.OSFileSystem{}, packageDir: replacedDir, replacement: replacement}

	assets, err := parseNPM(context.Background(), env, root+"\n")
	if !errors.Is(err, errParserLoss) {
		t.Fatalf("error=%v", err)
	}
	testutil.AssertAsset(t, assets, "pkg:npm/valid@1.0.0")
	for _, asset := range assets {
		if strings.Contains(asset.ID, "original") || strings.Contains(asset.ID, "replacement-marker") {
			t.Fatalf("replaced manifest accepted: %+v", asset)
		}
	}
}

func paddedNPMManifest(t *testing.T, name string, size int) string {
	t.Helper()
	prefix := fmt.Sprintf(`{"name":%q,"version":"1.0.0","padding":"`, name)
	suffix := `"}`
	if size < len(prefix)+len(suffix) {
		t.Fatalf("manifest size %d is too small", size)
	}
	return prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
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

func successfulRunner(t *testing.T) *testutil.FakeRunner {
	t.Helper()
	missingRoot := filepath.Join(t.TempDir(), "missing-package-root")
	return &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		commandKey("npm", "root", "-g"):                             {Stdout: missingRoot + "\n"},
		commandKey("python3", "-m", "pip", "list", "--format=json"): {Stdout: `[{"name":"fixture","version":"1.0.0"}]`},
		commandKey("pipx", "list", "--json"):                        {Stdout: `{"venvs":{"fixture":{"metadata":{"main_package":{"package":"fixture","package_version":"1.0.0"}}}}}`},
		commandKey("go", "env", "GOPATH"):                           {Stdout: missingRoot + "\n"},
	}}
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

func optInEnvironment(t *testing.T, home string, runner *testutil.FakeRunner) collector.Environment {
	t.Helper()
	env := testutil.Environment(t, home)
	env.Scope.ExternalProbes = true
	inspector := &fakeInspector{
		evidence: make(map[string]platform.ExecutableEvidence),
		errors:   make(map[string]error),
	}
	for _, probe := range probes() {
		key := commandKey(probe.command, probe.args...)
		if executableMissing(runner.Errors[key]) {
			inspector.errors[probe.command] = exec.ErrNotFound
			continue
		}
		digest := sha256.Sum256([]byte(probe.command))
		inspector.evidence[probe.command] = platform.ExecutableEvidence{
			Command: probe.command, Path: filepath.Join("/fake-bin", probe.command),
			LocationRef: "$HOME/.fake-bin/" + probe.command, SHA256: fmt.Sprintf("%x", digest), Mode: 0o755,
		}
	}
	env.Inspector = inspector
	env.Runner = basenameRunner{delegate: runner}
	return env
}

type basenameRunner struct{ delegate *testutil.FakeRunner }

func (r basenameRunner) Run(ctx context.Context, command string, args ...string) (platform.CommandResult, error) {
	return r.delegate.Run(ctx, filepath.Base(command), args...)
}

type faultFS struct {
	platform.FileSystem
	readDirErrors  map[string]error
	readFileErrors map[string]error
}

func (f faultFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	if err := f.readDirErrors[name]; err != nil {
		return nil, err
	}
	rootedFS, ok := f.FileSystem.(platform.RootedFileSystem)
	if !ok {
		return nil, errors.New("test filesystem does not support rooted access")
	}
	root, err := rootedFS.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &faultRootedDirectory{RootedDirectory: root, path: name, fs: f}, nil
}

type faultRootedDirectory struct {
	platform.RootedDirectory
	path string
	fs   faultFS
}

func (r *faultRootedDirectory) OpenRoot(name string) (platform.RootedDirectory, error) {
	childPath := filepath.Join(r.path, name)
	if err := r.fs.readDirErrors[childPath]; err != nil {
		return nil, err
	}
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &faultRootedDirectory{RootedDirectory: child, path: childPath, fs: r.fs}, nil
}

func (r *faultRootedDirectory) Open(name string) (platform.RootedFile, error) {
	if name == "." {
		if err := r.fs.readDirErrors[r.path]; err != nil {
			return nil, err
		}
	} else if err := r.fs.readFileErrors[filepath.Join(r.path, name)]; err != nil {
		return nil, err
	}
	return r.RootedDirectory.Open(name)
}

type replacingRootedFS struct {
	platform.OSFileSystem
	packageDir  string
	replacement string
	once        sync.Once
	replaceErr  error
}

func (f *replacingRootedFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &replacingRootedDirectory{RootedDirectory: root, path: name, fs: f}, nil
}

type replacingRootedDirectory struct {
	platform.RootedDirectory
	path string
	fs   *replacingRootedFS
}

func (r *replacingRootedDirectory) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &replacingRootedDirectory{RootedDirectory: child, path: filepath.Join(r.path, name), fs: r.fs}, nil
}

func (r *replacingRootedDirectory) Open(name string) (platform.RootedFile, error) {
	if r.path == r.fs.packageDir && name == "package.json" {
		r.fs.once.Do(func() {
			r.fs.replaceErr = os.Rename(r.fs.replacement, filepath.Join(r.path, name))
		})
		if r.fs.replaceErr != nil {
			return nil, r.fs.replaceErr
		}
	}
	return r.RootedDirectory.Open(name)
}

type fakeInspector struct {
	failOnCall bool
	evidence   map[string]platform.ExecutableEvidence
	errors     map[string]error
	verifyErr  map[string]error
	events     *[]string
}

func (f *fakeInspector) Inspect(_ context.Context, _ string, command string) (platform.ExecutableEvidence, error) {
	if f.failOnCall {
		panic("executable inspector called")
	}
	if f.events != nil {
		*f.events = append(*f.events, "inspect:"+command)
	}
	return f.evidence[command], f.errors[command]
}

func (f *fakeInspector) Verify(evidence platform.ExecutableEvidence) error {
	if f.events != nil {
		*f.events = append(*f.events, "verify:"+evidence.Command)
	}
	return f.verifyErr[evidence.Command]
}

type failRunner struct{}

func (failRunner) Run(context.Context, string, ...string) (platform.CommandResult, error) {
	panic("runner called")
}

type recordingRunner struct {
	events  *[]string
	results map[string]platform.CommandResult
	errors  map[string]error
}

func (r *recordingRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult, error) {
	key := commandKey(command, args...)
	if r.events != nil {
		*r.events = append(*r.events, "run:"+key)
	}
	return r.results[key], r.errors[key]
}

func missingInspectorErrors(except ...string) map[string]error {
	allowed := make(map[string]struct{}, len(except))
	for _, command := range except {
		allowed[command] = struct{}{}
	}
	errorsByCommand := make(map[string]error)
	for _, capability := range Capabilities() {
		if _, ok := allowed[capability.Executable]; !ok {
			errorsByCommand[capability.Executable] = exec.ErrNotFound
		}
	}
	return errorsByCommand
}

func assertPackageTarget(t *testing.T, result model.CollectorResult, targetID string, status model.TargetStatus, assets, observations int) {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID == targetID {
			if target.Status != status || target.Assets != assets || target.Observations != observations {
				t.Fatalf("target=%+v", target)
			}
			return
		}
	}
	t.Fatalf("missing target %q", targetID)
}

func hasPackageError(result model.CollectorResult, code string) bool {
	for _, issue := range result.Errors {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func containsEventSequence(events, sequence []string) bool {
	for index := 0; index+len(sequence) <= len(events); index++ {
		if reflect.DeepEqual(events[index:index+len(sequence)], sequence) {
			return true
		}
	}
	return false
}

func assertPackageCountsMatchEmitted(t *testing.T, result model.CollectorResult) {
	t.Helper()
	for _, target := range result.Targets {
		observations := 0
		for _, observation := range result.Observations {
			if observation.Source == target.TargetID {
				observations++
			}
		}
		if target.Assets != observations || target.Observations != observations {
			t.Fatalf("target counts do not match emitted evidence: target=%+v observations=%+v", target, result.Observations)
		}
	}
}

func (f faultFS) ReadDir(path string) ([]os.DirEntry, error) {
	if err := f.readDirErrors[path]; err != nil {
		return nil, err
	}
	return f.FileSystem.ReadDir(path)
}

func (f faultFS) ReadFile(path string) ([]byte, error) {
	if err := f.readFileErrors[path]; err != nil {
		return nil, err
	}
	return f.FileSystem.ReadFile(path)
}
