# SSC Init Foundation and Baseline Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained macOS `ssc-init` CLI that discovers the current user's developer supply-chain assets, records a baseline in SQLite, reports explicit coverage, and emits a stable JSON result.

**Architecture:** A pure-Go command delegates to focused collectors through a small interface, normalizes their assets into a deterministic inventory graph, and stores immutable scan snapshots in an embedded SQLite database. All operating-system access is injected behind filesystem and command-runner interfaces so fixtures test discovery without reading the developer's real laptop.

**Tech Stack:** Go 1.26.5, Go standard library, `modernc.org/sqlite` v1.56.0, SQLite 3, JSON Schema fixtures, macOS arm64/amd64 cross-builds.

## Global Constraints

- Product and CLI name: `SSC Init` and `ssc-init`.
- Module path: `github.com/s1ns3nz0/ssc-init`.
- macOS is the only supported runtime in this plan; both `darwin/arm64` and `darwin/amd64` must compile.
- Build with `CGO_ENABLED=0`; no user-installed Python, Node.js, Homebrew, Docker, YARA, database, or compiler is required at runtime.
- Run under the current user's permissions; never request `sudo` or scan arbitrary personal files.
- Discovery is read-only; a failed collector yields Partial coverage instead of failing or claiming a complete scan.
- Do not store source contents, environment-variable values, tokens, credentials, or raw secret matches.
- Replace the home path with `$HOME` in persisted and rendered paths.
- JSON output uses schema version `ssc-init.scan.v1`.
- Tests use inert fixtures and temporary directories; tests must never inspect the host user's real configuration.
- Required checks before each commit: `go test ./...`, `go vet ./...`, and `git diff --check`.

This plan deliberately stops at a working baseline inventory slice. Content analyzers and TI, organization policy and enforcement, host plugins, and scheduling/signing distribution are separate implementation slices because each has an independent security boundary and release gate. Their implementations consume the `ssc-init.scan.v1` result and canonical asset IDs established here.

---

## File map

- `go.mod`, `go.sum`: pinned Go module and pure-Go SQLite dependency.
- `cmd/ssc-init/main.go`: process entry point only.
- `internal/cli/run.go`: subcommand parsing, streams, exit codes, and dependency assembly.
- `internal/model/asset.go`: canonical asset and relationship types.
- `internal/model/scan.go`: scan, coverage, error, and delta types.
- `internal/platform/fs.go`: injected read-only filesystem contract and operating-system implementation.
- `internal/platform/runner.go`: injected command runner with timeout and output limits.
- `internal/platform/paths.go`: macOS data paths and `$HOME` redaction.
- `internal/collector/collector.go`: collector contract and environment.
- `internal/collector/orchestrator.go`: bounded concurrent collection and failure containment.
- `internal/testutil/fixture.go`: synthetic-home and fake-runner test support shared by collector tests.
- `internal/testutil/assert.go`: canonical asset assertions shared by collector tests.
- `internal/collector/agents/collector.go`: Claude, Codex, Cursor, and Windsurf plugin/skill discovery.
- `internal/collector/mcp/collector.go`: MCP configuration and command/endpoint inventory.
- `internal/collector/ide/collector.go`: VS Code-family and JetBrains extension inventory.
- `internal/collector/packages/collector.go`: global developer package and tool inventory.
- `internal/collector/projects/collector.go`: bounded project-root and lockfile discovery.
- `internal/inventory/graph.go`: deterministic deduplication and relationships.
- `internal/inventory/hash.go`: bounded SHA-256 artifact hashing.
- `internal/store/sqlite.go`: connection setup and transaction boundary.
- `internal/store/migrations.go`: embedded schema migrations.
- `internal/store/snapshots.go`: scan persistence and retrieval.
- `internal/report/json.go`: stable JSON report encoder.
- `internal/scan/service.go`: collection, normalization, persistence, and delta orchestration.
- `internal/doctor/doctor.go`: runtime and coverage diagnostics.
- `testdata/home/`: synthetic home directory fixtures.
- `testdata/golden/`: stable expected JSON outputs.
- `scripts/build-darwin.sh`: reproducible static cross-build and checksum generation.

---

### Task 1: Bootstrap the CLI and stable domain contracts

**Files:**
- Create: `go.mod`
- Create: `cmd/ssc-init/main.go`
- Create: `internal/cli/run.go`
- Create: `internal/cli/run_test.go`
- Create: `internal/model/asset.go`
- Create: `internal/model/scan.go`

**Interfaces:**
- Produces: `cli.Run(ctx context.Context, args []string, stdout, stderr io.Writer) int` and `cli.App.Run(ctx context.Context, args []string, stdout, stderr io.Writer) int`.
- Produces: `model.Asset`, `model.Relationship`, `model.CollectorResult`, `model.ScanResult`, and their enum constants.

- [ ] **Step 1: Write the failing CLI contract test**

```go
func TestRunVersion(t *testing.T) {
    var out, errOut bytes.Buffer
    code := Run(context.Background(), []string{"version", "--json"}, &out, &errOut)
    if code != 0 { t.Fatalf("code=%d stderr=%s", code, errOut.String()) }
    var got map[string]string
    if err := json.Unmarshal(out.Bytes(), &got); err != nil { t.Fatal(err) }
    if got["product"] != "SSC Init" || got["command"] != "ssc-init" { t.Fatalf("got=%v", got) }
}

func TestRunUnknownCommand(t *testing.T) {
    var out, errOut bytes.Buffer
    if code := Run(context.Background(), []string{"wat"}, &out, &errOut); code != 2 { t.Fatalf("code=%d", code) }
    if !strings.Contains(errOut.String(), "unknown command: wat") { t.Fatalf("stderr=%q", errOut.String()) }
}
```

- [ ] **Step 2: Run the focused tests and verify the red state**

Run: `go test ./internal/cli -run 'TestRunVersion|TestRunUnknownCommand' -v`  
Expected: FAIL because `Run` is undefined.

- [ ] **Step 3: Add the module, model types, and minimal command implementation**

```go
module github.com/s1ns3nz0/ssc-init

go 1.26
```

```go
// internal/model/asset.go
type AssetType string
const (
    AssetAgentPlugin AssetType = "agent-plugin"
    AssetSkill       AssetType = "agent-skill"
    AssetMCP         AssetType = "mcp-server"
    AssetIDEExtension AssetType = "ide-extension"
    AssetPackage     AssetType = "package"
    AssetProject     AssetType = "project"
    AssetTool        AssetType = "tool"
)
type Asset struct {
    ID string `json:"id"`
    Type AssetType `json:"type"`
    Name string `json:"name"`
    Version string `json:"version,omitempty"`
    Path string `json:"path,omitempty"`
    Source string `json:"source,omitempty"`
    SHA256 string `json:"sha256,omitempty"`
    Metadata map[string]string `json:"metadata,omitempty"`
}
type Relationship struct { From string `json:"from"`; To string `json:"to"`; Kind string `json:"kind"` }
```

```go
// internal/model/scan.go
type CoverageStatus string
const (
    CoverageComplete CoverageStatus = "complete"
    CoveragePartial CoverageStatus = "partial"
    CoverageSkipped CoverageStatus = "skipped"
    CoverageUnavailable CoverageStatus = "unavailable"
    CoverageFailed CoverageStatus = "failed"
)
type CoverageError struct { Code string `json:"code"`; Message string `json:"message"`; Path string `json:"path,omitempty"` }
type CollectorResult struct { Collector string `json:"collector"`; Status CoverageStatus `json:"status"`; Assets []Asset `json:"assets,omitempty"`; Relationships []Relationship `json:"relationships,omitempty"`; Errors []CoverageError `json:"errors,omitempty"` }
type ScanResult struct { SchemaVersion string `json:"schemaVersion"`; ScanID string `json:"scanId"`; Status string `json:"status"`; StartedAt time.Time `json:"startedAt"`; FinishedAt time.Time `json:"finishedAt"`; Coverage []CollectorResult `json:"coverage"` }
```

```go
// internal/cli/run.go
type App struct { Version string }
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
    return (App{Version:"dev"}).Run(ctx,args,stdout,stderr)
}
func (a App) Run(_ context.Context, args []string, stdout, stderr io.Writer) int {
    if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
        _ = json.NewEncoder(stdout).Encode(map[string]string{"product":"SSC Init", "command":"ssc-init", "version":a.Version})
        return 0
    }
    command := ""
    if len(args) > 0 { command = args[0] }
    fmt.Fprintf(stderr, "unknown command: %s\n", command)
    return 2
}
```

```go
// cmd/ssc-init/main.go
func main() {
    os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
```

- [ ] **Step 4: Run formatting and verification**

Run: `go fmt ./... && go test ./... && go vet ./... && git diff --check`  
Expected: all commands exit 0.

- [ ] **Step 5: Commit the bootstrap**

```bash
git add go.mod cmd/ssc-init internal/cli internal/model
git commit -m "feat: bootstrap ssc-init CLI contracts"
```

### Task 2: Isolate filesystem, command, and macOS path access

**Files:**
- Create: `internal/platform/fs.go`
- Create: `internal/platform/runner.go`
- Create: `internal/platform/runner_test.go`
- Create: `internal/platform/paths.go`
- Create: `internal/platform/paths_test.go`

**Interfaces:**
- Produces: `platform.FileSystem` with `ReadFile`, `ReadDir`, `Stat`, and `WalkDir`.
- Produces: `platform.Runner.Run(ctx, command, args...) (platform.CommandResult, error)`.
- Produces: `platform.PathsForHome(home string) platform.Paths` and `platform.RedactHome(home, value string) string`.

- [ ] **Step 1: Write failing path-redaction and bounded-runner tests**

```go
func TestRedactHomeOnlyOnPathBoundary(t *testing.T) {
    home := "/Users/alice"
    if got := RedactHome(home, "/Users/alice/.claude/settings.json"); got != "$HOME/.claude/settings.json" { t.Fatal(got) }
    if got := RedactHome(home, "/Users/alice2/file"); got != "/Users/alice2/file" { t.Fatal(got) }
}

func TestExecRunnerLimitsOutput(t *testing.T) {
    r := ExecRunner{Timeout: time.Second, MaxOutputBytes: 4}
    got, err := r.Run(context.Background(), "/bin/echo", "123456")
    if err != nil { t.Fatal(err) }
    if got.Stdout != "1234" || !got.Truncated { t.Fatalf("got=%+v", got) }
}
```

- [ ] **Step 2: Verify the tests fail**

Run: `go test ./internal/platform -v`  
Expected: FAIL because `RedactHome` and `ExecRunner` are undefined.

- [ ] **Step 3: Implement OS adapters with no shell interpolation**

```go
type FileSystem interface {
    ReadFile(name string) ([]byte, error)
    ReadDir(name string) ([]os.DirEntry, error)
    Stat(name string) (os.FileInfo, error)
    WalkDir(root string, fn fs.WalkDirFunc) error
}
type OSFileSystem struct{}
func (OSFileSystem) ReadFile(name string) ([]byte,error) { return os.ReadFile(name) }
func (OSFileSystem) ReadDir(name string) ([]os.DirEntry,error) { return os.ReadDir(name) }
func (OSFileSystem) Stat(name string) (os.FileInfo,error) { return os.Stat(name) }
func (OSFileSystem) WalkDir(root string, fn fs.WalkDirFunc) error { return filepath.WalkDir(root, fn) }
```

```go
type CommandResult struct { Stdout, Stderr string; ExitCode int; Truncated bool }
type Runner interface { Run(context.Context, string, ...string) (CommandResult, error) }
type ExecRunner struct { Timeout time.Duration; MaxOutputBytes int }
```

`ExecRunner` must call `exec.CommandContext(command, args...)` directly, never `sh -c`; copy at most `MaxOutputBytes` from each stream and return timeout as a typed error.

- [ ] **Step 4: Verify the adapter boundary**

Run: `go fmt ./... && go test ./internal/platform -race && go vet ./... && git diff --check`  
Expected: PASS, including the boundary-redaction and truncation assertions.

- [ ] **Step 5: Commit the platform layer**

```bash
git add internal/platform
git commit -m "feat: add bounded macOS platform adapters"
```

### Task 3: Add the collector contract and partial-coverage orchestrator

**Files:**
- Create: `internal/collector/collector.go`
- Create: `internal/collector/orchestrator.go`
- Create: `internal/collector/orchestrator_test.go`
- Create: `internal/testutil/fixture.go`
- Create: `internal/testutil/assert.go`

**Interfaces:**
- Consumes: `model.CollectorResult`, `platform.FileSystem`, and `platform.Runner`.
- Produces: `collector.Collector`, `collector.Environment`, and `collector.Orchestrator.Collect(ctx, env) []model.CollectorResult`.

- [ ] **Step 1: Write the failing failure-containment test**

```go
type fakeCollector struct { name string; result model.CollectorResult; err error }
func (f fakeCollector) Name() string { return f.name }
func (f fakeCollector) Collect(context.Context, Environment) (model.CollectorResult, error) { return f.result, f.err }

func TestOrchestratorContainsCollectorFailure(t *testing.T) {
    o := Orchestrator{Timeout: 50*time.Millisecond, MaxConcurrent: 2, Collectors: []Collector{
        fakeCollector{name:"ok", result:model.CollectorResult{Collector:"ok", Status:model.CoverageComplete}},
        fakeCollector{name:"bad", err:errors.New("denied")},
    }}
    got := o.Collect(context.Background(), Environment{})
    if len(got) != 2 || got[0].Collector != "bad" || got[0].Status != model.CoverageFailed { t.Fatalf("got=%+v", got) }
    if got[1].Collector != "ok" || got[1].Status != model.CoverageComplete { t.Fatalf("got=%+v", got) }
}
```

- [ ] **Step 2: Verify the orchestrator test fails**

Run: `go test ./internal/collector -run TestOrchestratorContainsCollectorFailure -v`  
Expected: FAIL because the collector interfaces do not exist.

- [ ] **Step 3: Implement bounded concurrency and deterministic result ordering**

```go
type Environment struct { Home string; FS platform.FileSystem; Runner platform.Runner; Now func() time.Time }
type Collector interface { Name() string; Collect(context.Context, Environment) (model.CollectorResult, error) }
type Orchestrator struct { Collectors []Collector; Timeout time.Duration; MaxConcurrent int }
```

Each collector runs with `context.WithTimeout`; convert returned errors, panics, and deadlines into its own coverage record; sort final results by `Collector`. Never cancel successful sibling collectors because one collector fails.

Add the shared fixture helpers in this task so every later collector test uses an explicit synthetic home:

```go
package testutil
func Environment(t *testing.T, relativeRoot string) collector.Environment {
    t.Helper()
    home, err := filepath.Abs(relativeRoot); if err != nil { t.Fatal(err) }
    return collector.Environment{Home:home, FS:platform.OSFileSystem{}, Runner:&FakeRunner{}, Now:func() time.Time { return time.Unix(1_700_000_000,0).UTC() }}
}
type FakeRunner struct { Results map[string]platform.CommandResult; Errors map[string]error; Calls []string }
func (r *FakeRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult,error) {
    key := strings.Join(append([]string{command},args...), "\x1f"); r.Calls = append(r.Calls,key)
    return r.Results[key], r.Errors[key]
}
func AssertAsset(t *testing.T, assets []model.Asset, id string) model.Asset {
    t.Helper(); for _, asset := range assets { if asset.ID == id { return asset } }; t.Fatalf("asset %s not found",id); return model.Asset{}
}
```

- [ ] **Step 4: Run race and package tests**

Run: `go fmt ./... && go test -race ./internal/collector && go vet ./... && git diff --check`  
Expected: PASS with deterministic ordering under `-race`.

- [ ] **Step 5: Commit the orchestrator**

```bash
git add internal/collector internal/testutil
git commit -m "feat: isolate collector failures"
```

### Task 4: Discover AI host assets and MCP configurations

**Files:**
- Create: `internal/collector/agents/collector.go`
- Create: `internal/collector/agents/collector_test.go`
- Create: `internal/collector/mcp/collector.go`
- Create: `internal/collector/mcp/collector_test.go`
- Create: `internal/collector/mcp/parser.go`
- Create: `testdata/home/.claude/settings.json`
- Create: `testdata/home/.codex/plugins/example/.codex-plugin/plugin.json`
- Create: `testdata/home/.cursor/mcp.json`

**Interfaces:**
- Consumes: `collector.Environment` and `model.Asset`.
- Produces: `agents.New() collector.Collector` and `mcp.New() collector.Collector`.
- Produces canonical MCP IDs as `mcp:<host>:<name>` without persisting environment values.

- [ ] **Step 1: Write failing fixture-based discovery tests**

```go
func TestMCPCollectorRedactsEnvironmentValues(t *testing.T) {
    env := testutil.Environment(t, "../../../testdata/home")
    got, err := mcp.New().Collect(context.Background(), env)
    if err != nil { t.Fatal(err) }
    asset := testutil.AssertAsset(t, got.Assets, "mcp:cursor:filesystem")
    if asset.Metadata["env_keys"] != "GITHUB_TOKEN" { t.Fatalf("metadata=%v", asset.Metadata) }
    encoded, _ := json.Marshal(asset)
    if bytes.Contains(encoded, []byte("fixture-secret")) { t.Fatal("secret persisted") }
}

func TestAgentCollectorFindsCodexPlugin(t *testing.T) {
    env := testutil.Environment(t, "../../../testdata/home")
    got, err := agents.New().Collect(context.Background(), env)
    if err != nil { t.Fatal(err) }
    testutil.AssertAsset(t, got.Assets, "agent-plugin:codex:example")
}
```

- [ ] **Step 2: Verify both collector tests fail**

Run: `go test ./internal/collector/agents ./internal/collector/mcp -v`  
Expected: FAIL because both collectors are undefined.

- [ ] **Step 3: Implement explicit path catalogs and safe JSON parsing**

The agent collector inspects only these roots in this plan: `.claude/plugins`, `.claude/skills`, `.codex/plugins`, `.codex/skills`, `.cursor/plugins`, `.cursor/skills`, and `.windsurf`. The MCP collector reads `.claude.json`, `.claude/settings.json`, `.cursor/mcp.json`, `.windsurf/mcp.json`, and the project `.vscode/mcp.json` paths emitted by `projects.New` in Task 6.

```go
type serverConfig struct { Command string `json:"command"`; Args []string `json:"args"`; URL string `json:"url"`; Env map[string]string `json:"env"` }
func sanitizeServer(host, name string, cfg serverConfig) model.Asset {
    keys := make([]string,0,len(cfg.Env)); for key := range cfg.Env { keys = append(keys,key) }; sort.Strings(keys)
    return model.Asset{ID:"mcp:"+host+":"+name, Type:model.AssetMCP, Name:name,
        Metadata:map[string]string{"command":cfg.Command,"args":strings.Join(cfg.Args,"\x1f"),"url":cfg.URL,"env_keys":strings.Join(keys,",")}}
}
```

Reject files larger than 4 MiB, reject duplicate JSON object keys in the MCP parser, and record malformed files as Partial coverage with a redacted path.

- [ ] **Step 4: Verify discovery and secret redaction**

Run: `go fmt ./... && go test ./internal/collector/agents ./internal/collector/mcp -race && git diff --check`  
Expected: PASS; `rg -n 'fixture-secret' testdata` finds the fixture only, while JSON outputs in tests contain no value.

- [ ] **Step 5: Commit AI and MCP discovery**

```bash
git add internal/collector/agents internal/collector/mcp testdata/home/.claude testdata/home/.codex testdata/home/.cursor
git commit -m "feat: inventory agent and MCP assets"
```

### Task 5: Discover IDE extensions without executing the IDE

**Files:**
- Create: `internal/collector/ide/collector.go`
- Create: `internal/collector/ide/manifest.go`
- Create: `internal/collector/ide/collector_test.go`
- Create: `testdata/home/.vscode/extensions/acme.safe-1.2.3/package.json`
- Create: `testdata/home/Library/Application Support/JetBrains/Idea/plugins/sample/META-INF/plugin.xml`

**Interfaces:**
- Produces: `ide.New() collector.Collector`.
- Produces IDs `ide-extension:<host>:<publisher>.<name>@<version>` and metadata for publisher, entry point, activation events, and declared capabilities.

- [ ] **Step 1: Write failing VS Code and JetBrains fixture tests**

```go
func TestCollectorFindsVSCodeAndJetBrainsExtensions(t *testing.T) {
    got, err := ide.New().Collect(context.Background(), testutil.Environment(t, "../../../testdata/home"))
    if err != nil { t.Fatal(err) }
    testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.safe@1.2.3")
    testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.sample@1.0.0")
}
```

- [ ] **Step 2: Verify the test fails**

Run: `go test ./internal/collector/ide -v`  
Expected: FAIL because `ide.New` is undefined.

- [ ] **Step 3: Implement read-only manifest parsing**

Scan direct child directories of `.vscode/extensions`, `.vscode-insiders/extensions`, `.cursor/extensions`, `.windsurf/extensions`, and `.vscode-oss/extensions`. Read `package.json` without loading JavaScript. For JetBrains, walk only `Library/Application Support/JetBrains/*/plugins/*/META-INF/plugin.xml`, with a depth and file-count cap of 10,000 entries.

```go
type vscodeManifest struct { Name, Publisher, Version, Main, Browser string; ActivationEvents []string `json:"activationEvents"` }
type jetBrainsManifest struct { ID string `xml:"id"`; Name string `xml:"name"`; Version string `xml:"version"` }
```

Malformed manifests create Partial coverage and do not suppress valid sibling extensions.

- [ ] **Step 4: Run collector and full model tests**

Run: `go fmt ./... && go test -race ./internal/collector/ide ./internal/model && go vet ./... && git diff --check`  
Expected: PASS without launching `code`, `cursor`, or any JetBrains executable.

- [ ] **Step 5: Commit IDE discovery**

```bash
git add internal/collector/ide testdata/home/.vscode testdata/home/Library
git commit -m "feat: inventory IDE extensions"
```

### Task 6: Discover packages, tools, projects, manifests, and lockfiles

**Files:**
- Create: `internal/collector/packages/collector.go`
- Create: `internal/collector/packages/collector_test.go`
- Create: `internal/collector/projects/collector.go`
- Create: `internal/collector/projects/collector_test.go`
- Create: `internal/collector/projects/excludes.go`
- Create: `testdata/home/Projects/sample/package.json`
- Create: `testdata/home/Projects/sample/package-lock.json`
- Create: `testdata/home/Projects/sample/.git/config`

**Interfaces:**
- Produces: `packages.New() collector.Collector` and `projects.New(roots []string) collector.Collector`.
- Produces package IDs in Package URL form when possible and project IDs as `project:sha256(<redacted canonical path>)`.

- [ ] **Step 1: Write failing bounded-discovery tests**

```go
func TestProjectsCollectorFindsLockfileAndSkipsNodeModules(t *testing.T) {
    env := testutil.Environment(t, "../../../testdata/home")
    got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), env)
    if err != nil { t.Fatal(err) }
    manifest := testutil.AssertAsset(t, got.Assets, "project-file:manifest:$HOME/Projects/sample/package.json")
    lockfile := testutil.AssertAsset(t, got.Assets, "project-file:lockfile:$HOME/Projects/sample/package-lock.json")
    if manifest.Path != "$HOME/Projects/sample/package.json" || lockfile.Path != "$HOME/Projects/sample/package-lock.json" { t.Fatalf("manifest=%+v lockfile=%+v",manifest,lockfile) }
    for _, a := range got.Assets { if strings.Contains(a.Path, "node_modules") { t.Fatalf("unexpected=%s", a.Path) } }
}
```

- [ ] **Step 2: Verify package and project tests fail**

Run: `go test ./internal/collector/packages ./internal/collector/projects -v`  
Expected: FAIL because the constructors are undefined.

- [ ] **Step 3: Implement bounded roots and command capability probes**

Project roots are the supplied roots only. Exclude `.git/objects`, `node_modules`, `.venv`, `venv`, `vendor`, `dist`, `build`, `Library`, `.cache`, and hidden package-manager caches. Cap discovery at 100,000 entries and depth 12 per root. Recognize `package.json`, npm/pnpm/yarn/bun lockfiles, `pyproject.toml`, `requirements*.txt`, `uv.lock`, `Cargo.toml`, `Cargo.lock`, `go.mod`, and `go.sum`.

The package collector probes commands with fixed arguments only: `npm root -g`, `python3 -m pip list --format=json`, `pipx list --json`, `uv tool list`, `cargo install --list`, `go env GOPATH`, `brew list --versions`, and `docker image ls --format {{json .}}`. A missing executable yields Skipped for that ecosystem; a stopped Docker daemon yields Unavailable.

- [ ] **Step 4: Verify caps, exclusions, and missing-tool behavior**

Run: `go fmt ./... && go test -race ./internal/collector/packages ./internal/collector/projects && git diff --check`  
Expected: PASS; fake runner assertions confirm no `sh -c` call and no command outside the fixed catalog.

- [ ] **Step 5: Commit developer package and project discovery**

```bash
git add internal/collector/packages internal/collector/projects testdata/home/Projects
git commit -m "feat: inventory developer packages and projects"
```

### Task 7: Normalize assets, relationships, hashes, and deltas

**Files:**
- Create: `internal/inventory/graph.go`
- Create: `internal/inventory/graph_test.go`
- Create: `internal/inventory/hash.go`
- Create: `internal/inventory/hash_test.go`
- Modify: `internal/model/asset.go`
- Modify: `internal/model/scan.go`

**Interfaces:**
- Consumes: all `model.CollectorResult` values.
- Produces: `inventory.Build(results []model.CollectorResult) model.Inventory`.
- Produces: `inventory.Diff(previous, current model.Inventory) model.Delta`.
- Produces: `inventory.HashFile(ctx, fs, path, maxBytes) (digest string, status model.HashStatus, err error)`.

- [ ] **Step 1: Write failing deterministic graph and bounded-hash tests**

```go
func TestBuildDeduplicatesAndSorts(t *testing.T) {
    in := []model.CollectorResult{{Assets:[]model.Asset{{ID:"b",Name:"B"},{ID:"a",Name:"A"},{ID:"a",Name:"A"}}}}
    got := Build(in)
    if ids(got.Assets) != "a,b" { t.Fatalf("ids=%s", ids(got.Assets)) }
}

func TestHashFileReportsOversize(t *testing.T) {
    path := filepath.Join(t.TempDir(), "artifact")
    if err := os.WriteFile(path, []byte("abcdef"), 0o600); err != nil { t.Fatal(err) }
    _, status, err := HashFile(context.Background(), platform.OSFileSystem{}, path, 4)
    if err != nil || status != model.HashOversize { t.Fatalf("status=%s err=%v", status, err) }
}
```

- [ ] **Step 2: Verify inventory tests fail**

Run: `go test ./internal/inventory -v`  
Expected: FAIL because graph and hash functions are undefined.

- [ ] **Step 3: Implement deterministic normalization**

`Build` merges exact IDs, unions metadata only when values agree, records a `metadata-conflict` coverage error otherwise, sorts assets by ID and relationships by `(From,Kind,To)`, and removes dangling relationships. `Diff` classifies Added, Removed, and Changed by canonical JSON after excluding observation timestamps. `HashFile` reads at most `maxBytes+1`, returns Oversize instead of hashing partial content, and checks context cancellation.

```go
type Inventory struct { Assets []Asset `json:"assets"`; Relationships []Relationship `json:"relationships"` }
type ChangeKind string
const (ChangeAdded ChangeKind="added"; ChangeRemoved ChangeKind="removed"; ChangeChanged ChangeKind="changed")
type Change struct { Kind ChangeKind `json:"kind"`; AssetID string `json:"assetId"` }
type Delta struct { Changes []Change `json:"changes"` }
type HashStatus string
const (HashComplete HashStatus="complete"; HashOversize HashStatus="oversize"; HashUnavailable HashStatus="unavailable")
```

- [ ] **Step 4: Run determinism and race tests repeatedly**

Run: `go fmt ./... && go test -race -count=20 ./internal/inventory && go vet ./... && git diff --check`  
Expected: PASS on all 20 runs with byte-identical ordering.

- [ ] **Step 5: Commit inventory normalization**

```bash
git add internal/inventory internal/model
git commit -m "feat: normalize inventory snapshots"
```

### Task 8: Persist immutable snapshots in pure-Go SQLite

**Files:**
- Modify: `go.mod`
- Create: `internal/store/sqlite.go`
- Create: `internal/store/migrations.go`
- Create: `internal/store/snapshots.go`
- Create: `internal/store/snapshots_test.go`

**Interfaces:**
- Consumes: `model.ScanResult` and `model.Inventory`.
- Produces: `store.Open(path string) (*store.Store, error)`.
- Produces: `(*Store).SaveScan(ctx, scan, inventory) error`, `LatestInventory(ctx) (model.Inventory, bool, error)`, and `Close() error`.

- [ ] **Step 1: Write the failing transaction and secret-storage tests**

```go
func TestSaveAndLoadLatestInventory(t *testing.T) {
    s, err := Open(filepath.Join(t.TempDir(), "state.db")); if err != nil { t.Fatal(err) }; defer s.Close()
    want := model.Inventory{Assets:[]model.Asset{{ID:"mcp:cursor:fs",Type:model.AssetMCP,Metadata:map[string]string{"env_keys":"TOKEN"}}}}
    scan := model.ScanResult{SchemaVersion:"ssc-init.scan.v1",ScanID:"scan-1",Status:"complete",StartedAt:time.Unix(1,0).UTC(),FinishedAt:time.Unix(2,0).UTC()}
    if err := s.SaveScan(context.Background(), scan, want); err != nil { t.Fatal(err) }
    got, ok, err := s.LatestInventory(context.Background())
    if err != nil || !ok || !reflect.DeepEqual(got, want) { t.Fatalf("ok=%v got=%+v err=%v", ok,got,err) }
    info, err := os.Stat(s.Path()); if err != nil { t.Fatal(err) }
    if info.Mode().Perm() != 0o600 { t.Fatalf("mode=%o",info.Mode().Perm()) }
}
```

- [ ] **Step 2: Add the pinned driver and verify the test fails for missing store APIs**

Run: `go get modernc.org/sqlite@v1.56.0 && go test ./internal/store -v`  
Expected: FAIL because `Open` and snapshot methods are undefined; `go.mod` pins Go 1.26 and SQLite v1.56.0.

- [ ] **Step 3: Implement schema v1 and atomic scan writes**

```sql
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE scans(id TEXT PRIMARY KEY, schema_version TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL);
CREATE TABLE assets(scan_id TEXT NOT NULL, asset_id TEXT NOT NULL, asset_json BLOB NOT NULL, PRIMARY KEY(scan_id,asset_id), FOREIGN KEY(scan_id) REFERENCES scans(id));
CREATE TABLE relationships(scan_id TEXT NOT NULL, from_id TEXT NOT NULL, kind TEXT NOT NULL, to_id TEXT NOT NULL, PRIMARY KEY(scan_id,from_id,kind,to_id));
CREATE TABLE coverage(scan_id TEXT NOT NULL, collector TEXT NOT NULL, result_json BLOB NOT NULL, PRIMARY KEY(scan_id,collector));
```

Open with `PRAGMA foreign_keys=ON`, `journal_mode=WAL`, and `busy_timeout=5000`. Save the scan, assets, relationships, and coverage in one transaction; rollback on any error. Set database and parent directory permissions to `0600` and `0700` respectively.

- [ ] **Step 4: Verify SQLite, rollback, and CGO-free compilation**

Run: `go fmt ./... && go test -race ./internal/store && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go test ./internal/store && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go test ./internal/store && git diff --check`  
Expected: every command exits 0.

- [ ] **Step 5: Commit the store**

```bash
git add go.mod go.sum internal/store
git commit -m "feat: persist inventory snapshots"
```

### Task 9: Wire baseline scanning, JSON reporting, status, and doctor

**Files:**
- Create: `internal/scan/service.go`
- Create: `internal/scan/service_test.go`
- Create: `internal/report/json.go`
- Create: `internal/report/json_test.go`
- Create: `internal/doctor/doctor.go`
- Create: `internal/doctor/doctor_test.go`
- Modify: `internal/cli/run.go`
- Modify: `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`
- Create: `testdata/golden/baseline.json`

**Interfaces:**
- Consumes: collector orchestrator, inventory builder, store, and platform paths.
- Produces: `scan.NewService(orchestrator collector.Orchestrator, snapshots scan.SnapshotStore, now func() time.Time, newID func() string) *scan.Service`.
- Produces: `(*scan.Service).Baseline(ctx) (model.ScanResult, model.Inventory, model.Delta, error)`.
- Produces: `report.WriteJSON(w io.Writer, scan model.ScanResult, inventory model.Inventory, delta model.Delta) error`.
- Produces: commands `scan --baseline --json`, `status --json`, and `doctor --json`.

- [ ] **Step 1: Write failing end-to-end CLI tests with injected dependencies**

```go
func TestBaselineJSONReportsPartialCoverageAndPersists(t *testing.T) {
    snapshots := &memorySnapshots{}
    orchestrator := collector.Orchestrator{Timeout:time.Second,MaxConcurrent:2,Collectors:[]collector.Collector{
        fakeCollector{name:"agents",result:model.CollectorResult{Collector:"agents",Status:model.CoverageComplete}},
        fakeCollector{name:"docker",err:errors.New("daemon unavailable")},
    }}
    scanner := scan.NewService(orchestrator,snapshots,func() time.Time{return time.Unix(1_700_000_000,0).UTC()},func() string{return "00000000-0000-4000-8000-000000000001"})
    app := App{Version:"test",BaselineScanner:scanner,StatusReader:snapshots,Doctor:fakeDoctor{}}
    var out, errOut bytes.Buffer
    code := app.Run(context.Background(), []string{"scan","--baseline","--json"}, &out, &errOut)
    if code != 0 { t.Fatalf("code=%d stderr=%s", code,errOut.String()) }
    assertGoldenJSON(t, "../../testdata/golden/baseline.json", out.Bytes())
    if len(snapshots.saved) != 1 { t.Fatal("scan not persisted") }
}
```

The test file defines `memorySnapshots` with `SaveScan` and `LatestInventory`, `fakeCollector` with the Task 3 collector contract, and `fakeDoctor.Check(context.Context) doctor.Result`; each fake stores only arguments needed by the assertions.

- [ ] **Step 2: Verify service, report, doctor, and CLI tests fail**

Run: `go test ./internal/scan ./internal/report ./internal/doctor ./internal/cli -v`  
Expected: FAIL because the service and commands are not wired.

- [ ] **Step 3: Implement the application flow and exit-code contract**

`Baseline` records start time, collects results, builds inventory, loads the previous inventory, computes delta, derives overall status Complete or Partial, assigns a UUID-shaped random scan ID from 16 cryptographic bytes, saves atomically, and returns the result. JSON reporting uses `json.Encoder` with HTML escaping disabled and a trailing newline. Extend `cli.App` with the exact fields `BaselineScanner cli.BaselineScanner`, `StatusReader cli.StatusReader`, and `Doctor cli.Doctor`; each is a one-method interface matching the methods defined in this task.

Exit codes are fixed: `0` completed or partial scan with no blocking verdict, `1` internal fatal error before a scan can be persisted, `2` CLI usage error. Blocking verdict exit codes are outside this foundation contract and must not be emitted here.

`doctor` reports product/version, `GOOS/GOARCH`, database directory writability, core data paths, available collector ecosystems, and missing optional commands without reading asset contents.

- [ ] **Step 4: Run golden, race, and complete repository checks**

Run: `go fmt ./... && go test -race ./... && go vet ./... && git diff --check`  
Expected: PASS and golden JSON contains `"schemaVersion":"ssc-init.scan.v1"`, `"status":"partial"`, and the failed `docker` coverage entry.

- [ ] **Step 5: Commit the usable baseline CLI**

```bash
git add cmd internal/cli internal/scan internal/report internal/doctor testdata/golden
git commit -m "feat: add baseline scan workflow"
```

### Task 10: Add reproducible macOS builds and acceptance smoke tests

**Files:**
- Create: `scripts/build-darwin.sh`
- Create: `scripts/build-darwin_test.go`
- Create: `internal/acceptance/baseline_test.go`
- Create: `internal/acceptance/memory_store_test.go`
- Create: `README.md`
- Create: `LICENSE`
- Create: `.gitignore`

**Interfaces:**
- Consumes: complete `ssc-init` CLI.
- Produces: `dist/ssc-init-darwin-arm64`, `dist/ssc-init-darwin-amd64`, and `dist/checksums.txt`.

- [ ] **Step 1: Write failing build-script and fixture acceptance tests**

```go
func TestBaselineFixtureNeverReadsRealHome(t *testing.T) {
    env := testutil.Environment(t, "../../testdata/home")
    orchestrator := collector.Orchestrator{Timeout:time.Second,MaxConcurrent:4,Collectors:[]collector.Collector{
        agents.New(),mcp.New(),ide.New(),projects.New([]string{"$HOME/Projects"}),packages.New(),
    }}
    snapshots := acceptance.NewMemorySnapshots()
    svc := scan.NewService(orchestrator,snapshots,env.Now,func() string{return "00000000-0000-4000-8000-000000000001"})
    result, inventory, _, err := svc.Baseline(context.Background()); if err != nil { t.Fatal(err) }
    var out bytes.Buffer; if err := report.WriteJSON(&out,result,inventory,model.Delta{}); err != nil { t.Fatal(err) }
    if realHome := os.Getenv("HOME"); realHome != "" && strings.Contains(out.String(),realHome) { t.Fatal("real home leaked") }
    if result.Status != "complete" && result.Status != "partial" { t.Fatalf("status=%s", result.Status) }
}

func TestBuildScriptDeclaresStaticTargets(t *testing.T) {
    raw, err := os.ReadFile("../../scripts/build-darwin.sh"); if err != nil { t.Fatal(err) }
    for _, want := range []string{"CGO_ENABLED=0", "GOOS=darwin", "GOARCH=arm64", "GOARCH=amd64", "shasum -a 256"} {
        if !bytes.Contains(raw, []byte(want)) { t.Fatalf("missing %s", want) }
    }
}
```

- [ ] **Step 2: Verify the acceptance tests fail**

Run: `go test ./internal/acceptance ./scripts -v`  
Expected: FAIL because the acceptance helper and build script do not exist.

- [ ] **Step 3: Implement the deterministic build and concise operator documentation**

```bash
#!/bin/sh
set -eu
export CGO_ENABLED=0 GOOS=darwin
mkdir -p dist
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export SOURCE_DATE_EPOCH
GOARCH=arm64 go build -trimpath -buildvcs=true -ldflags="-s -w" -o dist/ssc-init-darwin-arm64 ./cmd/ssc-init
GOARCH=amd64 go build -trimpath -buildvcs=true -ldflags="-s -w" -o dist/ssc-init-darwin-amd64 ./cmd/ssc-init
(cd dist && shasum -a 256 ssc-init-darwin-arm64 ssc-init-darwin-amd64 > checksums.txt)
```

`internal/acceptance/memory_store_test.go` defines `NewMemorySnapshots` with the same in-memory `scan.SnapshotStore` implementation used by the test. `README.md` must state the tagline, current macOS/current-user scope, exact commands, data location, no-safety-guarantee language, and the absence of runtime dependencies. `LICENSE` contains Apache-2.0. `.gitignore` ignores `/dist/`, local database files, and local reports.

- [ ] **Step 4: Run the foundation release gate**

Run: `go fmt ./... && go test -race ./... && go vet ./... && sh scripts/build-darwin.sh && file dist/ssc-init-darwin-* && shasum -a 256 -c dist/checksums.txt && git diff --check`  
Expected: both files identify as Mach-O executables for their declared architectures; checksums report `OK`; all tests and vet pass.

- [ ] **Step 5: Commit the foundation release slice**

```bash
git add scripts internal/acceptance README.md LICENSE .gitignore
git commit -m "build: add static macOS release checks"
```

---

## Foundation completion checkpoint

Run:

```bash
go test -race ./...
go vet ./...
sh scripts/build-darwin.sh
./dist/ssc-init-darwin-arm64 version --json
./dist/ssc-init-darwin-arm64 doctor --json
./dist/ssc-init-darwin-arm64 scan --baseline --json
git status --short
```

Expected:

- all tests and vet pass;
- both static macOS binaries and their verified checksums exist;
- version, doctor, and baseline commands emit valid JSON;
- the baseline persists to the user data directory only when the real CLI is invoked;
- any unavailable ecosystem appears in coverage instead of causing a false complete result;
- `git status --short` is empty after the final commit.
