package scripts_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// workflowUses matches the action reference of every `uses:` step.
var workflowUses = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)

// workflowPinned matches an action reference pinned to a full 40-hex commit
// sha. A tag or branch ref is mutable and is rejected.
var workflowPinned = regexp.MustCompile(`^[^@]+@[0-9a-f]{40}$`)

// unpinnedWorkflowActions returns every action reference in the workflow that
// is not pinned to a full commit sha, plus the total number of references seen.
func unpinnedWorkflowActions(workflow string) (unpinned []string, total int) {
	for _, match := range workflowUses.FindAllStringSubmatch(workflow, -1) {
		total++
		if !workflowPinned.MatchString(match[1]) {
			unpinned = append(unpinned, match[1])
		}
	}
	return unpinned, total
}

func readCIWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCIWorkflowPinsEveryActionToACommitSHA(t *testing.T) {
	unpinned, total := unpinnedWorkflowActions(readCIWorkflow(t))
	if total == 0 {
		t.Fatal("ci workflow declares no actions to pin")
	}
	for _, reference := range unpinned {
		t.Errorf("action %q is not pinned to a commit sha", reference)
	}
}

func TestUnpinnedWorkflowActionsRejectsMutableRefs(t *testing.T) {
	mutable := `jobs:
  gates:
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@main
      - uses: actions/cache@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
`
	unpinned, total := unpinnedWorkflowActions(mutable)
	if total != 3 {
		t.Fatalf("counted %d action references, want 3", total)
	}
	want := []string{"actions/checkout@v5", "actions/setup-go@main"}
	if strings.Join(unpinned, ",") != strings.Join(want, ",") {
		t.Fatalf("unpinned actions %q, want %q", unpinned, want)
	}
}

func TestCIWorkflowIsStructurallyValidYAML(t *testing.T) {
	workflow := readCIWorkflow(t)
	if strings.Contains(workflow, "\t") {
		t.Fatal("ci workflow indents with a tab, which yaml forbids")
	}
	if !strings.HasSuffix(workflow, "\n") {
		t.Fatal("ci workflow does not end with a newline")
	}
	for _, key := range []string{"name:", "on:", "permissions:", "jobs:"} {
		if !strings.Contains("\n"+workflow, "\n"+key) {
			t.Errorf("ci workflow has no top-level %q key", key)
		}
	}
	for number, line := range strings.Split(workflow, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indent := len(line) - len(trimmed); indent%2 != 0 {
			t.Errorf("line %d has odd indentation %d", number+1, indent)
		}
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %d has trailing whitespace", number+1)
		}
	}
}

func TestCIWorkflowRunsTheReleaseGatesOnMacOS(t *testing.T) {
	workflow := readCIWorkflow(t)
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
			t.Errorf("ci workflow missing %q", want)
		}
	}
	if regexp.MustCompile(`(?m)^\s*runs-on:.*-latest`).MatchString(workflow) {
		t.Error("ci workflow uses a floating -latest runner label")
	}
}

func TestCIWorkflowRunsExplicitReleaseModeOnlyForVersionTags(t *testing.T) {
	workflow := readCIWorkflow(t)
	want := `      - name: Tagged release build
        if: startsWith(github.ref, 'refs/tags/v')
        env:
          SSC_INIT_RELEASE: "1"
        run: sh scripts/build-darwin.sh
`
	if !strings.Contains(workflow, want) {
		t.Fatalf("ci workflow does not run the fail-closed release contract on version tags")
	}
}

// The workflow must not hardcode a toolchain version that can drift away from
// the module's own; it reads go.mod instead.
func TestCIWorkflowTakesItsGoVersionFromGoMod(t *testing.T) {
	workflow := readCIWorkflow(t)
	if regexp.MustCompile(`(?m)^\s*go-version:`).MatchString(workflow) {
		t.Error("ci workflow hardcodes go-version instead of reading go.mod")
	}
	if !strings.Contains(workflow, "go-version-file: go.mod") {
		t.Fatal("ci workflow does not read go-version-file: go.mod")
	}
	goMod, err := os.ReadFile(filepath.Join(repositoryRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^go [0-9]+\.[0-9]+`).Match(goMod) {
		t.Fatal("go.mod declares no go directive for the workflow to read")
	}
}

func TestCIWorkflowIsLeastPrivilegeAndUsesOnlyBundlePublicationSecrets(t *testing.T) {
	workflow := readCIWorkflow(t)
	if !strings.Contains("\n"+workflow, "\npermissions:\n  contents: read\n") {
		t.Error("ci workflow has no read-only top-level permissions block")
	}
	if regexp.MustCompile(`(?m)^\s*[a-z-]+: write`).MatchString(workflow) {
		t.Error("ci workflow grants a write permission")
	}
	allowed := []string{"secrets.SSC_INIT_TI_BUNDLE_SIGNING_SEED_BASE64", "secrets.SSC_INIT_POLICY_BUNDLE_SIGNING_SEED_BASE64"}
	if strings.Count(workflow, "secrets.") != len(allowed) {
		t.Error("ci workflow uses an unexpected number of secret inputs")
	}
	for _, name := range allowed {
		if !strings.Contains(workflow, name) {
			t.Errorf("ci workflow is missing family-scoped secret %q", name)
		}
	}
	for _, forbidden := range []string{"APPLE_ID", "NOTARY", "SIGNING_IDENTITY", "DEVELOPER_ID"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("ci workflow unexpectedly wires obsolete Apple release credential %q", forbidden)
		}
	}
}
