package acceptance

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

// hookDigestPattern matches any lowercase sha256 digest the hook summary must
// never print.
var hookDigestPattern = regexp.MustCompile(`[0-9a-f]{64}`)

// hookChangedPluginRow matches the severity-ladder row a mutated plugin payload
// must produce.
var hookChangedPluginRow = regexp.MustCompile(`(?m)^  CHANGED\s+agent-plugin`)

// TestHookLifecycleInitialBaselineThenSilent drives `ssc-init hook` four times
// through the real collector pipeline and a real SQLite store in an isolated
// home: the first run records an initial baseline without rungs, the second run
// is silent, mutating a payload file promotes the plugin to CHANGED, and the
// run after that is silent again — proving a content change echoes exactly
// once, not on every following run.
func TestHookLifecycleInitialBaselineThenSilent(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v1\n")
	run := newHookRunner(t, home)

	first := run("first run")
	if !strings.Contains(first, "initial baseline recorded") {
		t.Fatalf("first run must record an initial baseline:\n%s", first)
	}
	for label := range rungLabelsUnderTest {
		if strings.Contains(first, label) {
			t.Fatalf("initial baseline must not print rung %q:\n%s", label, first)
		}
	}

	if second := run("second run"); second != "" {
		t.Fatalf("second run must be silent, got:\n%s", second)
	}

	writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v2\n")

	third := run("third run")
	if !hookChangedPluginRow.MatchString(third) {
		t.Fatalf("mutated payload must print a CHANGED agent-plugin row:\n%s", third)
	}
	if digest := hookDigestPattern.FindString(third); digest != "" {
		t.Fatalf("third run leaked digest %q in:\n%s", digest, third)
	}
	if strings.Contains(third, home) {
		t.Fatalf("third run leaked the home path in:\n%s", third)
	}

	if fourth := run("fourth run"); fourth != "" {
		t.Fatalf("fourth run must be silent — the content change must not echo, got:\n%s", fourth)
	}
}

// TestHookReportsTheFirstAssetInstalledAfterAnEmptyBaseline drives the machine
// whose first baseline recorded nothing: the run that finds the first tool ever
// installed has a delta indistinguishable from an initial baseline, yet a
// snapshot already exists, so it must report NEW instead of swallowing it.
func TestHookReportsTheFirstAssetInstalledAfterAnEmptyBaseline(t *testing.T) {
	home := t.TempDir()
	run := newHookRunner(t, home)

	if first := run("first run"); first != "" {
		t.Fatalf("an empty home records an empty baseline silently, got:\n%s", first)
	}

	writeMatrixFile(t, filepath.Join(home, ".claude", "skills", "docx", "SKILL.md"), "---\nname: docx\n---\nbody\n")

	second := run("second run")
	if strings.Contains(second, "initial baseline") {
		t.Fatalf("the second run has a predecessor and must not claim an initial baseline:\n%s", second)
	}
	if !regexp.MustCompile(`(?m)^  NEW\s+agent-skill\s+docx \(claude\)$`).MatchString(second) {
		t.Fatalf("the first installed skill must be reported NEW:\n%s", second)
	}

	writeMatrixFile(t, filepath.Join(home, ".claude", "skills", "pptx", "SKILL.md"), "---\nname: pptx\n---\nbody\n")

	third := run("third run")
	if !regexp.MustCompile(`(?m)^  NEW\s+agent-skill\s+pptx \(claude\)$`).MatchString(third) {
		t.Fatalf("the second installed skill must be reported NEW:\n%s", third)
	}
}

// newHookRunner wires `ssc-init hook` over the real collector pipeline, a real
// SQLite store, and one isolated home, and returns a function running it once.
func newHookRunner(t *testing.T, home string) func(label string) string {
	t.Helper()
	snapshots, err := store.Open(filepath.Join(privateMatrixTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snapshots.Close() })

	environment := collector.Environment{
		Home: home, Platform: "darwin",
		Scope:  model.ScanScope{Platform: "darwin"},
		FS:     &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		Runner: &matrixRunner{failOnCall: true}, Inspector: &matrixInspector{failOnCall: true},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	scans := 0
	service := scan.NewService(
		collector.Orchestrator{
			Timeout: time.Second, MaxConcurrent: 1,
			Collectors: []collector.Collector{agents.New()},
		},
		snapshots,
		environment.Now,
		func() string {
			scans++
			return fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", scans)
		},
		environment,
	)
	app := cli.App{BaselineScanner: service}

	return func(label string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := app.Run(context.Background(), []string{"hook"}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit=%d stderr=%q", label, code, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("%s: stderr=%q", label, stderr.String())
		}
		return stdout.String()
	}
}

// rungLabelsUnderTest is the closed set of rung labels the first run must not
// print. It intentionally duplicates internal/report rather than exporting it:
// acceptance asserts the public output contract, not the renderer's internals.
var rungLabelsUnderTest = map[string]struct{}{
	"NEW": {}, "CHANGED": {}, "UNVERIFIED": {}, "UPGRADED": {}, "REMOVED": {},
}
