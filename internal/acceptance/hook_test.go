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

// hookCacheWarmLine matches the grouped evidence rows the second run may print
// when the store-backed evidence cache flips its miss/hit metadata.
var hookCacheWarmLine = regexp.MustCompile(`^  changed\s+\d+ evidence records( \(.+\))?$`)

// TestHookLifecycleFirstDriftThenCacheWarmThenSilent drives `ssc-init hook`
// three times through the real collector pipeline and a real SQLite store in
// an isolated home: the initial baseline reports drift, the second run may
// only report the grouped cache-warm evidence rows, and the third run is
// silent because nothing changed.
func TestHookLifecycleFirstDriftThenCacheWarmThenSilent(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v1\n")

	snapshots, err := store.Open(filepath.Join(privateMatrixTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()

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

	run := func(label string) string {
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

	first := run("first run")
	if !strings.Contains(first, "toolchain drift") || !strings.Contains(first, "added") {
		t.Fatalf("initial baseline must report drift:\n%s", first)
	}

	second := run("second run")
	for _, line := range strings.Split(strings.TrimSuffix(second, "\n"), "\n") {
		if line == "" || line == "ssc-init: toolchain drift since last snapshot" || hookCacheWarmLine.MatchString(line) {
			continue
		}
		t.Fatalf("second run printed unexpected line %q in:\n%s", line, second)
	}
	if digest := hookDigestPattern.FindString(second); digest != "" {
		t.Fatalf("second run leaked digest %q in:\n%s", digest, second)
	}
	if strings.Contains(second, home) {
		t.Fatalf("second run leaked the home path in:\n%s", second)
	}

	if third := run("third run"); third != "" {
		t.Fatalf("third run must be silent, got:\n%s", third)
	}
}
