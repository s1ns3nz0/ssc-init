package cli

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseOptions(t *testing.T) {
	got, err := ParseOptions([]string{
		"scan", "--baseline", "--json",
		"--project-root", "/Volumes/work",
		"--project-root=$HOME/Developer",
		"--external-probes",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Options{
		Command:        "scan",
		JSON:           true,
		Baseline:       true,
		ExternalProbes: true,
		ProjectRoots:   []string{"/Volumes/work", "$HOME/Developer"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}

func TestParseOptionsAcceptsPolicyInitAndOverride(t *testing.T) {
	got, err := ParseOptions([]string{"policy", "init", "--policy", "$HOME/team/policy.json"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != "policy" || got.PolicyCommand != "init" || got.PolicyPath != "$HOME/team/policy.json" {
		t.Fatalf("options=%+v", got)
	}
	for _, args := range [][]string{{"policy"}, {"policy", "init", "--policy", "../escape"}, {"policy", "init", "--policy", "/tmp/a", "--policy", "/tmp/b"}} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted invalid policy options: %v", args)
		}
	}
}

func TestParseOptionsAcceptsPolicyPinForms(t *testing.T) {
	for _, args := range [][]string{{"policy", "pin"}, {"policy", "pin", "--update", "agent-plugin:claude:x@1.0.0"}} {
		if _, err := ParseOptions(args); err != nil {
			t.Fatalf("rejected %v: %v", args, err)
		}
	}
	for _, args := range [][]string{{"policy", "pin", "--update"}, {"policy", "pin", "--update", "x", "--update", "y"}} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestParseOptionsAcceptsPolicyCheckForms(t *testing.T) {
	for _, args := range [][]string{{"policy", "check"}, {"policy", "check", "--json"}, {"policy", "check", "--pretty"}, {"policy", "check", "--policy", "/tmp/policy.json", "--json"}} {
		if _, err := ParseOptions(args); err != nil {
			t.Fatalf("rejected %v: %v", args, err)
		}
	}
	if _, err := ParseOptions([]string{"policy", "check", "--json", "--pretty"}); err == nil {
		t.Fatal("accepted two output formats")
	}
}

func TestParseOptionsAcceptsOnlyDocumentedCommandForms(t *testing.T) {
	tests := []struct {
		args []string
		want Options
	}{
		{args: []string{"version", "--json"}, want: Options{Command: "version", JSON: true}},
		{args: []string{"doctor", "--json"}, want: Options{Command: "doctor", JSON: true}},
		{args: []string{"status", "--json"}, want: Options{Command: "status", JSON: true}},
		{args: []string{"scan", "--json", "--baseline"}, want: Options{Command: "scan", JSON: true, Baseline: true}},
		{args: []string{"scan", "--project-root=$HOME", "--baseline", "--json"}, want: Options{Command: "scan", JSON: true, Baseline: true, ProjectRoots: []string{"$HOME"}}},
		{args: []string{"scan", "--baseline", "--pretty"}, want: Options{Command: "scan", Pretty: true, Baseline: true}},
		{args: []string{"status", "--pretty"}, want: Options{Command: "status", Pretty: true}},
		{args: []string{"hook"}, want: Options{Command: "hook"}},
	}
	for _, testCase := range tests {
		got, err := ParseOptions(testCase.args)
		if err != nil {
			t.Fatalf("args=%q err=%v", testCase.args, err)
		}
		if !reflect.DeepEqual(got, testCase.want) {
			t.Fatalf("args=%q got=%+v want=%+v", testCase.args, got, testCase.want)
		}
	}
}

func TestParseOptionsAcceptsInstallAndRollback(t *testing.T) {
	digest := strings.Repeat("a", 64)
	got, err := ParseOptions([]string{
		"install", "--from", "/tmp/ssc-init", "--version", "v0.2.0",
		"--sha256", digest, "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Options{
		Command:        "install",
		JSON:           true,
		InstallSource:  "/tmp/ssc-init",
		InstallVersion: "v0.2.0",
		InstallDigest:  digest,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
	// Flag order is not part of the contract; the value set is.
	reordered, err := ParseOptions([]string{
		"install", "--json", "--sha256", digest, "--version", "v0.2.0", "--from", "/tmp/ssc-init",
	})
	if err != nil || !reflect.DeepEqual(reordered, want) {
		t.Fatalf("reordered=%+v err=%v", reordered, err)
	}
	rollback, err := ParseOptions([]string{"rollback", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rollback, Options{Command: "rollback", JSON: true}) {
		t.Fatalf("rollback=%+v", rollback)
	}
}

func TestParseOptionsAcceptsOnlyExplicitLocalBundleCommands(t *testing.T) {
	got, err := ParseOptions([]string{"bundle", "install", "--family", "ti", "--from", "/tmp/bundle.json", "--signature", "/tmp/bundle.sig", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	want := Options{Command: "bundle", BundleCommand: "install", BundleFamily: "ti", BundleSource: "/tmp/bundle.json", BundleSignature: "/tmp/bundle.sig", JSON: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("options=%+v want=%+v", got, want)
	}
	for _, args := range [][]string{
		{"bundle", "status", "--family", "policy", "--json"},
		{"bundle", "rollback", "--family", "ti", "--json"},
	} {
		if _, err := ParseOptions(args); err != nil {
			t.Fatalf("rejected %v: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"bundle", "install", "--family", "ti", "--from", "https://example.invalid/bundle", "--signature", "/tmp/sig", "--json"},
		{"bundle", "install", "--family", "other", "--from", "/tmp/b", "--signature", "/tmp/s", "--json"},
		{"bundle", "status", "--family", "ti", "--from", "/tmp/b", "--json"},
	} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted invalid bundle command: %v", args)
		}
	}
}

func TestParseOptionsRejectsUndocumentedInstallForms(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, invalid := range [][]string{
		{"install"},
		{"install", "--json"},
		{"install", "--from", "relative/path", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "latest", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", "short", "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", strings.ToUpper(digest), "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", strings.Repeat("a", 63) + "g", "--json"},
		{"install", "--from", "/tmp/x", "--from", "/tmp/y", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--version", "v0.3.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--json", "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--pretty"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest},
		{"install", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--json"},
		{"install", "--from=/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--json", "leftover"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256", digest, "--json", "--external-probes"},
		{"install", "--from", "/tmp/x/", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/../etc/x", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x\x00", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "--version", "v0.2.0", "--sha256", digest, "--json"},
		{"install", "--from", "/tmp/x", "--version", "v0.2.0", "--sha256"},
		{"rollback"},
		{"rollback", "--json", "--pretty"},
		{"rollback", "--pretty"},
		{"rollback", "--json", "--json"},
		{"rollback", "--json", "extra"},
	} {
		if _, err := ParseOptions(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestParseOptionsRejectsAmbiguousForms(t *testing.T) {
	tests := [][]string{
		{"scan", "--project-root", "relative", "--baseline", "--json"},
		{"scan", "--project-root", "$HOMEevil/work", "--baseline", "--json"},
		{"scan", "--project-root"},
		{"scan", "--json"},
		{"scan", "--baseline"},
		{"status", "--external-probes"},
		{"scan", "--baseline", "--json", "--external-probes=true"},
		{"scan", "--baseline", "--json", "--project-root", "/tmp/a", "--project-root", "/tmp/a"},
		{"scan", "--baseline", "--json", "--project-root", "/tmp/a", "--project-root", filepath.Join("/tmp/a", ".")},
		{"scan", "--baseline", "--json", "--project-root", "$HOME/a", "--project-root", "$HOME/a/."},
		{"scan", "--baseline", "--json", "--unknown"},
		{"scan", "--baseline", "--json", "leftover"},
		{"scan", "--baseline", "--baseline", "--json"},
		{"scan", "--baseline", "--json", "--json"},
		{"scan", "--baseline", "--json", "--external-probes", "--external-probes"},
		{"version"},
		{"doctor", "--json", "extra"},
		{"status", "--json", "--project-root=/tmp/a"},
		{"unknown", "--json"},
		{},
		{"scan", "--baseline", "--json", "--pretty"},
		{"scan", "--baseline", "--pretty", "--pretty"},
		{"status", "--json", "--pretty"},
		{"status", "--pretty", "--pretty"},
		{"version", "--pretty"},
		{"doctor", "--pretty"},
		{"hook", "--json"},
		{"hook", "--pretty"},
		{"hook", "extra"},
	}
	for _, args := range tests {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestParseAdapterEvaluateOptions(t *testing.T) {
	got, err := ParseOptions([]string{"adapter", "evaluate"})
	if err != nil || got.Command != "adapter" || got.AdapterCommand != "evaluate" {
		t.Fatalf("options=%+v err=%v", got, err)
	}
	for _, args := range [][]string{{"adapter"}, {"adapter", "evaluate", "--json"}, {"adapter", "unknown"}} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestParseQuarantinePreviewApplyAndRestoreOptions(t *testing.T) {
	valid := [][]string{
		{"quarantine", "preview", "--asset-id", "tool:a", "--observation-id", "observation:a", "--evidence-id", "evidence:a", "--json"},
		{"quarantine", "apply", "--asset-id", "tool:a", "--observation-id", "observation:a", "--evidence-id", "evidence:a", "--approval-id", "approval:a", "--json"},
		{"quarantine", "restore-preview", "--record-id", "quarantine:a", "--json"},
		{"quarantine", "restore-apply", "--record-id", "quarantine:a", "--approval-id", "approval:a", "--json"},
	}
	for _, args := range valid {
		if got, err := ParseOptions(args); err != nil || got.Command != "quarantine" {
			t.Fatalf("args=%q options=%+v err=%v", args, got, err)
		}
	}
	for _, args := range [][]string{
		{"quarantine", "preview", "--asset-id", "tool:a", "--json"},
		{"quarantine", "apply", "--asset-id", "tool:a", "--observation-id", "observation:a", "--evidence-id", "evidence:a", "--json"},
		{"quarantine", "restore-preview", "--record-id", "quarantine:a", "--approval-id", "approval:a", "--json"},
		{"quarantine", "restore-apply", "--record-id", "quarantine:a", "--approval-id", "approval:a"},
		{"quarantine", "unknown", "--json"},
	} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestParseSchedulePreviewOptions(t *testing.T) {
	got, err := ParseOptions([]string{"schedule", "preview", "--json"})
	if err != nil || got.ScheduleCommand != "preview" || !got.JSON {
		t.Fatalf("options=%+v err=%v", got, err)
	}
	for _, command := range []string{"install", "remove"} {
		if got, err := ParseOptions([]string{"schedule", command, "--json"}); err != nil || got.ScheduleCommand != command {
			t.Fatalf("command=%s options=%+v err=%v", command, got, err)
		}
	}
	for _, args := range [][]string{{"schedule"}, {"schedule", "preview"}, {"schedule", "preview", "--pretty"}, {"schedule", "unknown", "--json"}} {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}
