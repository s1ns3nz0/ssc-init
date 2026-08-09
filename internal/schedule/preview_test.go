package schedule

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPreviewShowsExactDailyJobWithoutAbsoluteHome(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "Library", "Application Support", "SSC Init", "core", "versions", "v1.0.0", "ssc-init")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := (Manager{Home: home, Executable: executable}).Preview()
	if err != nil || !got.Valid() {
		t.Fatalf("preview=%+v err=%v", got, err)
	}
	if got.Label != Label || !reflect.DeepEqual(got.Command, []string{"$HOME/Library/Application Support/SSC Init/core/versions/v1.0.0/ssc-init", "scan", "--baseline", "--json"}) || got.Hour != 9 || got.Minute != 0 || got.StandardOut != "$HOME/Library/Application Support/SSC Init/reports/daily.stdout.log" || got.StandardError != "$HOME/Library/Application Support/SSC Init/reports/daily.stderr.log" || got.RemovalCommand != "ssc-init schedule remove --json" {
		t.Fatalf("preview=%+v", got)
	}
}

func TestPreviewRejectsExecutableOutsideHomeOrUnsafeVersion(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "private")
	for _, executable := range []string{
		"/tmp/ssc-init",
		filepath.Join(home, "Library", "Application Support", "SSC Init", "core", "versions", "latest", "ssc-init"),
		filepath.Join(home, "Library", "Application Support", "SSC Init", "core", "versions", "v1.0.0", "other"),
	} {
		if _, err := (Manager{Home: home, Executable: executable}).Preview(); err == nil {
			t.Fatalf("accepted %q", executable)
		}
	}
}

func TestPreviewValidationRejectsEnforcementOrMutableFields(t *testing.T) {
	valid := Preview{SchemaVersion: SchemaV1, Label: Label, Command: []string{"$HOME/a/ssc-init", "scan", "--baseline", "--json"}, Hour: 9, Minute: 0, StandardOut: "$HOME/a/daily.stdout.log", StandardError: "$HOME/a/daily.stderr.log", RemovalCommand: "ssc-init schedule remove --json", Capability: "scheduled"}
	if !valid.Valid() {
		t.Fatal("valid preview rejected")
	}
	for _, mutate := range []func(*Preview){
		func(v *Preview) { v.Label = "other" },
		func(v *Preview) { v.Command = append(v.Command, "--external-probes") },
		func(v *Preview) { v.Hour = 24 },
		func(v *Preview) { v.StandardOut = "/private/out" },
		func(v *Preview) { v.Capability = "enforced" },
	} {
		candidate := valid
		candidate.Command = append([]string(nil), valid.Command...)
		mutate(&candidate)
		if candidate.Valid() {
			t.Fatalf("invalid preview accepted: %+v", candidate)
		}
	}
}
