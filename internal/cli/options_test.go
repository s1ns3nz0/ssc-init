package cli

import (
	"path/filepath"
	"reflect"
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
	}
	for _, args := range tests {
		if _, err := ParseOptions(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}
