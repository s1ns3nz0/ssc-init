package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

func TestRunWritesUnsignedBundleAndPublicAttributionReport(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	code := run([]string{
		"--osv-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "osv-vulnerable.json"),
		"--osv-license", "CC-BY-4.0",
		"--osv-base-url", "https://osv.dev/vulnerability/",
		"--openssf-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "openssf-malicious.json"),
		"--openssf-license", "CC-BY-4.0",
		"--openssf-base-url", "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/",
		"--version", "2026.08.14", "--sequence", "42", "--key-id", "ti-production-2026",
		"--generated-at", "2026-08-14T00:00:00Z", "--valid-from", "2026-08-13T23:00:00Z", "--valid-until", "2026-08-21T00:00:00Z",
		"--output-dir", output,
	}, stdout, stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC))
	if err != nil || envelope.Sequence != 42 || len(envelope.TI.Records) != 4 {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
	report, err := os.ReadFile(filepath.Join(output, "attribution-report.json"))
	var summary struct {
		Malicious  int `json:"malicious"`
		Vulnerable int `json:"vulnerable"`
	}
	decodeErr := json.Unmarshal(report, &summary)
	if err != nil || decodeErr != nil || summary.Malicious != 2 || summary.Vulnerable != 2 || report[len(report)-1] != '\n' {
		t.Fatalf("report=%s err=%v", report, err)
	}
	if _, err := os.Stat(filepath.Join(output, "ti-bundle.sig")); !os.IsNotExist(err) {
		t.Fatalf("publisher unexpectedly signed output: %v", err)
	}
}

func TestRunRejectsImplicitOrNonAbsolutePaths(t *testing.T) {
	for name, args := range map[string][]string{
		"no sources":      {"--version", "2026.08.14"},
		"relative source": {"--osv-source", "source.json"},
		"relative output": {"--output-dir", "output"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := run(args, new(bytes.Buffer), new(bytes.Buffer)); code != 2 {
				t.Fatalf("code=%d", code)
			}
		})
	}
}

func TestRunRefusesToOverwritePublicationArtifacts(t *testing.T) {
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, "ti-bundle.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(validArgs(t, output), new(bytes.Buffer), new(bytes.Buffer)); code != 1 {
		t.Fatalf("code=%d", code)
	}
	raw, err := os.ReadFile(filepath.Join(output, "ti-bundle.json"))
	if err != nil || string(raw) != "existing" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
}

func validArgs(t *testing.T, output string) []string {
	t.Helper()
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"--osv-source", filepath.Join(repositoryRoot, "internal", "tipublish", "testdata", "osv-vulnerable.json"),
		"--osv-license", "CC-BY-4.0", "--osv-base-url", "https://osv.dev/vulnerability/",
		"--version", "2026.08.14", "--sequence", "42", "--key-id", "ti-production-2026",
		"--generated-at", "2026-08-14T00:00:00Z", "--valid-from", "2026-08-13T23:00:00Z", "--valid-until", "2026-08-21T00:00:00Z",
		"--output-dir", output,
	}
}
