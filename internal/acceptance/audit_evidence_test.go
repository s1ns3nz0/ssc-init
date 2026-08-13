package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/audit"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

func TestAuditEvidenceLifecycle(t *testing.T) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(userHome, ".ssc-init-audit-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := "PRIVATE_AUDIT_MARKER_DO_NOT_PERSIST"
	writeMatrixFile(t, filepath.Join(home, ".codex", "skills", "demo", "SKILL.md"), "---\nname: demo\ndescription: "+marker+"\n---\nbody\n")

	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(privateMatrixTempDir(t), "ssc-init")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ssc-init")
	build.Dir = repo
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("build: %v: %s", buildErr, output)
	}
	run := func(args ...string) string {
		t.Helper()
		command := exec.CommandContext(context.Background(), bin, args...)
		command.Env = append(os.Environ(), "HOME="+home)
		output, runErr := command.CombinedOutput()
		if runErr != nil {
			t.Fatalf("ssc-init %s: %v: %s", strings.Join(args, " "), runErr, output)
		}
		if bytes.Contains(output, []byte(marker)) {
			t.Fatalf("private marker escaped through %s", strings.Join(args, " "))
		}
		return string(output)
	}

	scanOutput := run("scan", "--baseline", "--pretty", "--label", "audit-mac")
	assertOrderedAuditSections(t, scanOutput)
	dataDir := filepath.Join(home, "Library", "Application Support", "SSC Init")
	manager := &audit.Manager{Root: filepath.Join(dataDir, "audit"), Home: home, Now: time.Now, Random: rand.Reader, Render: audit.ReportText}
	listed, err := manager.List(context.Background())
	if err != nil || len(listed) != 1 || !listed[0].Valid {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	stored := listed[0]
	verified, err := manager.Open(context.Background(), stored.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Record.Run.ScanID == "" || verified.Record.Run.ID != stored.RunID || !strings.Contains(scanOutput, stored.RunID) {
		t.Fatalf("scan/archive identity mismatch: stored=%+v run=%+v", stored, verified.Record.Run)
	}
	snapshots, err := store.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if closeErr := snapshots.Close(); err == nil {
		err = closeErr
	}
	if err != nil || !initialized || snapshot.Scan.ScanID != verified.Record.Run.ScanID {
		t.Fatalf("snapshot/archive identity mismatch: initialized=%v scan=%q run=%q err=%v", initialized, snapshot.Scan.ScanID, verified.Record.Run.ScanID, err)
	}
	managedPath := filepath.Join(dataDir, "audit", filepath.Base(stored.SafePath))
	if got := run("audit", "list", "--pretty"); !strings.Contains(got, stored.RunID) || !strings.Contains(got, "audit-mac") {
		t.Fatalf("list output=%q", got)
	}
	if got := run("audit", "show", stored.RunID, "--section", "assets"); !strings.Contains(got, "ASSETS") {
		t.Fatalf("show output=%q", got)
	}
	if got := run("audit", "verify", managedPath, "--pretty"); !strings.Contains(got, stored.SHA256) || !strings.Contains(got, "unsigned") {
		t.Fatalf("verify output=%q", got)
	}

	exportDir := privateMatrixTempDir(t)
	internalPath := filepath.Join(exportDir, "internal.zip")
	redactedPath := filepath.Join(exportDir, "redacted.zip")
	run("audit", "export", stored.RunID, "--output", internalPath)
	run("audit", "export", stored.RunID, "--output", redactedPath, "--redacted")
	internal := verifyAuditFile(t, internalPath)
	redacted := verifyAuditFile(t, redactedPath)
	if internal.Record.Run.ID != stored.RunID || redacted.Record.Run.ID == stored.RunID || redacted.ZIPSHA256 == internal.ZIPSHA256 {
		t.Fatalf("redaction is linkable: internal=%q redacted=%q", internal.Record.Run.ID, redacted.Record.Run.ID)
	}
	if bytes.Contains(mustReadFile(t, internalPath), []byte(marker)) || bytes.Contains(mustReadFile(t, redactedPath), []byte(marker)) {
		t.Fatal("private source marker persisted in an archive")
	}
	if err := os.Remove(filepath.Join(dataDir, "state.db")); err != nil {
		t.Fatal(err)
	}
	status := run("status", "--pretty")
	assertOrderedAuditSections(t, status)
	if !strings.Contains(status, stored.RunID) {
		t.Fatalf("offline status lost archive: %q", status)
	}
}

func assertOrderedAuditSections(t *testing.T, output string) {
	t.Helper()
	position := -1
	for _, section := range []string{"SUMMARY", "FINDINGS", "CHANGES", "COVERAGE", "ASSETS", "AUDIT EVIDENCE"} {
		next := strings.Index(output, section)
		if next <= position {
			t.Fatalf("section %q is missing or out of order: %q", section, output)
		}
		position = next
	}
}

func verifyAuditFile(t *testing.T, path string) audit.Verified {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := audit.Verify(file, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
