package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/quarantine"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

func TestQuarantineCLIRequiresPreviewBoundApprovalAndRestoresExactly(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, ".tools", "manifest.json")
	content := []byte("fixture bytes")
	writeMatrixFile(t, source, string(content))
	if err := os.Chmod(source, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	assetID, observationID, evidenceID := "tool:fixture", "observation:fixture", "evidence:fixture"
	inventory := model.Inventory{
		Assets:       []model.Asset{{ID: assetID, Type: model.AssetTool, Name: "fixture"}},
		Observations: []model.Observation{{ID: observationID, AssetID: assetID, Scope: model.ScopeUser, LocationRef: "$HOME/.tools/manifest.json"}},
		Evidence:     []model.ContentEvidence{{ID: evidenceID, AssetID: assetID, ObservationID: observationID, Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: fmt.Sprintf("%x", digest)}},
	}
	dataDir := filepath.Join(home, "Library", "Application Support", "SSC Init")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := &quarantine.Manager{Home: home, Recorder: database}
	app := cli.App{StatusReader: adapterSnapshot{inventory: inventory}, Quarantine: manager, QuarantineReader: database}

	base := []string{"--asset-id", assetID, "--observation-id", observationID, "--evidence-id", evidenceID}
	preview := runQuarantineCLI(t, app, append([]string{"quarantine", "preview"}, append(base, "--json")...))
	var proposal quarantine.Proposal
	if err := json.Unmarshal(preview, &proposal); err != nil || !proposal.Valid() {
		t.Fatalf("proposal=%+v err=%v", proposal, err)
	}
	wrong := append([]string{"quarantine", "apply"}, base...)
	wrong = append(wrong, "--approval-id", "approval:wrong", "--json")
	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), wrong, &stdout, &stderr)
	_, sourceErr := os.Lstat(source)
	if code != 1 || sourceErr != nil {
		t.Fatalf("wrong approval code=%d stderr=%q sourceErr=%v", code, stderr.String(), sourceErr)
	}
	apply := append([]string{"quarantine", "apply"}, base...)
	apply = append(apply, "--approval-id", proposal.ApprovalID, "--json")
	var quarantined quarantine.Record
	if err := json.Unmarshal(runQuarantineCLI(t, app, apply), &quarantined); err != nil || quarantined.State != quarantine.StateQuarantined {
		t.Fatalf("record=%+v err=%v", quarantined, err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source remains: %v", err)
	}

	restorePreview := runQuarantineCLI(t, app, []string{"quarantine", "restore-preview", "--record-id", quarantined.ID, "--json"})
	if err := json.Unmarshal(restorePreview, &proposal); err != nil || !proposal.Valid() || proposal.Action != "restore" {
		t.Fatalf("restore proposal=%+v err=%v", proposal, err)
	}
	runQuarantineCLI(t, app, []string{"quarantine", "restore-apply", "--record-id", quarantined.ID, "--approval-id", proposal.ApprovalID, "--json"})
	restored, err := os.ReadFile(source)
	info, statErr := os.Lstat(source)
	if err != nil || statErr != nil || !bytes.Equal(restored, content) || info.Mode().Perm() != 0o755 {
		t.Fatalf("restored=%q info=%v err=%v statErr=%v", restored, info, err, statErr)
	}
}

func runQuarantineCLI(t *testing.T, app cli.App, args []string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := app.Run(context.Background(), args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("args=%q code=%d stderr=%q", args, code, stderr.String())
	}
	return stdout.Bytes()
}
