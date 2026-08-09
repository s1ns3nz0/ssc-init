package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

type policyAcceptanceState struct {
	*store.Store
	snapshot model.Snapshot
}

func (state *policyAcceptanceState) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
	return state.snapshot, true, nil
}

type policyAcceptancePayload struct {
	Violations []policy.Violation `json:"violations"`
	Applied    []policy.Applied   `json:"exceptionsApplied"`
	Expired    []policy.Applied   `json:"exceptionsExpired"`
}

type policyAcceptanceScanner struct {
	scan      model.ScanResult
	inventory model.Inventory
	delta     model.Delta
}

func (scanner policyAcceptanceScanner) Baseline(context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
	return scanner.scan, scanner.inventory, scanner.delta, false, nil
}

func TestPolicyNeverEntersTheScanContract(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	scanner := policyAcceptanceScanner{
		scan:      model.ScanResult{SchemaVersion: "ssc-init.scan.v4", ScanID: "scan-isolated", Status: model.ScanComplete, StartedAt: now, FinishedAt: now},
		inventory: model.Inventory{Assets: []model.Asset{}, Observations: []model.Observation{}, Evidence: []model.ContentEvidence{}, Relationships: []model.Relationship{}, Errors: []model.CoverageError{}},
		delta:     model.Delta{Changes: []model.Change{}},
	}
	document := loadPolicyAcceptanceDocument(t, now, "")
	outputs := make([]string, 2)
	for index, app := range []cli.App{{BaselineScanner: scanner}, {BaselineScanner: scanner, PolicyDocument: document}} {
		var stdout, stderr bytes.Buffer
		if code := app.Run(context.Background(), []string{"scan", "--baseline", "--json"}, &stdout, &stderr); code != 0 {
			t.Fatalf("scan %d code=%d stderr=%s", index, code, stderr.String())
		}
		outputs[index] = stdout.String()
	}
	if outputs[0] != outputs[1] || strings.Contains(strings.ToLower(outputs[0]), "policy") {
		t.Fatalf("policy changed scan contract:\nwithout=%s\nwith=%s", outputs[0], outputs[1])
	}
}

func TestPolicyLifecycleAgainstAnIsolatedHome(t *testing.T) {
	ctx := context.Background()
	opened, err := store.Open(filepath.Join(privateMatrixTempDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	assetID := "agent-plugin:claude:helpful-utils@1.0.0"
	projectID := "project:sha256:" + strings.Repeat("c", 64)
	state := &policyAcceptanceState{Store: opened, snapshot: policySnapshotAt(assetID, projectID, strings.Repeat("a", 64), now)}

	starter, err := policy.Load(policy.Starter())
	if err != nil {
		t.Fatal(err)
	}
	if code, payload := runPolicyAcceptanceCheck(t, state, starter, now); code != 0 || len(payload.Violations) != 0 {
		t.Fatalf("inert starter code=%d payload=%+v", code, payload)
	}

	enabled := loadPolicyAcceptanceDocument(t, now, "")
	if code, payload := runPolicyAcceptanceCheck(t, state, enabled, now); code != 3 || len(payload.Violations) != 1 || payload.Violations[0].RuleID != "unpinned" {
		t.Fatalf("unpinned code=%d payload=%+v", code, payload)
	}

	app := cli.App{StatusReader: state, PolicyStore: state, Now: func() time.Time { return now }}
	var stdout, stderr bytes.Buffer
	if code := app.Run(ctx, []string{"policy", "pin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("pin code=%d stderr=%s", code, stderr.String())
	}
	if code, payload := runPolicyAcceptanceCheck(t, state, enabled, now); code != 0 || len(payload.Violations) != 0 {
		t.Fatalf("pinned code=%d payload=%+v", code, payload)
	}

	state.snapshot = policySnapshotAt(assetID, projectID, strings.Repeat("b", 64), now.Add(time.Hour))
	if code, payload := runPolicyAcceptanceCheck(t, state, enabled, now); code != 3 || len(payload.Violations) != 1 || payload.Violations[0].RuleID != "pin-mismatch" {
		t.Fatalf("mismatch code=%d payload=%+v", code, payload)
	}

	expires := now.Add(30 * 24 * time.Hour)
	excepted := loadPolicyAcceptanceDocument(t, now, fmt.Sprintf(
		`,"exceptions":[{"ruleId":"pin-mismatch","scope":"project","projectId":"%s","reason":"temporary migration","expiresAt":"%s"}]`,
		projectID, expires.Format(time.RFC3339)))
	if code, payload := runPolicyAcceptanceCheck(t, state, excepted, now); code != 0 || len(payload.Applied) != 1 {
		t.Fatalf("exception code=%d payload=%+v", code, payload)
	}
	if code, payload := runPolicyAcceptanceCheck(t, state, excepted, expires.Add(time.Second)); code != 3 || len(payload.Violations) != 1 || len(payload.Expired) != 1 {
		t.Fatalf("expired code=%d payload=%+v", code, payload)
	}
}

func policySnapshotAt(assetID, projectID, digest string, at time.Time) model.Snapshot {
	return model.Snapshot{
		Scan: model.ScanResult{SchemaVersion: "ssc-init.scan.v4", ScanID: "scan-1", Status: model.ScanComplete, FinishedAt: at},
		Inventory: model.Inventory{
			Assets:       []model.Asset{{ID: assetID, Type: model.AssetAgentPlugin, Name: "helpful-utils", Version: "1.0.0", Source: "claude"}},
			Observations: []model.Observation{{AssetID: assetID, ProjectID: projectID}},
			Evidence:     []model.ContentEvidence{{AssetID: assetID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidenceComplete, Digest: digest}},
		},
	}
}

func loadPolicyAcceptanceDocument(t *testing.T, now time.Time, exceptions string) policy.Document {
	t.Helper()
	source := fmt.Sprintf(`{"schemaVersion":"ssc-init.policy.v1","rules":[
		{"id":"unpinned","family":"pin","enabled":true,"description":"require a pin"},
		{"id":"pin-mismatch","family":"pin","enabled":true,"description":"require the pinned digest"}
	]%s}`, exceptions)
	document, err := policy.Load([]byte(source))
	if err != nil {
		t.Fatalf("load policy at %s: %v", now, err)
	}
	return document
}

func runPolicyAcceptanceCheck(t *testing.T, state *policyAcceptanceState, document policy.Document, now time.Time) (int, policyAcceptancePayload) {
	t.Helper()
	app := cli.App{StatusReader: state, PolicyStore: state, PolicyDocument: document, Now: func() time.Time { return now }}
	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), []string{"policy", "check"}, &stdout, &stderr)
	if code != 0 && code != 3 {
		t.Fatalf("policy check code=%d stderr=%s", code, stderr.String())
	}
	var payload policyAcceptancePayload
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode policy output: %v; stdout=%q", err, stdout.String())
	}
	return code, payload
}
