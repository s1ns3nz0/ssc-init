package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/adapter"
	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type adapterSnapshot struct{ inventory model.Inventory }

func (s adapterSnapshot) LatestSnapshot(context.Context) (model.Snapshot, bool, error) {
	return model.Snapshot{Inventory: s.inventory}, true, nil
}

type adapterFindings struct{ result finding.Result }

func (s adapterFindings) Evaluate(context.Context, model.Inventory) (finding.Result, error) {
	return s.result, nil
}

func TestClaudeCodexCursorProduceTheSameCoreVerdict(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	asset := model.Asset{ID: "agent-plugin:shared:fixture@1.0.0", Type: model.AssetAgentPlugin, Name: "fixture", Version: "1.0.0"}
	result := finding.Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{{
		ID: "finding:shared", AssetID: asset.ID, AssetType: asset.Type, Version: asset.Version,
		Verdict: model.VerdictSuspicious, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
		Level: 4, RuleIDs: []string{"ssc-init/flow/credential-egress"}, DetectedAt: now, Action: model.ActionAdvisory,
	}}}
	var baseline []adapter.FindingView
	for _, host := range []adapter.Host{adapter.HostClaude, adapter.HostCodex, adapter.HostCursor} {
		input := fmt.Sprintf(`{"schemaVersion":"%s","host":"%s","event":"on-demand","capability":"on-demand","assetIds":[%q]}`, adapter.SchemaV1, host, asset.ID)
		app := cli.App{AdapterInput: bytes.NewBufferString(input), StatusReader: adapterSnapshot{inventory: model.Inventory{Assets: []model.Asset{asset}}}, FindingService: adapterFindings{result: result}}
		var stdout, stderr bytes.Buffer
		if code := app.Run(context.Background(), []string{"adapter", "evaluate"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("host=%q code=%d stderr=%q", host, code, stderr.String())
		}
		var evaluation adapter.Evaluation
		if err := json.Unmarshal(stdout.Bytes(), &evaluation); err != nil || !evaluation.Valid() || evaluation.Intelligence != "unavailable" || evaluation.Policy != "inactive" {
			t.Fatalf("host=%q evaluation=%+v err=%v", host, evaluation, err)
		}
		if baseline == nil {
			baseline = evaluation.Findings
		} else if !reflect.DeepEqual(evaluation.Findings, baseline) {
			t.Fatalf("host=%q changed core verdict: %+v != %+v", host, evaluation.Findings, baseline)
		}
	}
}

func TestAdapterBenignTwinSaysNoFindingWithoutSafeClaim(t *testing.T) {
	input := `{"schemaVersion":"ssc-init.adapter-invocation.v1","host":"cursor","event":"on-demand","capability":"on-demand"}`
	app := cli.App{AdapterInput: bytes.NewBufferString(input), StatusReader: adapterSnapshot{}, FindingService: adapterFindings{result: finding.Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{}}}}
	var stdout, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"adapter", "evaluate"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if bytes.Contains(bytes.ToLower(stdout.Bytes()), []byte(`"safe"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"findings":[]`)) {
		t.Fatalf("misleading benign response: %s", stdout.Bytes())
	}
}
