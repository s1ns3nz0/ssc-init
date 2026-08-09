package adapter

import (
	"reflect"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/finding"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestEvaluateSelectsUrgentFindingsWithoutChangingCoreVerdict(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	input := finding.Result{Intelligence: "fresh", Policy: "fresh", Findings: []model.Finding{
		adapterFinding("finding:medium", "asset:medium", model.SeverityMedium, model.VerdictNeedsReview, model.ActionAdvisory, now),
		adapterFinding("finding:critical-b", "asset:critical-b", model.SeverityCritical, model.VerdictKnownMalicious, model.ActionBlocked, now),
		adapterFinding("finding:low", "asset:low", model.SeverityLow, model.VerdictSuspicious, model.ActionAdvisory, now),
		adapterFinding("finding:high", "asset:high", model.SeverityHigh, model.VerdictBehaviorMalicious, model.ActionPaused, now),
		adapterFinding("finding:info", "asset:info", model.SeverityInformational, model.VerdictNoFinding, model.ActionAllowed, now),
		adapterFinding("finding:critical-a", "asset:critical-a", model.SeverityCritical, model.VerdictKnownMalicious, model.ActionBlocked, now),
	}}
	original := append([]model.Finding(nil), input.Findings...)
	invocation := Invocation{SchemaVersion: SchemaV1, Host: HostClaude, Event: EventPostExecution, Capability: CapabilityAdvisory}

	got, err := Evaluate(invocation, input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input.Findings, original) {
		t.Fatal("core findings were mutated")
	}
	wantIDs := []string{"finding:critical-a", "finding:critical-b", "finding:high", "finding:medium", "finding:low"}
	if len(got.Findings) != len(wantIDs) {
		t.Fatalf("findings=%+v", got.Findings)
	}
	for index, view := range got.Findings {
		if view.ID != wantIDs[index] {
			t.Fatalf("finding order=%+v", got.Findings)
		}
		var source model.Finding
		for _, candidate := range input.Findings {
			if candidate.ID == view.ID {
				source = candidate
			}
		}
		if view.Verdict != source.Verdict || view.Severity != source.Severity || view.Confidence != source.Confidence || view.Action != source.Action || !reflect.DeepEqual(view.RuleIDs, source.RuleIDs) {
			t.Fatalf("core verdict changed: view=%+v source=%+v", view, source)
		}
	}
	if !got.Valid() {
		t.Fatalf("invalid result: %+v", got)
	}
}

func TestEvaluateKeepsVerdictPayloadIdenticalAcrossHosts(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	input := finding.Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{
		adapterFinding("finding:one", "asset:one", model.SeverityHigh, model.VerdictSuspicious, model.ActionAdvisory, now),
	}}
	var baseline []FindingView
	for _, host := range []Host{HostClaude, HostCodex, HostCursor} {
		got, err := Evaluate(Invocation{SchemaVersion: SchemaV1, Host: host, Event: EventPostExecution, Capability: CapabilityAdvisory}, input)
		if err != nil {
			t.Fatal(err)
		}
		if baseline == nil {
			baseline = got.Findings
		} else if !reflect.DeepEqual(got.Findings, baseline) {
			t.Fatalf("host %q changed verdict payload: %+v != %+v", host, got.Findings, baseline)
		}
	}
}

func TestEvaluateLimitsOutputToExplicitCanonicalAssets(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	input := finding.Result{Intelligence: "fresh", Policy: "inactive", Findings: []model.Finding{
		adapterFinding("finding:one", "asset:one", model.SeverityHigh, model.VerdictSuspicious, model.ActionAdvisory, now),
		adapterFinding("finding:two", "asset:two", model.SeverityCritical, model.VerdictKnownMalicious, model.ActionBlocked, now),
	}}
	got, err := Evaluate(Invocation{SchemaVersion: SchemaV1, Host: HostCursor, Event: EventPreExecution, Capability: CapabilityAdvisory, AssetIDs: []string{"asset:one"}}, input)
	if err != nil || len(got.Findings) != 1 || got.Findings[0].AssetID != "asset:one" {
		t.Fatalf("evaluation=%+v err=%v", got, err)
	}
}

func TestEvaluateRejectsInvalidInvocationAndFinding(t *testing.T) {
	if _, err := Evaluate(Invocation{}, finding.Result{}); err == nil || err.Error() != "invalid adapter invocation" {
		t.Fatalf("invalid invocation err=%v", err)
	}
	bad := adapterFinding("finding:bad", "asset:bad", model.SeverityHigh, model.VerdictSuspicious, model.ActionAdvisory, time.Unix(10, 0).UTC())
	bad.RuleIDs = []string{"/Users/private/rule"}
	invocation := Invocation{SchemaVersion: SchemaV1, Host: HostCodex, Event: EventOnDemand, Capability: CapabilityOnDemand}
	if _, err := Evaluate(invocation, finding.Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{bad}}); err == nil || err.Error() != "invalid adapter finding" {
		t.Fatalf("invalid finding err=%v", err)
	}
}

func adapterFinding(id, assetID string, severity model.Severity, verdict model.Verdict, action model.FindingAction, now time.Time) model.Finding {
	return model.Finding{ID: id, AssetID: assetID, AssetType: model.AssetAgentPlugin, Verdict: verdict, Severity: severity, Confidence: model.ConfidenceHigh, Level: 1, RuleIDs: []string{"ssc-init/test"}, DetectedAt: now, Action: action}
}
