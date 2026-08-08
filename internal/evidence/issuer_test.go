package evidence

import (
	"context"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

func TestBindCollectorResultIssuesSiblingTargetsUntilRuntimeClear(t *testing.T) {
	result := model.CollectorResult{Collector: "fixture"}
	issuer := BindCollectorResult(&result)
	firstObservation, err := identity.FinalizeObservation(model.Observation{AssetID: "asset", Collector: "fixture", Scope: model.ScopeUser, LocationRef: "$HOME/fixture/first"})
	if err != nil {
		t.Fatal(err)
	}
	secondObservation, err := identity.FinalizeObservation(model.Observation{AssetID: "asset", Collector: "fixture", Scope: model.ScopeUser, LocationRef: "$HOME/fixture/second"})
	if err != nil {
		t.Fatal(err)
	}
	firstValue := model.LocalEvidenceTarget{TargetID: "fixture.first", AssetID: "asset", ObservationID: firstObservation.ID, Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration}
	secondValue := firstValue
	secondValue.TargetID = "fixture.second"
	secondValue.ObservationID = secondObservation.ID
	first := issuer.Issue(firstValue, Anchor{})
	rebound := BindCollectorResult(&result)
	if rebound != issuer {
		t.Fatalf("active issuer was replaced: first=%p rebound=%p", issuer, rebound)
	}
	if _, _, ok := verifyIssuedTarget(first, rebound); !ok {
		t.Fatal("already-issued sibling stopped verifying after repeated bind")
	}
	second := rebound.Issue(secondValue, Anchor{})
	result.LocalEvidenceTargets = []model.LocalEvidenceTarget{first, second}

	if result.LocalEvidenceIssuer != issuer {
		t.Fatal("issuer was not bound to collector result")
	}
	if _, _, ok := verifyIssuedTarget(first, issuer); !ok {
		t.Fatal("first sibling did not verify")
	}
	if _, _, ok := verifyIssuedTarget(second, issuer); !ok {
		t.Fatal("second sibling did not verify")
	}
	got := (Engine{SemanticHasher: func(model.Observation) (string, error) { return strings.Repeat("a", 64), nil }}).Collect(context.Background(), collector.Environment{}, model.Inventory{
		Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{firstObservation, secondObservation},
	}, []model.CollectorResult{result})
	if len(got.Evidence) != 2 || got.Evidence[0].Status != model.EvidenceComplete || got.Evidence[1].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v", got)
	}
	if issuer.Issue(firstValue, Anchor{}).Provenance != nil {
		t.Fatal("cleared bound issuer issued another target")
	}
}

type foreignRuntimeClearer struct{ calls int }

func (value *foreignRuntimeClearer) ClearRuntimeEvidence() { value.calls++ }

func TestBindCollectorResultFailsClosedForInactiveOrForeignLifecycle(t *testing.T) {
	t.Run("inactive issuer", func(t *testing.T) {
		result := model.CollectorResult{}
		inactive := BindCollectorResult(&result)
		inactive.ClearRuntimeEvidence()

		if got := BindCollectorResult(&result); got != nil {
			t.Fatalf("inactive lifecycle was silently replaced: %p", got)
		}
		if result.LocalEvidenceIssuer != inactive {
			t.Fatal("failed bind mutated the existing inactive lifecycle")
		}
	})

	t.Run("foreign clearer", func(t *testing.T) {
		foreign := &foreignRuntimeClearer{}
		result := model.CollectorResult{LocalEvidenceIssuer: foreign}

		if got := BindCollectorResult(&result); got != nil {
			t.Fatalf("foreign lifecycle was silently replaced: %p", got)
		}
		if result.LocalEvidenceIssuer != foreign || foreign.calls != 0 {
			t.Fatalf("failed bind changed foreign lifecycle: hook=%T calls=%d", result.LocalEvidenceIssuer, foreign.calls)
		}
	})
}

func TestIssuerRejectsIdenticalTargetProofFromUnexpectedIssuer(t *testing.T) {
	target := model.LocalEvidenceTarget{
		TargetID: "fixture.manifest", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "asset/manifest.json",
	}
	anchor := issuerAnchorFixture()
	expected := NewIssuer()
	foreign := NewIssuer()
	candidate := expected.Issue(target, anchor)
	candidate.Provenance = foreign.Issue(target, anchor).Provenance
	if _, _, ok := verifyIssuedTarget(candidate, expected); ok {
		t.Fatal("identical-field proof from another issuer accepted")
	}
}

func TestClearedIssuerCannotIssueAgain(t *testing.T) {
	issuer := NewIssuer()
	target := model.LocalEvidenceTarget{
		TargetID: "fixture.manifest", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "asset/manifest.json",
	}
	issuer.clearRuntime()

	issued := issuer.Issue(target, issuerAnchorFixture())
	if issued.Provenance != nil {
		t.Fatal("cleared issuer attached new provenance")
	}
	if _, _, ok := verifyIssuedTarget(issued, issuer); ok {
		t.Fatal("cleared issuer verified a new target")
	}
}

func TestIssuerRejectsEveryMutatedTargetField(t *testing.T) {
	issuer := NewIssuer()
	original := issuer.Issue(model.LocalEvidenceTarget{
		TargetID: "fixture.manifest", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "asset/manifest.json",
	}, issuerAnchorFixture())
	mutations := []func(*model.LocalEvidenceTarget){
		func(v *model.LocalEvidenceTarget) { v.TargetID = "fixture.other" },
		func(v *model.LocalEvidenceTarget) { v.AssetID = "other" },
		func(v *model.LocalEvidenceTarget) { v.ObservationID = "other" },
		func(v *model.LocalEvidenceTarget) { v.Kind = model.EvidenceTreeSHA256 },
		func(v *model.LocalEvidenceTarget) { v.Subject = model.EvidenceSubjectPayloadTree },
		func(v *model.LocalEvidenceTarget) { v.PresetStatus = model.EvidenceSkipped },
		func(v *model.LocalEvidenceTarget) { v.RootPath = "/other/root" },
		func(v *model.LocalEvidenceTarget) { v.RelativePath = "asset/other.json" },
	}
	for index, mutate := range mutations {
		candidate := original
		mutate(&candidate)
		if _, _, ok := verifyIssuedTarget(candidate, issuer); ok {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

func TestIssuerRejectsEveryMutatedAnchorField(t *testing.T) {
	issuer := NewIssuer()
	original := issuer.Issue(model.LocalEvidenceTarget{
		TargetID: "fixture.manifest", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "asset/manifest.json",
	}, issuerAnchorFixture())
	mutations := []func(*Anchor){
		func(v *Anchor) { v.Root.Device++ },
		func(v *Anchor) { v.AssetRoot.Inode++ },
		func(v *Anchor) { v.AssetRelativePath = "other" },
		func(v *Anchor) { v.RelativePath = "asset/other.json" },
		func(v *Anchor) { v.Digest = strings.Repeat("b", 64) },
		func(v *Anchor) { v.Size++ },
		func(v *Anchor) { v.Mode++ },
		func(v *Anchor) { v.Fingerprint.ChangeTimeNS++ },
		func(v *Anchor) { v.MaxBytes++ },
	}
	for index, mutate := range mutations {
		candidate := original
		proof := *(candidate.Provenance.(*issuedTargetProof))
		mutate(&proof.anchor)
		candidate.Provenance = &proof
		if _, _, ok := verifyIssuedTarget(candidate, issuer); ok {
			t.Fatalf("anchor mutation %d accepted", index)
		}
	}
}

func issuerAnchorFixture() Anchor {
	return Anchor{
		Root:              platform.FileFingerprint{Device: 1, Inode: 2, Mode: 3, Size: 4, ModTimeNS: 5, ChangeTimeNS: 6},
		AssetRoot:         platform.FileFingerprint{Device: 7, Inode: 8, Mode: 9, Size: 10, ModTimeNS: 11, ChangeTimeNS: 12},
		AssetRelativePath: "asset", RelativePath: "asset/manifest.json", Digest: strings.Repeat("a", 64),
		Size: 13, Mode: 0o600, Fingerprint: platform.FileFingerprint{Device: 14, Inode: 15, Mode: 16, Size: 13, ModTimeNS: 17, ChangeTimeNS: 18}, MaxBytes: 64,
	}
}
