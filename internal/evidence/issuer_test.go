package evidence

import (
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestIssuerRejectsEveryMutatedTargetField(t *testing.T) {
	issuer := NewIssuer()
	original := issuer.Issue(model.LocalEvidenceTarget{
		TargetID: "agents.codex.skills.content", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectSkillDocument,
		RootPath: "/runtime/root", RelativePath: "fixture/SKILL.md",
	}, Anchor{Root: platform.FileFingerprint{Device: 1, Inode: 2}})
	mutations := []func(*model.LocalEvidenceTarget){
		func(v *model.LocalEvidenceTarget) { v.TargetID = "other" },
		func(v *model.LocalEvidenceTarget) { v.AssetID = "other" },
		func(v *model.LocalEvidenceTarget) { v.ObservationID = "other" },
		func(v *model.LocalEvidenceTarget) { v.Kind = model.EvidenceTreeSHA256 },
		func(v *model.LocalEvidenceTarget) { v.Subject = model.EvidenceSubjectManifest },
		func(v *model.LocalEvidenceTarget) { v.PresetStatus = model.EvidenceSkipped },
		func(v *model.LocalEvidenceTarget) { v.RootPath = "/other/root" },
		func(v *model.LocalEvidenceTarget) { v.RelativePath = "../escape" },
	}
	for _, mutate := range mutations {
		candidate := original
		mutate(&candidate)
		if _, ok := verifyIssuedTarget(candidate); ok {
			t.Fatalf("mutation accepted: %+v", candidate)
		}
	}
}

func TestIssuerRejectsProvenanceCopiedAcrossTargets(t *testing.T) {
	first := NewIssuer().Issue(model.LocalEvidenceTarget{
		TargetID: "one", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "one.json",
	}, Anchor{})
	second := NewIssuer().Issue(model.LocalEvidenceTarget{
		TargetID: "two", AssetID: "asset", ObservationID: "observation",
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: "/runtime/root", RelativePath: "two.json",
	}, Anchor{})
	second.Provenance = first.Provenance
	if _, ok := verifyIssuedTarget(second); ok {
		t.Fatal("foreign provenance accepted")
	}
}
