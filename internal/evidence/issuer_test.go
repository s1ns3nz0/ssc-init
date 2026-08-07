package evidence

import (
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

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
