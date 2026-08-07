package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestEngineRejectsUnexpectedIssuerAndWrongCollectorBeforeOpeningRoot(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name   string
		mutate func(*model.CollectorResult, *model.Observation)
	}{
		{name: "unexpected-issuer", mutate: func(result *model.CollectorResult, _ *model.Observation) { result.LocalEvidenceIssuer = NewIssuer() }},
		{name: "wrong-result-collector", mutate: func(result *model.CollectorResult, _ *model.Observation) { result.Collector = "other" }},
		{name: "wrong-observation-collector", mutate: func(_ *model.CollectorResult, observation *model.Observation) { observation.Collector = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := NewIssuer()
			target := fixture.fileTarget(issuer, "fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			observation := fixture.observation
			result := model.CollectorResult{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}
			test.mutate(&result, &observation)
			recorder := &recordingSessionFS{}
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventoryWith(observation), []model.CollectorResult{result})
			assertRejectedWithoutOpen(t, got, recorder)
		})
	}
}

func TestEngineClearsFullCapacityAndBothIssuersOnEarlyForeignIssuerRejection(t *testing.T) {
	fixture := newEngineFixture(t)
	expected := NewIssuer()
	foreign := NewIssuer()
	target := fixture.fileTarget(foreign, "fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
	proof := target.Provenance.(*issuedTargetProof)
	backing := make([]model.LocalEvidenceTarget, 1, 3)
	backing[0] = target
	full := backing[:cap(backing)]
	full[1], full[2] = target, target
	results := []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: expected, LocalEvidenceTargets: backing}}
	recorder := &recordingSessionFS{}

	got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), results)

	assertRejectedWithoutOpen(t, got, recorder)
	assertRuntimeCleared(t, results, full, expected, proof)
	if foreign.nonce != ([sha256.Size]byte{}) || foreign.active {
		t.Fatal("foreign issuer nonce survived")
	}
}

func TestEngineClearsDistinctProofsStoredOnlyInSpareCapacity(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	logical := fixture.fileTarget(issuer, "fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
	spareOne := fixture.fileTarget(issuer, "fixture.spare-one", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
	spareTwo := fixture.fileTarget(issuer, "fixture.spare-two", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
	proofs := []*issuedTargetProof{
		logical.Provenance.(*issuedTargetProof),
		spareOne.Provenance.(*issuedTargetProof),
		spareTwo.Provenance.(*issuedTargetProof),
	}
	backing := make([]model.LocalEvidenceTarget, 1, 3)
	full := backing[:cap(backing)]
	full[0], full[1], full[2] = logical, spareOne, spareTwo
	results := []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: backing}}

	got := (Engine{}).Collect(context.Background(), collector.Environment{FS: platform.OSFileSystem{}}, fixture.inventory(), results)

	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("collection=%+v", got)
	}
	for index, proof := range proofs {
		if proof.issuer != nil || proof.anchor != (Anchor{}) || proof.canonical != ([sha256.Size]byte{}) || proof.seal != ([sha256.Size]byte{}) {
			t.Fatalf("proof[%d] survived: %+v", index, proof)
		}
	}
	if issuer.nonce != ([sha256.Size]byte{}) || issuer.active || results[0].LocalEvidenceIssuer != nil || results[0].LocalEvidenceTargets != nil {
		t.Fatalf("issuer/result survived issuer=%+v result=%+v", issuer, results[0])
	}
	for index := range full {
		if full[index] != (model.LocalEvidenceTarget{}) {
			t.Fatalf("full[%d]=%+v", index, full[index])
		}
	}
}

func TestEngineRejectsInvalidTargetContractBeforeOpeningRoot(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name   string
		target func(*Issuer) (model.LocalEvidenceTarget, Anchor)
	}{
		{name: "path-target-id", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("fixture/secret")
			return v, a
		}},
		{name: "control-target-id", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("fixture.bad\nvalue")
			return v, a
		}},
		{name: "collector-prefix", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("other.semantic")
			return v, a
		}},
		{name: "kind-subject", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("fixture.semantic")
			v.Subject = model.EvidenceSubjectManifest
			return v, a
		}},
		{name: "semantic-path", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("fixture.semantic")
			v.RootPath = fixture.root
			return v, a
		}},
		{name: "semantic-anchor", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, _ := fixture.semanticTarget("fixture.semantic")
			return v, fixture.anchor
		}},
		{name: "package-attempt", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			return model.LocalEvidenceTarget{TargetID: "fixture.package", AssetID: fixture.assetID, ObservationID: fixture.observation.ID, Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent}, Anchor{}
		}},
		{name: "preset-path", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v, a := fixture.semanticTarget("fixture.semantic")
			v.PresetStatus, v.RootPath = model.EvidenceUnsupported, fixture.root
			return v, a
		}},
		{name: "file-no-root-anchor", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.Root = platform.FileFingerprint{}
			return v, a
		}},
		{name: "file-no-asset-anchor", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.AssetRoot = platform.FileFingerprint{}
			return v, a
		}},
		{name: "file-no-content-anchor", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.RelativePath, a.Digest, a.Fingerprint = "", "", platform.FileFingerprint{}
			return v, a
		}},
		{name: "file-bad-max", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.MaxBytes = 0
			return v, a
		}},
		{name: "content-anchor-size-conflict", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.Fingerprint.Size++
			return v, a
		}},
		{name: "content-anchor-mode-conflict", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			a := fixture.anchor
			a.Mode ^= 0o100
			return v, a
		}},
		{name: "tree-content-outside-asset", target: func(_ *Issuer) (model.LocalEvidenceTarget, Anchor) {
			v := fixture.treeTargetValue("fixture.tree")
			a := fixture.anchor
			a.RelativePath = "sibling/manifest.json"
			return v, a
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := NewIssuer()
			value, anchor := test.target(issuer)
			target := issuer.Issue(value, anchor)
			recorder := &recordingSessionFS{}
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
			assertRejectedWithoutOpen(t, got, recorder)
		})
	}
}

func TestEngineAcceptsIssuedUnsafeRelativePathAsTerminalPathInvalid(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	value := fixture.fileTargetValue("fixture.entrypoint", model.EvidenceSubjectEntrypointMain, "asset/../outside.js")
	target := issuer.Issue(value, fixture.anchor)
	recorder := &recordingSessionFS{}
	got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || !hasEvidenceError(got.Evidence[0], "path_invalid") || recorder.absoluteOpenCount() != 0 {
		t.Fatalf("collection=%+v opens=%v", got, recorder.opened())
	}
}

func TestEngineRejectsEveryDuplicateTargetAndEvidenceIdentity(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name    string
		targets func(*Issuer) []model.LocalEvidenceTarget
	}{
		{name: "target-id", targets: func(issuer *Issuer) []model.LocalEvidenceTarget {
			first, anchor := fixture.semanticTarget("fixture.duplicate")
			second := first
			return []model.LocalEvidenceTarget{issuer.Issue(first, anchor), issuer.Issue(second, anchor)}
		}},
		{name: "evidence-id", targets: func(issuer *Issuer) []model.LocalEvidenceTarget {
			first, anchor := fixture.semanticTarget("fixture.first")
			second := first
			second.TargetID = "fixture.second"
			return []model.LocalEvidenceTarget{issuer.Issue(first, anchor), issuer.Issue(second, anchor)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := NewIssuer()
			targets := test.targets(issuer)
			recorder := &recordingSessionFS{}
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: targets}})
			if len(got.Evidence) != 0 || len(got.Coverage.Targets) != 0 || len(got.Coverage.Errors) != 2 || recorder.absoluteOpenCount() != 0 {
				t.Fatalf("collection=%+v opens=%v", got, recorder.opened())
			}
		})
	}
}

func TestEngineRejectsDuplicateGraphIDsBeforeOpeningRoot(t *testing.T) {
	fixture := newEngineFixture(t)
	for _, name := range []string{"asset", "observation"} {
		t.Run(name, func(t *testing.T) {
			issuer := NewIssuer()
			target := fixture.fileTarget(issuer, "fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative)
			inventory := fixture.inventory()
			if name == "asset" {
				inventory.Assets = append(inventory.Assets, inventory.Assets[0])
			} else {
				inventory.Observations = append(inventory.Observations, inventory.Observations[0])
			}
			recorder := &recordingSessionFS{}
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, inventory, []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
			assertRejectedWithoutOpen(t, got, recorder)
		})
	}
}

func TestEngineRejectsObservationsWhoseCurrentFieldsDoNotReproduceStoredIdentity(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name      string
		collector string
		mutate    func(*model.Observation)
	}{
		{name: "coordinated-origin-and-semantic-mutation", collector: "other", mutate: func(value *model.Observation) {
			value.Collector = "other"
			value.Source = "other.source"
			value.Consumers = []string{"other"}
			value.Metadata = map[string]string{"safe": "changed"}
		}},
		{name: "stale-metadata", collector: "fixture", mutate: func(value *model.Observation) {
			value.Metadata = map[string]string{"safe": "changed"}
		}},
		{name: "stale-consumers", collector: "fixture", mutate: func(value *model.Observation) {
			value.Consumers = []string{"changed"}
		}},
		{name: "stale-source", collector: "fixture", mutate: func(value *model.Observation) {
			value.Source = "changed.source"
		}},
		{name: "malformed-required-field", collector: "fixture", mutate: func(value *model.Observation) {
			value.LocationRef = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := cloneObservation(fixture.observation)
			test.mutate(&observation)
			issuer := NewIssuer()
			target := issuer.Issue(model.LocalEvidenceTarget{
				TargetID: test.collector + ".semantic", AssetID: fixture.assetID, ObservationID: observation.ID,
				Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration,
			}, Anchor{})
			var calls atomic.Int32
			got := (Engine{ContextSemanticHasher: func(context.Context, model.Observation) (string, error) {
				calls.Add(1)
				return strings.Repeat("a", 64), nil
			}}).Collect(context.Background(), collector.Environment{}, model.Inventory{
				Assets: []model.Asset{{ID: fixture.assetID}}, Observations: []model.Observation{observation},
			}, []model.CollectorResult{{Collector: test.collector, LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
			if len(got.Evidence) != 0 || len(got.Coverage.Targets) != 0 || len(got.Coverage.Errors) != 1 || got.Coverage.Errors[0].Code != "target_rejected" || calls.Load() != 0 {
				t.Fatalf("calls=%d collection=%+v", calls.Load(), got)
			}
		})
	}
}

func TestEngineUsesHeldDistinctRootAndAssetDescriptorsForManifestAnchoredEntrypoint(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	target := fixture.fileTarget(issuer, "fixture.entrypoint", model.EvidenceSubjectEntrypointMain, fixture.entrypointRootRelative)
	recorder := &recordingSessionFS{delegate: platform.OSFileSystem{}}
	got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	want := sha256.Sum256([]byte("entrypoint"))
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceComplete || got.Evidence[0].Digest != hex.EncodeToString(want[:]) {
		t.Fatalf("collection=%+v", got)
	}
	if recorder.absoluteOpenCount() != 2 || recorder.relativeOpenCount("asset") != 2 || recorder.absoluteOpened(fixture.asset) {
		t.Fatalf("descriptor opens=%v", recorder.opened())
	}
	if !recorder.allClosed() {
		t.Fatalf("unclosed descriptors=%v", recorder.closeState())
	}
}

func TestEngineSupportsFileTargetWhoseAssetIsTheCatalogRoot(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "go.mod")
	contents := []byte("module example.invalid/root\n")
	if err := os.WriteFile(manifest, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	observation := finalizedEvidenceObservation(t, "asset")
	observation.ID = ""
	observation.Collector = "projects"
	var err error
	observation, err = identity.FinalizeObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	rootFingerprint := fileFingerprint(t, root)
	anchor := Anchor{
		Root: rootFingerprint, AssetRoot: rootFingerprint, AssetRelativePath: "",
		RelativePath: "go.mod", Digest: hex.EncodeToString(digest[:]), Size: int64(len(contents)),
		Mode: 0o600, Fingerprint: fileFingerprint(t, manifest), MaxBytes: 32 << 20,
	}
	issuer := NewIssuer()
	target := issuer.Issue(model.LocalEvidenceTarget{
		TargetID: "projects.go-mod", AssetID: "asset", ObservationID: observation.ID,
		Kind: model.EvidenceFileSHA256, Subject: "project-manifest:go.mod", RootPath: root, RelativePath: "go.mod",
	}, anchor)
	recorder := &recordingSessionFS{delegate: platform.OSFileSystem{}}

	got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, model.Inventory{
		Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation},
	}, []model.CollectorResult{{Collector: "projects", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})

	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceComplete || got.Evidence[0].Digest != hex.EncodeToString(digest[:]) {
		t.Fatalf("collection=%+v", got)
	}
	if recorder.relativeOpenCount(".") != 0 || !recorder.allClosed() {
		t.Fatalf("opens=%v closes=%v", recorder.opened(), recorder.closeState())
	}
}

func TestEngineRejectsInvalidSameRootAssetBindingsBeforeOpen(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name   string
		mutate func(*Anchor)
	}{
		{name: "empty-path-mismatched-fingerprint", mutate: func(anchor *Anchor) { anchor.AssetRelativePath = "" }},
		{name: "nonempty-path-same-fingerprint", mutate: func(anchor *Anchor) { anchor.AssetRoot = anchor.Root }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := fixture.anchor
			test.mutate(&anchor)
			issuer := NewIssuer()
			target := issuer.Issue(fixture.fileTargetValue("fixture.manifest", model.EvidenceSubjectManifest, fixture.manifestRootRelative), anchor)
			recorder := &recordingSessionFS{}
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
			assertRejectedWithoutOpen(t, got, recorder)
		})
	}
}

func TestEngineRejectsRootAssetAndContentAnchorSwaps(t *testing.T) {
	fixture := newEngineFixture(t)
	tests := []struct {
		name   string
		mutate func()
	}{
		{name: "root", mutate: func() {
			if err := os.Chmod(fixture.root, 0o711); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "asset", mutate: func() {
			if err := os.Chmod(fixture.asset, 0o711); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "content", mutate: func() {
			if err := os.WriteFile(fixture.manifest, []byte("changed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fresh := newEngineFixture(t)
			fixture = fresh
			issuer := NewIssuer()
			target := fixture.fileTarget(issuer, "fixture.entrypoint", model.EvidenceSubjectEntrypointMain, fixture.entrypointRootRelative)
			test.mutate()
			got := (Engine{}).Collect(context.Background(), collector.Environment{FS: platform.OSFileSystem{}}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
			if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || got.Evidence[0].Digest != "" || !hasEvidenceError(got.Evidence[0], "identity_changed") || len(got.CacheWrites) != 0 {
				t.Fatalf("collection=%+v", got)
			}
		})
	}
}

func TestEngineDiscardsDigestAndCacheWritesWhenAnchorChangesDuringCollection(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	treeAnchor := fixture.anchor
	treeAnchor.MaxBytes = 0
	target := issuer.Issue(fixture.treeTargetValue("fixture.tree"), treeAnchor)
	var calls atomic.Int32
	ctx := context.WithValue(context.Background(), afterOpenFileContextKey{}, func() {
		if calls.Add(1) == 2 {
			if err := os.Chmod(fixture.asset, 0o711); err != nil {
				panic(err)
			}
		}
	})
	got := (Engine{Cache: newRecordingLeafCache()}).Collect(ctx, collector.Environment{FS: platform.OSFileSystem{}}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || got.Evidence[0].Digest != "" || len(got.CacheWrites) != 0 || !hasEvidenceError(got.Evidence[0], "identity_changed") {
		t.Fatalf("calls=%d collection=%+v", calls.Load(), got)
	}
}

func TestEngineRebindsRootAndAssetPathnamesAfterCollection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*engineFixture)
	}{
		{name: "catalog-root-renamed-and-replaced", mutate: func(fixture *engineFixture) {
			held := fixture.root + "-held"
			if err := os.Rename(fixture.root, held); err != nil {
				panic(err)
			}
			if err := os.Mkdir(fixture.root, 0o700); err != nil {
				panic(err)
			}
			fixture.t.Cleanup(func() { _ = os.RemoveAll(held) })
		}},
		{name: "asset-name-renamed-and-replaced", mutate: func(fixture *engineFixture) {
			held := fixture.asset + "-held"
			if err := os.Rename(fixture.asset, held); err != nil {
				panic(err)
			}
			if err := os.Mkdir(fixture.asset, 0o700); err != nil {
				panic(err)
			}
			fixture.t.Cleanup(func() { _ = os.RemoveAll(held) })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEngineFixture(t)
			issuer := NewIssuer()
			anchor := fixture.anchor
			anchor.MaxBytes = 0
			target := issuer.Issue(fixture.treeTargetValue("fixture.tree"), anchor)
			var calls atomic.Int32
			ctx := context.WithValue(context.Background(), afterOpenFileContextKey{}, func() {
				if calls.Add(1) == 2 {
					test.mutate(fixture)
				}
			})
			recorder := &recordingSessionFS{delegate: platform.OSFileSystem{}, stableDescriptorIdentity: true}

			got := (Engine{Cache: newRecordingLeafCache()}).Collect(ctx, collector.Environment{FS: recorder}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})

			if calls.Load() < 2 || len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || got.Evidence[0].Digest != "" || !hasEvidenceError(got.Evidence[0], "identity_changed") || len(got.CacheWrites) != 0 {
				t.Fatalf("calls=%d collection=%+v", calls.Load(), got)
			}
			if !recorder.allClosed() {
				t.Fatalf("opens=%v closes=%v", recorder.opened(), recorder.closeState())
			}
		})
	}
}

func TestEngineCoverageStatusMatrix(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []model.EvidenceStatus
		want      model.CoverageStatus
		rejectOne bool
	}{
		{name: "complete", statuses: []model.EvidenceStatus{model.EvidenceComplete}, want: model.CoverageComplete},
		{name: "required-unsupported", statuses: []model.EvidenceStatus{model.EvidenceUnsupported}, want: model.CoveragePartial},
		{name: "all-skipped", statuses: []model.EvidenceStatus{model.EvidenceSkipped, model.EvidenceSkipped}, want: model.CoverageSkipped},
		{name: "mixed-skipped-complete", statuses: []model.EvidenceStatus{model.EvidenceSkipped, model.EvidenceComplete}, want: model.CoverageComplete},
		{name: "unavailable", statuses: []model.EvidenceStatus{model.EvidenceUnavailable}, want: model.CoveragePartial},
		{name: "rejected", rejectOne: true, want: model.CoveragePartial},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := collectStatusFixture(t, test.statuses, test.rejectOne)
			if got.Coverage.Status != test.want {
				t.Fatalf("status=%s want=%s collection=%+v", got.Coverage.Status, test.want, got)
			}
		})
	}
}

func TestEngineAllowsPackageAndContainerSkippedPresets(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	targets := []model.LocalEvidenceTarget{
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "fixture.package", AssetID: fixture.assetID, ObservationID: fixture.observation.ID, Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, PresetStatus: model.EvidenceSkipped}, Anchor{}),
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "fixture.container", AssetID: fixture.assetID, ObservationID: fixture.observation.ID, Kind: model.EvidenceContainerIdentity, Subject: model.EvidenceSubjectContainerImage, PresetStatus: model.EvidenceSkipped}, Anchor{}),
	}
	got := (Engine{}).Collect(context.Background(), collector.Environment{}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: targets}})
	if got.Coverage.Status != model.CoverageSkipped || len(got.Coverage.Errors) != 0 || len(got.Evidence) != 2 {
		t.Fatalf("collection=%+v", got)
	}
	for _, record := range got.Evidence {
		if record.Status != model.EvidenceSkipped || record.Algorithm != "" || record.Digest != "" || record.Size != 0 {
			t.Fatalf("record=%+v", record)
		}
	}
}

func TestEngineBoundsBlockedSemanticHasherAndClearsRuntimeState(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	value, anchor := fixture.semanticTarget("fixture.semantic")
	target := issuer.Issue(value, anchor)
	proof := target.Provenance.(*issuedTargetProof)
	backing := make([]model.LocalEvidenceTarget, 1, 3)
	backing[0] = target
	full := backing[:cap(backing)]
	full[1], full[2] = target, target
	results := []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: backing}}
	release := make(chan struct{})
	finished := make(chan Collection, 1)
	go func() {
		finished <- (Engine{TargetTimeout: 20 * time.Millisecond, callbackLimiter: newCallbackLimiter(maxEvidenceCallbacks), ContextSemanticHasher: func(context.Context, model.Observation) (string, error) {
			<-release
			return strings.Repeat("a", 64), nil
		}}).Collect(context.Background(), collector.Environment{}, fixture.inventory(), results)
	}()
	var got Collection
	select {
	case got = <-finished:
	case <-time.After(time.Second):
		t.Fatal("engine blocked on semantic hasher")
	}
	close(release)
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || !hasEvidenceError(got.Evidence[0], "time_limit") {
		t.Fatalf("collection=%+v", got)
	}
	assertRuntimeCleared(t, results, full, issuer, proof)
}

func TestEngineDeepClonesSemanticObservationAndRecoversPanic(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.observation.Consumers = []string{"fixture"}
	fixture.observation.Metadata = map[string]string{"safe": "original"}
	fixture.observation.ID = ""
	var err error
	fixture.observation, err = identity.FinalizeObservation(fixture.observation)
	if err != nil {
		t.Fatal(err)
	}
	issuer := NewIssuer()
	value, anchor := fixture.semanticTarget("fixture.semantic")
	target := issuer.Issue(value, anchor)
	got := (Engine{ContextSemanticHasher: func(_ context.Context, observation model.Observation) (string, error) {
		observation.Consumers[0] = "changed"
		observation.Metadata["safe"] = "changed"
		panic("fixture")
	}}).Collect(context.Background(), collector.Environment{}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if fixture.observation.Consumers[0] != "fixture" || fixture.observation.Metadata["safe"] != "original" {
		t.Fatalf("source observation mutated: %+v", fixture.observation)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable {
		t.Fatalf("collection=%+v", got)
	}
}

func TestEngineInstallsPlannedSimpleSemanticHasherDirectly(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	value, anchor := fixture.semanticTarget("fixture.semantic")
	target := issuer.Issue(value, anchor)
	var calls atomic.Int32
	got := (Engine{SemanticHasher: func(model.Observation) (string, error) {
		calls.Add(1)
		return strings.Repeat("c", 64), nil
	}}).Collect(context.Background(), collector.Environment{}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if calls.Load() != 1 || len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceComplete || got.Evidence[0].Digest != strings.Repeat("c", 64) {
		t.Fatalf("calls=%d collection=%+v", calls.Load(), got)
	}
}

func TestEnginePrefersContextSemanticHasherWhenBothAreInstalled(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	value, anchor := fixture.semanticTarget("fixture.semantic")
	target := issuer.Issue(value, anchor)
	var simpleCalls, contextCalls atomic.Int32
	got := (Engine{
		SemanticHasher: func(model.Observation) (string, error) {
			simpleCalls.Add(1)
			return strings.Repeat("a", 64), nil
		},
		ContextSemanticHasher: func(context.Context, model.Observation) (string, error) {
			contextCalls.Add(1)
			return strings.Repeat("b", 64), nil
		},
	}).Collect(context.Background(), collector.Environment{}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if simpleCalls.Load() != 0 || contextCalls.Load() != 1 || len(got.Evidence) != 1 || got.Evidence[0].Digest != strings.Repeat("b", 64) {
		t.Fatalf("simple=%d context=%d collection=%+v", simpleCalls.Load(), contextCalls.Load(), got)
	}
}

func TestEngineBoundsPermanentSemanticAndCacheCallbackAccumulationAcrossCalls(t *testing.T) {
	fixture := newEngineFixture(t)
	limiter := newCallbackLimiter(maxEvidenceCallbacks)
	var spawned atomic.Int32
	blocked := func(context.Context, model.Observation) (string, error) {
		spawned.Add(1)
		select {}
	}
	engine := Engine{TargetTimeout: 10 * time.Millisecond, ContextSemanticHasher: blocked, callbackLimiter: limiter}
	firstInventory, firstResult := semanticBatchFixture(t, fixture, 12, false)
	first := engine.Collect(context.Background(), collector.Environment{}, firstInventory, []model.CollectorResult{firstResult})
	deadline := time.After(time.Second)
	for spawned.Load() < maxEvidenceCallbacks {
		select {
		case <-deadline:
			t.Fatalf("spawned=%d", spawned.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	secondInventory, secondResult := semanticBatchFixture(t, fixture, 8, false)
	second := engine.Collect(context.Background(), collector.Environment{}, secondInventory, []model.CollectorResult{secondResult})
	if spawned.Load() != maxEvidenceCallbacks || len(first.Evidence) != 12 || len(second.Evidence) != 8 {
		t.Fatalf("spawned=%d first=%+v second=%+v", spawned.Load(), first, second)
	}
	for _, collection := range []Collection{first, second} {
		for _, record := range collection.Evidence {
			if record.Status != model.EvidenceUnavailable || !hasEvidenceError(record, "time_limit") {
				t.Fatalf("record=%+v", record)
			}
		}
	}
	cache := &engineCountingCache{}
	issuer := NewIssuer()
	target := issuer.Issue(fixture.treeTargetValue("fixture.tree"), fixture.anchorWithoutContent())
	got := (Engine{TargetTimeout: 10 * time.Millisecond, Cache: cache, callbackLimiter: limiter}).Collect(context.Background(), collector.Environment{FS: platform.OSFileSystem{}}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if cache.calls.Load() != 0 || len(got.Evidence) != 1 || got.Evidence[0].Status == model.EvidenceComplete || len(got.CacheWrites) != 0 {
		t.Fatalf("cacheCalls=%d collection=%+v", cache.calls.Load(), got)
	}
}

func TestEngineCancellationWinsSimultaneousSemanticResult(t *testing.T) {
	fixture := newEngineFixture(t)
	for iteration := 0; iteration < 64; iteration++ {
		issuer := NewIssuer()
		value, anchor := fixture.semanticTarget("fixture.semantic")
		target := issuer.Issue(value, anchor)
		ctx, cancel := context.WithCancel(context.Background())
		got := (Engine{SemanticHasher: func(model.Observation) (string, error) {
			cancel()
			return strings.Repeat("a", 64), nil
		}, callbackLimiter: newCallbackLimiter(maxEvidenceCallbacks)}).Collect(ctx, collector.Environment{}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
		if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || !hasEvidenceError(got.Evidence[0], "time_limit") {
			t.Fatalf("iteration=%d collection=%+v", iteration, got)
		}
	}
}

func TestBoundedCacheCancellationWinsSimultaneousLookupResult(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		cache := boundedLeafCache{base: engineCancelingCache{cancel: cancel}, limiter: newCallbackLimiter(maxEvidenceCallbacks)}
		entry, found, err := cache.Lookup(ctx, CacheKey{})
		if !errors.Is(err, context.Canceled) || found || entry != (CacheEntry{}) {
			t.Fatalf("iteration=%d entry=%+v found=%v err=%v", iteration, entry, found, err)
		}
	}
}

func TestCallbackAwaitHelpersPreferCancellationWhenBothChannelsAreReady(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		semanticContext, cancelSemantic := context.WithCancel(context.Background())
		semanticResults := make(chan semanticResult, 1)
		semanticResults <- semanticResult{digest: strings.Repeat("a", 64)}
		cancelSemantic()
		if got, err := awaitSemanticResult(semanticContext, semanticResults); !errors.Is(err, context.Canceled) || got != (semanticResult{}) {
			t.Fatalf("semantic iteration=%d got=%+v err=%v", iteration, got, err)
		}

		cacheContext, cancelCache := context.WithCancel(context.Background())
		cacheResults := make(chan cacheLookupResult, 1)
		cacheResults <- cacheLookupResult{entry: CacheEntry{Status: model.EvidenceComplete}, found: true}
		cancelCache()
		if got, err := awaitCacheResult(cacheContext, cacheResults); !errors.Is(err, context.Canceled) || got != (cacheLookupResult{}) {
			t.Fatalf("cache iteration=%d got=%+v err=%v", iteration, got, err)
		}
	}
}

func TestEngineBoundsBlockedCache(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	target := issuer.Issue(fixture.treeTargetValue("fixture.tree"), fixture.anchorWithoutContent())
	release := make(chan struct{})
	cache := engineBlockingCache{release: release}
	finished := make(chan Collection, 1)
	go func() {
		finished <- (Engine{TargetTimeout: 20 * time.Millisecond, Cache: cache, callbackLimiter: newCallbackLimiter(maxEvidenceCallbacks)}).Collect(context.Background(), collector.Environment{FS: platform.OSFileSystem{}}, fixture.inventory(), []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	}()
	select {
	case got := <-finished:
		close(release)
		if len(got.Evidence) != 1 || got.Evidence[0].Status == model.EvidenceComplete || len(got.CacheWrites) != 0 {
			t.Fatalf("collection=%+v", got)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("engine blocked on cache")
	}
}

func TestEngineNeverRunsMoreThanFourWorkersAndOrdersPermutations(t *testing.T) {
	fixture := newEngineFixture(t)
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	hasher := func(context.Context, model.Observation) (string, error) {
		current := active.Add(1)
		for {
			seen := maximum.Load()
			if current <= seen || maximum.CompareAndSwap(seen, current) {
				break
			}
		}
		<-release
		active.Add(-1)
		return strings.Repeat("a", 64), nil
	}
	inventory, result := semanticBatchFixture(t, fixture, 8, false)
	finished := make(chan Collection, 1)
	go func() {
		finished <- (Engine{ContextSemanticHasher: hasher}).Collect(context.Background(), collector.Environment{}, inventory, []model.CollectorResult{result})
	}()
	deadline := time.After(time.Second)
	for maximum.Load() < 4 {
		select {
		case <-deadline:
			t.Fatalf("maximum=%d", maximum.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if maximum.Load() != 4 {
		t.Fatalf("maximum=%d", maximum.Load())
	}
	close(release)
	got := <-finished
	if len(got.Evidence) != 8 || len(got.Coverage.Targets) != 8 {
		t.Fatalf("collection=%+v", got)
	}
	firstInventory, firstResult := semanticBatchFixture(t, fixture, 8, false)
	secondInventory, secondResult := semanticBatchFixture(t, fixture, 8, true)
	first := (Engine{ContextSemanticHasher: func(context.Context, model.Observation) (string, error) { return strings.Repeat("b", 64), nil }}).Collect(context.Background(), collector.Environment{}, firstInventory, []model.CollectorResult{firstResult})
	second := (Engine{ContextSemanticHasher: func(context.Context, model.Observation) (string, error) { return strings.Repeat("b", 64), nil }}).Collect(context.Background(), collector.Environment{}, secondInventory, []model.CollectorResult{secondResult})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("permutation changed output:\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestEngineParentCancellationStillReturnsOneTerminalAndClears(t *testing.T) {
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	value, anchor := fixture.semanticTarget("fixture.semantic")
	target := issuer.Issue(value, anchor)
	proof := target.Provenance.(*issuedTargetProof)
	backing := []model.LocalEvidenceTarget{target}
	results := []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: backing}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := (Engine{ContextSemanticHasher: func(context.Context, model.Observation) (string, error) { return strings.Repeat("a", 64), nil }}).Collect(ctx, collector.Environment{}, fixture.inventory(), results)
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable {
		t.Fatalf("collection=%+v", got)
	}
	assertRuntimeCleared(t, results, backing, issuer, proof)
}

type engineFixture struct {
	t                      *testing.T
	root, asset            string
	manifest               string
	entrypoint             string
	assetID                string
	observation            model.Observation
	anchor                 Anchor
	manifestRootRelative   string
	entrypointRootRelative string
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	root := t.TempDir()
	asset := filepath.Join(root, "asset")
	if err := os.MkdirAll(filepath.Join(asset, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(asset, "manifest.json")
	entrypoint := filepath.Join(asset, "dist", "main.js")
	if err := os.WriteFile(manifest, []byte("manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entrypoint, []byte("entrypoint"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation := finalizedEvidenceObservation(t, "asset")
	manifestDigest := sha256.Sum256([]byte("manifest"))
	return &engineFixture{
		t: t, root: root, asset: asset, manifest: manifest, entrypoint: entrypoint, assetID: "asset", observation: observation,
		manifestRootRelative: filepath.Join("asset", "manifest.json"), entrypointRootRelative: filepath.Join("asset", "dist", "main.js"),
		anchor: Anchor{Root: fileFingerprint(t, root), AssetRoot: fileFingerprint(t, asset), AssetRelativePath: "asset", RelativePath: filepath.Join("asset", "manifest.json"), Digest: hex.EncodeToString(manifestDigest[:]), Size: 8, Mode: 0o600, Fingerprint: fileFingerprint(t, manifest), MaxBytes: 64 << 20},
	}
}

func (f *engineFixture) inventory() model.Inventory { return f.inventoryWith(f.observation) }
func (f *engineFixture) inventoryWith(observation model.Observation) model.Inventory {
	return model.Inventory{Assets: []model.Asset{{ID: f.assetID}}, Observations: []model.Observation{observation}}
}
func (f *engineFixture) fileTargetValue(id, subject, relative string) model.LocalEvidenceTarget {
	return model.LocalEvidenceTarget{TargetID: id, AssetID: f.assetID, ObservationID: f.observation.ID, Kind: model.EvidenceFileSHA256, Subject: subject, RootPath: f.root, RelativePath: relative}
}
func (f *engineFixture) fileTarget(issuer *Issuer, id, subject, relative string) model.LocalEvidenceTarget {
	return issuer.Issue(f.fileTargetValue(id, subject, relative), f.anchor)
}
func (f *engineFixture) treeTargetValue(id string) model.LocalEvidenceTarget {
	return model.LocalEvidenceTarget{TargetID: id, AssetID: f.assetID, ObservationID: f.observation.ID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, RootPath: f.root, RelativePath: "asset"}
}
func (f *engineFixture) semanticTarget(id string) (model.LocalEvidenceTarget, Anchor) {
	return model.LocalEvidenceTarget{TargetID: id, AssetID: f.assetID, ObservationID: f.observation.ID, Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration}, Anchor{}
}
func (f *engineFixture) anchorWithoutContent() Anchor {
	value := f.anchor
	value.RelativePath, value.Digest, value.Size, value.Mode, value.Fingerprint, value.MaxBytes = "", "", 0, 0, platform.FileFingerprint{}, 0
	return value
}

func collectStatusFixture(t *testing.T, statuses []model.EvidenceStatus, rejectOne bool) Collection {
	t.Helper()
	fixture := newEngineFixture(t)
	issuer := NewIssuer()
	var targets []model.LocalEvidenceTarget
	var observations []model.Observation
	for index, status := range statuses {
		observation := finalizedObservationAt(t, fixture.assetID, index)
		observations = append(observations, observation)
		value := model.LocalEvidenceTarget{TargetID: "fixture.status" + string(rune('a'+index)), AssetID: fixture.assetID, ObservationID: observation.ID, Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration}
		if status == model.EvidenceSkipped {
			value.PresetStatus = status
		}
		if status == model.EvidenceUnsupported {
			value.PresetStatus = status
		}
		targets = append(targets, issuer.Issue(value, Anchor{}))
	}
	if rejectOne {
		value, _ := fixture.semanticTarget("wrong.target")
		targets = append(targets, issuer.Issue(value, Anchor{}))
		observations = append(observations, fixture.observation)
	}
	hasher := func(ctx context.Context, observation model.Observation) (string, error) {
		for index, item := range observations {
			if item.ID == observation.ID && statuses[index] == model.EvidenceUnavailable {
				return "", errors.New("unavailable")
			}
		}
		return strings.Repeat("a", 64), nil
	}
	return (Engine{ContextSemanticHasher: hasher}).Collect(context.Background(), collector.Environment{}, model.Inventory{Assets: []model.Asset{{ID: fixture.assetID}}, Observations: observations}, []model.CollectorResult{{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: targets}})
}

func semanticBatchFixture(t *testing.T, fixture *engineFixture, count int, reverse bool) (model.Inventory, model.CollectorResult) {
	t.Helper()
	issuer := NewIssuer()
	observations := make([]model.Observation, 0, count)
	targets := make([]model.LocalEvidenceTarget, 0, count)
	for index := 0; index < count; index++ {
		observation := finalizedObservationAt(t, fixture.assetID, index)
		observations = append(observations, observation)
		value := model.LocalEvidenceTarget{TargetID: "fixture.semantic" + string(rune('a'+index)), AssetID: fixture.assetID, ObservationID: observation.ID, Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration}
		targets = append(targets, issuer.Issue(value, Anchor{}))
	}
	if reverse {
		sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID > targets[j].TargetID })
	}
	return model.Inventory{Assets: []model.Asset{{ID: fixture.assetID}}, Observations: observations}, model.CollectorResult{Collector: "fixture", LocalEvidenceIssuer: issuer, LocalEvidenceTargets: targets}
}

func finalizedObservationAt(t *testing.T, assetID string, index int) model.Observation {
	t.Helper()
	value, err := identity.FinalizeObservation(model.Observation{AssetID: assetID, Collector: "fixture", Scope: model.ScopeUser, LocationRef: "$HOME/fixture/" + string(rune('a'+index))})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func finalizedEvidenceObservation(t *testing.T, assetID string) model.Observation {
	return finalizedObservationAt(t, assetID, 0)
}

func fileFingerprint(t *testing.T, path string) platform.FileFingerprint {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, ok := platform.Fingerprint(info)
	if !ok {
		t.Fatal("Darwin fingerprint unavailable")
	}
	return fingerprint
}

func assertRejectedWithoutOpen(t *testing.T, got Collection, recorder *recordingSessionFS) {
	t.Helper()
	if len(got.Evidence) != 0 || len(got.Coverage.Targets) != 0 || len(got.Coverage.Errors) != 1 || got.Coverage.Errors[0].Code != "target_rejected" || recorder.absoluteOpenCount() != 0 {
		t.Fatalf("collection=%+v opens=%v", got, recorder.opened())
	}
}

func assertRuntimeCleared(t *testing.T, results []model.CollectorResult, backing []model.LocalEvidenceTarget, issuer *Issuer, proof *issuedTargetProof) {
	t.Helper()
	if results[0].LocalEvidenceTargets != nil || results[0].LocalEvidenceIssuer != nil {
		t.Fatalf("result runtime survived: %+v", results[0])
	}
	for index := range backing {
		if backing[index] != (model.LocalEvidenceTarget{}) {
			t.Fatalf("backing[%d]=%+v", index, backing[index])
		}
	}
	if issuer.nonce != ([sha256.Size]byte{}) || issuer.active {
		t.Fatal("issuer nonce survived")
	}
	if proof.issuer != nil || proof.anchor != (Anchor{}) || proof.canonical != ([sha256.Size]byte{}) || proof.seal != ([sha256.Size]byte{}) {
		t.Fatalf("proof survived: %+v", proof)
	}
}

func hasEvidenceError(record model.ContentEvidence, code string) bool {
	for _, err := range record.Errors {
		if err.Code == code {
			return true
		}
	}
	return false
}

type engineBlockingCache struct{ release <-chan struct{} }

func (cache engineBlockingCache) Lookup(context.Context, CacheKey) (CacheEntry, bool, error) {
	<-cache.release
	return CacheEntry{}, false, nil
}

type engineCountingCache struct{ calls atomic.Int32 }

func (cache *engineCountingCache) Lookup(context.Context, CacheKey) (CacheEntry, bool, error) {
	cache.calls.Add(1)
	return CacheEntry{}, false, nil
}

type engineCancelingCache struct{ cancel context.CancelFunc }

func (cache engineCancelingCache) Lookup(context.Context, CacheKey) (CacheEntry, bool, error) {
	cache.cancel()
	return CacheEntry{Status: model.EvidenceComplete}, true, nil
}

type recordingSessionFS struct {
	delegate                 platform.OSFileSystem
	stableDescriptorIdentity bool
	mu                       sync.Mutex
	opens                    []string
	closes                   map[string]int
}

func (f *recordingSessionFS) ReadFile(name string) ([]byte, error) { return f.delegate.ReadFile(name) }
func (f *recordingSessionFS) ReadDir(name string) ([]os.DirEntry, error) {
	return f.delegate.ReadDir(name)
}
func (f *recordingSessionFS) Stat(name string) (os.FileInfo, error) { return f.delegate.Stat(name) }
func (f *recordingSessionFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	return f.delegate.WalkDir(root, fn)
}
func (f *recordingSessionFS) OpenRoot(path string) (platform.RootedDirectory, error) {
	f.record(path)
	root, err := f.delegate.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return f.wrapRoot(root, path), nil
}
func (f *recordingSessionFS) wrapRoot(root platform.RootedDirectory, label string) *recordingRoot {
	wrapped := &recordingRoot{RootedDirectory: root, recorder: f, label: label}
	if f.stableDescriptorIdentity {
		wrapped.identity, _ = root.Lstat(".")
	}
	return wrapped
}
func (f *recordingSessionFS) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens = append(f.opens, path)
	if f.closes == nil {
		f.closes = map[string]int{}
	}
}
func (f *recordingSessionFS) recordClose(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes[path]++
}
func (f *recordingSessionFS) opened() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.opens...)
}
func (f *recordingSessionFS) absoluteOpenCount() int {
	count := 0
	for _, value := range f.opened() {
		if filepath.IsAbs(value) {
			count++
		}
	}
	return count
}
func (f *recordingSessionFS) relativeOpenCount(path string) int {
	count := 0
	for _, value := range f.opened() {
		if value == path {
			count++
		}
	}
	return count
}
func (f *recordingSessionFS) absoluteOpened(path string) bool {
	for _, value := range f.opened() {
		if value == path {
			return true
		}
	}
	return false
}
func (f *recordingSessionFS) allClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.opens) == 0 {
		return false
	}
	opened := make(map[string]int, len(f.opens))
	for _, label := range f.opens {
		opened[label]++
	}
	if len(opened) != len(f.closes) {
		return false
	}
	for label, count := range opened {
		if f.closes[label] != count {
			return false
		}
	}
	return true
}
func (f *recordingSessionFS) closeState() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for key, value := range f.closes {
		out[key] = value
	}
	return out
}

type recordingRoot struct {
	platform.RootedDirectory
	recorder *recordingSessionFS
	label    string
	identity os.FileInfo
}

func (root *recordingRoot) Lstat(path string) (os.FileInfo, error) {
	if path == "." && root.identity != nil {
		return root.identity, nil
	}
	return root.RootedDirectory.Lstat(path)
}

func (root *recordingRoot) OpenRoot(path string) (platform.RootedDirectory, error) {
	root.recorder.record(path)
	child, err := root.RootedDirectory.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return root.recorder.wrapRoot(child, path), nil
}
func (root *recordingRoot) Close() error {
	root.recorder.recordClose(root.label)
	return root.RootedDirectory.Close()
}
