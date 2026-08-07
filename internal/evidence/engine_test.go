package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

func TestEngineReturnsOneTerminalResultPerAcceptedTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"name":"fixture"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload", "main.js"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation := finalizedEvidenceObservation(t, "asset")
	issuer := NewIssuer()
	rootFingerprint := fileFingerprint(t, dir)
	manifest := []byte(`{"name":"fixture"}`)
	digest := sha256.Sum256(manifest)
	targets := []model.LocalEvidenceTarget{
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "file", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, RootPath: dir, RelativePath: "manifest.json"}, Anchor{Root: rootFingerprint, AssetRoot: rootFingerprint, RelativePath: "manifest.json", Digest: hex.EncodeToString(digest[:]), Size: int64(len(manifest)), Mode: 0o600, Fingerprint: fileFingerprint(t, filepath.Join(dir, "manifest.json"))}),
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "tree", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, RootPath: dir, RelativePath: "payload"}, Anchor{Root: rootFingerprint, AssetRoot: rootFingerprint}),
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "semantic", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration}, Anchor{}),
		issuer.Issue(model.LocalEvidenceTarget{TargetID: "preset", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, PresetStatus: model.EvidenceUnsupported}, Anchor{}),
	}
	got := (Engine{}).Collect(context.Background(), evidenceEnvironment(t, dir), model.Inventory{
		Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation},
	}, []model.CollectorResult{{Collector: "fixture", LocalEvidenceTargets: targets}})
	if len(got.Coverage.Targets) != 4 || len(got.Evidence) != 4 {
		t.Fatalf("coverage=%+v evidence=%+v", got.Coverage, got.Evidence)
	}
	for _, target := range got.Coverage.Targets {
		if target.EvidenceID == "" || target.Status == "" {
			t.Fatalf("non-terminal target: %+v", target)
		}
	}
	if got.Evidence[2].Status != model.EvidenceUnsupported {
		t.Fatalf("semantic evidence=%+v", got.Evidence[2])
	}
}

func TestEngineRejectsMismatchedObservationAssetBeforeOpeningRoot(t *testing.T) {
	dir := t.TempDir()
	fs := &recordingEvidenceFS{}
	observation := finalizedEvidenceObservation(t, "asset-b")
	target := NewIssuer().Issue(model.LocalEvidenceTarget{
		TargetID: "fixture.manifest", AssetID: "asset-a", ObservationID: observation.ID,
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: dir, RelativePath: "manifest.json",
	}, Anchor{})
	got := (Engine{}).Collect(context.Background(), collector.Environment{Home: dir, FS: fs}, model.Inventory{
		Assets: []model.Asset{{ID: "asset-a"}, {ID: "asset-b"}}, Observations: []model.Observation{observation},
	}, []model.CollectorResult{{Collector: "fixture", LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if len(got.Evidence) != 0 || len(got.Coverage.Errors) != 1 || got.Coverage.Errors[0].Code != "target_rejected" || fs.openRootCalls() != 0 {
		t.Fatalf("collection=%+v opens=%d", got, fs.openRootCalls())
	}
}

func TestEngineMakesSignedUnsafePathUnavailableWithoutOpeningRoot(t *testing.T) {
	dir := t.TempDir()
	fs := &recordingEvidenceFS{}
	observation := finalizedEvidenceObservation(t, "asset")
	target := NewIssuer().Issue(model.LocalEvidenceTarget{
		TargetID: "unsafe", AssetID: "asset", ObservationID: observation.ID,
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest,
		RootPath: dir, RelativePath: "../outside",
	}, Anchor{})
	got := (Engine{}).Collect(context.Background(), collector.Environment{Home: dir, FS: fs}, model.Inventory{
		Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation},
	}, []model.CollectorResult{{LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if len(got.Evidence) != 1 || got.Evidence[0].Status != model.EvidenceUnavailable || !hasEvidenceError(got.Evidence[0], "path_invalid") || fs.openRootCalls() != 0 {
		t.Fatalf("collection=%+v opens=%d", got, fs.openRootCalls())
	}
}

func TestEngineRejectsDuplicateTargetIDs(t *testing.T) {
	dir := t.TempDir()
	observation := finalizedEvidenceObservation(t, "asset")
	issuer := NewIssuer()
	makeTarget := func(subject string) model.LocalEvidenceTarget {
		return issuer.Issue(model.LocalEvidenceTarget{TargetID: "duplicate", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidencePackageContent, Subject: subject, PresetStatus: model.EvidenceUnsupported}, Anchor{})
	}
	got := (Engine{}).Collect(context.Background(), evidenceEnvironment(t, dir), model.Inventory{
		Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation},
	}, []model.CollectorResult{{LocalEvidenceTargets: []model.LocalEvidenceTarget{makeTarget(model.EvidenceSubjectPackageContent), makeTarget(model.EvidenceSubjectContainerImage)}}})
	if len(got.Evidence) != 0 || len(got.Coverage.Targets) != 0 || len(got.Coverage.Errors) != 2 {
		t.Fatalf("collection=%+v", got)
	}
	for _, err := range got.Coverage.Errors {
		if err.Code != "target_rejected" {
			t.Fatalf("error=%+v", err)
		}
	}
}

func TestEngineClearsCallerVisibleEvidenceTargets(t *testing.T) {
	dir := t.TempDir()
	observation := finalizedEvidenceObservation(t, "asset")
	target := NewIssuer().Issue(model.LocalEvidenceTarget{TargetID: "preset", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, PresetStatus: model.EvidenceUnsupported, RootPath: "/private/root"}, Anchor{})
	results := []model.CollectorResult{{LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}}
	backing := results[0].LocalEvidenceTargets
	_ = (Engine{}).Collect(context.Background(), evidenceEnvironment(t, dir), model.Inventory{Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation}}, results)
	if results[0].LocalEvidenceTargets != nil {
		t.Fatalf("visible targets survived: %+v", results[0].LocalEvidenceTargets)
	}
	if backing[0] != (model.LocalEvidenceTarget{}) {
		t.Fatalf("target backing array survived: %+v", backing[0])
	}
}

func TestEngineDiscardsFileDigestWhenAnchorChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation := finalizedEvidenceObservation(t, "asset")
	digest := sha256.Sum256([]byte("first"))
	target := NewIssuer().Issue(model.LocalEvidenceTarget{TargetID: "file", AssetID: "asset", ObservationID: observation.ID, Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, RootPath: dir, RelativePath: "manifest.json"}, Anchor{
		Root: fileFingerprint(t, dir), AssetRoot: fileFingerprint(t, dir), RelativePath: "manifest.json", Digest: hex.EncodeToString(digest[:]), Size: 5, Mode: 0o600, Fingerprint: fileFingerprint(t, path),
	})
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := (Engine{}).Collect(context.Background(), evidenceEnvironment(t, dir), model.Inventory{Assets: []model.Asset{{ID: "asset"}}, Observations: []model.Observation{observation}}, []model.CollectorResult{{LocalEvidenceTargets: []model.LocalEvidenceTarget{target}}})
	if len(got.Evidence) != 1 || got.Evidence[0].Digest != "" || got.Evidence[0].Status != model.EvidenceUnavailable || !hasEvidenceError(got.Evidence[0], "identity_changed") {
		t.Fatalf("collection=%+v", got)
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

func finalizedEvidenceObservation(t *testing.T, assetID string) model.Observation {
	t.Helper()
	observation, err := identity.FinalizeObservation(model.Observation{AssetID: assetID, Collector: "fixture", Scope: model.ScopeUser, LocationRef: "$HOME/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return observation
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

func evidenceEnvironment(t *testing.T, home string) collector.Environment {
	t.Helper()
	return collector.Environment{Home: home, FS: platform.OSFileSystem{}}
}

type recordingEvidenceFS struct {
	platform.OSFileSystem
	mu    sync.Mutex
	opens int
}

func (fs *recordingEvidenceFS) OpenRoot(path string) (platform.RootedDirectory, error) {
	fs.mu.Lock()
	fs.opens++
	fs.mu.Unlock()
	return (platform.OSFileSystem{}).OpenRoot(path)
}

func (fs *recordingEvidenceFS) openRootCalls() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.opens
}
