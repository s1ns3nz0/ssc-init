package acceptance

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

func TestPythonLockfileProvenanceAcceptance(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Projects", "app")
	privacyMarker := "private-python-marker"
	sourceURL := "https://private-user:private-password@packages.example.invalid/simple"
	credential := "private-password"
	filename := "private-wheel-name.whl"
	localPath := "../private-local-source"
	firstHash := strings.Repeat("ab", 32)
	secondHash := strings.Repeat("cd", 32)
	immutableHash := strings.Repeat("ef", 32)

	writeMatrixFile(t, filepath.Join(project, "requirements.txt"), "Requirements__Demo==1.0.0 ; implementation_name == '"+privacyMarker+"' --hash=sha256:"+immutableHash+"\n")
	writeMatrixFile(t, filepath.Join(project, "Pipfile.lock"), `{"default":{"Pipfile__Multi":{"version":"==2.0.0","hashes":["sha256:`+firstHash+`","sha256:`+secondHash+`"],"markers":"`+privacyMarker+`"}}}`)
	writeMatrixFile(t, filepath.Join(project, "poetry.lock"), `[[package]]
name = "Poetry__Source"
version = "3.0.0"
markers = "`+privacyMarker+`"
source = { type = "url", url = "`+sourceURL+`" }
files = [{ file = "`+filename+`", hash = "sha256:`+immutableHash+`" }]
`)
	writeMatrixFile(t, filepath.Join(project, "uv.lock"), `[[package]]
name = "UV__Local"
version = "4.0.0"
source = { directory = "`+localPath+`" }
`)

	result := runIsolatedBaseline(t, baselineOptions{home: home})
	assets := make(map[string]model.Asset, len(result.Inventory.Assets))
	for _, asset := range result.Inventory.Assets {
		assets[asset.ID] = asset
	}
	want := map[string]struct {
		lockfile  string
		status    model.ProvenanceStatus
		integrity string
	}{
		"pkg:pypi/requirements-demo@1.0.0": {"requirements.txt", model.ProvenanceImmutable, "sha256:" + immutableHash},
		"pkg:pypi/pipfile-multi@2.0.0":     {"Pipfile.lock", model.ProvenanceUnknown, ""},
		"pkg:pypi/poetry-source@3.0.0":     {"poetry.lock", model.ProvenanceMutable, ""},
		"pkg:pypi/uv-local@4.0.0":          {"uv.lock", model.ProvenanceMutable, ""},
	}
	for packageID, expected := range want {
		packageAsset, found := assets[packageID]
		if !found || packageAsset.Provenance == nil || packageAsset.Provenance.Status != expected.status || packageAsset.Provenance.Integrity != expected.integrity {
			t.Fatalf("package %q asset=%+v", packageID, packageAsset)
		}
		declaredBy := false
		for _, relationship := range result.Inventory.Relationships {
			if relationship.From == packageID && relationship.Kind == model.RelationshipDeclaredBy && assets[relationship.To].Name == expected.lockfile {
				declaredBy = true
			}
		}
		if !declaredBy {
			t.Fatalf("package %q has no declared-by edge to %q: %+v", packageID, expected.lockfile, result.Inventory.Relationships)
		}
	}

	encodedInventory, err := json.Marshal(result.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{privacyMarker, sourceURL, credential, filename, localPath, firstHash, secondHash, home} {
		if strings.Contains(string(result.Report), private) {
			t.Fatalf("serialized report leaked %q: %s", private, result.Report)
		}
		if strings.Contains(string(encodedInventory), private) {
			t.Fatalf("marshaled inventory leaked %q: %s", private, encodedInventory)
		}
	}
	if result.Runner == nil || result.Runner.callCount() != 0 {
		t.Fatalf("default scan executed commands: %+v", result.Runner)
	}
}

func TestConflictingPythonLockfileFactsPersistConservatively(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Projects", "app")
	digest := strings.Repeat("ab", 32)
	writeMatrixFile(t, filepath.Join(project, "requirements.txt"), "shared-demo==1.0.0\n")
	writeMatrixFile(t, filepath.Join(project, "Pipfile.lock"), `{"default":{"shared-demo":{"version":"==1.0.0","hashes":["sha256:`+digest+`"]}}}`)

	result := runIsolatedBaseline(t, baselineOptions{home: home})
	reopened := reopenLatestSnapshot(t, result.DatabasePath)
	packageID := "pkg:pypi/shared-demo@1.0.0"
	packageAssets := 0
	for _, asset := range reopened.Inventory.Assets {
		if asset.ID != packageID {
			continue
		}
		packageAssets++
		if asset.Provenance == nil || asset.Provenance.Status != model.ProvenanceUnknown || asset.Provenance.Integrity != "" {
			t.Fatalf("persisted package=%+v", asset)
		}
	}
	declaredBy := 0
	for _, relationship := range reopened.Inventory.Relationships {
		if relationship.From == packageID && relationship.Kind == model.RelationshipDeclaredBy {
			declaredBy++
		}
	}
	if packageAssets != 1 || declaredBy != 2 {
		t.Fatalf("package assets=%d declared-by=%d snapshot=%+v", packageAssets, declaredBy, reopened)
	}
	for _, coverage := range reopened.Scan.Coverage {
		if coverage.Collector != "projects" {
			continue
		}
		coveragePackageAssets := 0
		for _, asset := range coverage.Assets {
			if asset.ID == packageID {
				coveragePackageAssets++
			}
		}
		if coveragePackageAssets != 1 {
			t.Fatalf("persisted project coverage has %d package assets: %+v", coveragePackageAssets, coverage.Assets)
		}
	}
}

func TestDockerIdentityRelationshipAndV4PrivacyAcceptance(t *testing.T) {
	home := t.TempDir()
	runner, inspector := dockerProbeFixture(t, home)
	first := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: filepath.Join(privateMatrixTempDir(t), "first.db"),
		externalProbes: true, runner: runner, inspector: inspector,
	})
	if first.Scan.SchemaVersion != "ssc-init.scan.v7" {
		t.Fatalf("schema=%q", first.Scan.SchemaVersion)
	}
	container := requireContentEvidence(t, first.Inventory, "package", model.EvidenceSubjectContainerImage)
	if container.Status != model.EvidenceComplete || container.Algorithm != "sha256" || container.Digest != strings.Repeat("c", 64) {
		t.Fatalf("container=%+v", container)
	}
	probed := false
	for _, relationship := range first.Inventory.Relationships {
		if relationship.Kind == model.RelationshipProbedBy && strings.HasPrefix(relationship.From, "pkg:docker/") && strings.HasPrefix(relationship.To, "tool-executable:sha256:") {
			probed = true
		}
		if !model.ValidRelationshipKind(relationship.Kind) || relationship.From == relationship.To {
			t.Fatalf("invalid relationship=%+v", relationship)
		}
	}
	if !probed {
		t.Fatalf("missing Docker probe relationship: %+v", first.Inventory.Relationships)
	}
	if strings.Contains(string(first.Report), home) || strings.Contains(string(first.Report), "private marker") {
		t.Fatalf("Program D output leaked host data: %s", first.Report)
	}

	dockerPath := filepath.Join(home, "fake-bin", "docker")
	changedRunner, ok := runner.(*matrixRunner)
	if !ok {
		t.Fatalf("runner=%T", runner)
	}
	changedRunner.results[matrixCommandKey(dockerPath, "image", "ls", "--no-trunc", "--format", "{{json .}}")] = platform.CommandResult{
		Stdout: `{"Repository":"demo-image","Tag":"1.0.0","ID":"sha256:` + strings.Repeat("d", 64) + `"}` + "\n",
	}
	second := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: first.DatabasePath, scanID: "00000000-0000-4000-8000-0000000000d2",
		externalProbes: true, runner: runner, inspector: inspector,
	})
	changed := requireContentEvidence(t, second.Inventory, "package", model.EvidenceSubjectContainerImage)
	if changed.ID != container.ID || changed.Digest == container.Digest {
		t.Fatalf("Docker identity mutation was not reflected: before=%+v after=%+v", container, changed)
	}
	deltaFound := false
	for _, change := range second.Delta.Changes {
		if change.Entity == model.ChangeEntityEvidence && change.EntityID == container.ID && change.Kind == model.ChangeChanged {
			deltaFound = true
		}
	}
	if !deltaFound {
		t.Fatalf("Docker identity mutation missing from delta: %+v", second.Delta)
	}
}

func TestProjectProvenanceDeclaredByAcceptance(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, "Projects", "app", "package-lock.json"), `{"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}}`)
	result := runIsolatedBaseline(t, baselineOptions{home: home})

	var packageAsset model.Asset
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "pkg:npm/demo@1.2.3" {
			packageAsset = asset
		}
	}
	if packageAsset.Provenance == nil || packageAsset.Provenance.Status != model.ProvenanceImmutable {
		t.Fatalf("package=%+v", packageAsset)
	}
	found := false
	for _, relationship := range result.Inventory.Relationships {
		if relationship.From == packageAsset.ID && relationship.Kind == model.RelationshipDeclaredBy {
			found = true
		}
	}
	if !found {
		t.Fatalf("relationships=%+v", result.Inventory.Relationships)
	}
	if result.Runner == nil || result.Runner.calls != 0 {
		t.Fatalf("default scan executed commands: %+v", result.Runner)
	}
}
