package acceptance

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

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
