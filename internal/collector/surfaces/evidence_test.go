package surfaces

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestHomeFileEvidenceIsDescriptorRootedAndComplete(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export DEMO=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := surfaceFixtureResult(t)
	status := issueHomeFileEvidence(context.Background(), testutil.Environment(t, home), &result, "surfaces.shell.zshrc", ".zshrc", result.Assets[0].ID, result.Observations[0].ID, model.EvidenceSubjectShellStartup)
	if status != model.EvidenceComplete || len(result.LocalEvidenceTargets) != 1 {
		t.Fatalf("status=%s targets=%+v", status, result.LocalEvidenceTargets)
	}
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete || collection.Evidence[0].Digest == "" {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestHomeFileEvidenceFailsClosedForSymlinkAndOversize(t *testing.T) {
	for _, testCase := range []struct {
		name string
		make func(t *testing.T, home string)
		want model.EvidenceStatus
	}{
		{name: "symlink", make: func(t *testing.T, home string) {
			if err := os.WriteFile(filepath.Join(home, "real"), []byte("content"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real", filepath.Join(home, ".zshrc")); err != nil {
				t.Fatal(err)
			}
		}, want: model.EvidenceUnavailable},
		{name: "oversize", make: func(t *testing.T, home string) {
			if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(strings.Repeat("x", int(maxSurfaceFileBytes)+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: model.EvidenceOversize},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			testCase.make(t, home)
			result := surfaceFixtureResult(t)
			got := issueHomeFileEvidence(context.Background(), testutil.Environment(t, home), &result, "surfaces.shell.zshrc", ".zshrc", result.Assets[0].ID, result.Observations[0].ID, model.EvidenceSubjectShellStartup)
			if got != testCase.want || len(result.LocalEvidenceTargets) != 1 || result.LocalEvidenceTargets[0].PresetStatus != testCase.want {
				t.Fatalf("status=%s targets=%+v", got, result.LocalEvidenceTargets)
			}
		})
	}
}

func surfaceFixtureResult(t *testing.T) model.CollectorResult {
	t.Helper()
	asset := model.Asset{ID: "shell-startup:zshrc", Type: model.AssetShellStartup, Name: ".zshrc"}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: asset.ID, Collector: "surfaces", Scope: model.ScopeUser,
		LocationRef: "$HOME/.zshrc", Source: "surfaces.shell.zshrc",
	})
	if err != nil {
		t.Fatal(err)
	}
	return model.CollectorResult{Collector: "surfaces", Assets: []model.Asset{asset}, Observations: []model.Observation{observation}}
}
