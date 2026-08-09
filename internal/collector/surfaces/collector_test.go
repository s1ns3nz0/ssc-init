package surfaces

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestShellStartupCollectorUsesOnlyTheClosedCatalog(t *testing.T) {
	home := t.TempDir()
	for _, entry := range shellCatalog {
		path := filepath.Join(home, filepath.FromSlash(entry.relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("startup "+entry.relative), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".zlogin"), []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != len(shellCatalog) || len(got.Observations) != len(shellCatalog) || len(got.LocalEvidenceTargets) != len(shellCatalog) {
		t.Fatalf("assets=%d observations=%d evidence=%d", len(got.Assets), len(got.Observations), len(got.LocalEvidenceTargets))
	}
	names := make([]string, 0, len(got.Assets))
	for _, asset := range got.Assets {
		if asset.Type != model.AssetShellStartup || asset.Path != "" {
			t.Fatalf("asset=%+v", asset)
		}
		names = append(names, asset.Name)
	}
	sort.Strings(names)
	want := []string{".bash_profile", ".bashrc", ".profile", ".zprofile", ".zshrc", "config.fish"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names=%q want=%q", names, want)
	}
	for _, asset := range got.Assets {
		if asset.Name == ".zlogin" {
			t.Fatalf("unrelated startup file collected: %+v", asset)
		}
	}
}

func TestShellStartupCollectorRejectsSymlinkAndReportsMissing(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "real"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(home, ".zshrc")); err != nil {
		t.Fatal(err)
	}
	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]model.TargetStatus)
	for _, target := range got.Targets {
		statuses[target.TargetID] = target.Status
	}
	if statuses["surfaces.shell.zshrc"] != model.TargetPartial || statuses["surfaces.shell.bashrc"] != model.TargetNotPresent {
		t.Fatalf("targets=%+v", got.Targets)
	}
	if len(got.Assets) != 0 || len(got.LocalEvidenceTargets) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestSurfaceTargetCatalogIsExactAndSorted(t *testing.T) {
	targets := New().Targets()
	if len(targets) != 8 {
		t.Fatalf("targets=%+v", targets)
	}
	for index, target := range targets {
		if target.Collector != "surfaces" || target.Platform != "darwin" || target.Scope != model.ScopeUser || index > 0 && targets[index-1].ID >= target.ID {
			t.Fatalf("targets=%+v", targets)
		}
	}
}
