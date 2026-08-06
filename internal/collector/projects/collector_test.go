package projects_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestProjectCollectorAdvertisesOnlyRootTarget(t *testing.T) {
	home := t.TempDir()
	roots, err := projects.ResolveRoots(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	projectCollector := projects.New(roots)
	want := []model.TargetSpec{{
		ID: "projects.root", Collector: "projects", Scope: model.ScopeProject,
		Platform: "darwin", Method: model.TargetDirectory,
	}}
	if got := projectCollector.Targets(); !reflect.DeepEqual(got, want) {
		t.Fatalf("targets=%+v want=%+v", got, want)
	}
	mutated := projectCollector.Targets()
	mutated[0].ID = "mutated"
	if got := projectCollector.Targets(); !reflect.DeepEqual(got, want) {
		t.Fatalf("targets changed through caller slice: %+v", got)
	}
	var _ collector.TargetedCollector = projectCollector
}

func TestProjectCollectorResolvesLegacyStringRootsAgainstEnvironmentHome(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, "Projects", "sample", ".mcp.json")
	writeProjectFile(t, config, `{}`)
	got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != config || got.Targets[0].InstanceRef != "$HOME/Projects" {
		t.Fatalf("result=%+v", got)
	}
}

func TestProjectCollectorRecognizesOnlyFixedProjectConfigs(t *testing.T) {
	home := t.TempDir()
	configuredRoot := filepath.Join(home, "Projects")
	project := filepath.Join(configuredRoot, "sample")
	files := map[string]string{
		".mcp.json":                            `{"mcpServers":{}}`,
		filepath.Join(".cursor", "mcp.json"):   `{"mcpServers":{}}`,
		filepath.Join(".codex", "config.toml"): `[mcp_servers]`,
		filepath.Join(".vscode", "mcp.json"):   `{"servers":{}}`,
		"unknown.json":                         `{}`,
		"unknown.toml":                         `value = true`,
		"package.json":                         `{}`,
	}
	for relative, contents := range files {
		writeProjectFile(t, filepath.Join(project, relative), contents)
	}
	roots, err := projects.ResolveRoots(home, []string{configuredRoot})
	if err != nil {
		t.Fatal(err)
	}
	got, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("status=%q errors=%+v targets=%+v", got.Status, got.Errors, got.Targets)
	}
	if len(got.Targets) != 1 {
		t.Fatalf("targets=%+v", got.Targets)
	}
	target := got.Targets[0]
	if target.TargetID != "projects.root" || target.InstanceRef != "$HOME/Projects" || target.Status != model.TargetComplete || target.Assets != 5 || target.Observations != 4 {
		t.Fatalf("target=%+v", target)
	}
	if len(got.Assets) != 5 || len(got.Observations) != 4 || len(got.LocalTargets) != 4 || len(got.Relationships) != 4 {
		t.Fatalf("assets=%d observations=%d localTargets=%d relationships=%d", len(got.Assets), len(got.Observations), len(got.LocalTargets), len(got.Relationships))
	}

	wantTargets := []model.LocalTarget{
		{TargetID: "mcp.codex.project", InstanceRef: "$HOME/Projects/sample/.codex/config.toml", Path: filepath.Join(project, ".codex", "config.toml"), Format: "toml", Host: "codex", Consumers: []string{"codex"}},
		{TargetID: "mcp.cursor.project", InstanceRef: "$HOME/Projects/sample/.cursor/mcp.json", Path: filepath.Join(project, ".cursor", "mcp.json"), Format: "json", Host: "cursor", Consumers: []string{"cursor"}},
		{TargetID: "mcp.shared.project", InstanceRef: "$HOME/Projects/sample/.mcp.json", Path: filepath.Join(project, ".mcp.json"), Format: "json", Host: "shared", Consumers: []string{"claude-code", "vscode"}},
		{TargetID: "mcp.vscode.project", InstanceRef: "$HOME/Projects/sample/.vscode/mcp.json", Path: filepath.Join(project, ".vscode", "mcp.json"), Format: "json", Host: "vscode", Consumers: []string{"vscode"}},
	}
	if !reflect.DeepEqual(got.LocalTargets, wantTargets) {
		t.Fatalf("localTargets=%+v want=%+v", got.LocalTargets, wantTargets)
	}
	assetIDs := make(map[string]struct{}, len(got.Assets))
	for _, asset := range got.Assets {
		assetIDs[asset.ID] = struct{}{}
		if asset.Path != "" || strings.Contains(asset.ID, home) || strings.Contains(asset.Name, home) {
			t.Fatalf("asset contains a location field: %+v", asset)
		}
	}
	for _, observation := range got.Observations {
		if !strings.HasPrefix(observation.LocationRef, "$HOME/Projects/sample/") || observation.ProjectID == "" {
			t.Fatalf("observation=%+v", observation)
		}
		if _, exists := assetIDs[observation.AssetID]; !exists {
			t.Fatalf("observation references absent asset: %+v", observation)
		}
		if _, exists := assetIDs[observation.ProjectID]; !exists {
			t.Fatalf("observation references absent project: %+v", observation)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), home) || strings.Contains(string(encoded), "unknown.json") || strings.Contains(string(encoded), "package.json") {
		t.Fatalf("serialized project result leaked or misclassified a path: %s", encoded)
	}
}

func TestProjectCollectorDistinguishesMissingAndUnavailableRoots(t *testing.T) {
	home := t.TempDir()
	missing := filepath.Join(home, "missing")
	notDirectory := filepath.Join(home, "not-a-directory")
	writeProjectFile(t, notDirectory, "fixture")
	roots, err := projects.ResolveRoots(home, []string{missing, notDirectory})
	if err != nil {
		t.Fatal(err)
	}
	got, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]model.TargetStatus)
	for _, target := range got.Targets {
		statuses[target.InstanceRef] = target.Status
	}
	if statuses["$HOME/missing"] != model.TargetNotPresent || statuses["$HOME/not-a-directory"] != model.TargetUnavailable {
		t.Fatalf("targets=%+v", got.Targets)
	}
	if got.Status != model.CoveragePartial {
		t.Fatalf("status=%q", got.Status)
	}
}

func TestProjectCollectorReportsSafelyEmptyRootComplete(t *testing.T) {
	home := t.TempDir()
	empty := filepath.Join(home, "empty")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	roots, err := projects.ResolveRoots(home, []string{empty})
	if err != nil {
		t.Fatal(err)
	}
	got, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete || len(got.Targets) != 1 || got.Targets[0].Status != model.TargetComplete {
		t.Fatalf("result=%+v", got)
	}
	if len(got.Assets) != 0 || len(got.Observations) != 0 || len(got.LocalTargets) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func TestProjectCollectorHidesExternalAbsoluteLocations(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	rawConfig := filepath.Join(external, "client-name", ".mcp.json")
	writeProjectFile(t, rawConfig, `{}`)
	roots, err := projects.ResolveRoots(home, []string{external})
	if err != nil {
		t.Fatal(err)
	}
	got, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Observations) != 1 || !strings.HasPrefix(got.Observations[0].LocationRef, "external-root-1/path-sha256:") {
		t.Fatalf("observations=%+v", got.Observations)
	}
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != rawConfig || got.LocalTargets[0].InstanceRef != got.Observations[0].LocationRef {
		t.Fatalf("localTargets=%+v observations=%+v", got.LocalTargets, got.Observations)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), external) || strings.Contains(string(encoded), "client-name") {
		t.Fatalf("serialized result leaked external location: %s", encoded)
	}
}

func writeProjectFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
