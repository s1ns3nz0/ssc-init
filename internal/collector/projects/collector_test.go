package projects_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestProjectCollectorDiscoversManifestEvidenceAtConfiguredRoot(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	writeProjectFile(t, filepath.Join(root, "package.json"), `{"name":"fixture"}`)
	roots, err := projects.ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	result, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != 1 || result.Assets[0].Type != model.AssetProject || len(result.Observations) != 1 {
		t.Fatalf("assets=%+v observations=%+v", result.Assets, result.Observations)
	}
	observation := result.Observations[0]
	if observation.AssetID != result.Assets[0].ID || observation.LocationRef != "$HOME/workspace" || observation.Metadata["root_ref"] != "$HOME/workspace" {
		t.Fatalf("observation=%+v asset=%+v", observation, result.Assets[0])
	}
	if len(result.LocalEvidenceTargets) != 1 {
		t.Fatalf("evidence targets=%+v", result.LocalEvidenceTargets)
	}
	target := result.LocalEvidenceTargets[0]
	if target.TargetID != "projects.manifest.package.json" || target.AssetID != observation.AssetID || target.ObservationID != observation.ID || target.Subject != "project-manifest:package.json" || target.RootPath != root || target.RelativePath != "package.json" || target.PresetStatus != "" {
		t.Fatalf("evidence target=%+v", target)
	}
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete || collection.Evidence[0].Digest == "" || collection.Evidence[0].ObservationID != observation.ID {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestProjectCollectorDiscoversOnlyClosedGitHooksAndVSCodeLaunchConfig(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	project := filepath.Join(root, "app")
	for relative, contents := range map[string]string{
		filepath.Join(".git", "hooks", "pre-commit"):        "#!/bin/sh\nexit 0\n",
		filepath.Join(".git", "hooks", "pre-commit.sample"): "sample",
		filepath.Join(".git", "hooks", "private-hook"):      "private",
		filepath.Join(".vscode", "launch.json"):             `{"version":"0.2.0","configurations":[]}`,
		"launch.json":                                       `{"must":"not be collected"}`,
	} {
		writeProjectFile(t, filepath.Join(project, relative), contents)
	}
	result := collectProjectsAt(t, home, root)
	subjects := make(map[string]int)
	for _, target := range result.LocalEvidenceTargets {
		subjects[target.Subject]++
	}
	if subjects[model.EvidenceSubjectGitHook] != 1 || subjects[model.EvidenceSubjectLaunchConfig] != 1 || len(result.LocalEvidenceTargets) != 2 {
		t.Fatalf("subjects=%v targets=%+v", subjects, result.LocalEvidenceTargets)
	}
	assetTypes := make(map[model.AssetType]int)
	for _, asset := range result.Assets {
		assetTypes[asset.Type]++
	}
	if assetTypes[model.AssetGitHook] != 1 || assetTypes[model.AssetLaunchConfig] != 1 || len(result.Relationships) != 2 {
		t.Fatalf("assetTypes=%v relationships=%+v", assetTypes, result.Relationships)
	}
	assetIDs := make(map[string]struct{}, len(result.Assets))
	for _, asset := range result.Assets {
		assetIDs[asset.ID] = struct{}{}
	}
	for _, target := range result.LocalEvidenceTargets {
		if strings.HasSuffix(target.RelativePath, ".sample") || strings.HasSuffix(target.RelativePath, "private-hook") || target.RelativePath == "app/launch.json" {
			t.Fatalf("unexpected target=%+v", target)
		}
		if _, ok := assetIDs[target.AssetID]; !ok {
			t.Fatalf("target has no asset endpoint: %+v", target)
		}
	}
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 2 || collection.Coverage.Status != model.CoverageComplete {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestMalformedLaunchConfigKeepsHashEvidenceAndMarksOnlyProjectPartial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	writeProjectFile(t, filepath.Join(root, "app", ".vscode", "launch.json"), `{"configurations":[`)
	result := collectProjectsAt(t, home, root)
	if result.Status != model.CoveragePartial || len(result.Errors) != 1 || result.Errors[0].Code != "launch_malformed" {
		t.Fatalf("result=%+v", result)
	}
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete || collection.Evidence[0].Subject != model.EvidenceSubjectLaunchConfig {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestProjectCollectorConnectsPackagesToImmutableLockfileProvenance(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	writeProjectFile(t, filepath.Join(root, "package-lock.json"), `{"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}}`)
	result := collectProjectsAt(t, home, root)

	var packageAsset model.Asset
	var lockfileID string
	for _, asset := range result.Assets {
		switch {
		case asset.ID == "pkg:npm/demo@1.2.3":
			packageAsset = asset
		case asset.Source == "project-lockfile":
			lockfileID = asset.ID
		}
	}
	if packageAsset.Provenance == nil || packageAsset.Provenance.Status != model.ProvenanceImmutable || packageAsset.Provenance.Integrity != "sha256:"+strings.Repeat("aa", 32) || lockfileID == "" {
		t.Fatalf("package=%+v lockfileID=%q assets=%+v", packageAsset, lockfileID, result.Assets)
	}
	want := model.Relationship{From: packageAsset.ID, Kind: model.RelationshipDeclaredBy, To: lockfileID}
	found := false
	for _, relationship := range result.Relationships {
		found = found || relationship == want
	}
	if !found {
		t.Fatalf("missing relationship=%+v in %+v", want, result.Relationships)
	}
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("manifest evidence was not preserved: %+v", collection)
	}
}

func TestMalformedLockfileKeepsEvidenceAndMarksProvenancePartial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	writeProjectFile(t, filepath.Join(root, "Cargo.lock"), "not valid cargo lock syntax = [")
	result := collectProjectsAt(t, home, root)
	if result.Status != model.CoveragePartial || len(result.Errors) != 1 || result.Errors[0].Code != "provenance_malformed" {
		t.Fatalf("result=%+v", result)
	}
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceComplete {
		t.Fatalf("evidence=%+v", collection)
	}
}

func TestProjectCollectorEmitsCompleteExactCatalogForOneProject(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	names := []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
		"pyproject.toml", "Pipfile", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "go.mod", "go.sum",
		"Cargo.toml", "Cargo.lock", "Brewfile",
	}
	for _, name := range names {
		contents := name + " contents"
		switch name {
		case "package-lock.json", "npm-shrinkwrap.json":
			contents = `{"packages":{}}`
		case "go.sum", "Cargo.lock":
			contents = ""
		}
		writeProjectFile(t, filepath.Join(root, name), contents)
	}
	for _, name := range []string{"requirements-dev.txt", "Package.json", "package.json.bak", "xCargo.toml"} {
		writeProjectFile(t, filepath.Join(root, name), "must not be evidence")
	}
	result := collectProjectsAt(t, home, root)
	if len(result.Assets) != 1 || len(result.Observations) != 1 || len(result.LocalEvidenceTargets) != len(names) {
		t.Fatalf("assets=%+v observations=%+v targets=%+v", result.Assets, result.Observations, result.LocalEvidenceTargets)
	}
	wantTargets := make(map[string]struct{}, len(names))
	for _, name := range names {
		prefix := "projects.manifest."
		if strings.Contains(projectEvidenceSubjectForTest(name), "lockfile") {
			prefix = "projects.lockfile."
		}
		wantTargets[prefix+name] = struct{}{}
	}
	for _, target := range result.LocalEvidenceTargets {
		if _, ok := wantTargets[target.TargetID]; !ok || target.Subject != projectEvidenceSubjectForTest(filepath.Base(target.RelativePath)) || target.ObservationID != result.Observations[0].ID || target.AssetID != result.Assets[0].ID {
			t.Fatalf("unexpected target=%+v", target)
		}
		delete(wantTargets, target.TargetID)
	}
	if len(wantTargets) != 0 {
		t.Fatalf("missing targets=%v", wantTargets)
	}
	collection := collectProjectEvidence(t, home, result)
	if collection.Coverage.Status != model.CoverageComplete || len(collection.Evidence) != len(names) {
		t.Fatalf("collection=%+v", collection)
	}
	for _, record := range collection.Evidence {
		if record.Status != model.EvidenceComplete || record.Algorithm != "sha256" || len(record.Digest) != 64 {
			t.Fatalf("record=%+v", record)
		}
	}
}

func TestProjectEvidenceSeparatesProjectsSharingBasenames(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	writeProjectFile(t, filepath.Join(root, "a", "package.json"), `{"name":"same"}`)
	writeProjectFile(t, filepath.Join(root, "b", "package.json"), `{"name":"same"}`)
	result := collectProjectsAt(t, home, root)
	if len(result.Assets) != 2 || len(result.Observations) != 2 || len(result.LocalEvidenceTargets) != 2 {
		t.Fatalf("result=%+v", result)
	}
	if result.LocalEvidenceTargets[0].TargetID != result.LocalEvidenceTargets[1].TargetID || result.LocalEvidenceTargets[0].ObservationID == result.LocalEvidenceTargets[1].ObservationID || result.LocalEvidenceTargets[0].AssetID == result.LocalEvidenceTargets[1].AssetID {
		t.Fatalf("targets=%+v", result.LocalEvidenceTargets)
	}
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 2 || collection.Evidence[0].ID == collection.Evidence[1].ID {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestProjectEvidenceOversizeDoesNotSuppressSafeSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	large := filepath.Join(root, "package-lock.json")
	writeProjectFile(t, large, "x")
	if err := os.Truncate(large, (32<<20)+1); err != nil {
		t.Fatal(err)
	}
	writeProjectFile(t, filepath.Join(root, "package.json"), `{"name":"safe"}`)
	result := collectProjectsAt(t, home, root)
	if len(result.LocalEvidenceTargets) != 2 {
		t.Fatalf("targets=%+v", result.LocalEvidenceTargets)
	}
	for _, target := range result.LocalEvidenceTargets {
		if target.TargetID == "projects.lockfile.package-lock.json" && (target.PresetStatus != model.EvidenceOversize || target.RootPath != "" || target.RelativePath != "") {
			t.Fatalf("oversize target=%+v", target)
		}
	}
	collection := collectProjectEvidence(t, home, result)
	statuses := map[string]model.EvidenceStatus{}
	for _, record := range collection.Evidence {
		statuses[record.Subject] = record.Status
	}
	if statuses["project-manifest:package.json"] != model.EvidenceComplete || statuses["project-lockfile:package-lock.json"] != model.EvidenceOversize {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestProjectEvidenceDetectsMutationAfterCollection(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "workspace")
	manifest := filepath.Join(root, "package.json")
	writeProjectFile(t, manifest, `{"name":"before"}`)
	result := collectProjectsAt(t, home, root)
	writeProjectFile(t, manifest, `{"name":"after-longer"}`)
	collection := collectProjectEvidence(t, home, result)
	if len(collection.Evidence) != 1 || collection.Evidence[0].Status != model.EvidenceUnavailable || len(collection.Evidence[0].Errors) != 1 || collection.Evidence[0].Errors[0].Code != "identity_changed" {
		t.Fatalf("collection=%+v", collection)
	}
}

func TestProjectEvidenceRuntimePathsNeverSerialize(t *testing.T) {
	home := t.TempDir()
	external := filepath.Join(t.TempDir(), "secret-client-name")
	writeProjectFile(t, filepath.Join(external, "package.json"), `{"token":"RAW_PROJECT_CONTENT_SECRET"}`)
	result := collectProjectsAt(t, home, external)
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	encoded, err := json.Marshal(struct {
		Result     model.CollectorResult
		Inventory  model.Inventory
		Collection evidence.Collection
	}{result, graph, collection})
	if err != nil {
		t.Fatal(err)
	}
	// Catalog target IDs and subjects intentionally disclose only the closed
	// basename vocabulary; runtime absolute and project directory names do not.
	for _, forbidden := range []string{external, "secret-client-name", "RAW_PROJECT_CONTENT_SECRET"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized result leaked %q: %s", forbidden, encoded)
		}
	}
	if len(result.Observations) != 1 || !strings.HasPrefix(result.Observations[0].LocationRef, "external-root-1/path-sha256:") || len(collection.Evidence) != 1 {
		t.Fatalf("observation=%+v", result.Observations)
	}
}

func TestEveryProjectCatalogFileMutationChangesOnlyItsEvidence(t *testing.T) {
	names := []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
		"pyproject.toml", "Pipfile", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "go.mod", "go.sum",
		"Cargo.toml", "Cargo.lock", "Brewfile",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, "workspace")
			path := filepath.Join(root, name)
			sibling := "package.json"
			if name == sibling {
				sibling = "requirements.txt"
			}
			writeProjectFile(t, path, "before")
			writeProjectFile(t, filepath.Join(root, sibling), "stable sibling")
			beforeCollection, beforeInventory := collectProjectInventory(t, home, collectProjectsAt(t, home, root))
			writeProjectFile(t, path, "after")
			afterCollection, afterInventory := collectProjectInventory(t, home, collectProjectsAt(t, home, root))
			if len(beforeCollection.Evidence) != 2 || len(afterCollection.Evidence) != 2 {
				t.Fatalf("before=%+v after=%+v", beforeCollection, afterCollection)
			}
			beforeBySubject := evidenceBySubject(beforeCollection.Evidence)
			afterBySubject := evidenceBySubject(afterCollection.Evidence)
			mutatedSubject := projectEvidenceSubjectForTest(name)
			siblingSubject := projectEvidenceSubjectForTest(sibling)
			if beforeBySubject[mutatedSubject].ID == "" || beforeBySubject[mutatedSubject].ID != afterBySubject[mutatedSubject].ID || beforeBySubject[mutatedSubject].Digest == afterBySubject[mutatedSubject].Digest {
				t.Fatalf("mutated evidence before=%+v after=%+v", beforeBySubject[mutatedSubject], afterBySubject[mutatedSubject])
			}
			if beforeBySubject[siblingSubject].ID == "" || !reflect.DeepEqual(beforeBySubject[siblingSubject], afterBySubject[siblingSubject]) {
				t.Fatalf("sibling evidence changed: before=%+v after=%+v", beforeBySubject[siblingSubject], afterBySubject[siblingSubject])
			}
			delta := inventory.Diff(beforeInventory, afterInventory)
			want := []model.Change{{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: beforeBySubject[mutatedSubject].ID}}
			if !reflect.DeepEqual(delta.Changes, want) {
				t.Fatalf("delta=%+v want=%+v before=%+v after=%+v", delta.Changes, want, beforeInventory.Evidence, afterInventory.Evidence)
			}
		})
	}
}

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
	var _ func([]projects.Root) collector.TargetedCollector = projects.New
}

func TestProjectCollectorRejectsForgedRootWithoutLeakage(t *testing.T) {
	forged := []projects.Root{{
		Path: "/private/very-sensitive-client-root",
		Ref:  "private-ref-must-not-leak",
	}}
	assertRejectedRoots(t, forged, "/private/very-sensitive-client-root", "private-ref-must-not-leak")
}

func TestProjectCollectorRejectsMutatedResolvedRootWithoutLeakage(t *testing.T) {
	home := t.TempDir()
	for _, testCase := range []struct {
		name      string
		mutate    func(*projects.Root)
		forbidden string
	}{
		{name: "path", mutate: func(root *projects.Root) { root.Path = "/private/mutated-client-root" }, forbidden: "/private/mutated-client-root"},
		{name: "relative path", mutate: func(root *projects.Root) { root.Path = "relative-client-root" }, forbidden: "relative-client-root"},
		{name: "non-canonical path", mutate: func(root *projects.Root) { root.Path += "/../Projects" }, forbidden: "/../Projects"},
		{name: "ref", mutate: func(root *projects.Root) { root.Ref = "mutated-ref-must-not-leak" }, forbidden: "mutated-ref-must-not-leak"},
		{name: "non-deterministic ref", mutate: func(root *projects.Root) { root.Ref = "external-root-9" }, forbidden: "external-root-9"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
			if err != nil {
				t.Fatal(err)
			}
			testCase.mutate(&roots[0])
			assertRejectedRoots(t, roots, testCase.forbidden)
		})
	}
}

func TestProjectCollectorRejectsInvalidResolvedRootSets(t *testing.T) {
	home := t.TempDir()
	valid, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	firstExternal, err := projects.ResolveRoots(home, []string{filepath.Join(filepath.Dir(home), "external-a")})
	if err != nil {
		t.Fatal(err)
	}
	secondExternal, err := projects.ResolveRoots(home, []string{filepath.Join(filepath.Dir(home), "external-b")})
	if err != nil {
		t.Fatal(err)
	}
	sorted, err := projects.ResolveRoots(home, []string{"$HOME/a", "$HOME/z"})
	if err != nil {
		t.Fatal(err)
	}
	reversed := []projects.Root{sorted[1], sorted[0]}
	excess := make([]projects.Root, 33)
	for index := range excess {
		excess[index] = valid[0]
	}
	for _, testCase := range []struct {
		name      string
		roots     []projects.Root
		forbidden string
	}{
		{name: "empty", roots: nil},
		{name: "duplicate", roots: []projects.Root{valid[0], valid[0]}, forbidden: "$HOME/Projects"},
		{name: "excess", roots: excess, forbidden: "$HOME/Projects"},
		{name: "misordered", roots: reversed, forbidden: "$HOME/z"},
		{name: "duplicate external ref", roots: []projects.Root{firstExternal[0], secondExternal[0]}, forbidden: "external-root-1"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			assertRejectedRoots(t, testCase.roots, testCase.forbidden)
		})
	}
}

func TestProjectCollectorCopiesValidatedRootsBeforeCollection(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, "Projects", "sample", ".mcp.json")
	writeProjectFile(t, config, `{}`)
	roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	projectCollector := projects.New(roots)
	roots[0].Path = "/private/mutated-after-new"
	roots[0].Ref = "mutated-after-new"
	got, err := projectCollector.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].InstanceRef != "$HOME/Projects" || len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != config {
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
	if target.TargetID != "projects.root" || target.InstanceRef != "$HOME/Projects" || target.Status != model.TargetComplete || target.Assets != 5 || target.Observations != 5 {
		t.Fatalf("target=%+v", target)
	}
	if len(got.Assets) != 5 || len(got.Observations) != 5 || len(got.LocalTargets) != 4 || len(got.LocalEvidenceTargets) != 1 || len(got.Relationships) != 4 {
		t.Fatalf("assets=%d observations=%d localTargets=%d localEvidenceTargets=%d relationships=%d", len(got.Assets), len(got.Observations), len(got.LocalTargets), len(got.LocalEvidenceTargets), len(got.Relationships))
	}

	wantTargets := []model.LocalTarget{
		{TargetID: "mcp.codex.project", InstanceRef: "$HOME/Projects/sample/.codex/config.toml", Path: filepath.Join(project, ".codex", "config.toml"), Format: "toml", Host: "codex", Consumers: []string{"codex"}},
		{TargetID: "mcp.cursor.project", InstanceRef: "$HOME/Projects/sample/.cursor/mcp.json", Path: filepath.Join(project, ".cursor", "mcp.json"), Format: "json", Host: "cursor", Consumers: []string{"cursor"}},
		{TargetID: "mcp.shared.project", InstanceRef: "$HOME/Projects/sample/.mcp.json", Path: filepath.Join(project, ".mcp.json"), Format: "json", Host: "shared", Consumers: []string{"claude-code", "vscode"}},
		{TargetID: "mcp.vscode.project", InstanceRef: "$HOME/Projects/sample/.vscode/mcp.json", Path: filepath.Join(project, ".vscode", "mcp.json"), Format: "json", Host: "vscode", Consumers: []string{"vscode"}},
	}
	publicTargets := append([]model.LocalTarget(nil), got.LocalTargets...)
	for index := range publicTargets {
		if publicTargets[index].Provenance == nil {
			t.Fatalf("local target is missing runtime provenance: %+v", publicTargets[index])
		}
		publicTargets[index].Provenance = nil
	}
	if !reflect.DeepEqual(publicTargets, wantTargets) {
		t.Fatalf("localTargets=%+v want=%+v", publicTargets, wantTargets)
	}
	assetIDs := make(map[string]struct{}, len(got.Assets))
	for _, asset := range got.Assets {
		assetIDs[asset.ID] = struct{}{}
		if asset.Path != "" || strings.Contains(asset.ID, home) || strings.Contains(asset.Name, home) {
			t.Fatalf("asset contains a location field: %+v", asset)
		}
	}
	for _, observation := range got.Observations {
		if !strings.HasPrefix(observation.LocationRef, "$HOME/Projects/sample") || observation.ProjectID == "" {
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
	wantTargets := []model.TargetCoverage{
		{TargetID: "projects.root", InstanceRef: "$HOME/missing", Status: model.TargetNotPresent},
		{
			TargetID: "projects.root", InstanceRef: "$HOME/not-a-directory", Status: model.TargetUnavailable,
			Errors: []model.CoverageError{{Code: "root_unavailable", Message: "configured project root is unavailable"}},
		},
	}
	if !reflect.DeepEqual(got.Targets, wantTargets) {
		t.Fatalf("targets=%+v want=%+v", got.Targets, wantTargets)
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
	wantTarget := model.TargetCoverage{TargetID: "projects.root", InstanceRef: "$HOME/empty", Status: model.TargetComplete}
	if got.Status != model.CoverageComplete || !reflect.DeepEqual(got.Targets, []model.TargetCoverage{wantTarget}) {
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
	if len(got.Observations) != 2 {
		t.Fatalf("observations=%+v", got.Observations)
	}
	configObservation := model.Observation{}
	for _, observation := range got.Observations {
		if observation.Source == "mcp.shared.project" {
			configObservation = observation
		}
		if !strings.HasPrefix(observation.LocationRef, "external-root-1/path-sha256:") {
			t.Fatalf("unsafe external observation=%+v", observation)
		}
	}
	if len(got.LocalTargets) != 1 || got.LocalTargets[0].Path != rawConfig || got.LocalTargets[0].InstanceRef != configObservation.LocationRef {
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

func collectProjectsAt(t *testing.T, home, root string) model.CollectorResult {
	t.Helper()
	roots, err := projects.ResolveRoots(home, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	result, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func collectProjectEvidence(t *testing.T, home string, result model.CollectorResult) evidence.Collection {
	t.Helper()
	graph := inventory.Build([]model.CollectorResult{result})
	return (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
}

func collectProjectInventory(t *testing.T, home string, result model.CollectorResult) (evidence.Collection, model.Inventory) {
	t.Helper()
	graph := inventory.Build([]model.CollectorResult{result})
	collection := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
	graph.Evidence = inventory.NormalizeEvidence(collection.Evidence)
	return collection, graph
}

func evidenceBySubject(values []model.ContentEvidence) map[string]model.ContentEvidence {
	result := make(map[string]model.ContentEvidence, len(values))
	for _, value := range values {
		result[value.Subject] = value
	}
	return result
}

func projectEvidenceSubjectForTest(name string) string {
	lockfiles := map[string]struct{}{
		"package-lock.json": {}, "npm-shrinkwrap.json": {}, "pnpm-lock.yaml": {}, "yarn.lock": {}, "bun.lock": {}, "bun.lockb": {},
		"poetry.lock": {}, "Pipfile.lock": {}, "uv.lock": {}, "go.sum": {}, "Cargo.lock": {},
	}
	if _, ok := lockfiles[name]; ok {
		return "project-lockfile:" + name
	}
	return "project-manifest:" + name
}

func assertRejectedRoots(t *testing.T, roots []projects.Root, forbidden ...string) {
	t.Helper()
	if refs := projects.RootRefs(roots); refs != nil {
		t.Fatalf("forged roots exposed refs=%q", refs)
	}
	got, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, t.TempDir()))
	if err == nil || err.Error() != "invalid project roots" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if len(got.Targets) != 0 || len(got.Assets) != 0 || len(got.Observations) != 0 || len(got.LocalTargets) != 0 {
		t.Fatalf("rejected roots produced evidence: %+v", got)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, value := range forbidden {
		if value != "" && (strings.Contains(string(encoded), value) || strings.Contains(err.Error(), value)) {
			t.Fatalf("rejected root leaked %q: result=%s err=%v", value, encoded, err)
		}
	}
}
