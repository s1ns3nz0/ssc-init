package ide

import (
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestIDECatalogDeclaresFixedRootsAndUnsupportedSurfaces(t *testing.T) {
	want := []targetDeclaration{
		{spec: literalIDETarget("ide.cursor.extensions", "cursor", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".cursor/extensions", manifestPath: "package.json", supported: true},
		{spec: literalIDETarget("ide.custom-roots", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
		{spec: literalIDETarget("ide.dev-container", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
		{spec: literalIDETarget("ide.environment-relocated", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
		{spec: literalIDETarget("ide.jetbrains.plugins", "jetbrains", model.ScopeIDEProfile, "xml", model.TargetDirectory), relativePath: "Library/Application Support/JetBrains/<product>/plugins", manifestPath: "META-INF/plugin.xml", supported: true, expanded: true},
		{spec: literalIDETarget("ide.remote-ssh", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
		{spec: literalIDETarget("ide.remote-wsl", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
		{spec: literalIDETarget("ide.service-api", "", model.ScopeSystem, "", model.TargetServiceAPI)},
		{spec: literalIDETarget("ide.vscode-insiders.extensions", "vscode-insiders", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode-insiders/extensions", manifestPath: "package.json", supported: true},
		{spec: literalIDETarget("ide.vscode-oss.extensions", "vscode-oss", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode-oss/extensions", manifestPath: "package.json", supported: true},
		{spec: literalIDETarget("ide.vscode.extensions", "vscode", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode/extensions", manifestPath: "package.json", supported: true},
		{spec: literalIDETarget("ide.windsurf.extensions", "windsurf", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".windsurf/extensions", manifestPath: "package.json", supported: true},
	}
	if got := catalogDeclarations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog=\n%+v\nwant=\n%+v", got, want)
	}

	var targeted collector.TargetedCollector = New()
	first := targeted.Targets()
	if len(first) != len(want) {
		t.Fatalf("targets=%+v", first)
	}
	for index, declaration := range want {
		if first[index] != declaration.spec {
			t.Fatalf("target[%d]=%+v want=%+v", index, first[index], declaration.spec)
		}
	}
	first[0].ID = "mutated"
	if targeted.Targets()[0].ID != "ide.cursor.extensions" {
		t.Fatal("Targets returned mutable catalog storage")
	}
}

func literalIDETarget(id, host string, scope model.ObservationScope, format string, method model.TargetMethod) model.TargetSpec {
	return model.TargetSpec{
		ID: id, Collector: "ide", Host: host, Scope: scope,
		Platform: "darwin", Format: format, Method: method,
	}
}
