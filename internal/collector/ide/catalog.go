package ide

import "github.com/ssc-init/ssc-init/internal/model"

type targetDeclaration struct {
	spec         model.TargetSpec
	relativePath string
	manifestPath string
	supported    bool
	expanded     bool
}

var immutableCatalog = []targetDeclaration{
	{spec: ideTargetSpec("ide.cursor.extensions", "cursor", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".cursor/extensions", manifestPath: "package.json", supported: true},
	{spec: ideTargetSpec("ide.custom-roots", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
	{spec: ideTargetSpec("ide.dev-container", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
	{spec: ideTargetSpec("ide.environment-relocated", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
	{spec: ideTargetSpec("ide.jetbrains.plugins", "jetbrains", model.ScopeIDEProfile, "xml", model.TargetDirectory), relativePath: "Library/Application Support/JetBrains/<product>/plugins", manifestPath: "META-INF/plugin.xml", supported: true, expanded: true},
	{spec: ideTargetSpec("ide.remote-ssh", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
	{spec: ideTargetSpec("ide.remote-wsl", "", model.ScopeIDEProfile, "", model.TargetDirectory)},
	{spec: ideTargetSpec("ide.service-api", "", model.ScopeSystem, "", model.TargetServiceAPI)},
	{spec: ideTargetSpec("ide.vscode-insiders.extensions", "vscode-insiders", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode-insiders/extensions", manifestPath: "package.json", supported: true},
	{spec: ideTargetSpec("ide.vscode-oss.extensions", "vscode-oss", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode-oss/extensions", manifestPath: "package.json", supported: true},
	{spec: ideTargetSpec("ide.vscode.extensions", "vscode", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".vscode/extensions", manifestPath: "package.json", supported: true},
	{spec: ideTargetSpec("ide.windsurf.extensions", "windsurf", model.ScopeIDEProfile, "json", model.TargetDirectory), relativePath: ".windsurf/extensions", manifestPath: "package.json", supported: true},
}

func ideTargetSpec(id, host string, scope model.ObservationScope, format string, method model.TargetMethod) model.TargetSpec {
	return model.TargetSpec{
		ID: id, Collector: "ide", Host: host, Scope: scope,
		Platform: "darwin", Format: format, Method: method,
	}
}

func catalogDeclarations() []targetDeclaration {
	return append([]targetDeclaration(nil), immutableCatalog...)
}

func catalogSpecs() []model.TargetSpec {
	declarations := catalogDeclarations()
	specs := make([]model.TargetSpec, len(declarations))
	for index, declaration := range declarations {
		specs[index] = declaration.spec
	}
	return specs
}
