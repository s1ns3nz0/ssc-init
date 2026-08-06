package mcp

import (
	"sort"

	"github.com/ssc-init/ssc-init/internal/model"
)

type targetDeclaration struct {
	spec         model.TargetSpec
	relativePath string
	consumers    []string
	container    string
	supported    bool
}

var immutableCatalog = []targetDeclaration{
	{spec: targetSpec("mcp.claude-code.legacy-user", "claude-code", model.ScopeUser, "json", model.TargetFile), relativePath: ".claude/settings.json", consumers: []string{"claude-code"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.claude-code.user", "claude-code", model.ScopeUser, "json", model.TargetFile), relativePath: ".claude.json", consumers: []string{"claude-code"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.claude-desktop.user", "claude-desktop", model.ScopeUser, "json", model.TargetFile), relativePath: "Library/Application Support/Claude/claude_desktop_config.json", consumers: []string{"claude-desktop"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.codex.project", "codex", model.ScopeProject, "toml", model.TargetFile), relativePath: ".codex/config.toml", consumers: []string{"codex"}, supported: true},
	{spec: targetSpec("mcp.codex.user", "codex", model.ScopeUser, "toml", model.TargetFile), relativePath: ".codex/config.toml", consumers: []string{"codex"}, supported: true},
	{spec: targetSpec("mcp.cursor.project", "cursor", model.ScopeProject, "json", model.TargetFile), relativePath: ".cursor/mcp.json", consumers: []string{"cursor"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.cursor.user", "cursor", model.ScopeUser, "json", model.TargetFile), relativePath: ".cursor/mcp.json", consumers: []string{"cursor"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.dev-container", "", model.ScopeProject, "", model.TargetFile)},
	{spec: targetSpec("mcp.dynamic-api", "", model.ScopeUser, "", model.TargetDynamicAPI)},
	{spec: targetSpec("mcp.environment-relocated", "", model.ScopeUser, "", model.TargetFile)},
	{spec: targetSpec("mcp.github-copilot.user", "github-copilot", model.ScopeUser, "json", model.TargetFile), relativePath: ".copilot/mcp-config.json", consumers: []string{"github-copilot"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.profile-specific", "", model.ScopeIDEProfile, "", model.TargetFile)},
	{spec: targetSpec("mcp.remote-user", "", model.ScopeUser, "", model.TargetFile)},
	{spec: targetSpec("mcp.service-managed", "", model.ScopeSystem, "", model.TargetServiceAPI)},
	{spec: targetSpec("mcp.shared.project", "shared", model.ScopeProject, "json", model.TargetFile), relativePath: ".mcp.json", consumers: []string{"claude-code", "vscode"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.vscode-insiders.user", "vscode-insiders", model.ScopeUser, "json", model.TargetFile), relativePath: "Library/Application Support/Code - Insiders/User/mcp.json", consumers: []string{"vscode-insiders"}, container: "servers", supported: true},
	{spec: targetSpec("mcp.vscode.project", "vscode", model.ScopeProject, "json", model.TargetFile), relativePath: ".vscode/mcp.json", consumers: []string{"vscode"}, container: "servers", supported: true},
	{spec: targetSpec("mcp.vscode.user", "vscode", model.ScopeUser, "json", model.TargetFile), relativePath: "Library/Application Support/Code/User/mcp.json", consumers: []string{"vscode"}, container: "servers", supported: true},
	{spec: targetSpec("mcp.windsurf.legacy-user", "windsurf", model.ScopeUser, "json", model.TargetFile), relativePath: ".windsurf/mcp.json", consumers: []string{"windsurf"}, container: "mcpServers", supported: true},
	{spec: targetSpec("mcp.windsurf.user", "windsurf", model.ScopeUser, "json", model.TargetFile), relativePath: ".codeium/windsurf/mcp_config.json", consumers: []string{"windsurf"}, container: "mcpServers", supported: true},
}

func targetSpec(id, host string, scope model.ObservationScope, format string, method model.TargetMethod) model.TargetSpec {
	return model.TargetSpec{
		ID: id, Collector: "mcp", Host: host, Scope: scope,
		Platform: "darwin", Format: format, Method: method,
	}
}

func catalogDeclarations() []targetDeclaration {
	result := make([]targetDeclaration, len(immutableCatalog))
	for index, declaration := range immutableCatalog {
		result[index] = declaration
		result[index].consumers = append([]string(nil), declaration.consumers...)
	}
	return result
}

func catalogSpecs() []model.TargetSpec {
	declarations := catalogDeclarations()
	specs := make([]model.TargetSpec, len(declarations))
	for index, declaration := range declarations {
		specs[index] = declaration.spec
	}
	return specs
}

func declarationByID(id string) (targetDeclaration, bool) {
	index := sort.Search(len(immutableCatalog), func(index int) bool {
		return immutableCatalog[index].spec.ID >= id
	})
	if index >= len(immutableCatalog) || immutableCatalog[index].spec.ID != id {
		return targetDeclaration{}, false
	}
	declaration := immutableCatalog[index]
	declaration.consumers = append([]string(nil), declaration.consumers...)
	return declaration, true
}
