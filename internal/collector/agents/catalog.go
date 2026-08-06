package agents

import "github.com/ssc-init/ssc-init/internal/model"

type markerKind string

const (
	markerClaudePlugin markerKind = "claude-plugin"
	markerCodexPlugin  markerKind = "codex-plugin"
	markerSkill        markerKind = "skill"
)

type targetDeclaration struct {
	spec         model.TargetSpec
	relativePath string
	kind         model.AssetType
	marker       markerKind
	supported    bool
}

var immutableCatalog = []targetDeclaration{
	{spec: agentTargetSpec("agents.claude.plugins", "claude", model.TargetDirectory), relativePath: ".claude/plugins", kind: model.AssetAgentPlugin, marker: markerClaudePlugin, supported: true},
	{spec: agentTargetSpec("agents.claude.skills", "claude", model.TargetDirectory), relativePath: ".claude/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
	{spec: agentTargetSpec("agents.codex.plugins", "codex", model.TargetDirectory), relativePath: ".codex/plugins", kind: model.AssetAgentPlugin, marker: markerCodexPlugin, supported: true},
	{spec: agentTargetSpec("agents.codex.skills", "codex", model.TargetDirectory), relativePath: ".codex/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
	{spec: agentTargetSpec("agents.cursor.plugins", "cursor", model.TargetDirectory), relativePath: ".cursor/plugins", kind: model.AssetAgentPlugin},
	{spec: agentTargetSpec("agents.cursor.skills", "cursor", model.TargetDirectory), relativePath: ".cursor/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
	{spec: agentTargetSpec("agents.custom-roots", "", model.TargetDirectory)},
	{spec: agentTargetSpec("agents.dynamic-api", "", model.TargetDynamicAPI)},
	{spec: agentTargetSpec("agents.environment-relocated", "", model.TargetDirectory)},
	{spec: agentTargetSpec("agents.remote-host", "", model.TargetDirectory)},
	{spec: agentTargetSpec("agents.windsurf.plugins", "windsurf", model.TargetDirectory), relativePath: ".windsurf", kind: model.AssetAgentPlugin},
}

func agentTargetSpec(id, host string, method model.TargetMethod) model.TargetSpec {
	return model.TargetSpec{
		ID: id, Collector: "agents", Host: host, Scope: model.ScopeUser,
		Platform: "darwin", Method: method,
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
