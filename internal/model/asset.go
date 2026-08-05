package model

// AssetType identifies the category of an inventoried asset.
type AssetType string

const (
	AssetAgentPlugin  AssetType = "agent-plugin"
	AssetSkill        AssetType = "agent-skill"
	AssetMCP          AssetType = "mcp-server"
	AssetIDEExtension AssetType = "ide-extension"
	AssetPackage      AssetType = "package"
	AssetProject      AssetType = "project"
	AssetTool         AssetType = "tool"
)

// Asset is a supply-chain component discovered during a scan.
type Asset struct {
	ID       string            `json:"id"`
	Type     AssetType         `json:"type"`
	Name     string            `json:"name"`
	Version  string            `json:"version,omitempty"`
	Path     string            `json:"path,omitempty"`
	Source   string            `json:"source,omitempty"`
	SHA256   string            `json:"sha256,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Relationship describes a directed connection between two assets.
type Relationship struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
