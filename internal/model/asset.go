package model

import "time"

// AssetType identifies the category of an inventoried asset.
type AssetType string

const (
	AssetAgentPlugin       AssetType = "agent-plugin"
	AssetSkill             AssetType = "agent-skill"
	AssetMCP               AssetType = "mcp-server"
	AssetIDEExtension      AssetType = "ide-extension"
	AssetPackage           AssetType = "package"
	AssetProject           AssetType = "project"
	AssetTool              AssetType = "tool"
	AssetShellStartup      AssetType = "shell-startup"
	AssetGitHook           AssetType = "git-hook"
	AssetCredentialHelper  AssetType = "credential-helper"
	AssetLaunchConfig      AssetType = "launch-config"
	AssetProcess           AssetType = "process"
	AssetListeningEndpoint AssetType = "listening-endpoint"
)

// SignatureStatus is the closed result of platform signature inspection. It
// reports a verification fact, never a safety verdict.
type SignatureStatus string

const (
	SignatureValid       SignatureStatus = "valid"
	SignatureInvalid     SignatureStatus = "invalid"
	SignatureUnsigned    SignatureStatus = "unsigned"
	SignatureUnavailable SignatureStatus = "unavailable"
	SignatureUnsupported SignatureStatus = "unsupported"
)

func (status SignatureStatus) Valid() bool {
	switch status {
	case SignatureValid, SignatureInvalid, SignatureUnsigned, SignatureUnavailable, SignatureUnsupported:
		return true
	default:
		return false
	}
}

// ProvenanceStatus states whether the locally available source fixes an exact
// artifact. Unknown and unsupported remain explicit non-claims.
type ProvenanceStatus string

const (
	ProvenanceImmutable   ProvenanceStatus = "immutable"
	ProvenanceMutable     ProvenanceStatus = "mutable"
	ProvenanceUnknown     ProvenanceStatus = "unknown"
	ProvenanceUnavailable ProvenanceStatus = "unavailable"
	ProvenanceUnsupported ProvenanceStatus = "unsupported"
)

func (status ProvenanceStatus) Valid() bool {
	switch status {
	case ProvenanceImmutable, ProvenanceMutable, ProvenanceUnknown, ProvenanceUnavailable, ProvenanceUnsupported:
		return true
	default:
		return false
	}
}

// Signature contains bounded machine identities only. Certificate display
// names and authority chains are intentionally excluded.
type Signature struct {
	Status     SignatureStatus `json:"status"`
	Identifier string          `json:"identifier,omitempty"`
	TeamID     string          `json:"teamId,omitempty"`
}

// Provenance contains a normalized local source and, only when it is an exact
// SHA-256 fact, its algorithm-tagged integrity value. URLs and paths are never
// represented here.
type Provenance struct {
	Status    ProvenanceStatus `json:"status"`
	Ecosystem string           `json:"ecosystem"`
	Source    string           `json:"source,omitempty"`
	Integrity string           `json:"integrity,omitempty"`
}

// MetadataObservedAt is the sole metadata timestamp excluded from inventory
// change detection. All other metadata remains change-significant.
const MetadataObservedAt = "observedAt"

// Asset is a supply-chain component discovered during a scan.
type Asset struct {
	ID         string            `json:"id"`
	Type       AssetType         `json:"type"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Path       string            `json:"path,omitempty"`
	Source     string            `json:"source,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	ObservedAt time.Time         `json:"observedAt,omitempty,omitzero"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Signature  *Signature        `json:"signature,omitempty"`
	Provenance *Provenance       `json:"provenance,omitempty"`
}

// Relationship describes a directed connection between two assets.
type Relationship struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

const (
	RelationshipContains   = "contains"
	RelationshipConfigures = "configures"
	RelationshipUses       = "uses"
	RelationshipSameAs     = "same-as"
	RelationshipProbedBy   = "probed-by"
	RelationshipDeclaredBy = "declared-by"
	RelationshipResolvesTo = "resolves-to"
	RelationshipExecutes   = "executes"
	RelationshipConnectsTo = "connects-to"
)

// ValidRelationshipKind reports whether kind belongs to the persisted graph
// vocabulary. Collectors must not mint relationship semantics dynamically.
func ValidRelationshipKind(kind string) bool {
	switch kind {
	case RelationshipContains, RelationshipConfigures, RelationshipUses, RelationshipSameAs, RelationshipProbedBy, RelationshipDeclaredBy,
		RelationshipResolvesTo, RelationshipExecutes, RelationshipConnectsTo:
		return true
	default:
		return false
	}
}
