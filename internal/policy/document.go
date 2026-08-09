// Package policy evaluates a local policy document against an inventory
// snapshot. Evaluation is pure: it reads no file, starts no process, and opens
// no socket. Loading a document is the only I/O the package's callers perform,
// and they perform it, not this package — Load takes bytes, so there is no
// path for this package to traverse and no symlink for it to follow.
package policy

import "time"

// SchemaVersion is the only document version this build accepts.
const SchemaVersion = "ssc-init.policy.v1"

// Family is the closed set of rule families. Behavioral rules require
// analyzers that do not exist (design §3, [TI]); the family is deliberately
// absent rather than accepted-and-ignored, so a document written against a
// later build fails loudly here instead of silently protecting nothing.
type Family string

const (
	FamilyShape  Family = "shape"
	FamilyChange Family = "change"
	FamilyPin    Family = "pin"
)

// Scope is the closed set of local exception scopes (design §9.3). Publisher-
// wide and all-version scopes are absent by construction: they are the
// prohibited forms, and a scope this build cannot express is a scope a
// document cannot claim.
type Scope string

const (
	ScopeRun     Scope = "run"
	ScopeAsset   Scope = "asset"
	ScopeProject Scope = "project"
)

// Document is a parsed ssc-init.policy.v1 file.
type Document struct {
	SchemaVersion string      `json:"schemaVersion"`
	Rules         []Rule      `json:"rules"`
	Exceptions    []Exception `json:"exceptions,omitempty"`
}

// Rule is one policy rule. A disabled rule is still parsed and still reported
// by policy check: level 5 ships every rule disabled, and a reader must be able
// to see what is available without editing anything.
type Rule struct {
	ID          string `json:"id"`
	Family      Family `json:"family"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	Match       *Match `json:"match,omitempty"`
}

// Match is the closed set of facts a rule may test. Every field is a set of
// exact values except MetadataContains, and an empty string in a set matches
// an absent or empty fact — so ["latest", ""] covers both mutable forms design
// §6.3 names. There is deliberately no regular expression: a user-supplied
// pattern is an evaluation-time risk surface, and exact sets plus substrings
// express every rule this build has facts for.
type Match struct {
	AssetType         []string            `json:"assetType,omitempty"`
	AssetName         []string            `json:"assetName,omitempty"`
	AssetVersion      []string            `json:"assetVersion,omitempty"`
	Host              []string            `json:"host,omitempty"`
	ObservationSource []string            `json:"observationSource,omitempty"`
	MetadataEquals    map[string][]string `json:"metadataEquals,omitempty"`
	MetadataContains  map[string][]string `json:"metadataContains,omitempty"`
	EvidenceStatus    []string            `json:"evidenceStatus,omitempty"`
	Rungs             []string            `json:"rungs,omitempty"`
}

// Exception is a time- and scope-bound suppression (precedence level 4).
// Declared here so the document shape is stable; Task 7 owns its validation
// and Load performs none beyond rejecting unknown and duplicate keys.
type Exception struct {
	RuleID    string    `json:"ruleId"`
	Scope     Scope     `json:"scope"`
	AssetID   string    `json:"assetId,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	ProjectID string    `json:"projectId,omitempty"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expiresAt"`
}
