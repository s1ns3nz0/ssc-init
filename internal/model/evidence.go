package model

type EvidenceKind string

const (
	EvidenceFileSHA256        EvidenceKind = "file-sha256"
	EvidenceTreeSHA256        EvidenceKind = "tree-sha256"
	EvidenceSemanticSHA256    EvidenceKind = "semantic-sha256"
	EvidencePackageContent    EvidenceKind = "package-content"
	EvidenceContainerIdentity EvidenceKind = "container-identity"
)

type EvidenceStatus string

const (
	EvidenceComplete    EvidenceStatus = "complete"
	EvidencePartial     EvidenceStatus = "partial"
	EvidenceOversize    EvidenceStatus = "oversize"
	EvidenceUnavailable EvidenceStatus = "unavailable"
	EvidenceUnsupported EvidenceStatus = "unsupported"
	EvidenceSkipped     EvidenceStatus = "skipped"
)

const (
	EvidenceSubjectManifest          = "manifest"
	EvidenceSubjectSkillDocument     = "skill-document"
	EvidenceSubjectEntrypointMain    = "entrypoint-main"
	EvidenceSubjectEntrypointBrowser = "entrypoint-browser"
	EvidenceSubjectPayloadTree       = "payload-tree"
	EvidenceSubjectMCPDeclaration    = "mcp-declaration"
	EvidenceSubjectPackageContent    = "package-content"
	EvidenceSubjectContainerImage    = "container-image"
)

// ProjectEvidenceSubject reports whether subject is one of the closed project
// manifest and lockfile evidence subjects.
func ProjectEvidenceSubject(subject string) bool {
	switch subject {
	case "project-manifest:package.json",
		"project-lockfile:package-lock.json",
		"project-lockfile:npm-shrinkwrap.json",
		"project-lockfile:pnpm-lock.yaml",
		"project-lockfile:yarn.lock",
		"project-lockfile:bun.lock",
		"project-lockfile:bun.lockb",
		"project-manifest:pyproject.toml",
		"project-manifest:Pipfile",
		"project-manifest:requirements.txt",
		"project-lockfile:poetry.lock",
		"project-lockfile:Pipfile.lock",
		"project-lockfile:uv.lock",
		"project-manifest:go.mod",
		"project-lockfile:go.sum",
		"project-manifest:Cargo.toml",
		"project-lockfile:Cargo.lock",
		"project-manifest:Brewfile":
		return true
	default:
		return false
	}
}

type ContentEvidence struct {
	ID            string            `json:"id"`
	AssetID       string            `json:"assetId"`
	ObservationID string            `json:"observationId"`
	Kind          EvidenceKind      `json:"kind"`
	Subject       string            `json:"subject"`
	Status        EvidenceStatus    `json:"status"`
	Algorithm     string            `json:"algorithm,omitempty"`
	Digest        string            `json:"digest,omitempty"`
	Size          int64             `json:"size,omitempty"`
	Files         int               `json:"files,omitempty"`
	Directories   int               `json:"directories,omitempty"`
	Symlinks      int               `json:"symlinks,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Errors        []EvidenceError   `json:"errors,omitempty"`
}

type EvidenceError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type EvidenceCoverage struct {
	Status  CoverageStatus         `json:"status"`
	Targets []EvidenceTargetResult `json:"targets"`
	Errors  []CoverageError        `json:"errors,omitempty"`
}

type EvidenceTargetResult struct {
	TargetID      string          `json:"targetId"`
	AssetID       string          `json:"assetId"`
	ObservationID string          `json:"observationId"`
	EvidenceID    string          `json:"evidenceId"`
	Status        EvidenceStatus  `json:"status"`
	Errors        []EvidenceError `json:"errors,omitempty"`
}

// LocalEvidenceTarget contains runtime-only filesystem evidence inputs.
type LocalEvidenceTarget struct {
	TargetID      string         `json:"-"`
	AssetID       string         `json:"-"`
	ObservationID string         `json:"-"`
	Kind          EvidenceKind   `json:"-"`
	Subject       string         `json:"-"`
	PresetStatus  EvidenceStatus `json:"-"`
	RootPath      string         `json:"-"`
	RelativePath  string         `json:"-"`
	Provenance    any            `json:"-"`
}
