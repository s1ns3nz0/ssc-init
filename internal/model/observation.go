package model

type ObservationScope string

const (
	ScopeUser            ObservationScope = "user"
	ScopeProject         ObservationScope = "project"
	ScopeIDEProfile      ObservationScope = "ide-profile"
	ScopeToolEnvironment ObservationScope = "tool-environment"
	ScopeSystem          ObservationScope = "system"
)

type Observation struct {
	ID          string            `json:"id"`
	AssetID     string            `json:"assetId"`
	Collector   string            `json:"collector"`
	Host        string            `json:"host,omitempty"`
	Consumers   []string          `json:"consumers,omitempty"`
	Scope       ObservationScope  `json:"scope"`
	LocationRef string            `json:"locationRef"`
	ProjectID   string            `json:"projectId,omitempty"`
	Source      string            `json:"source,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type TargetMethod string

const (
	TargetFile       TargetMethod = "file"
	TargetDirectory  TargetMethod = "directory"
	TargetCommand    TargetMethod = "command"
	TargetDynamicAPI TargetMethod = "dynamic-api"
	TargetServiceAPI TargetMethod = "service-api"
)

type TargetStatus string

const (
	TargetComplete    TargetStatus = "complete"
	TargetNotPresent  TargetStatus = "not_present"
	TargetPartial     TargetStatus = "partial"
	TargetUnavailable TargetStatus = "unavailable"
	TargetUnsupported TargetStatus = "unsupported"
	TargetSkipped     TargetStatus = "skipped"
)

type TargetSpec struct {
	ID        string           `json:"id"`
	Collector string           `json:"collector"`
	Host      string           `json:"host,omitempty"`
	Scope     ObservationScope `json:"scope"`
	Platform  string           `json:"platform"`
	Format    string           `json:"format,omitempty"`
	Method    TargetMethod     `json:"method"`
}

type TargetCoverage struct {
	TargetID     string          `json:"targetId"`
	InstanceRef  string          `json:"instanceRef,omitempty"`
	Status       TargetStatus    `json:"status"`
	Assets       int             `json:"assets"`
	Observations int             `json:"observations"`
	Errors       []CoverageError `json:"errors,omitempty"`
}

type ScanScope struct {
	Platform       string   `json:"platform"`
	CatalogVersion string   `json:"catalogVersion"`
	ProjectRoots   []string `json:"projectRoots"`
	ExternalProbes bool     `json:"externalProbes"`
}

type LocalTarget struct {
	TargetID    string   `json:"-"`
	InstanceRef string   `json:"-"`
	Path        string   `json:"-"`
	Format      string   `json:"-"`
	Host        string   `json:"-"`
	Consumers   []string `json:"-"`
	Provenance  any      `json:"-"`
}

type ChangeEntity string

const (
	ChangeEntityAsset       ChangeEntity = "asset"
	ChangeEntityEvidence    ChangeEntity = "evidence"
	ChangeEntityObservation ChangeEntity = "observation"
)
