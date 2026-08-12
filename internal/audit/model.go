// Package audit defines the closed, privacy-safe record used by audit archives.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const schemaVersion = "ssc-init.audit-record.v1"

type Profile string

const (
	ProfileInternal Profile = "internal"
	ProfileRedacted Profile = "redacted"
)

type State string

const (
	StateComplete State = "complete"
	StatePartial  State = "partial"
	StateFailed   State = "failed"
)

type Stage string

const (
	StageInitialize Stage = "initialize"
	StageDiscover   Stage = "discover"
	StageCollect    Stage = "collect"
	StageAnalyze    Stage = "analyze"
	StagePersist    Stage = "persist"
	StageRender     Stage = "render"
	StageArchive    Stage = "archive"
)

type Run struct {
	ID, ScanID, DeviceID, Label, Product, Version string
	StartedAt, FinishedAt                         time.Time
}

type Failure struct {
	Stage Stage  `json:"stage"`
	Code  string `json:"code"`
}

const (
	CodeInitializeFailed  = "initialize_failed"
	CodeDiscoveryFailed   = "discovery_failed"
	CodeCollectorFailed   = "collector_failed"
	CodeAnalyzerFailed    = "analyzer_failed"
	CodePersistenceFailed = "persistence_failed"
	CodeRenderFailed      = "render_failed"
	CodeAuditUnavailable  = "audit_unavailable"
)

// Summary contains counts only, so it exposes no additional identifiers.
type Summary struct {
	Assets          int `json:"assets"`
	Observations    int `json:"observations"`
	Evidence        int `json:"evidence"`
	Relationships   int `json:"relationships"`
	Findings        int `json:"findings"`
	Collectors      int `json:"collectors"`
	EvidenceTargets int `json:"evidenceTargets"`
	Changes         int `json:"changes"`
}

type Record struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	Profile          Profile                 `json:"profile"`
	State            State                   `json:"state"`
	Run              Run                     `json:"run"`
	Summary          Summary                 `json:"summary"`
	Inventory        model.Inventory         `json:"inventory,omitempty"`
	Findings         []model.Finding         `json:"findings,omitempty"`
	Coverage         []model.CollectorResult `json:"coverage,omitempty"`
	EvidenceCoverage *model.EvidenceCoverage `json:"evidenceCoverage,omitempty"`
	Changes          model.Delta             `json:"changes,omitempty"`
	Failure          *Failure                `json:"failure,omitempty"`
}

var (
	runIDPattern    = regexp.MustCompile(`\Arun:hex:[0-9a-f]{32}\z`)
	deviceIDPattern = regexp.MustCompile(`\Adevice:sha256:[0-9a-f]{64}\z`)
)

// Build constructs a normalized record from a complete or partial scan.
func Build(scan model.ScanResult, inventory model.Inventory, delta model.Delta, findings []model.Finding, run Run) (Record, error) {
	state, ok := scanState(scan.Status)
	if !ok {
		return Record{}, errors.New("audit requires a complete or partial scan")
	}
	clonedInventory, err := cloneInventory(inventory)
	if err != nil {
		return Record{}, err
	}
	clonedFindings, err := cloneFindings(findings)
	if err != nil {
		return Record{}, err
	}
	clonedCoverage, err := cloneCoverage(scan.Coverage)
	if err != nil {
		return Record{}, err
	}
	clonedDelta, err := cloneDelta(delta)
	if err != nil {
		return Record{}, err
	}
	record := Record{
		SchemaVersion: schemaVersion,
		Profile:       ProfileInternal,
		State:         state,
		Run:           normalizeRun(run),
		Inventory:     clonedInventory,
		Findings:      clonedFindings,
		Coverage:      clonedCoverage,
		Changes:       clonedDelta,
	}
	if scan.EvidenceCoverage.Status != "" || len(scan.EvidenceCoverage.Targets) != 0 || len(scan.EvidenceCoverage.Errors) != 0 {
		coverage, err := cloneEvidenceCoverage(scan.EvidenceCoverage)
		if err != nil {
			return Record{}, err
		}
		record.EvidenceCoverage = &coverage
	}
	normalizeRecord(&record)
	record.Summary = summarize(record)
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

// BuildFailure constructs a closed receipt for a failed audit-producing run.
func BuildFailure(run Run, stage Stage, code string) (Record, error) {
	if !validFailure(stage, code) {
		return Record{}, errors.New("invalid audit failure")
	}
	record := Record{
		SchemaVersion: schemaVersion,
		Profile:       ProfileInternal,
		State:         StateFailed,
		Run:           normalizeRun(run),
		Failure:       &Failure{Stage: stage, Code: code},
	}
	record.Summary = summarize(record)
	if err := Validate(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func scanState(status model.ScanStatus) (State, bool) {
	switch status {
	case model.ScanComplete:
		return StateComplete, true
	case model.ScanPartial:
		return StatePartial, true
	default:
		return "", false
	}
}

// ValidLabel reports whether value is a closed, human-safe run label.
func ValidLabel(value string) bool {
	if len(value) < 1 || len(value) > 64 || !utf8.ValidString(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(" ._-", rune(character))) {
			return false
		}
	}
	return asciiAlphanumeric(value[0]) && asciiAlphanumeric(value[len(value)-1])
}

func asciiAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validFailure(stage Stage, code string) bool {
	switch stage {
	case StageInitialize:
		return code == CodeInitializeFailed
	case StageDiscover:
		return code == CodeDiscoveryFailed
	case StageCollect:
		return code == CodeCollectorFailed
	case StageAnalyze:
		return code == CodeAnalyzerFailed
	case StagePersist:
		return code == CodePersistenceFailed
	case StageRender:
		return code == CodeRenderFailed
	case StageArchive:
		return code == CodeAuditUnavailable
	default:
		return false
	}
}

func normalizeRun(run Run) Run {
	run.StartedAt = run.StartedAt.UTC()
	run.FinishedAt = run.FinishedAt.UTC()
	return run
}

func normalizeRecord(record *Record) {
	record.Run = normalizeRun(record.Run)
	sort.Slice(record.Inventory.Assets, func(left, right int) bool {
		return record.Inventory.Assets[left].ID < record.Inventory.Assets[right].ID
	})
	for index := range record.Inventory.Assets {
		normalizeAsset(&record.Inventory.Assets[index])
	}
	sort.Slice(record.Inventory.Observations, func(left, right int) bool {
		return record.Inventory.Observations[left].ID < record.Inventory.Observations[right].ID
	})
	for index := range record.Inventory.Observations {
		normalizeObservation(&record.Inventory.Observations[index])
	}
	sort.Slice(record.Inventory.Evidence, func(left, right int) bool {
		return record.Inventory.Evidence[left].ID < record.Inventory.Evidence[right].ID
	})
	for index := range record.Inventory.Evidence {
		normalizeEvidence(&record.Inventory.Evidence[index])
	}
	sort.Slice(record.Inventory.Relationships, func(left, right int) bool {
		a, b := record.Inventory.Relationships[left], record.Inventory.Relationships[right]
		return relationshipKey(a) < relationshipKey(b)
	})
	sort.Slice(record.Inventory.Errors, func(left, right int) bool {
		return coverageErrorKey(record.Inventory.Errors[left]) < coverageErrorKey(record.Inventory.Errors[right])
	})
	sort.Slice(record.Inventory.Findings, func(left, right int) bool {
		return record.Inventory.Findings[left].ID < record.Inventory.Findings[right].ID
	})
	for index := range record.Inventory.Findings {
		normalizeFinding(&record.Inventory.Findings[index])
	}
	sort.Slice(record.Inventory.AnalyzerFacts, func(left, right int) bool {
		return record.Inventory.AnalyzerFacts[left].ID < record.Inventory.AnalyzerFacts[right].ID
	})
	clearCoverageErrors(record.Inventory.Errors)
	for index := range record.Inventory.Evidence {
		clearEvidenceErrors(record.Inventory.Evidence[index].Errors)
	}
	sort.Slice(record.Findings, func(left, right int) bool { return record.Findings[left].ID < record.Findings[right].ID })
	for index := range record.Findings {
		normalizeFinding(&record.Findings[index])
	}
	sort.Slice(record.Coverage, func(left, right int) bool { return record.Coverage[left].Collector < record.Coverage[right].Collector })
	sort.Slice(record.Changes.Changes, func(left, right int) bool {
		a, b := record.Changes.Changes[left], record.Changes.Changes[right]
		return string(a.Entity)+"\x00"+a.EntityID+"\x00"+string(a.Kind) < string(b.Entity)+"\x00"+b.EntityID+"\x00"+string(b.Kind)
	})
	for index := range record.Coverage {
		normalizeCollectorResult(&record.Coverage[index])
	}
	if record.EvidenceCoverage != nil {
		sort.Slice(record.EvidenceCoverage.Targets, func(left, right int) bool {
			return evidenceTargetKey(record.EvidenceCoverage.Targets[left]) < evidenceTargetKey(record.EvidenceCoverage.Targets[right])
		})
		sort.Slice(record.EvidenceCoverage.Errors, func(left, right int) bool {
			return coverageErrorKey(record.EvidenceCoverage.Errors[left]) < coverageErrorKey(record.EvidenceCoverage.Errors[right])
		})
		clearCoverageErrors(record.EvidenceCoverage.Errors)
		for index := range record.EvidenceCoverage.Targets {
			normalizeEvidenceTarget(&record.EvidenceCoverage.Targets[index])
			clearEvidenceErrors(record.EvidenceCoverage.Targets[index].Errors)
		}
	}
}

func normalizeCollectorResult(result *model.CollectorResult) {
	sort.Slice(result.Assets, func(left, right int) bool { return result.Assets[left].ID < result.Assets[right].ID })
	sort.Slice(result.Relationships, func(left, right int) bool {
		return relationshipKey(result.Relationships[left]) < relationshipKey(result.Relationships[right])
	})
	sort.Slice(result.Errors, func(left, right int) bool {
		return coverageErrorKey(result.Errors[left]) < coverageErrorKey(result.Errors[right])
	})
	sort.Slice(result.Targets, func(left, right int) bool {
		return targetCoverageKey(result.Targets[left]) < targetCoverageKey(result.Targets[right])
	})
	sort.Slice(result.Observations, func(left, right int) bool { return result.Observations[left].ID < result.Observations[right].ID })
	for index := range result.Assets {
		normalizeAsset(&result.Assets[index])
	}
	for index := range result.Observations {
		normalizeObservation(&result.Observations[index])
	}
	clearCoverageErrors(result.Errors)
	for index := range result.Targets {
		if result.Targets[index].InstanceRef != "" && !instanceToken(result.Targets[index].InstanceRef) && !exportToken(result.Targets[index].InstanceRef) {
			result.Targets[index].InstanceRef = targetInstanceToken(result.Targets[index].InstanceRef)
		}
		sort.Slice(result.Targets[index].Errors, func(left, right int) bool {
			return coverageErrorKey(result.Targets[index].Errors[left]) < coverageErrorKey(result.Targets[index].Errors[right])
		})
		clearCoverageErrors(result.Targets[index].Errors)
	}
	sort.Slice(result.Targets, func(left, right int) bool {
		return targetCoverageKey(result.Targets[left]) < targetCoverageKey(result.Targets[right])
	})
}

func targetInstanceToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "instance:sha256:" + hex.EncodeToString(digest[:])
}

func instanceToken(value string) bool {
	return strings.HasPrefix(value, "instance:sha256:") && sha256Hex(strings.TrimPrefix(value, "instance:sha256:"))
}

func normalizeAsset(asset *model.Asset) {
	asset.ObservedAt = asset.ObservedAt.UTC()
	asset.Path, asset.Source, asset.Metadata = "", "", nil
}

func normalizeObservation(observation *model.Observation) {
	observation.Host, observation.LocationRef, observation.Source = "", "", ""
	observation.Consumers, observation.Metadata = nil, nil
}

func normalizeEvidence(evidence *model.ContentEvidence) {
	evidence.Metadata = nil
	sort.Slice(evidence.Errors, func(left, right int) bool { return evidence.Errors[left].Code < evidence.Errors[right].Code })
}

func normalizeEvidenceTarget(target *model.EvidenceTargetResult) {
	sort.Slice(target.Errors, func(left, right int) bool { return target.Errors[left].Code < target.Errors[right].Code })
}

func normalizeFinding(finding *model.Finding) {
	finding.DetectedAt = finding.DetectedAt.UTC()
	for _, values := range []*[]string{&finding.RuleIDs, &finding.IntelligenceIDs, &finding.EvidenceIDs, &finding.CampaignIDs, &finding.AttackTechniques} {
		sort.Strings(*values)
	}
	sort.Slice(finding.Bundles, func(left, right int) bool {
		a, b := finding.Bundles[left], finding.Bundles[right]
		return a.Family+"\x00"+fmt.Sprintf("%020d", a.Sequence)+"\x00"+a.Digest < b.Family+"\x00"+fmt.Sprintf("%020d", b.Sequence)+"\x00"+b.Digest
	})
}

func relationshipKey(value model.Relationship) string {
	return value.From + "\x00" + value.To + "\x00" + value.Kind
}
func coverageErrorKey(value model.CoverageError) string {
	return value.Code + "\x00" + value.Message + "\x00" + value.Path
}

func targetCoverageKey(value model.TargetCoverage) string {
	return value.TargetID + "\x00" + value.InstanceRef
}

func evidenceTargetKey(value model.EvidenceTargetResult) string {
	return value.TargetID + "\x00" + value.AssetID + "\x00" + value.ObservationID + "\x00" + value.EvidenceID
}

func summarize(record Record) Summary {
	summary := Summary{
		Assets:        len(record.Inventory.Assets),
		Observations:  len(record.Inventory.Observations),
		Evidence:      len(record.Inventory.Evidence),
		Relationships: len(record.Inventory.Relationships),
		Findings:      len(record.Findings),
		Collectors:    len(record.Coverage),
		Changes:       len(record.Changes.Changes),
	}
	if record.EvidenceCoverage != nil {
		summary.EvidenceTargets = len(record.EvidenceCoverage.Targets)
	}
	return summary
}

func cloneInventory(value model.Inventory) (model.Inventory, error) { return clone(value) }
func cloneFindings(value []model.Finding) ([]model.Finding, error)  { return clone(value) }
func cloneCoverage(value []model.CollectorResult) ([]model.CollectorResult, error) {
	return clone(value)
}
func cloneEvidenceCoverage(value model.EvidenceCoverage) (model.EvidenceCoverage, error) {
	return clone(value)
}
func cloneDelta(value model.Delta) (model.Delta, error) { return clone(value) }

func clone[T any](value T) (T, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		var zero T
		return zero, errors.New("audit model must be JSON serializable")
	}
	var copied T
	if err := json.Unmarshal(encoded, &copied); err != nil {
		var zero T
		return zero, errors.New("audit model must be JSON deserializable")
	}
	return copied, nil
}
