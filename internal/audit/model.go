// Package audit defines the closed, privacy-safe record used by audit archives.
package audit

import (
	"encoding/json"
	"errors"
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
	record := Record{
		SchemaVersion: schemaVersion,
		Profile:       ProfileInternal,
		State:         state,
		Run:           normalizeRun(run),
		Inventory:     cloneInventory(inventory),
		Findings:      cloneFindings(findings),
		Coverage:      cloneCoverage(scan.Coverage),
		Changes:       cloneDelta(delta),
	}
	coverage := cloneEvidenceCoverage(scan.EvidenceCoverage)
	record.EvidenceCoverage = &coverage
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
	sort.Slice(record.Inventory.Observations, func(left, right int) bool {
		return record.Inventory.Observations[left].ID < record.Inventory.Observations[right].ID
	})
	sort.Slice(record.Inventory.Evidence, func(left, right int) bool {
		return record.Inventory.Evidence[left].ID < record.Inventory.Evidence[right].ID
	})
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
	sort.Slice(record.Inventory.AnalyzerFacts, func(left, right int) bool {
		return record.Inventory.AnalyzerFacts[left].ID < record.Inventory.AnalyzerFacts[right].ID
	})
	clearCoverageErrors(record.Inventory.Errors)
	for index := range record.Inventory.Evidence {
		clearEvidenceErrors(record.Inventory.Evidence[index].Errors)
	}
	sort.Slice(record.Findings, func(left, right int) bool { return record.Findings[left].ID < record.Findings[right].ID })
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
			return record.EvidenceCoverage.Targets[left].TargetID < record.EvidenceCoverage.Targets[right].TargetID
		})
		sort.Slice(record.EvidenceCoverage.Errors, func(left, right int) bool {
			return coverageErrorKey(record.EvidenceCoverage.Errors[left]) < coverageErrorKey(record.EvidenceCoverage.Errors[right])
		})
		clearCoverageErrors(record.EvidenceCoverage.Errors)
		for index := range record.EvidenceCoverage.Targets {
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
	sort.Slice(result.Targets, func(left, right int) bool { return result.Targets[left].TargetID < result.Targets[right].TargetID })
	sort.Slice(result.Observations, func(left, right int) bool { return result.Observations[left].ID < result.Observations[right].ID })
	clearCoverageErrors(result.Errors)
	for index := range result.Targets {
		clearCoverageErrors(result.Targets[index].Errors)
	}
}

func relationshipKey(value model.Relationship) string {
	return value.From + "\x00" + value.To + "\x00" + value.Kind
}
func coverageErrorKey(value model.CoverageError) string {
	return value.Code + "\x00" + value.Message + "\x00" + value.Path
}

func summarize(record Record) Summary {
	summary := Summary{
		Assets:        len(record.Inventory.Assets),
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

func cloneInventory(value model.Inventory) model.Inventory                      { return clone(value) }
func cloneFindings(value []model.Finding) []model.Finding                       { return clone(value) }
func cloneCoverage(value []model.CollectorResult) []model.CollectorResult       { return clone(value) }
func cloneEvidenceCoverage(value model.EvidenceCoverage) model.EvidenceCoverage { return clone(value) }
func cloneDelta(value model.Delta) model.Delta                                  { return clone(value) }

func clone[T any](value T) T {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("audit model must be JSON serializable: " + err.Error())
	}
	var copied T
	if err := json.Unmarshal(encoded, &copied); err != nil {
		panic("audit model must be JSON deserializable: " + err.Error())
	}
	return copied
}
