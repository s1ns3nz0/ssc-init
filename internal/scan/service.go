// Package scan coordinates one immutable baseline snapshot.
package scan

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/analyzer"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/mcp"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const schemaVersion = "ssc-init.scan.v7"

type FailureStage string

const (
	FailureInitialize FailureStage = "initialize"
	FailureCollect    FailureStage = "collect"
	FailureAnalyze    FailureStage = "analyze"
	FailurePersist    FailureStage = "persist"
)

type FailureError struct {
	Stage FailureStage
	err   error
}

func (e *FailureError) Error() string { return "baseline scan failed" }
func (e *FailureError) Unwrap() error { return e.err }

func NewFailure(stage FailureStage, err error) error { return &FailureError{Stage: stage, err: err} }

func FailureStageOf(err error) (FailureStage, bool) {
	var failure *FailureError
	if !errors.As(err, &failure) {
		return "", false
	}
	return failure.Stage, true
}

// DefaultBudget bounds one baseline scan. Design §12 allows the initial
// baseline at most 10 minutes; exceeding a time budget must produce a partial
// result naming the unscanned targets rather than a silently truncated
// complete one.
const DefaultBudget = 10 * time.Minute

// SnapshotStore is the persistence boundary required by a baseline scan.
type SnapshotStore interface {
	SaveScan(context.Context, model.ScanResult, model.Inventory) error
	LatestSnapshot(context.Context) (model.Snapshot, bool, error)
}

// Service runs collectors and persists their normalized result.
type Service struct {
	// Budget bounds collection and evidence for one scan. It is a
	// construction-time value — NewService sets DefaultBudget — and is not
	// user-configurable. A non-positive value disables the budget.
	Budget       time.Duration
	orchestrator collector.Orchestrator
	snapshots    SnapshotStore
	now          func() time.Time
	newID        func() string
	environment  collector.Environment
	hasEnv       bool
	configErr    error
}

// NewService constructs a baseline service. Supplying one environment enables
// real host collection and the project-aware MCP follow-up. No environment is
// useful for collectors whose tests do not access the host. More than one is
// ambiguous and causes Baseline to fail before persistence.
func NewService(orchestrator collector.Orchestrator, snapshots SnapshotStore, now func() time.Time, newID func() string, environments ...collector.Environment) *Service {
	service := &Service{Budget: DefaultBudget, orchestrator: orchestrator, snapshots: snapshots, now: now, newID: newID}
	if service.now == nil {
		service.now = func() time.Time { return time.Now().UTC() }
	}
	if service.newID == nil {
		service.newID = randomUUIDv4
	}
	switch len(environments) {
	case 0:
		service.environment.Scope.CatalogVersion = collector.CatalogVersion
	case 1:
		service.environment = environments[0]
		service.environment.Scope = buildScope(service.environment)
		service.environment.Platform = service.environment.Scope.Platform
		service.hasEnv = true
	default:
		service.configErr = errors.New("scan service has an ambiguous environment")
	}
	return service
}

// Baseline collects, normalizes, compares, and atomically saves one snapshot.
// The reported bool is true when no previous snapshot existed — the first run
// on this machine. A delta cannot carry that fact, because a first snapshot
// recording zero assets makes the run after it look like a first run.
func (s *Service) Baseline(ctx context.Context) (model.ScanResult, model.Inventory, model.Delta, bool, error) {
	if s == nil || s.snapshots == nil {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, errors.New("scan service is not configured")
	}
	if s.configErr != nil {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, s.configErr
	}
	if err := ctx.Err(); err != nil {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, err
	}

	startedAt := s.now().UTC()
	if startedAt.IsZero() {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, errors.New("capture scan start time")
	}
	// Collection and evidence run under the budget; persistence runs under the
	// caller's context so an overrun still commits its partial result. Only the
	// caller's own context distinguishes the two outcomes: while it is live, a
	// done budget context means the budget bound, never a caller cancellation.
	budgetCtx, cancelBudget := s.withBudget(ctx)
	defer cancelBudget()

	results := s.orchestrator.Collect(budgetCtx, s.environment)
	if err := ctx.Err(); err != nil {
		clearRuntimeState(results)
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, err
	}
	if s.hasEnv {
		results = s.collectProjectMCP(budgetCtx, results)
		if err := ctx.Err(); err != nil {
			clearRuntimeState(results)
			return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, err
		}
	}
	for index := range results {
		results[index].LocalTargets = nil
	}

	current := inventory.Build(results)
	if current.Observations == nil {
		current.Observations = []model.Observation{}
	}
	collection := s.collectLocalEvidence(budgetCtx, current, results)
	if err := ctx.Err(); err != nil {
		clearRuntimeState(results)
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, err
	}
	current.Evidence = append(current.Evidence, collection.Evidence...)
	if len(collection.AnalyzerFacts) > 0 {
		current.AnalyzerFacts = append([]model.AnalyzerFact(nil), collection.AnalyzerFacts...)
	}
	sort.SliceStable(current.Evidence, func(i, j int) bool {
		return current.Evidence[i].ID < current.Evidence[j].ID
	})

	previousSnapshot, exists, err := s.snapshots.LatestSnapshot(ctx)
	if err != nil {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, NewFailure(FailurePersist, errors.New("load previous inventory"))
	}
	previous := previousSnapshot.Inventory
	if !exists {
		previous = model.Inventory{Assets: []model.Asset{}, Relationships: []model.Relationship{}}
	}
	delta := inventory.Diff(previous, current)

	scanID := s.newID()
	if !validUUIDv4(scanID) {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, errors.New("create scan identifier")
	}
	finishedAt := s.now().UTC()
	if finishedAt.IsZero() {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, errors.New("capture scan finish time")
	}
	if finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	result := model.ScanResult{
		SchemaVersion:    schemaVersion,
		ScanID:           scanID,
		Status:           overallStatus(results, current, collection.Coverage.Status),
		StartedAt:        startedAt,
		FinishedAt:       finishedAt,
		Coverage:         results,
		EvidenceCoverage: collection.Coverage,
		Scope:            s.environment.Scope,
		AnalyzerCoverage: collection.AnalyzerCoverage,
	}
	if err := s.snapshots.SaveScan(ctx, result, current); err != nil {
		return model.ScanResult{}, model.Inventory{}, model.Delta{}, false, NewFailure(FailurePersist, errors.New("save baseline snapshot"))
	}
	if writer, ok := s.snapshots.(evidence.CacheWriter); ok && len(collection.CacheWrites) > 0 {
		_ = writer.StoreContentCache(ctx, collection.CacheWrites)
	}
	return result, current, delta, !exists, nil
}

// withBudget bounds collection and evidence. A caller context that is already
// bounded more tightly keeps its own deadline, so a caller deadline stays a
// cancellation rather than becoming a budget overrun.
func (s *Service) withBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.Budget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.Budget)
}

// clearRuntimeState drops the runtime-only evidence and target state of results
// abandoned by a cancellation, which never reach the normal clearing path.
func clearRuntimeState(results []model.CollectorResult) {
	collector.ClearLocalEvidenceTargets(results)
	for index := range results {
		for targetIndex := range results[index].LocalTargets {
			results[index].LocalTargets[targetIndex] = model.LocalTarget{}
		}
		results[index].LocalTargets = nil
	}
}

// collectLocalEvidence runs the bounded local evidence engine against the
// normalized graph and clears every runtime target before the result is used
// for reporting or persistence. The persistent store's content cache is wired
// automatically; other snapshot stores use the explicit disabled cache.
func (s *Service) collectLocalEvidence(ctx context.Context, current model.Inventory, results []model.CollectorResult) evidence.Collection {
	engine := evidence.Engine{Cache: evidence.DisabledLeafCache{}, Analyzer: analyzer.Scanner{}}
	if cache, ok := s.snapshots.(evidence.LeafCache); ok {
		engine.Cache = cache
	}
	collection := engine.Collect(ctx, s.environment, current, results)
	if collection.Coverage.Targets == nil {
		collection.Coverage.Targets = []model.EvidenceTargetResult{}
	}
	return collection
}

func (s *Service) collectProjectMCP(ctx context.Context, results []model.CollectorResult) []model.CollectorResult {
	projectTargets := make([]model.LocalTarget, 0)
	for index := range results {
		localTargets := results[index].LocalTargets
		results[index].LocalTargets = nil
		for targetIndex := range localTargets {
			target := &localTargets[targetIndex]
			if results[index].Collector == "projects" && s.validProjectLocalTarget(target) && mcp.ValidProjectTarget(s.environment.Home, target) {
				projectTargets = append(projectTargets, *target)
			}
			localTargets[targetIndex] = model.LocalTarget{}
		}
	}
	followUp := collector.Orchestrator{
		Collectors:    []collector.Collector{mcp.New(projectTargets...)},
		Timeout:       s.orchestrator.Timeout,
		MaxConcurrent: 1,
	}.Collect(ctx, s.environment)
	for index := range projectTargets {
		projectTargets[index] = model.LocalTarget{}
	}
	projectTargets = nil
	if len(followUp) != 1 {
		return results
	}

	merged := make([]model.CollectorResult, 0, len(results)+1)
	for index := range results {
		if results[index].Collector == "mcp" {
			// The initial MCP result is replaced by the sealed follow-up, so
			// its runtime evidence state must not survive the merge.
			collector.ClearLocalEvidenceTargets(results[index : index+1])
			continue
		}
		merged = append(merged, results[index])
	}
	merged = append(merged, followUp[0])
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].Collector < merged[j].Collector })
	return merged
}

func (s *Service) validProjectLocalTarget(target *model.LocalTarget) bool {
	for _, configured := range s.orchestrator.Collectors {
		if projects.ValidLocalTarget(configured, s.environment.Home, target) {
			return true
		}
	}
	return false
}

func buildScope(environment collector.Environment) model.ScanScope {
	scope := environment.Scope
	if environment.Platform != "" {
		scope.Platform = environment.Platform
	}
	scope.CatalogVersion = collector.CatalogVersion
	scope.ProjectRoots = append([]string(nil), scope.ProjectRoots...)
	return scope
}

func overallStatus(results []model.CollectorResult, current model.Inventory, evidenceStatus model.CoverageStatus) model.ScanStatus {
	if evidenceStatus != model.CoverageComplete {
		return model.ScanPartial
	}
	if len(results) == 0 || len(current.Errors) > 0 {
		return model.ScanPartial
	}
	for _, result := range results {
		if result.Status != model.CoverageComplete {
			return model.ScanPartial
		}
	}
	return model.ScanComplete
}

func randomUUIDv4() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ""
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func validUUIDv4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '4' {
		return false
	}
	if !strings.ContainsRune("89abAB", rune(value[19])) {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}
