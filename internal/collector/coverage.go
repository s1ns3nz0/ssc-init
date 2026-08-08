package collector

import (
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

// CatalogVersion identifies the immutable target catalog used by v2 scans.
const CatalogVersion = "ssc-init.catalog.v1"

// TargetedCollector advertises the target contract enforced by the
// orchestrator. Collectors without a target catalog remain compatible.
type TargetedCollector interface {
	Collector
	Targets() []model.TargetSpec
}

// ApplyTargetContract validates and deterministically aggregates one targeted
// collector result.
func ApplyTargetContract(collectorName string, specs []model.TargetSpec, result model.CollectorResult) model.CollectorResult {
	sortedSpecs := append([]model.TargetSpec(nil), specs...)
	sort.Slice(sortedSpecs, func(i, j int) bool { return sortedSpecs[i].ID < sortedSpecs[j].ID })

	knownTargets := make(map[string]struct{}, len(sortedSpecs))
	for _, spec := range sortedSpecs {
		if !validTargetSpec(collectorName, spec) {
			return targetContractViolation(collectorName, result)
		}
		if _, duplicate := knownTargets[spec.ID]; duplicate {
			return targetContractViolation(collectorName, result)
		}
		knownTargets[spec.ID] = struct{}{}
	}

	targets := append([]model.TargetCoverage(nil), result.Targets...)
	reportedTargets := make(map[string]struct{}, len(targets))
	instances := make(map[targetInstance]struct{}, len(targets))
	for _, target := range targets {
		if _, known := knownTargets[target.TargetID]; !known || !validTargetCoverage(target) {
			return targetContractViolation(collectorName, result)
		}
		key := targetInstance{targetID: target.TargetID, instanceRef: target.InstanceRef}
		if _, duplicate := instances[key]; duplicate {
			return targetContractViolation(collectorName, result)
		}
		instances[key] = struct{}{}
		reportedTargets[target.TargetID] = struct{}{}
	}

	for _, spec := range sortedSpecs {
		if _, reported := reportedTargets[spec.ID]; reported {
			continue
		}
		targets = append(targets, model.TargetCoverage{
			TargetID: spec.ID,
			Status:   model.TargetUnsupported,
			Errors: []model.CoverageError{{
				Code:    "target_not_reported",
				Message: "target was not reported",
			}},
		})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].TargetID == targets[j].TargetID {
			return targets[i].InstanceRef < targets[j].InstanceRef
		}
		return targets[i].TargetID < targets[j].TargetID
	})

	result.Collector = collectorName
	result.Targets = targets
	if result.Status != model.CoverageFailed {
		result.Status = AggregateTargetStatus(targets)
	}
	return result
}

// AggregateTargetStatus returns the only collector status justified by the
// reported target statuses.
func AggregateTargetStatus(targets []model.TargetCoverage) model.CoverageStatus {
	if len(targets) == 0 {
		return model.CoveragePartial
	}
	allComplete := true
	allSkipped := true
	allUnavailable := true
	for _, target := range targets {
		if target.Status != model.TargetComplete && target.Status != model.TargetNotPresent {
			allComplete = false
		}
		if target.Status != model.TargetSkipped {
			allSkipped = false
		}
		if target.Status != model.TargetUnavailable {
			allUnavailable = false
		}
	}
	switch {
	case allComplete:
		return model.CoverageComplete
	case allSkipped:
		return model.CoverageSkipped
	case allUnavailable:
		return model.CoverageUnavailable
	default:
		return model.CoveragePartial
	}
}

type targetInstance struct {
	targetID    string
	instanceRef string
}

func validTargetSpec(collectorName string, spec model.TargetSpec) bool {
	if collectorName == "" || spec.ID == "" || spec.Collector != collectorName || spec.Platform != "darwin" {
		return false
	}
	switch spec.Scope {
	case model.ScopeUser, model.ScopeProject, model.ScopeIDEProfile, model.ScopeToolEnvironment, model.ScopeSystem:
	default:
		return false
	}
	switch spec.Method {
	case model.TargetFile, model.TargetDirectory, model.TargetCommand, model.TargetDynamicAPI, model.TargetServiceAPI:
		return true
	default:
		return false
	}
}

func validTargetCoverage(target model.TargetCoverage) bool {
	if target.TargetID == "" || target.Assets < 0 || target.Observations < 0 {
		return false
	}
	switch target.Status {
	case model.TargetComplete, model.TargetNotPresent, model.TargetPartial, model.TargetUnavailable, model.TargetUnsupported, model.TargetSkipped:
		return true
	default:
		return false
	}
}

// targetContractViolation discards the offending result, so its sealed runtime
// evidence state is cleared before the failure replaces it.
func targetContractViolation(collectorName string, rejected model.CollectorResult) model.CollectorResult {
	ClearLocalEvidenceTargets([]model.CollectorResult{rejected})
	return failedResult(collectorName, "coverage_contract_violation", "collector violated target coverage contract")
}
