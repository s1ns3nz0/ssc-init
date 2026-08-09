package finding

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/analyzer"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

type ActiveReader interface {
	Active(context.Context) (bundle.ActiveBundle, error)
}

type Result struct {
	Intelligence string          `json:"intelligence"`
	Policy       string          `json:"policy"`
	Findings     []model.Finding `json:"findings"`
}

type Service struct {
	TI, Policy ActiveReader
	Local      policy.Result
	Now        func() time.Time
}

func (s Service) Evaluate(ctx context.Context, inventory model.Inventory) (Result, error) {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	result := Result{Intelligence: "unavailable", Policy: "inactive", Findings: []model.Finding{}}
	var correlated []model.Finding
	if s.TI != nil {
		ti, err := s.TI.Active(ctx)
		if err != nil && !errors.Is(err, bundle.ErrActiveUnavailable) {
			return Result{}, err
		}
		if err == nil {
			result.Intelligence = string(ti.Status.Freshness)
			correlated = Correlate(inventory, ti, now)
			if ti.Status.Freshness == bundle.FreshnessStale || ti.Status.Freshness == bundle.FreshnessExpired {
				for index := range correlated {
					correlated[index].Confidence = lowerConfidence(correlated[index].Confidence)
				}
			}
		}
	}
	facts := append([]model.AnalyzerFact(nil), inventory.AnalyzerFacts...)
	facts = append(facts, analyzer.MutableFacts(inventory)...)
	correlated = append(correlated, CorrelateAnalyzer(inventory, facts, now)...)
	var activePolicy *bundle.ActiveBundle
	if s.Policy != nil {
		value, policyErr := s.Policy.Active(ctx)
		if policyErr == nil {
			activePolicy, result.Policy = &value, string(value.Status.Freshness)
		} else if !errors.Is(policyErr, bundle.ErrActiveUnavailable) {
			return Result{}, policyErr
		}
	}
	result.Findings = Decide(DecisionInput{Inventory: inventory, Findings: correlated, Policy: activePolicy, Local: s.Local, Now: now})
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].ID < result.Findings[j].ID })
	return result, nil
}

func lowerConfidence(value model.Confidence) model.Confidence {
	if value == model.ConfidenceHigh {
		return model.ConfidenceMedium
	}
	return model.ConfidenceLow
}
