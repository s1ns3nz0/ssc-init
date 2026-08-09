package runtime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const (
	processTargetID  = "runtime.processes"
	listenerTargetID = "runtime.tcp-listeners"
	psPath           = "/bin/ps"
	lsofPath         = "/usr/sbin/lsof"
)

type runtimeCollector struct{}

func New() collector.TargetedCollector { return &runtimeCollector{} }

func (*runtimeCollector) Name() string { return "runtime" }

func (*runtimeCollector) Targets() []model.TargetSpec {
	return []model.TargetSpec{
		{ID: processTargetID, Collector: "runtime", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "ps-fields", Method: model.TargetCommand},
		{ID: listenerTargetID, Collector: "runtime", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "lsof-fields", Method: model.TargetCommand},
	}
}

func (c *runtimeCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	if !env.Scope.ExternalProbes {
		for _, target := range c.Targets() {
			result.Targets = append(result.Targets, model.TargetCoverage{TargetID: target.ID, Status: model.TargetSkipped})
		}
		result.Status = model.CoverageSkipped
		return result, nil
	}
	if env.Runner == nil {
		for _, target := range c.Targets() {
			result.Targets = append(result.Targets, runtimeTargetError(target.ID, model.TargetUnavailable, "runner_unavailable", "runtime probe is unavailable"))
		}
		result.Status = model.CoveragePartial
		return result, nil
	}

	processTarget := model.TargetCoverage{TargetID: processTargetID, Status: model.TargetComplete}
	processOutput, runErr := env.Runner.Run(ctx, psPath, "-axo", "pid=,comm=")
	if err := ctx.Err(); err != nil {
		return model.CollectorResult{Collector: c.Name()}, err
	}
	processes := []processFact(nil)
	if runErr != nil || processOutput.ExitCode != 0 {
		processTarget = runtimeTargetError(processTargetID, model.TargetUnavailable, "probe_failed", "runtime process probe failed")
	} else if processOutput.Truncated {
		processTarget = runtimeTargetError(processTargetID, model.TargetPartial, "output_truncated", "runtime process output was truncated")
	} else if parsed, err := parseProcessSnapshot(processOutput.Stdout); err != nil {
		processTarget = runtimeTargetError(processTargetID, model.TargetPartial, "output_malformed", "runtime process output is malformed")
	} else {
		processes = parsed
		for _, fact := range processes {
			asset, observation, ok := processAssetObservation(fact)
			if !ok {
				processTarget.Status = model.TargetPartial
				processTarget.Errors = append(processTarget.Errors, model.CoverageError{Code: "identity_rejected", Message: "runtime process identity was rejected"})
				continue
			}
			result.Assets = append(result.Assets, asset)
			result.Observations = append(result.Observations, observation)
			processTarget.Assets++
			processTarget.Observations++
		}
	}
	result.Targets = append(result.Targets, processTarget)

	listenerTarget := model.TargetCoverage{TargetID: listenerTargetID, Status: model.TargetComplete}
	listenerOutput, runErr := env.Runner.Run(ctx, lsofPath, "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn")
	if err := ctx.Err(); err != nil {
		return model.CollectorResult{Collector: c.Name()}, err
	}
	if runErr != nil || listenerOutput.ExitCode != 0 {
		listenerTarget = runtimeTargetError(listenerTargetID, model.TargetUnavailable, "probe_failed", "runtime listener probe failed")
	} else if listenerOutput.Truncated {
		listenerTarget = runtimeTargetError(listenerTargetID, model.TargetPartial, "output_truncated", "runtime listener output was truncated")
	} else if listeners, err := parseListenerSnapshot(listenerOutput.Stdout); err != nil {
		listenerTarget = runtimeTargetError(listenerTargetID, model.TargetPartial, "output_malformed", "runtime listener output is malformed")
	} else {
		for _, fact := range listeners {
			asset, observation, ok := listenerAssetObservation(fact)
			if !ok {
				listenerTarget.Status = model.TargetPartial
				listenerTarget.Errors = append(listenerTarget.Errors, model.CoverageError{Code: "identity_rejected", Message: "runtime listener identity was rejected"})
				continue
			}
			result.Assets = append(result.Assets, asset)
			result.Observations = append(result.Observations, observation)
			listenerTarget.Assets++
			listenerTarget.Observations++
		}
	}
	result.Targets = append(result.Targets, listenerTarget)
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.Slice(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func processAssetObservation(fact processFact) (model.Asset, model.Observation, bool) {
	id := runtimeID("process", strconv.Itoa(fact.PID), fact.Executable)
	asset := model.Asset{ID: id, Type: model.AssetProcess, Name: fact.Executable, Source: "process-snapshot", Metadata: map[string]string{"pid": strconv.Itoa(fact.PID)}}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: id, Collector: "runtime", Scope: model.ScopeToolEnvironment,
		LocationRef: "runtime:process:" + strconv.Itoa(fact.PID), Source: processTargetID,
	})
	return asset, observation, err == nil
}

func listenerAssetObservation(fact listenerFact) (model.Asset, model.Observation, bool) {
	pid, port := strconv.Itoa(fact.PID), strconv.Itoa(fact.Port)
	id := runtimeID("listener", pid, fact.Protocol, port)
	asset := model.Asset{ID: id, Type: model.AssetListeningEndpoint, Name: "tcp-listener", Source: "listener-snapshot", Metadata: map[string]string{"port": port, "protocol": fact.Protocol, "pid": pid}}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: id, Collector: "runtime", Scope: model.ScopeToolEnvironment,
		LocationRef: "runtime:listener:" + pid + ":" + port, Source: listenerTargetID,
	})
	return asset, observation, err == nil
}

func runtimeID(prefix string, fields ...string) string {
	material := "ssc-init.runtime.v1\x00" + prefix
	for _, field := range fields {
		material += "\x00" + field
	}
	digest := sha256.Sum256([]byte(material))
	return fmt.Sprintf("%s:sha256:%x", prefix, digest)
}

func runtimeTargetError(id string, status model.TargetStatus, code, message string) model.TargetCoverage {
	return model.TargetCoverage{TargetID: id, Status: status, Errors: []model.CoverageError{{Code: code, Message: message}}}
}
