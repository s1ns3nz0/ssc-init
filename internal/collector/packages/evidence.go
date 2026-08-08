package packages

import (
	"context"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const dockerProbeTargetID = "packages.docker"

// issuePackageArtifactEvidence seals one path-free terminal target for a
// finalized package observation. Package and container artifacts are not local
// content, so the target is explicitly unsupported instead of silently absent:
// it carries no path, anchor, digest, size, count, or metadata, and the engine
// never touches the filesystem or a command runner to resolve it. Binding is
// deliberately reentrant so every package in one collector result shares the
// result's issuer while retaining an independent proof.
func issuePackageArtifactEvidence(ctx context.Context, result *model.CollectorResult, probe commandProbe, observation model.Observation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		return nil
	}
	target := model.LocalEvidenceTarget{
		TargetID: probe.targetID + ".content", AssetID: observation.AssetID, ObservationID: observation.ID,
		Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent,
		PresetStatus: model.EvidenceUnsupported,
	}
	if probe.targetID == dockerProbeTargetID {
		target.TargetID = dockerProbeTargetID + ".container-identity"
		target.Kind = model.EvidenceContainerIdentity
		target.Subject = model.EvidenceSubjectContainerImage
	}
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(target, evidence.Anchor{}))
	return ctx.Err()
}

// abortPackageCollection discards every sealed runtime target and issuer before
// an interrupted collection is returned, so no partially issued state escapes.
func abortPackageCollection(result *model.CollectorResult, err error) (model.CollectorResult, error) {
	if result == nil {
		return model.CollectorResult{Collector: "packages"}, err
	}
	runtime := []model.CollectorResult{*result}
	collector.ClearLocalEvidenceTargets(runtime)
	*result = model.CollectorResult{Collector: "packages"}
	return *result, err
}
