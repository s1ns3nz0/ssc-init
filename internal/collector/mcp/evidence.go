package mcp

import (
	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/model"
)

// issueMCPSemanticEvidence seals one path-free semantic target for a finalized
// MCP observation. Binding is deliberately reentrant: valid sibling servers
// share the collector result's issuer while retaining independent proofs.
func issueMCPSemanticEvidence(result *model.CollectorResult, declaration targetDeclaration, observation model.Observation) bool {
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		return false
	}
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(model.LocalEvidenceTarget{
		TargetID: declaration.spec.ID + ".semantic", AssetID: observation.AssetID, ObservationID: observation.ID,
		Kind: model.EvidenceSemanticSHA256, Subject: model.EvidenceSubjectMCPDeclaration,
	}, evidence.Anchor{}))
	return true
}
