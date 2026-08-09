package quarantine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestPreviewAndApplyRequireSameFreshExactSelection(t *testing.T) {
	home := physicalTempDir(t)
	content := []byte("fixture bytes")
	writeQuarantineFixture(t, filepath.Join(home, ".tools", "manifest.json"), content, 0o755)
	inventory, selection := proposalInventory(content, model.EvidenceSubjectManifest, model.EvidenceFileSHA256)
	recorder := &memoryRecorder{}
	manager := Manager{Home: home, Recorder: recorder}
	proposal, err := manager.Preview(context.Background(), inventory, selection)
	if err != nil || !proposal.Valid() || proposal.OriginalRef != "$HOME/.tools/manifest.json" || proposal.OriginalMode != 0o755 || len(recorder.records) != 0 {
		t.Fatalf("proposal=%+v records=%+v err=%v", proposal, recorder.records, err)
	}
	if _, err := manager.Apply(context.Background(), inventory, selection, "approval:sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong approval accepted")
	}
	if len(recorder.records) != 0 {
		t.Fatalf("wrong approval mutated state: %+v", recorder.records)
	}
	if _, err := manager.Apply(context.Background(), inventory, selection, proposal.ApprovalID); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewRejectsInferredOrIncompleteEvidence(t *testing.T) {
	home := physicalTempDir(t)
	content := []byte("fixture bytes")
	writeQuarantineFixture(t, filepath.Join(home, ".tools", "manifest.json"), content, 0o644)
	manager := Manager{Home: home, Recorder: &memoryRecorder{}}
	for _, mutate := range []func(*model.Inventory){
		func(v *model.Inventory) { v.Evidence[0].Kind = model.EvidenceTreeSHA256 },
		func(v *model.Inventory) { v.Evidence[0].Status = model.EvidencePartial },
		func(v *model.Inventory) { v.Evidence[0].Subject = model.EvidenceSubjectEntrypointMain },
		func(v *model.Inventory) { v.Observations[0].LocationRef = "$HOME/.tools" },
		func(v *model.Inventory) { v.Evidence[0].Digest = strings.Repeat("0", 64) },
	} {
		inventory, selection := proposalInventory(content, model.EvidenceSubjectManifest, model.EvidenceFileSHA256)
		mutate(&inventory)
		if _, err := manager.Preview(context.Background(), inventory, selection); err == nil {
			t.Fatalf("unsafe inventory accepted: %+v", inventory)
		}
	}
}

func proposalInventory(content []byte, subject string, kind model.EvidenceKind) (model.Inventory, Selection) {
	digest := sha256.Sum256(content)
	assetID, observationID, evidenceID := "tool:fixture", "observation:fixture", "evidence:fixture"
	return model.Inventory{
		Assets:       []model.Asset{{ID: assetID, Type: model.AssetTool, Name: "fixture"}},
		Observations: []model.Observation{{ID: observationID, AssetID: assetID, Scope: model.ScopeUser, LocationRef: "$HOME/.tools/manifest.json"}},
		Evidence:     []model.ContentEvidence{{ID: evidenceID, AssetID: assetID, ObservationID: observationID, Kind: kind, Subject: subject, Status: model.EvidenceComplete, Algorithm: "sha256", Digest: fmt.Sprintf("%x", digest)}},
	}, Selection{AssetID: assetID, ObservationID: observationID, EvidenceID: evidenceID}
}
