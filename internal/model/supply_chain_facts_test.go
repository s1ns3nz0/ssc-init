package model_test

import (
	"encoding/json"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestSupplyChainFactsHaveClosedStatusesAndStableJSON(t *testing.T) {
	asset := model.Asset{
		ID: "tool:test", Type: model.AssetTool, Name: "test",
		Signature:  &model.Signature{Status: model.SignatureValid, Identifier: "dev.sscinit.core", TeamID: "ABCDE12345"},
		Provenance: &model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "docker", Source: "local-daemon", Integrity: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	encoded, err := json.Marshal(asset)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"tool:test","type":"tool","name":"test","signature":{"status":"valid","identifier":"dev.sscinit.core","teamId":"ABCDE12345"},"provenance":{"status":"immutable","ecosystem":"docker","source":"local-daemon","integrity":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	if string(encoded) != want {
		t.Fatalf("encoded=%s want=%s", encoded, want)
	}
	for _, status := range []model.SignatureStatus{model.SignatureValid, model.SignatureInvalid, model.SignatureUnsigned, model.SignatureUnavailable, model.SignatureUnsupported} {
		if !status.Valid() {
			t.Fatalf("signature status %q is not valid", status)
		}
	}
	if model.SignatureStatus("safe").Valid() {
		t.Fatal("open signature status vocabulary")
	}
	for _, status := range []model.ProvenanceStatus{model.ProvenanceImmutable, model.ProvenanceMutable, model.ProvenanceUnknown, model.ProvenanceUnavailable, model.ProvenanceUnsupported} {
		if !status.Valid() {
			t.Fatalf("provenance status %q is not valid", status)
		}
	}
	if model.ProvenanceStatus("trusted").Valid() {
		t.Fatal("open provenance status vocabulary")
	}
}
