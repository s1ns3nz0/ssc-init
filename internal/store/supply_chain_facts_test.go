package store

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestValidateAssetRejectsMalformedSupplyChainFactsWithoutEcho(t *testing.T) {
	marker := "/private/secret-marker"
	for _, asset := range []model.Asset{
		{ID: "a", Type: model.AssetTool, Name: "a", Signature: &model.Signature{Status: "safe"}},
		{ID: "a", Type: model.AssetTool, Name: "a", Signature: &model.Signature{Status: model.SignatureValid, Identifier: marker, TeamID: "TEAM"}},
		{ID: "a", Type: model.AssetTool, Name: "a", Signature: &model.Signature{Status: model.SignatureUnsigned, TeamID: "TEAM"}},
		{ID: "a", Type: model.AssetPackage, Name: "a", Provenance: &model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "npm", Source: "registry", Integrity: "sha256:short"}},
		{ID: "a", Type: model.AssetPackage, Name: "a", Provenance: &model.Provenance{Status: model.ProvenanceUnknown, Ecosystem: "npm", Integrity: "sha256:" + strings.Repeat("a", 64)}},
	} {
		err := validateAsset(asset)
		if err == nil {
			t.Fatalf("accepted malformed facts: %+v", asset)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("validation echoed supplied value: %v", err)
		}
	}
}

func TestValidateAssetAcceptsClosedSupplyChainFacts(t *testing.T) {
	asset := model.Asset{ID: "a", Type: model.AssetTool, Name: "a",
		Signature:  &model.Signature{Status: model.SignatureValid, Identifier: "dev.sscinit.core", TeamID: "ABCDE12345"},
		Provenance: &model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "docker", Source: "local-daemon", Integrity: "sha256:" + strings.Repeat("a", 64)}}
	if err := validateAsset(asset); err != nil {
		t.Fatal(err)
	}
}
