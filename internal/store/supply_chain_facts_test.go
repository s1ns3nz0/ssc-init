package store

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestV4SnapshotRoundTripsSupplyChainFacts(t *testing.T) {
	parent := canonicalTempDir(t)
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(filepath.Join(parent, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	scan, inventory := validV3Snapshot(t, "scan-v4-facts")
	scan.SchemaVersion = "ssc-init.scan.v4"
	scan.StartedAt = time.Now().UTC().Add(-time.Second)
	scan.FinishedAt = time.Now().UTC()
	inventory.Assets[0].Signature = &model.Signature{Status: model.SignatureValid, Identifier: "dev.sscinit.core", TeamID: "ABCDE12345"}
	inventory.Assets[0].Provenance = &model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "docker", Source: "local-daemon", Integrity: "sha256:" + strings.Repeat("a", 64)}
	scan.Coverage[0].Assets = []model.Asset{inventory.Assets[0]}
	if err := opened.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	got, initialized, err := opened.LatestSnapshot(context.Background())
	if err != nil || !initialized {
		t.Fatalf("initialized=%v err=%v", initialized, err)
	}
	if !reflect.DeepEqual(got.Inventory.Assets[0].Signature, inventory.Assets[0].Signature) || !reflect.DeepEqual(got.Inventory.Assets[0].Provenance, inventory.Assets[0].Provenance) {
		t.Fatalf("facts lost: got=%+v want=%+v", got.Inventory.Assets[0], inventory.Assets[0])
	}
	if len(got.Scan.Coverage) != 1 || len(got.Scan.Coverage[0].Assets) != 1 || !reflect.DeepEqual(got.Scan.Coverage[0].Assets[0], inventory.Assets[0]) {
		t.Fatalf("coverage facts lost: %+v", got.Scan.Coverage)
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
