package model

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestInventoryJSONFieldOrderIsStableV3EvidenceContract(t *testing.T) {
	inventory := Inventory{
		Assets:        []Asset{{ID: "asset", Type: AssetTool, Name: "tool"}},
		Observations:  []Observation{{ID: "observation", AssetID: "asset", Collector: "packages", Scope: ScopeToolEnvironment, LocationRef: "$HOME/bin/tool"}},
		Evidence:      []ContentEvidence{},
		Relationships: []Relationship{{From: "asset", To: "asset", Kind: "same-as"}},
		Errors:        []CoverageError{{Code: "partial", Message: "partial evidence"}},
	}

	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"assets":[{"id":"asset","type":"tool","name":"tool"}],"observations":[{"id":"observation","assetId":"asset","collector":"packages","scope":"tool-environment","locationRef":"$HOME/bin/tool"}],"evidence":[],"relationships":[{"from":"asset","to":"asset","kind":"same-as"}],"errors":[{"code":"partial","message":"partial evidence"}]}`
	if string(encoded) != want {
		t.Fatalf("inventory JSON=%s\nwant=%s", encoded, want)
	}
}

func TestLocalEvidenceTargetDoesNotMarshalRuntimeValues(t *testing.T) {
	target := LocalEvidenceTarget{
		TargetID:      "TARGET_MARKER",
		AssetID:       "ASSET_MARKER",
		ObservationID: "OBSERVATION_MARKER",
		Kind:          EvidenceFileSHA256,
		Subject:       EvidenceSubjectManifest,
		PresetStatus:  EvidenceUnsupported,
		RootPath:      "/runtime/private/ROOT_PATH_MARKER",
		RelativePath:  "private/RELATIVE_PATH_MARKER",
		Provenance:    map[string]string{"PROVENANCE_MARKER": "SECRET_PROVENANCE_VALUE"},
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{}` {
		t.Fatalf("runtime target marshaled as %s", encoded)
	}
}

func TestProjectEvidenceSubjectsAreClosedToExactCatalog(t *testing.T) {
	valid := []string{
		"project-manifest:package.json", "project-lockfile:package-lock.json", "project-lockfile:npm-shrinkwrap.json",
		"project-lockfile:pnpm-lock.yaml", "project-lockfile:yarn.lock", "project-lockfile:bun.lock", "project-lockfile:bun.lockb",
		"project-manifest:pyproject.toml", "project-manifest:Pipfile", "project-manifest:requirements.txt",
		"project-lockfile:poetry.lock", "project-lockfile:Pipfile.lock", "project-lockfile:uv.lock",
		"project-manifest:go.mod", "project-lockfile:go.sum", "project-manifest:Cargo.toml",
		"project-lockfile:Cargo.lock", "project-manifest:Brewfile",
	}
	for _, subject := range valid {
		if !ProjectEvidenceSubject(subject) {
			t.Fatalf("valid project subject rejected: %q", subject)
		}
	}
	for _, subject := range []string{"project-manifest:Package.json", "project-manifest:requirements-dev.txt", "project-lockfile:package.json", "manifest", "project-manifest:"} {
		if ProjectEvidenceSubject(subject) {
			t.Fatalf("unexpected project subject accepted: %q", subject)
		}
	}
}

func TestScanV3MarshalsNonNilEmptyEvidenceContracts(t *testing.T) {
	value := struct {
		Scan      ScanResult `json:"scan"`
		Inventory Inventory  `json:"inventory"`
	}{
		Scan:      ScanResult{SchemaVersion: "ssc-init.scan.v3", EvidenceCoverage: EvidenceCoverage{Targets: []EvidenceTargetResult{}}},
		Inventory: Inventory{Assets: []Asset{}, Evidence: []ContentEvidence{}, Relationships: []Relationship{}},
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"targets":[]`, `"evidence":[]`} {
		if !bytes.Contains(encoded, []byte(fragment)) {
			t.Fatalf("missing %s in %s", fragment, encoded)
		}
	}
}
