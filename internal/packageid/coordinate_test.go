package packageid

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestCoordinateMatchesCollectorAndOSVIdentities(t *testing.T) {
	cases := []struct {
		asset           model.Asset
		ecosystem, name string
		want            string
	}{
		{model.Asset{ID: "pkg:npm/%40scope/tool@2.0.0", Type: model.AssetPackage, Name: "@scope/tool", Version: "2.0.0"}, "npm", "@scope/tool", "pkg:npm/%40scope/tool"},
		{model.Asset{ID: "pkg:pypi/Foo_Bar@1.0.0", Type: model.AssetPackage, Name: "Foo_Bar", Version: "1.0.0"}, "PyPI", "Foo_Bar", "pkg:pypi/foo-bar"},
		{model.Asset{ID: "pkg:go/example.com/mod@v1.2.0", Type: model.AssetPackage, Name: "example.com/mod", Version: "v1.2.0"}, "Go", "example.com/mod", "pkg:golang/example.com/mod"},
		{model.Asset{ID: "pkg:cargo/serde_core@1.0.0", Type: model.AssetPackage, Name: "serde_core", Version: "1.0.0"}, "crates.io", "serde_core", "pkg:cargo/serde_core"},
	}
	for _, tc := range cases {
		gotAsset, okAsset := Coordinate(tc.asset)
		gotOSV, okOSV := FromOSV(tc.ecosystem, tc.name)
		if !okAsset || !okOSV || gotAsset != tc.want || gotOSV != tc.want {
			t.Fatalf("asset=%q osv=%q", gotAsset, gotOSV)
		}
	}
}

func TestCoordinateProjectsCollectorGoIdentityToCanonicalCoordinate(t *testing.T) {
	asset := model.Asset{ID: "pkg:go/example.com/demo@v1.2.3", Type: model.AssetPackage, Name: "example.com/demo", Version: "v1.2.3"}
	coordinate, ok := Coordinate(asset)
	if !ok || coordinate != "pkg:golang/example.com/demo" {
		t.Fatalf("coordinate=%q ok=%v", coordinate, ok)
	}
}

func TestCoordinateRejectsPortableAbsoluteGoModulePaths(t *testing.T) {
	cases := []struct {
		name, assetID string
	}{
		{"C:/private/module", "pkg:go/C:/private/module@v1.0.0"},
		{"C:\\private\\module", "pkg:go/C%3A%5Cprivate%5Cmodule@v1.0.0"},
		{"//server/share", "pkg:go///server/share@v1.0.0"},
		{"/private/module", "pkg:go//private/module@v1.0.0"},
	}
	for _, tc := range cases {
		if coordinate, ok := FromOSV("Go", tc.name); ok || coordinate != "" {
			t.Fatalf("accepted OSV name=%q coordinate=%q", tc.name, coordinate)
		}
		asset := model.Asset{ID: tc.assetID, Type: model.AssetPackage, Name: tc.name, Version: "v1.0.0"}
		if coordinate, ok := Coordinate(asset); ok || coordinate != "" {
			t.Fatalf("accepted asset=%+v coordinate=%q", asset, coordinate)
		}
	}
}

func TestCoordinateRejectsMalformedOrAmbiguousAssetIdentity(t *testing.T) {
	valid := model.Asset{ID: "pkg:npm/example@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0"}
	cases := []model.Asset{
		{ID: valid.ID, Type: model.AssetTool, Name: valid.Name, Version: valid.Version},
		{ID: "pkg:unknown/example@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0"},
		{ID: "pkg:npm/example%ZZ@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0"},
		{ID: "pkg:npm/example@1.0.0?qualifier=value", Type: model.AssetPackage, Name: "example", Version: "1.0.0"},
		{ID: "pkg:npm/example@1.0.0#fragment", Type: model.AssetPackage, Name: "example", Version: "1.0.0"},
		{ID: "pkg:npm/@1.0.0", Type: model.AssetPackage, Name: "", Version: "1.0.0"},
		{ID: "pkg:npm/example@", Type: model.AssetPackage, Name: "example", Version: ""},
		{ID: "pkg:npm/%00example@1.0.0", Type: model.AssetPackage, Name: "\x00example", Version: "1.0.0"},
		{ID: "pkg:npm//etc@1.0.0", Type: model.AssetPackage, Name: "/etc", Version: "1.0.0"},
		{ID: valid.ID, Type: model.AssetPackage, Name: "other", Version: valid.Version},
	}
	for _, asset := range cases {
		if coordinate, ok := Coordinate(asset); ok || coordinate != "" {
			t.Fatalf("accepted asset=%+v coordinate=%q", asset, coordinate)
		}
	}
}

func TestFromOSVRejectsUnsupportedOrUnsafeIdentity(t *testing.T) {
	cases := []struct{ ecosystem, name string }{
		{"Maven", "example"},
		{"npm", ""},
		{"npm", "/etc"},
		{"PyPI", "bad\x00name"},
	}
	for _, tc := range cases {
		if coordinate, ok := FromOSV(tc.ecosystem, tc.name); ok || coordinate != "" {
			t.Fatalf("accepted ecosystem=%q name=%q coordinate=%q", tc.ecosystem, tc.name, coordinate)
		}
	}
}
