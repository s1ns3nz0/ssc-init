package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type cyclonedxDocument struct {
	BomFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	Components   []cyclonedxComponent  `json:"components"`
	Dependencies []cyclonedxDependency `json:"dependencies"`
}
type cyclonedxComponent struct {
	Type       string              `json:"type"`
	BomRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Hashes     []cyclonedxHash     `json:"hashes,omitempty"`
	Properties []cyclonedxProperty `json:"properties"`
}
type cyclonedxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}
type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cyclonedxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func WriteCycloneDX(writer io.Writer, inventory model.Inventory) error {
	assets := append([]model.Asset(nil), inventory.Assets...)
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	known := make(map[string]struct{}, len(assets))
	components := make([]cyclonedxComponent, 0, len(assets))
	for _, asset := range assets {
		known[asset.ID] = struct{}{}
		component := cyclonedxComponent{Type: componentType(asset.Type), BomRef: asset.ID, Name: asset.ID, Version: asset.Version, Properties: []cyclonedxProperty{{Name: "ssc-init:assetType", Value: string(asset.Type)}}}
		if asset.SHA256 != "" {
			component.Hashes = []cyclonedxHash{{Alg: "SHA-256", Content: asset.SHA256}}
		}
		components = append(components, component)
	}
	edges := make(map[string]map[string]struct{}, len(assets))
	for _, asset := range assets {
		edges[asset.ID] = map[string]struct{}{}
	}
	for _, relationship := range inventory.Relationships {
		if _, ok := known[relationship.From]; !ok {
			continue
		}
		if _, ok := known[relationship.To]; ok {
			edges[relationship.From][relationship.To] = struct{}{}
		}
	}
	dependencies := make([]cyclonedxDependency, 0, len(assets))
	for _, asset := range assets {
		values := make([]string, 0, len(edges[asset.ID]))
		for value := range edges[asset.ID] {
			values = append(values, value)
		}
		sort.Strings(values)
		dependencies = append(dependencies, cyclonedxDependency{Ref: asset.ID, DependsOn: values})
	}
	document := cyclonedxDocument{BomFormat: "CycloneDX", SpecVersion: "1.6", Version: 1, Components: components, Dependencies: dependencies}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func componentType(assetType model.AssetType) string {
	if assetType == model.AssetProject {
		return "application"
	}
	if assetType == model.AssetPackage {
		return "library"
	}
	return "framework"
}
