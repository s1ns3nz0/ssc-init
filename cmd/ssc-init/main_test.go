package main

import (
	"reflect"
	"testing"
)

func TestDoctorCatalogMatchesConfiguredCollectorsAndPackageProbes(t *testing.T) {
	ecosystems, commands := doctorCatalog()
	wantEcosystems := []string{"agents", "brew", "cargo", "docker", "go", "ide", "mcp", "npm", "pip", "pipx", "projects", "uv"}
	wantCommands := []string{"brew", "cargo", "docker", "go", "npm", "pipx", "python3", "uv"}
	if !reflect.DeepEqual(ecosystems, wantEcosystems) {
		t.Fatalf("ecosystems=%v want=%v", ecosystems, wantEcosystems)
	}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("commands=%v want=%v", commands, wantCommands)
	}
}
