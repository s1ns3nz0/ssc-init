package projects

import (
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestProjectEvidenceCatalogIsExactAndBounded(t *testing.T) {
	want := map[string]string{
		"package.json": "project-manifest:package.json", "package-lock.json": "project-lockfile:package-lock.json",
		"npm-shrinkwrap.json": "project-lockfile:npm-shrinkwrap.json", "pnpm-lock.yaml": "project-lockfile:pnpm-lock.yaml",
		"yarn.lock": "project-lockfile:yarn.lock", "bun.lock": "project-lockfile:bun.lock", "bun.lockb": "project-lockfile:bun.lockb",
		"pyproject.toml": "project-manifest:pyproject.toml", "Pipfile": "project-manifest:Pipfile",
		"requirements.txt": "project-manifest:requirements.txt", "poetry.lock": "project-lockfile:poetry.lock",
		"Pipfile.lock": "project-lockfile:Pipfile.lock", "uv.lock": "project-lockfile:uv.lock",
		"go.mod": "project-manifest:go.mod", "go.sum": "project-lockfile:go.sum",
		"Cargo.toml": "project-manifest:Cargo.toml", "Cargo.lock": "project-lockfile:Cargo.lock",
		"Brewfile": "project-manifest:Brewfile",
	}
	if len(evidenceCatalog) != len(want) {
		t.Fatalf("catalog entries=%d want=%d", len(evidenceCatalog), len(want))
	}
	for basename, subject := range want {
		definition, ok := evidenceCatalog[basename]
		if !ok || definition.basename != basename || definition.subject != subject || definition.maxBytes != 32<<20 || !model.ProjectEvidenceSubject(definition.subject) {
			t.Fatalf("basename=%q definition=%+v present=%v", basename, definition, ok)
		}
	}
	for _, name := range []string{"requirements-dev.txt", "Package.json", "package.JSON", "package.json.bak", "nested/package.json", "xCargo.toml"} {
		if _, ok := evidenceCatalog[name]; ok {
			t.Fatalf("catalog unexpectedly recognized %q", name)
		}
	}
}
