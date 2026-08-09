package projects

const maxProjectEvidenceBytes = int64(32 << 20)

type projectEvidenceDefinition struct {
	basename string
	subject  string
	maxBytes int64
}

var evidenceCatalog = map[string]projectEvidenceDefinition{
	"package.json":        {basename: "package.json", subject: "project-manifest:package.json", maxBytes: maxProjectEvidenceBytes},
	"package-lock.json":   {basename: "package-lock.json", subject: "project-lockfile:package-lock.json", maxBytes: maxProjectEvidenceBytes},
	"npm-shrinkwrap.json": {basename: "npm-shrinkwrap.json", subject: "project-lockfile:npm-shrinkwrap.json", maxBytes: maxProjectEvidenceBytes},
	"pnpm-lock.yaml":      {basename: "pnpm-lock.yaml", subject: "project-lockfile:pnpm-lock.yaml", maxBytes: maxProjectEvidenceBytes},
	"yarn.lock":           {basename: "yarn.lock", subject: "project-lockfile:yarn.lock", maxBytes: maxProjectEvidenceBytes},
	"bun.lock":            {basename: "bun.lock", subject: "project-lockfile:bun.lock", maxBytes: maxProjectEvidenceBytes},
	"bun.lockb":           {basename: "bun.lockb", subject: "project-lockfile:bun.lockb", maxBytes: maxProjectEvidenceBytes},
	"pyproject.toml":      {basename: "pyproject.toml", subject: "project-manifest:pyproject.toml", maxBytes: maxProjectEvidenceBytes},
	"Pipfile":             {basename: "Pipfile", subject: "project-manifest:Pipfile", maxBytes: maxProjectEvidenceBytes},
	"requirements.txt":    {basename: "requirements.txt", subject: "project-manifest:requirements.txt", maxBytes: maxProjectEvidenceBytes},
	"poetry.lock":         {basename: "poetry.lock", subject: "project-lockfile:poetry.lock", maxBytes: maxProjectEvidenceBytes},
	"Pipfile.lock":        {basename: "Pipfile.lock", subject: "project-lockfile:Pipfile.lock", maxBytes: maxProjectEvidenceBytes},
	"uv.lock":             {basename: "uv.lock", subject: "project-lockfile:uv.lock", maxBytes: maxProjectEvidenceBytes},
	"go.mod":              {basename: "go.mod", subject: "project-manifest:go.mod", maxBytes: maxProjectEvidenceBytes},
	"go.sum":              {basename: "go.sum", subject: "project-lockfile:go.sum", maxBytes: maxProjectEvidenceBytes},
	"Cargo.toml":          {basename: "Cargo.toml", subject: "project-manifest:Cargo.toml", maxBytes: maxProjectEvidenceBytes},
	"Cargo.lock":          {basename: "Cargo.lock", subject: "project-lockfile:Cargo.lock", maxBytes: maxProjectEvidenceBytes},
	"Brewfile":            {basename: "Brewfile", subject: "project-manifest:Brewfile", maxBytes: maxProjectEvidenceBytes},
	"launch.json":         {basename: "launch.json", subject: "launch-config", maxBytes: maxProjectEvidenceBytes},
}

func (definition projectEvidenceDefinition) targetID() string {
	if definition.subject == "launch-config" {
		return "projects.launch.vscode"
	}
	if definition.subject == "git-hook" {
		return "projects.git-hook." + definition.basename
	}
	if len(definition.subject) >= len("project-lockfile:") && definition.subject[:len("project-lockfile:")] == "project-lockfile:" {
		return "projects.lockfile." + definition.basename
	}
	return "projects.manifest." + definition.basename
}
