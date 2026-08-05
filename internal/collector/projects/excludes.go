package projects

import "path/filepath"

var excludedDirectoryNames = map[string]struct{}{
	"node_modules": {},
	".venv":        {},
	"venv":         {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	"Library":      {},
	".cache":       {},
	".npm":         {},
	".pnpm-store":  {},
	".yarn":        {},
	".bun":         {},
	".uv":          {},
	".tox":         {},
}

func excludedDirectory(path string) bool {
	name := filepath.Base(path)
	if _, excluded := excludedDirectoryNames[name]; excluded {
		return true
	}
	return name == "objects" && filepath.Base(filepath.Dir(path)) == ".git"
}
