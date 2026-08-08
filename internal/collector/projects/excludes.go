package projects

import "path/filepath"

var excludedDirectoryNames = map[string]struct{}{
	".git":         {},
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
	".cargo":       {},
	".rustup":      {},
	".gradle":      {},
	".m2":          {},
	".ivy2":        {},
	".nuget":       {},
	".pub-cache":   {},
}

func excludedDirectory(path string) bool {
	name := filepath.Base(path)
	if _, excluded := excludedDirectoryNames[name]; excluded {
		return true
	}
	return name == "objects" && filepath.Base(filepath.Dir(path)) == ".git"
}
