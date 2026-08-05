// Package projects discovers project manifests and lockfiles below explicit roots.
package projects

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	maxDepth          = 12
	maxEntriesPerRoot = 100_000
)

var errEntryLimit = errors.New("project entry limit reached")

type projectCollector struct {
	roots []string
}

// New returns a collector restricted to roots explicitly supplied by the caller.
func New(roots []string) collector.Collector {
	return &projectCollector{roots: append([]string(nil), roots...)}
}

func (*projectCollector) Name() string { return "projects" }

func (c *projectCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	resolvedRoots := uniqueRoots(c.roots, env.Home)
	if len(resolvedRoots) == 0 {
		result.Status = model.CoverageSkipped
		return result, nil
	}
	projectsByID := make(map[string]model.Asset)
	filesByID := make(map[string]model.Asset)
	relationships := make(map[string]model.Relationship)
	reachableRoots := 0

	for _, suppliedRoot := range resolvedRoots {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		root := suppliedRoot
		entries := 0
		depthLimited := false
		err := env.FS.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.Errors = append(result.Errors, coverageError("path_unavailable", "project path unavailable", env.Home, path))
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if path == root {
				reachableRoots++
				return nil
			}

			entries++
			if entries > maxEntriesPerRoot {
				return errEntryLimit
			}
			depth := pathDepth(root, path)
			if entry.IsDir() {
				if excludedDirectory(path) {
					return fs.SkipDir
				}
				if depth >= maxDepth {
					depthLimited = true
					return fs.SkipDir
				}
				return nil
			}
			if depth > maxDepth {
				depthLimited = true
				return nil
			}

			kind, recognized := projectFileKind(path)
			gitConfig := filepath.Base(path) == "config" && filepath.Base(filepath.Dir(path)) == ".git"
			if !recognized && !gitConfig {
				return nil
			}
			projectPath := filepath.Dir(path)
			if gitConfig {
				projectPath = filepath.Dir(filepath.Dir(path))
			}
			if kind == "mcp" {
				projectPath = filepath.Dir(filepath.Dir(path))
			}
			project := makeProject(env.Home, projectPath)
			projectsByID[project.ID] = project
			if !recognized {
				return nil
			}
			fileAsset := makeProjectFile(env.Home, path, kind)
			filesByID[fileAsset.ID] = fileAsset
			relationship := model.Relationship{From: project.ID, To: fileAsset.ID, Kind: "contains"}
			relationships[relationship.From+"\x00"+relationship.To+"\x00"+relationship.Kind] = relationship
			return nil
		})

		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return result, err
		case errors.Is(err, errEntryLimit):
			result.Errors = append(result.Errors, coverageError("entry_limit", "project root entry limit reached", env.Home, root))
		case err != nil:
			result.Errors = append(result.Errors, coverageError("root_unavailable", "project root unavailable", env.Home, root))
		}
		if depthLimited {
			result.Errors = append(result.Errors, coverageError("depth_limit", "project root depth limit reached", env.Home, root))
		}
	}

	result.Assets = sortedAssets(projectsByID, filesByID)
	result.Relationships = sortedRelationships(relationships)
	if len(result.Errors) > 0 {
		result.Status = model.CoveragePartial
		if reachableRoots == 0 && len(result.Assets) == 0 {
			result.Status = model.CoverageSkipped
		}
	}
	return result, nil
}

func uniqueRoots(roots []string, home string) []string {
	seen := make(map[string]struct{}, len(roots))
	resolved := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		root = expandHome(root, home)
		if !filepath.IsAbs(root) {
			root = filepath.Join(home, root)
		}
		root = filepath.Clean(root)
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		resolved = append(resolved, root)
	}
	sort.Strings(resolved)
	return resolved
}

func expandHome(path, home string) string {
	if path == "$HOME" {
		return home
	}
	prefix := "$HOME" + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return filepath.Join(home, strings.TrimPrefix(path, prefix))
	}
	return path
}

func pathDepth(root, path string) int {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." {
		return 0
	}
	return len(strings.Split(relative, string(filepath.Separator)))
}

func projectFileKind(path string) (string, bool) {
	name := filepath.Base(path)
	if name == "mcp.json" && filepath.Base(filepath.Dir(path)) == ".vscode" {
		return "mcp", true
	}
	switch name {
	case "package.json", "pyproject.toml", "Cargo.toml", "go.mod":
		return "manifest", true
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "uv.lock", "Cargo.lock", "go.sum":
		return "lockfile", true
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return "manifest", true
	}
	return "", false
}

func makeProject(home, path string) model.Asset {
	redacted := redactPath(home, path)
	digest := sha256.Sum256([]byte(redacted))
	return model.Asset{
		ID:   fmt.Sprintf("project:sha256:%x", digest),
		Type: model.AssetProject,
		Name: filepath.Base(path),
		Path: redacted,
	}
}

func makeProjectFile(home, path, kind string) model.Asset {
	redacted := redactPath(home, path)
	return model.Asset{
		ID:     "project-file:" + kind + ":" + redacted,
		Type:   model.AssetProject,
		Name:   filepath.Base(path),
		Path:   redacted,
		Source: kind,
	}
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}

func coverageError(code, message, home, path string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message, Path: redactPath(home, path)}
}

func sortedAssets(groups ...map[string]model.Asset) []model.Asset {
	assets := make([]model.Asset, 0)
	for _, group := range groups {
		for _, asset := range group {
			assets = append(assets, asset)
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	return assets
}

func sortedRelationships(byKey map[string]model.Relationship) []model.Relationship {
	relationships := make([]model.Relationship, 0, len(byKey))
	for _, relationship := range byKey {
		relationships = append(relationships, relationship)
	}
	sort.Slice(relationships, func(i, j int) bool {
		if relationships[i].From != relationships[j].From {
			return relationships[i].From < relationships[j].From
		}
		if relationships[i].To != relationships[j].To {
			return relationships[i].To < relationships[j].To
		}
		return relationships[i].Kind < relationships[j].Kind
	})
	return relationships
}
