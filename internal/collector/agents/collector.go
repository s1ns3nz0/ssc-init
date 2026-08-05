// Package agents inventories plugins and skills below known AI host roots.
package agents

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

type agentCollector struct{}

type assetRoot struct {
	host     string
	kind     model.AssetType
	relative string
}

// New returns a collector restricted to its built-in AI host path catalog.
func New() collector.Collector { return &agentCollector{} }

func (*agentCollector) Name() string { return "agents" }

func (c *agentCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	rootedFilesystem, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, model.CoverageError{
			Code:    "rooted_access_unavailable",
			Message: "rooted agent access is unavailable",
			Path:    "$HOME",
		})
		return result, nil
	}
	homeRoot, err := rootedFilesystem.OpenRoot(env.Home)
	if err != nil {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, model.CoverageError{
			Code:    "rooted_access_unavailable",
			Message: "rooted agent access is unavailable",
			Path:    "$HOME",
		})
		return result, nil
	}
	defer homeRoot.Close()

	assetsByID := make(map[string]model.Asset)
	roots := []assetRoot{
		{host: "claude", kind: model.AssetAgentPlugin, relative: filepath.Join(".claude", "plugins")},
		{host: "claude", kind: model.AssetSkill, relative: filepath.Join(".claude", "skills")},
		{host: "codex", kind: model.AssetAgentPlugin, relative: filepath.Join(".codex", "plugins")},
		{host: "codex", kind: model.AssetSkill, relative: filepath.Join(".codex", "skills")},
		{host: "cursor", kind: model.AssetAgentPlugin, relative: filepath.Join(".cursor", "plugins")},
		{host: "cursor", kind: model.AssetSkill, relative: filepath.Join(".cursor", "skills")},
		{host: "windsurf", kind: model.AssetAgentPlugin, relative: ".windsurf"},
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		path := filepath.Join(env.Home, root.relative)
		components := strings.Split(root.relative, string(filepath.Separator))
		rootedDirectory, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "path_unavailable",
					Message: "agent asset path unavailable",
					Path:    redactPath(env.Home, path),
				})
			}
			continue
		}
		directoryFile, err := platform.OpenVerifiedDirectory(rootedDirectory)
		if err != nil {
			_ = rootedDirectory.Close()
			result.Errors = append(result.Errors, model.CoverageError{
				Code:    "path_unavailable",
				Message: "agent asset path unavailable",
				Path:    redactPath(env.Home, path),
			})
			continue
		}
		entries, err := directoryFile.ReadDir(-1)
		_ = directoryFile.Close()
		if err != nil {
			_ = rootedDirectory.Close()
			result.Errors = append(result.Errors, model.CoverageError{
				Code:    "path_unavailable",
				Message: "agent asset path unavailable",
				Path:    redactPath(env.Home, path),
			})
			continue
		}

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				_ = rootedDirectory.Close()
				return result, err
			}
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			expected, err := rootedDirectory.Lstat(entry.Name())
			if err != nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
				continue
			}
			child, err := platform.OpenVerifiedRoot(ctx, rootedDirectory, entry.Name())
			if err != nil {
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "path_unavailable",
					Message: "agent asset path unavailable",
					Path:    redactPath(env.Home, filepath.Join(path, entry.Name())),
				})
				continue
			}
			opened, openedErr := child.Lstat(".")
			_ = child.Close()
			if openedErr != nil || !os.SameFile(expected, opened) {
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "path_unavailable",
					Message: "agent asset path unavailable",
					Path:    redactPath(env.Home, filepath.Join(path, entry.Name())),
				})
				continue
			}
			asset := makeAsset(root, entry.Name(), filepath.Join(path, entry.Name()), env.Home)
			assetsByID[asset.ID] = asset
		}
		_ = rootedDirectory.Close()
	}

	result.Assets = make([]model.Asset, 0, len(assetsByID))
	for _, asset := range assetsByID {
		result.Assets = append(result.Assets, asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	if len(result.Errors) > 0 {
		result.Status = model.CoveragePartial
	}
	return result, nil
}

func makeAsset(root assetRoot, name, path, home string) model.Asset {
	kind := "agent-plugin"
	if root.kind == model.AssetSkill {
		kind = "agent-skill"
	}
	return model.Asset{
		ID:   kind + ":" + root.host + ":" + name,
		Type: root.kind,
		Name: name,
		Path: redactPath(home, path),
	}
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}
