// Package agents inventories plugins and skills below known AI host roots.
package agents

import (
	"context"
	"errors"
	"io/fs"
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
		entries, err := readSafeDirectory(ctx, env.FS, env.Home, path)
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

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if !entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			asset := makeAsset(root, entry.Name(), filepath.Join(path, entry.Name()), env.Home)
			assetsByID[asset.ID] = asset
		}
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

func readSafeDirectory(ctx context.Context, filesystem platform.FileSystem, root, target string) ([]fs.DirEntry, error) {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fs.ErrInvalid
	}

	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := filesystem.ReadDir(current)
		if err != nil {
			return nil, err
		}
		var found fs.DirEntry
		for _, entry := range entries {
			if entry.Name() == part {
				found = entry
				break
			}
		}
		if found == nil {
			return nil, fs.ErrNotExist
		}
		if found.Type()&fs.ModeSymlink != 0 {
			return nil, errors.New("symlinked agent path")
		}
		if !found.IsDir() {
			return nil, fs.ErrInvalid
		}
		current = filepath.Join(current, part)
	}
	return filesystem.ReadDir(target)
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
