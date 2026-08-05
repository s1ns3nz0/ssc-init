// Package ide inventories extensions from fixed IDE manifest locations without
// starting an IDE or loading extension code.
package ide

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	maxManifestBytes    = 4 << 20
	maxVSCodeEntries    = 10_000
	maxJetBrainsEntries = 10_000
)

var errDirectoryEntryLimit = errors.New("directory entry limit reached")

type ideCollector struct{}

type vscodeRoot struct {
	host       string
	components []string
}

type entryBudget struct {
	remaining int
}

func newEntryBudget(limit int) *entryBudget {
	return &entryBudget{remaining: limit}
}

func (b *entryBudget) charge(entries int) bool {
	if entries < 0 || entries > b.remaining {
		return false
	}
	b.remaining -= entries
	return true
}

func (b *entryBudget) readDirectory(ctx context.Context, root platform.RootedDirectory) ([]os.DirEntry, error) {
	entries, err := readDirectory(ctx, root, b.remaining)
	if !b.charge(len(entries)) {
		return nil, errDirectoryEntryLimit
	}
	return entries, err
}

// New returns a collector restricted to built-in VS Code-family and JetBrains
// extension manifest locations.
func New() collector.Collector { return &ideCollector{} }

func (*ideCollector) Name() string { return "ide" }

func (c *ideCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	rootedFilesystem, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, coverageError("rooted_access_unavailable", "rooted IDE access is unavailable", env.Home, env.Home))
		return result, nil
	}
	homeRoot, err := rootedFilesystem.OpenRoot(env.Home)
	if err != nil {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, coverageError("rooted_access_unavailable", "rooted IDE access is unavailable", env.Home, env.Home))
		return result, nil
	}
	defer homeRoot.Close()

	assetsByID := make(map[string]model.Asset)
	roots := []vscodeRoot{
		{host: "vscode", components: []string{".vscode", "extensions"}},
		{host: "vscode-insiders", components: []string{".vscode-insiders", "extensions"}},
		{host: "cursor", components: []string{".cursor", "extensions"}},
		{host: "windsurf", components: []string{".windsurf", "extensions"}},
		{host: "vscode-oss", components: []string{".vscode-oss", "extensions"}},
	}
	for _, root := range roots {
		if err := c.collectVSCodeRoot(ctx, homeRoot, env.Home, root, assetsByID, &result); err != nil {
			return result, err
		}
	}
	if err := c.collectJetBrains(ctx, homeRoot, env.Home, assetsByID, &result); err != nil {
		return result, err
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

func (*ideCollector) collectVSCodeRoot(ctx context.Context, homeRoot platform.RootedDirectory, home string, root vscodeRoot, assets map[string]model.Asset, result *model.CollectorResult) error {
	rootPath := filepath.Join(append([]string{home}, root.components...)...)
	extensionsRoot, err := platform.OpenVerifiedRoot(ctx, homeRoot, root.components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !errors.Is(err, fs.ErrNotExist) {
			result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, rootPath))
		}
		return nil
	}
	defer extensionsRoot.Close()

	entries, err := readDirectory(ctx, extensionsRoot, maxVSCodeEntries)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, errDirectoryEntryLimit) {
			result.Errors = append(result.Errors, coverageError("entry_limit", "IDE extension entry limit reached", home, rootPath))
		} else {
			result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, rootPath))
		}
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryPath := filepath.Join(rootPath, entry.Name())
		info, err := extensionsRoot.Lstat(entry.Name())
		if err != nil {
			result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, entryPath))
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, entryPath))
			continue
		}
		if !info.IsDir() {
			continue
		}
		extensionRoot, err := platform.OpenVerifiedRoot(ctx, extensionsRoot, entry.Name())
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, entryPath))
			continue
		}
		contents, code := readManifest(ctx, extensionRoot, "package.json")
		_ = extensionRoot.Close()
		if err := ctx.Err(); err != nil {
			return err
		}
		manifestPath := filepath.Join(entryPath, "package.json")
		if code != "" {
			result.Errors = append(result.Errors, manifestError(code, home, manifestPath))
			continue
		}
		asset, err := parseVSCodeManifest(contents, root.host, home, entryPath)
		if err != nil {
			result.Errors = append(result.Errors, manifestError("manifest_invalid", home, manifestPath))
			continue
		}
		assets[asset.ID] = asset
	}
	return nil
}

func (*ideCollector) collectJetBrains(ctx context.Context, homeRoot platform.RootedDirectory, home string, assets map[string]model.Asset, result *model.CollectorResult) error {
	components := []string{"Library", "Application Support", "JetBrains"}
	rootPath := filepath.Join(append([]string{home}, components...)...)
	jetBrainsRoot, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !errors.Is(err, fs.ErrNotExist) {
			result.Errors = append(result.Errors, coverageError("path_unavailable", "JetBrains plugin path is unavailable", home, rootPath))
		}
		return nil
	}
	defer jetBrainsRoot.Close()

	budget := newEntryBudget(maxJetBrainsEntries)
	products, err := budget.readDirectory(ctx, jetBrainsRoot)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		appendJetBrainsTraversalError(err, home, rootPath, result)
	}
	for _, product := range products {
		if err := ctx.Err(); err != nil {
			return err
		}
		productPath := filepath.Join(rootPath, product.Name())
		productRoot, ok := openChildDirectory(ctx, jetBrainsRoot, product.Name(), home, productPath, result)
		if !ok {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}
		pluginsRoot, err := platform.OpenVerifiedRoot(ctx, productRoot, "plugins")
		_ = productRoot.Close()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if !errors.Is(err, fs.ErrNotExist) {
				result.Errors = append(result.Errors, coverageError("path_unavailable", "JetBrains plugin path is unavailable", home, filepath.Join(productPath, "plugins")))
			}
			continue
		}
		plugins, readErr := budget.readDirectory(ctx, pluginsRoot)
		if readErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				_ = pluginsRoot.Close()
				return ctxErr
			}
			appendJetBrainsTraversalError(readErr, home, filepath.Join(productPath, "plugins"), result)
			if !errors.Is(readErr, errDirectoryEntryLimit) {
				_ = pluginsRoot.Close()
				continue
			}
		}
		for _, plugin := range plugins {
			if err := ctx.Err(); err != nil {
				_ = pluginsRoot.Close()
				return err
			}
			pluginPath := filepath.Join(productPath, "plugins", plugin.Name())
			pluginRoot, ok := openChildDirectory(ctx, pluginsRoot, plugin.Name(), home, pluginPath, result)
			if !ok {
				if err := ctx.Err(); err != nil {
					_ = pluginsRoot.Close()
					return err
				}
				continue
			}
			metaRoot, err := platform.OpenVerifiedRoot(ctx, pluginRoot, "META-INF")
			_ = pluginRoot.Close()
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					_ = pluginsRoot.Close()
					return ctxErr
				}
				result.Errors = append(result.Errors, coverageError("path_unavailable", "JetBrains plugin path is unavailable", home, filepath.Join(pluginPath, "META-INF")))
				continue
			}
			contents, code := readManifest(ctx, metaRoot, "plugin.xml")
			_ = metaRoot.Close()
			if err := ctx.Err(); err != nil {
				_ = pluginsRoot.Close()
				return err
			}
			manifestPath := filepath.Join(pluginPath, "META-INF", "plugin.xml")
			if code != "" {
				result.Errors = append(result.Errors, manifestError(code, home, manifestPath))
				continue
			}
			asset, err := parseJetBrainsManifest(contents, home, pluginPath)
			if err != nil {
				result.Errors = append(result.Errors, manifestError("manifest_invalid", home, manifestPath))
				continue
			}
			assets[asset.ID] = asset
		}
		_ = pluginsRoot.Close()
	}
	return nil
}

func openChildDirectory(ctx context.Context, parent platform.RootedDirectory, name, home, path string, result *model.CollectorResult) (platform.RootedDirectory, bool) {
	info, err := parent.Lstat(name)
	if err != nil {
		result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, path))
		return nil, false
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, path))
		return nil, false
	}
	if !info.IsDir() {
		return nil, false
	}
	child, err := platform.OpenVerifiedRoot(ctx, parent, name)
	if err != nil {
		result.Errors = append(result.Errors, coverageError("path_unavailable", "IDE extension path is unavailable", home, path))
		return nil, false
	}
	return child, true
}

func readDirectory(ctx context.Context, root platform.RootedDirectory, limit int) ([]os.DirEntry, error) {
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	var entries []os.DirEntry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batchSize := 128
		if limit >= 0 {
			remainingWithSentinel := limit + 1 - len(entries)
			if remainingWithSentinel < batchSize {
				batchSize = remainingWithSentinel
			}
		}
		batch, err := directory.ReadDir(batchSize)
		entries = append(entries, batch...)
		if limit >= 0 && len(entries) > limit {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries[:limit], errDirectoryEntryLimit
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func readManifest(ctx context.Context, root platform.RootedDirectory, name string) ([]byte, string) {
	if err := ctx.Err(); err != nil {
		return nil, "manifest_unavailable"
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		return nil, "manifest_unavailable"
	}
	defer file.Close()
	if beforeOpen.Size() < 0 || beforeOpen.Size() > maxManifestBytes || opened.Size() < 0 || opened.Size() > maxManifestBytes {
		return nil, "manifest_oversized"
	}
	contents, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maxManifestBytes+1))
	if err != nil {
		return nil, "manifest_unavailable"
	}
	if len(contents) > maxManifestBytes {
		return nil, "manifest_oversized"
	}
	return contents, ""
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func appendJetBrainsTraversalError(err error, home, path string, result *model.CollectorResult) {
	if errors.Is(err, errDirectoryEntryLimit) {
		result.Errors = append(result.Errors, coverageError("entry_limit", "JetBrains plugin entry limit reached", home, path))
		return
	}
	result.Errors = append(result.Errors, coverageError("path_unavailable", "JetBrains plugin path is unavailable", home, path))
}

func manifestError(code, home, path string) model.CoverageError {
	message := "IDE extension manifest is unavailable"
	if code == "manifest_invalid" {
		message = "IDE extension manifest is invalid"
	}
	if code == "manifest_oversized" {
		message = "IDE extension manifest exceeds the size limit"
	}
	return coverageError(code, message, home, path)
}

func coverageError(code, message, home, path string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message, Path: redactPath(home, path)}
}

// Keep the fixed catalog visibly independent from command execution.
var _ collector.Collector = (*ideCollector)(nil)

// Compile-time use prevents accidental replacement of the fd-rooted boundary
// with a pathname-only filesystem.
var _ platform.RootedFileSystem = platform.OSFileSystem{}
