// Package mcp inventories MCP servers from fixed host configuration paths.
package mcp

import (
	"context"
	"errors"
	"io/fs"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const maxMCPConfigBytes = 4 << 20

type mcpCollector struct {
	projectAssets []model.Asset
}

type configTarget struct {
	host string
	path string
}

// New returns a collector restricted to known host paths and dedicated project
// MCP path assets emitted by the project collector.
func New(projectAssets ...model.Asset) collector.Collector {
	return &mcpCollector{projectAssets: append([]model.Asset(nil), projectAssets...)}
}

func (*mcpCollector) Name() string { return "mcp" }

func (c *mcpCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	assetsByID := make(map[string]model.Asset)
	targets := []configTarget{
		{host: "claude", path: filepath.Join(env.Home, ".claude.json")},
		{host: "claude", path: filepath.Join(env.Home, ".claude", "settings.json")},
		{host: "cursor", path: filepath.Join(env.Home, ".cursor", "mcp.json")},
		{host: "windsurf", path: filepath.Join(env.Home, ".windsurf", "mcp.json")},
	}
	targets = append(targets, c.projectTargets(ctx, env.Home)...)

	seenPaths := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		target.path = filepath.Clean(target.path)
		if _, duplicate := seenPaths[target.path]; duplicate {
			continue
		}
		seenPaths[target.path] = struct{}{}

		contents, code, message, exists := readConfig(ctx, env, target.path)
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if code != "" {
			result.Errors = append(result.Errors, configError(code, message, env.Home, target.path))
			continue
		}
		if !exists {
			continue
		}
		servers, err := parseConfig(contents)
		if err != nil {
			result.Errors = append(result.Errors, configError("config_invalid", "MCP configuration is invalid", env.Home, target.path))
			continue
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if name == "" {
				continue
			}
			asset := sanitizeServer(env.Home, target.host, name, servers[name])
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

func (c *mcpCollector) projectTargets(ctx context.Context, home string) []configTarget {
	targets := make([]configTarget, 0, len(c.projectAssets))
	for _, asset := range c.projectAssets {
		if ctx.Err() != nil {
			break
		}
		if asset.Type != model.AssetProject || asset.Source != "mcp" || asset.Name != "mcp.json" ||
			!strings.HasPrefix(asset.ID, "project-file:mcp:") {
			continue
		}
		path, ok := resolveProjectPath(home, asset.Path)
		if !ok || filepath.Base(path) != "mcp.json" || filepath.Base(filepath.Dir(path)) != ".vscode" {
			continue
		}
		targets = append(targets, configTarget{host: "vscode", path: path})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].path < targets[j].path })
	return targets
}

func resolveProjectPath(home, path string) (string, bool) {
	if path == "$HOME" {
		return filepath.Clean(home), true
	}
	prefix := "$HOME/"
	if strings.HasPrefix(filepath.ToSlash(path), prefix) {
		relative := strings.TrimPrefix(filepath.ToSlash(path), prefix)
		resolved := filepath.Clean(filepath.Join(home, filepath.FromSlash(relative)))
		rel, err := filepath.Rel(filepath.Clean(home), resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
		return resolved, true
	}
	if !filepath.IsAbs(path) {
		return "", false
	}
	return filepath.Clean(path), true
}

func readConfig(ctx context.Context, env collector.Environment, path string) ([]byte, string, string, bool) {
	if err := ctx.Err(); err != nil {
		return nil, "", "", false
	}
	info, err := env.FS.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", "", false
		}
		return nil, "config_unavailable", "MCP configuration is unavailable", false
	}
	if info.IsDir() {
		return nil, "config_invalid", "MCP configuration is invalid", true
	}
	if info.Size() < 0 || info.Size() > maxMCPConfigBytes {
		return nil, "config_oversized", "MCP configuration exceeds the size limit", true
	}
	contents, err := env.FS.ReadFile(path)
	if err != nil {
		return nil, "config_unavailable", "MCP configuration is unavailable", true
	}
	if len(contents) > maxMCPConfigBytes {
		return nil, "config_oversized", "MCP configuration exceeds the size limit", true
	}
	return contents, "", "", true
}

func sanitizeServer(home, host, name string, config serverConfig) model.Asset {
	keys := make([]string, 0, len(config.Env))
	for key := range config.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	args := sanitizeArgs(home, config.Args)
	return model.Asset{
		ID:   "mcp:" + host + ":" + name,
		Type: model.AssetMCP,
		Name: name,
		Metadata: map[string]string{
			"command":  redactHomeText(home, config.Command),
			"args":     strings.Join(args, "\x1f"),
			"url":      sanitizeURL(home, config.URL),
			"env_keys": strings.Join(keys, ","),
		},
	}
}

func sanitizeArgs(home string, args []string) []string {
	result := make([]string, len(args))
	redactNext := false
	for index, arg := range args {
		if redactNext {
			result[index] = "[REDACTED]"
			redactNext = false
			continue
		}
		if strings.Contains(arg, "://") {
			result[index] = sanitizeURL(home, arg)
			continue
		}
		if key, _, found := strings.Cut(arg, "="); found && sensitiveName(key) {
			result[index] = key + "=[REDACTED]"
			continue
		}
		if sensitiveName(arg) && strings.HasPrefix(arg, "-") {
			result[index] = arg
			redactNext = true
			continue
		}
		result[index] = redactHomeText(home, arg)
	}
	return result
}

func sanitizeURL(home, raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(redactHomeText(home, raw))
	if err != nil {
		return "[REDACTED]"
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if sensitiveName(key) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	if parsed.Fragment != "" {
		parsed.Fragment = "[REDACTED]"
	}
	return parsed.String()
}

func sensitiveName(value string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, value)
	for _, marker := range []string{
		"token", "secret", "password", "passwd", "credential", "authorization", "auth",
		"apikey", "accesskey", "privatekey", "clientsecret", "bearer", "signature",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return normalized == "h" || normalized == "header" || normalized == "headers" || normalized == "e" || normalized == "env"
}

func redactHomeText(home, value string) string {
	cleanHome := strings.TrimRight(filepath.Clean(home), string(filepath.Separator))
	if cleanHome == "" || cleanHome == "." {
		return value
	}
	if value == cleanHome {
		return "$HOME"
	}
	return strings.ReplaceAll(value, cleanHome+string(filepath.Separator), "$HOME/")
}

func configError(code, message, home, path string) model.CoverageError {
	return model.CoverageError{
		Code:    code,
		Message: message,
		Path:    filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path))),
	}
}
