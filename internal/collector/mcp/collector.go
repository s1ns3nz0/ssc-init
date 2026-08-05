// Package mcp inventories MCP servers from fixed host configuration paths.
package mcp

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const maxMCPConfigBytes = 4 << 20

const redactedValue = "[redacted]"

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
	rootedFilesystem, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, configError("rooted_access_unavailable", "rooted MCP access is unavailable", env.Home, env.Home))
		return result, nil
	}
	homeRoot, err := rootedFilesystem.OpenRoot(env.Home)
	if err != nil {
		result.Status = model.CoveragePartial
		result.Errors = append(result.Errors, configError("rooted_access_unavailable", "rooted MCP access is unavailable", env.Home, env.Home))
		return result, nil
	}
	defer homeRoot.Close()

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

		contents, code, message, exists := readConfig(ctx, homeRoot, env.Home, target.path)
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
		path, ok := canonicalProjectPath(home, asset)
		if !ok {
			continue
		}
		targets = append(targets, configTarget{host: "vscode", path: path})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].path < targets[j].path })
	return targets
}

func canonicalProjectPath(home string, asset model.Asset) (string, bool) {
	if asset.Type != model.AssetProject || asset.Source != "mcp" || asset.Name != "mcp.json" {
		return "", false
	}
	redacted := asset.Path
	if redacted != filepath.ToSlash(redacted) || !strings.HasPrefix(redacted, "$HOME/") || pathpkg.Clean(redacted) != redacted {
		return "", false
	}
	if asset.ID != "project-file:mcp:"+redacted || !strings.HasSuffix(redacted, "/.vscode/mcp.json") {
		return "", false
	}
	relative := strings.TrimPrefix(redacted, "$HOME/")
	resolved := filepath.Clean(filepath.Join(filepath.Clean(home), filepath.FromSlash(relative)))
	rel, err := filepath.Rel(filepath.Clean(home), resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	canonicalRedacted := filepath.ToSlash(platform.RedactHome(filepath.Clean(home), resolved))
	if canonicalRedacted != redacted {
		return "", false
	}
	return resolved, true
}

func readConfig(ctx context.Context, homeRoot platform.RootedDirectory, home, path string) ([]byte, string, string, bool) {
	if err := ctx.Err(); err != nil {
		return nil, "", "", false
	}
	relative, err := filepath.Rel(filepath.Clean(home), filepath.Clean(path))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, "config_unavailable", "MCP configuration is unavailable", false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	parent := homeRoot
	ownedParent := false
	if len(parts) > 1 {
		parent, err = platform.OpenVerifiedRoot(ctx, homeRoot, parts[:len(parts)-1]...)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, "", "", false
			}
			return nil, "config_unavailable", "MCP configuration is unavailable", false
		}
		ownedParent = true
	}
	if ownedParent {
		defer parent.Close()
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(parent, parts[len(parts)-1])
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", "", false
		}
		return nil, "config_unavailable", "MCP configuration is unavailable", false
	}
	defer file.Close()
	if beforeOpen.Size() < 0 || beforeOpen.Size() > maxMCPConfigBytes || opened.Size() < 0 || opened.Size() > maxMCPConfigBytes {
		return nil, "config_oversized", "MCP configuration exceeds the size limit", true
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxMCPConfigBytes+1))
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
			"command":  sanitizeCommand(home, config.Command),
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
			result[index] = redactedValue
			redactNext = false
			continue
		}
		if absoluteURL(arg) {
			result[index] = sanitizeURL(home, arg)
			continue
		}
		if key, value, found := strings.Cut(arg, "="); found {
			switch {
			case sensitiveName(key), credentialFlag(key):
				result[index] = key + "=" + redactedValue
			case strings.Contains(value, "://"):
				result[index] = key + "=" + sanitizeURL(home, value)
			default:
				result[index] = redactHomeText(home, arg)
			}
			continue
		}
		if prefix, ok := combinedCredentialFlag(arg); ok {
			result[index] = prefix + redactedValue
			continue
		}
		if credentialFlag(arg) {
			result[index] = arg
			redactNext = true
			continue
		}
		if safePrefix, ok := sensitiveTextPrefix(arg); ok {
			result[index] = safePrefix + redactedValue
			continue
		}
		result[index] = redactHomeText(home, arg)
	}
	return result
}

func sanitizeCommand(home, command string) string {
	command = redactHomeText(home, command)
	if command == "" {
		return ""
	}
	if absoluteURL(command) {
		return sanitizeURL(home, command)
	}
	if key, _, found := strings.Cut(command, "="); found && (sensitiveName(key) || credentialFlag(key)) {
		return key + "=" + redactedValue
	}
	if prefix, ok := sensitiveTextPrefix(command); ok {
		return prefix + redactedValue
	}
	if prefix, ok := combinedCredentialFlag(command); ok {
		return prefix + redactedValue
	}
	fields := strings.Fields(command)
	if len(fields) > 1 {
		for _, field := range fields {
			key := field
			if before, _, found := strings.Cut(field, "="); found {
				key = before
			}
			if credentialFlag(key) || sensitiveName(key) {
				return redactedValue
			}
			if _, ok := combinedCredentialFlag(field); ok {
				return redactedValue
			}
		}
	}
	return command
}

func absoluteURL(value string) bool {
	if !strings.Contains(value, "://") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != ""
}

func sanitizeURL(home, raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(redactHomeText(home, raw))
	if err != nil {
		return redactedValue
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if sensitiveName(key) {
			query[key] = []string{redactedValue}
		}
	}
	parsed.RawQuery = query.Encode()
	if parsed.Fragment != "" {
		parsed.Fragment = redactedValue
	}
	return parsed.String()
}

func credentialFlag(value string) bool {
	if value == "-H" || value == "-e" {
		return true
	}
	return sensitiveLongFlag(value)
}

func combinedCredentialFlag(value string) (string, bool) {
	lower := strings.ToLower(value)
	if strings.HasPrefix(value, "-H") && len(value) > 2 {
		return value[:2], true
	}
	for _, flag := range []string{"--api-key", "--apikey", "--token"} {
		if strings.HasPrefix(lower, flag) && len(value) > len(flag) {
			if flag == "--token" && strings.HasPrefix(lower[len(flag):], "izer") {
				return "", false
			}
			return value[:len(flag)], true
		}
	}
	return "", false
}

func sensitiveLongFlag(value string) bool {
	if !strings.HasPrefix(value, "--") {
		return false
	}
	name := strings.TrimPrefix(value, "--")
	for _, exact := range []string{"header", "headers", "env", "bearer", "signature"} {
		if strings.EqualFold(name, exact) {
			return true
		}
	}
	return hasSensitiveComponent(name)
}

func sensitiveTextPrefix(value string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(lower, "authorization:"):
		return "Authorization: ", true
	case strings.HasPrefix(lower, "proxy-authorization:"):
		return "Proxy-Authorization: ", true
	case strings.HasPrefix(lower, "bearer "):
		return "Bearer ", true
	}
	return "", false
}

func sensitiveName(value string) bool {
	return hasSensitiveComponent(strings.TrimLeft(value, "-"))
}

func hasSensitiveComponent(value string) bool {
	components := semanticComponents(value)
	for _, component := range components {
		switch component {
		case "token", "secret", "password", "passwd", "credential", "credentials",
			"apikey", "accesskey", "privatekey", "clientsecret", "bearer", "signature", "key":
			return true
		}
	}
	if len(components) == 1 {
		switch components[0] {
		case "authorization", "auth", "header", "headers", "env":
			return true
		}
	}
	return false
}

func semanticComponents(value string) []string {
	runes := []rune(value)
	components := make([]string, 0, 4)
	for start := 0; start < len(runes); {
		for start < len(runes) && !unicode.IsLetter(runes[start]) && !unicode.IsDigit(runes[start]) {
			start++
		}
		if start == len(runes) {
			break
		}
		end := start
		for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end])) {
			end++
		}
		word := runes[start:end]
		wordStart := 0
		for index := 1; index < len(word); index++ {
			lowerToUpper := (unicode.IsLower(word[index-1]) || unicode.IsDigit(word[index-1])) && unicode.IsUpper(word[index])
			acronymToWord := unicode.IsUpper(word[index-1]) && unicode.IsUpper(word[index]) &&
				index+1 < len(word) && unicode.IsLower(word[index+1])
			if lowerToUpper || acronymToWord {
				components = append(components, strings.ToLower(string(word[wordStart:index])))
				wordStart = index
			}
		}
		components = append(components, strings.ToLower(string(word[wordStart:])))
		start = end
	}
	return components
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
