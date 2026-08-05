// Package packages inventories developer packages and tools using fixed probes.
package packages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const maxPackageManifestBytes = 1 << 20

type packageCollector struct{}

type commandProbe struct {
	ecosystem string
	command   string
	args      []string
	parse     func(context.Context, collector.Environment, string) ([]model.Asset, error)
}

// New returns a collector that invokes only its built-in direct-exec catalog.
func New() collector.Collector { return &packageCollector{} }

func (*packageCollector) Name() string { return "packages" }

func (c *packageCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	assetsByID := make(map[string]model.Asset)
	successful := 0
	missing := 0
	unavailable := 0
	failed := 0

	for _, probe := range probes() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		commandResult, err := env.Runner.Run(ctx, probe.command, probe.args...)
		if err != nil || commandResult.ExitCode > 0 {
			switch {
			case executableMissing(err):
				missing++
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "executable_missing",
					Message: probe.ecosystem + " probe skipped because its executable is missing",
				})
			case probe.ecosystem == "docker":
				unavailable++
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "docker_unavailable",
					Message: "Docker image inventory is unavailable",
				})
			default:
				failed++
				result.Errors = append(result.Errors, model.CoverageError{
					Code:    "probe_failed",
					Message: probe.ecosystem + " package probe failed",
				})
			}
			continue
		}

		successful++
		assets, parseErr := probe.parse(ctx, env, commandResult.Stdout)
		if parseErr != nil {
			failed++
			result.Errors = append(result.Errors, model.CoverageError{
				Code:    "probe_output_invalid",
				Message: probe.ecosystem + " package output could not be parsed",
			})
			continue
		}
		if commandResult.Truncated {
			failed++
			result.Errors = append(result.Errors, model.CoverageError{
				Code:    "probe_output_truncated",
				Message: probe.ecosystem + " package output was truncated",
			})
		}
		for _, asset := range assets {
			assetsByID[asset.ID] = asset
		}
	}

	result.Assets = make([]model.Asset, 0, len(assetsByID))
	for _, asset := range assetsByID {
		result.Assets = append(result.Assets, asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })

	switch {
	case successful == 0 && unavailable > 0 && failed == 0:
		result.Status = model.CoverageUnavailable
	case successful == 0 && missing == len(probes()):
		result.Status = model.CoverageSkipped
	case missing > 0 || unavailable > 0 || failed > 0:
		result.Status = model.CoveragePartial
	default:
		result.Status = model.CoverageComplete
	}
	return result, nil
}

func probes() []commandProbe {
	return []commandProbe{
		{ecosystem: "npm", command: "npm", args: []string{"root", "-g"}, parse: parseNPM},
		{ecosystem: "pip", command: "python3", args: []string{"-m", "pip", "list", "--format=json"}, parse: parsePip},
		{ecosystem: "pipx", command: "pipx", args: []string{"list", "--json"}, parse: parsePipx},
		{ecosystem: "uv", command: "uv", args: []string{"tool", "list"}, parse: parseUV},
		{ecosystem: "cargo", command: "cargo", args: []string{"install", "--list"}, parse: parseCargo},
		{ecosystem: "go", command: "go", args: []string{"env", "GOPATH"}, parse: parseGoPath},
		{ecosystem: "brew", command: "brew", args: []string{"list", "--versions"}, parse: parseBrew},
		{ecosystem: "docker", command: "docker", args: []string{"image", "ls", "--format", "{{json .}}"}, parse: parseDocker},
	}
}

func executableMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	var execErr *exec.Error
	return errors.As(err, &execErr)
}

func parseNPM(ctx context.Context, env collector.Environment, stdout string) ([]model.Asset, error) {
	root := firstLine(stdout)
	if root == "" {
		return nil, nil
	}
	entries, err := env.FS.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var manifests []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() {
			continue
		}
		entryPath := filepath.Join(root, entry.Name())
		if strings.HasPrefix(entry.Name(), "@") {
			scoped, readErr := env.FS.ReadDir(entryPath)
			if readErr != nil {
				continue
			}
			for _, packageEntry := range scoped {
				if packageEntry.IsDir() {
					manifests = append(manifests, filepath.Join(entryPath, packageEntry.Name(), "package.json"))
				}
			}
			continue
		}
		manifests = append(manifests, filepath.Join(entryPath, "package.json"))
	}
	sort.Strings(manifests)
	assets := make([]model.Asset, 0, len(manifests))
	for _, manifest := range manifests {
		info, statErr := env.FS.Stat(manifest)
		if statErr != nil || info.Size() > maxPackageManifestBytes {
			continue
		}
		contents, readErr := env.FS.ReadFile(manifest)
		if readErr != nil {
			continue
		}
		var parsed struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(contents, &parsed) != nil || parsed.Name == "" || parsed.Version == "" {
			continue
		}
		asset := purlAsset("npm", parsed.Name, parsed.Version, "npm")
		asset.Path = redactPath(env.Home, filepath.Dir(manifest))
		assets = append(assets, asset)
	}
	return assets, nil
}

func parsePip(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if strings.TrimSpace(stdout) == "" {
		return nil, nil
	}
	var packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(stdout), &packages); err != nil {
		return nil, err
	}
	assets := make([]model.Asset, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Name != "" && pkg.Version != "" {
			assets = append(assets, purlAsset("pypi", normalizePyPIName(pkg.Name), pkg.Version, "pip"))
		}
	}
	return assets, nil
}

func parsePipx(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if strings.TrimSpace(stdout) == "" {
		return nil, nil
	}
	type pipxPackage struct {
		Package        string `json:"package"`
		PackageVersion string `json:"package_version"`
	}
	var listing struct {
		Venvs map[string]struct {
			Metadata struct {
				MainPackage      pipxPackage            `json:"main_package"`
				InjectedPackages map[string]pipxPackage `json:"injected_packages"`
			} `json:"metadata"`
		} `json:"venvs"`
	}
	if err := json.Unmarshal([]byte(stdout), &listing); err != nil {
		return nil, err
	}
	var assets []model.Asset
	for _, venv := range listing.Venvs {
		packages := []pipxPackage{venv.Metadata.MainPackage}
		for _, injected := range venv.Metadata.InjectedPackages {
			packages = append(packages, injected)
		}
		for _, pkg := range packages {
			if pkg.Package != "" && pkg.PackageVersion != "" {
				assets = append(assets, purlAsset("pypi", normalizePyPIName(pkg.Package), pkg.PackageVersion, "pipx"))
			}
		}
	}
	return assets, nil
}

func parseUV(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") || len(fields[1]) == 1 {
			continue
		}
		assets = append(assets, purlAsset("pypi", normalizePyPIName(fields[0]), strings.TrimPrefix(fields[1], "v"), "uv"))
	}
	return assets, nil
}

func parseCargo(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, " ") || !strings.HasSuffix(strings.TrimSpace(line), ":") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ":"))
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "v") || len(fields[1]) == 1 {
			continue
		}
		assets = append(assets, purlAsset("cargo", fields[0], strings.TrimPrefix(fields[1], "v"), "cargo"))
	}
	return assets, nil
}

func parseGoPath(ctx context.Context, env collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	for _, goPath := range filepath.SplitList(strings.TrimSpace(stdout)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if goPath == "" {
			continue
		}
		binPath := filepath.Join(goPath, "bin")
		entries, err := env.FS.ReadDir(binPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			assets = append(assets, model.Asset{
				ID:     "tool:go:" + escapePURLSegment(name),
				Type:   model.AssetTool,
				Name:   name,
				Path:   redactPath(env.Home, filepath.Join(binPath, name)),
				Source: "go",
			})
		}
	}
	return assets, nil
}

func parseBrew(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, version := range fields[1:] {
			assets = append(assets, purlAsset("brew", fields[0], version, "homebrew"))
		}
	}
	return assets, nil
}

func parseDocker(_ context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var image struct {
			Repository string `json:"Repository"`
			Tag        string `json:"Tag"`
			ID         string `json:"ID"`
			Digest     string `json:"Digest"`
		}
		if err := json.Unmarshal([]byte(line), &image); err != nil {
			return nil, err
		}
		if image.Repository == "" || image.Repository == "<none>" {
			continue
		}
		version := image.Tag
		if version == "" || version == "<none>" {
			version = image.Digest
		}
		if version == "" || version == "<none>" {
			version = image.ID
		}
		if version == "" {
			continue
		}
		assets = append(assets, purlAsset("docker", image.Repository, version, "docker"))
	}
	return assets, nil
}

func purlAsset(packageType, name, version, source string) model.Asset {
	return model.Asset{
		ID:      fmt.Sprintf("pkg:%s/%s@%s", packageType, escapePURLName(name), escapePURLSegment(version)),
		Type:    model.AssetPackage,
		Name:    name,
		Version: version,
		Source:  source,
	}
}

func escapePURLName(name string) string {
	parts := strings.Split(name, "/")
	for index := range parts {
		parts[index] = escapePURLSegment(parts[index])
	}
	return strings.Join(parts, "/")
}

func escapePURLSegment(value string) string {
	escaped := url.PathEscape(value)
	escaped = strings.ReplaceAll(escaped, "@", "%40")
	return escaped
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	return strings.NewReplacer("_", "-", ".", "-").Replace(name)
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}
