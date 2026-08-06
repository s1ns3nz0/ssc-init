// Package packages inventories developer packages and tools using fixed probes.
package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

const (
	maxPackageManifestBytes           = 1 << 20
	absolutePackageExecutableRefLimit = 17
)

var (
	errFilesystemAccess = errors.New("package filesystem access incomplete")
	errParserLoss       = errors.New("package probe output was only partially parsed")
)

type packageCollector struct{}

// Capability describes one package ecosystem probe and the direct executable
// it requires. Values do not imply that the executable is installed.
type Capability struct {
	Ecosystem  string
	Executable string
}

type commandProbe struct {
	targetID  string
	ecosystem string
	command   string
	args      []string
	parse     func(context.Context, collector.Environment, string) ([]model.Asset, error)
}

// New returns a collector that invokes only its built-in direct-exec catalog.
func New() collector.Collector { return &packageCollector{} }

func (*packageCollector) Name() string { return "packages" }

func (*packageCollector) Targets() []model.TargetSpec {
	probeCatalog := probes()
	targets := make([]model.TargetSpec, len(probeCatalog))
	for index, probe := range probeCatalog {
		targets[index] = model.TargetSpec{
			ID: probe.targetID, Collector: "packages", Host: probe.ecosystem,
			Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: probeFormat(probe.targetID), Method: model.TargetCommand,
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}

func (c *packageCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name(), Status: model.CoverageComplete}
	if !env.Scope.ExternalProbes {
		for _, target := range c.Targets() {
			result.Targets = append(result.Targets, model.TargetCoverage{TargetID: target.ID, Status: model.TargetSkipped})
		}
		result.Status = model.CoverageSkipped
		return result, nil
	}

	for _, probe := range probes() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		target := model.TargetCoverage{TargetID: probe.targetID, Status: model.TargetComplete}
		if env.Inspector == nil {
			appendPackageIssue(&result, &target, model.TargetUnavailable, "inspector_unavailable", "executable inspection is unavailable")
			result.Targets = append(result.Targets, target)
			continue
		}
		evidence, err := env.Inspector.Inspect(ctx, env.Home, probe.command)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		if err != nil {
			if executableMissing(err) {
				target.Status = model.TargetNotPresent
			} else {
				appendPackageIssue(&result, &target, model.TargetUnavailable, "executable_unavailable", "package probe executable is unavailable")
			}
			result.Targets = append(result.Targets, target)
			continue
		}
		executableObservation, ok := appendExecutableEvidence(&result, &target, probe, evidence)
		if !ok {
			result.Targets = append(result.Targets, target)
			continue
		}
		if env.Runner == nil {
			appendPackageIssue(&result, &target, model.TargetUnavailable, "runner_unavailable", "package probe execution is unavailable")
			result.Targets = append(result.Targets, target)
			continue
		}
		commandResult, runErr := env.Runner.Run(ctx, evidence.Path, probe.args...)
		verifyErr := env.Inspector.Verify(evidence)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return result, ctxErr
		}
		if verifyErr != nil {
			appendPackageIssue(&result, &target, model.TargetPartial, "executable_replaced", "package probe executable identity changed")
		}
		if runErr != nil || commandResult.ExitCode != 0 {
			if verifyErr == nil && probe.targetID == "packages.docker" {
				appendPackageIssue(&result, &target, model.TargetUnavailable, "docker_unavailable", "Docker image inventory is unavailable")
			} else {
				appendPackageIssue(&result, &target, model.TargetPartial, "probe_failed", probe.ecosystem+" package probe failed")
			}
			result.Targets = append(result.Targets, target)
			continue
		}
		assets, parseErr := probe.parse(ctx, env, commandResult.Stdout)
		if err := ctx.Err(); err != nil {
			return result, err
		}
		for _, asset := range assets {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			appendPackageEvidence(&result, &target, env, probe, evidence, executableObservation, asset)
		}
		if parseErr != nil {
			if errors.Is(parseErr, errFilesystemAccess) {
				appendPackageIssue(&result, &target, model.TargetPartial, "filesystem_unavailable", probe.ecosystem+" package filesystem access was incomplete")
			}
			if errors.Is(parseErr, errParserLoss) || !errors.Is(parseErr, errFilesystemAccess) {
				appendPackageIssue(&result, &target, model.TargetPartial, "probe_output_invalid", probe.ecosystem+" package output could not be parsed")
			}
		}
		if commandResult.Truncated {
			appendPackageIssue(&result, &target, model.TargetPartial, "probe_output_truncated", probe.ecosystem+" package output was truncated")
		}
		result.Targets = append(result.Targets, target)
	}
	sort.SliceStable(result.Targets, func(i, j int) bool { return result.Targets[i].TargetID < result.Targets[j].TargetID })
	sort.SliceStable(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.SliceStable(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func appendExecutableEvidence(result *model.CollectorResult, target *model.TargetCoverage, probe commandProbe, evidence platform.ExecutableEvidence) (model.Observation, bool) {
	asset := model.Asset{
		ID: "tool-executable:sha256:" + evidence.SHA256, Type: model.AssetTool,
		Name: "executable", SHA256: evidence.SHA256,
	}
	metadata := map[string]string{
		"command_basename": evidence.Command,
		"mode":             strconv.FormatUint(uint64(evidence.Mode), 8),
		"probe_target_id":  probe.targetID,
	}
	if len(evidence.SymlinkRefs) > 0 {
		metadata["symlink_chain"] = strings.Join(evidence.SymlinkRefs, "\x1f")
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: asset.ID, Collector: "packages", Host: probe.ecosystem,
		Consumers: []string{probe.ecosystem}, Scope: model.ScopeToolEnvironment,
		LocationRef: evidence.LocationRef, Source: probe.targetID, Metadata: metadata,
	})
	if err != nil || !validExecutableEvidence(probe, evidence) {
		appendPackageIssue(result, target, model.TargetPartial, "executable_evidence_invalid", "package probe executable evidence is invalid")
		return model.Observation{}, false
	}
	result.Assets = append(result.Assets, asset)
	result.Observations = append(result.Observations, observation)
	target.Assets++
	target.Observations++
	return observation, true
}

func appendPackageEvidence(result *model.CollectorResult, target *model.TargetCoverage, env collector.Environment, probe commandProbe, evidence platform.ExecutableEvidence, executableObservation model.Observation, candidate model.Asset) {
	if !safePackageIdentity(candidate) {
		appendPackageIssue(result, target, model.TargetPartial, "identity_rejected", "package identity was rejected")
		return
	}
	locationRef := "probe-target:" + probe.targetID
	if candidate.Path != "" {
		locationRef = platform.SafeLocationRef(env.Home, candidate.Path, "external-package")
	}
	candidate.Path = ""
	candidate.Source = ""
	candidate.Metadata = nil
	metadata := map[string]string{
		"manager":                   probe.ecosystem,
		"probe_source":              evidence.Command,
		"probe_target_id":           probe.targetID,
		"executable_observation_id": executableObservation.ID,
	}
	if probe.targetID == "packages.docker" {
		metadata["locality"] = "unknown"
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: candidate.ID, Collector: "packages", Host: probe.ecosystem,
		Consumers: []string{probe.ecosystem}, Scope: model.ScopeToolEnvironment,
		LocationRef: locationRef, Source: probe.targetID, Metadata: metadata,
	})
	if err != nil {
		appendPackageIssue(result, target, model.TargetPartial, "identity_rejected", "package identity was rejected")
		return
	}
	result.Assets = append(result.Assets, candidate)
	result.Observations = append(result.Observations, observation)
	target.Assets++
	target.Observations++
}

func validExecutableEvidence(probe commandProbe, evidence platform.ExecutableEvidence) bool {
	if evidence.Command != probe.command || !filepath.IsAbs(evidence.Path) || !safePersistedExecutableRef(evidence.LocationRef) {
		return false
	}
	digest, err := hex.DecodeString(evidence.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return false
	}
	for _, ref := range evidence.SymlinkRefs {
		if !safePersistedExecutableRef(ref) {
			return false
		}
	}
	return true
}

func safePersistedExecutableRef(value string) bool {
	if value == "$HOME" || strings.HasPrefix(value, "$HOME/") {
		return !privacy.ContainsSensitiveValue(value)
	}
	label, digest, ok := strings.Cut(value, "/path-sha256:")
	if !ok || !strings.HasPrefix(label, "external-executable:") || privacy.ContainsSensitiveValue(value) {
		return false
	}
	ordinal, err := strconv.Atoi(strings.TrimPrefix(label, "external-executable:"))
	if err != nil || ordinal < 1 || ordinal > absolutePackageExecutableRefLimit {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func safePackageIdentity(candidate model.Asset) bool {
	if candidate.ID == "" || candidate.Name == "" || len(candidate.ID) > 4096 || len(candidate.Name) > 4096 || len(candidate.Version) > 4096 {
		return false
	}
	for _, value := range []string{candidate.ID, candidate.Name, candidate.Version} {
		if !utf8.ValidString(value) || filepath.IsAbs(value) || privacy.ContainsSensitiveValue(value) {
			return false
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func appendPackageIssue(result *model.CollectorResult, target *model.TargetCoverage, status model.TargetStatus, code, message string) {
	if target.Status == model.TargetComplete || status == model.TargetPartial {
		target.Status = status
	}
	issue := model.CoverageError{Code: code, Message: message}
	if len(target.Errors) < 128 {
		target.Errors = append(target.Errors, issue)
	}
	if len(result.Errors) < 128 {
		result.Errors = append(result.Errors, issue)
	}
}

func probes() []commandProbe {
	return []commandProbe{
		{targetID: "packages.npm", ecosystem: "npm", command: "npm", args: []string{"root", "-g"}, parse: parseNPM},
		{targetID: "packages.pip", ecosystem: "pip", command: "python3", args: []string{"-m", "pip", "list", "--format=json"}, parse: parsePip},
		{targetID: "packages.pipx", ecosystem: "pipx", command: "pipx", args: []string{"list", "--json"}, parse: parsePipx},
		{targetID: "packages.uv", ecosystem: "uv", command: "uv", args: []string{"tool", "list"}, parse: parseUV},
		{targetID: "packages.cargo", ecosystem: "cargo", command: "cargo", args: []string{"install", "--list"}, parse: parseCargo},
		{targetID: "packages.go", ecosystem: "go", command: "go", args: []string{"env", "GOPATH"}, parse: parseGoPath},
		{targetID: "packages.homebrew", ecosystem: "homebrew", command: "brew", args: []string{"list", "--versions"}, parse: parseBrew},
		{targetID: "packages.docker", ecosystem: "docker", command: "docker", args: []string{"image", "ls", "--format", "{{json .}}"}, parse: parseDocker},
	}
}

func probeFormat(targetID string) string {
	switch targetID {
	case "packages.pip", "packages.pipx":
		return "json"
	case "packages.docker":
		return "ndjson"
	default:
		return "text"
	}
}

// Capabilities returns a fresh, read-only description of the exact probes used
// by New. Mutating the returned slice cannot change collector behavior.
func Capabilities() []Capability {
	probeCatalog := probes()
	capabilities := make([]Capability, len(probeCatalog))
	for index, probe := range probeCatalog {
		capabilities[index] = Capability{Ecosystem: probe.ecosystem, Executable: probe.command}
	}
	return capabilities
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := firstLine(stdout)
	if root == "" {
		return nil, nil
	}
	entries, err := env.FS.ReadDir(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, errFilesystemAccess
	}
	var manifests []string
	accessIncomplete := false
	loss := false
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
				if !errors.Is(readErr, fs.ErrNotExist) {
					accessIncomplete = true
				}
				continue
			}
			for _, packageEntry := range scoped {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, statErr := env.FS.Stat(manifest)
		if statErr != nil {
			if !errors.Is(statErr, fs.ErrNotExist) {
				accessIncomplete = true
			} else {
				loss = true
			}
			continue
		}
		if info.Size() < 0 || info.Size() > maxPackageManifestBytes {
			loss = true
			continue
		}
		contents, readErr := env.FS.ReadFile(manifest)
		if readErr != nil {
			if !errors.Is(readErr, fs.ErrNotExist) {
				accessIncomplete = true
			} else {
				loss = true
			}
			continue
		}
		if len(contents) > maxPackageManifestBytes {
			loss = true
			continue
		}
		var parsed struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(contents, &parsed) != nil || parsed.Name == "" || parsed.Version == "" {
			loss = true
			continue
		}
		asset := purlAsset("npm", parsed.Name, parsed.Version, "npm")
		asset.Path = filepath.Dir(manifest)
		assets = append(assets, asset)
	}
	return assets, packageParseError(accessIncomplete, loss)
}

func parsePip(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	loss := false
	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pkg.Name != "" && pkg.Version != "" {
			assets = append(assets, purlAsset("pypi", normalizePyPIName(pkg.Name), pkg.Version, "pip"))
		} else {
			loss = true
		}
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func parsePipx(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	loss := false
	for _, venv := range listing.Venvs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		packages := []pipxPackage{venv.Metadata.MainPackage}
		for _, injected := range venv.Metadata.InjectedPackages {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			packages = append(packages, injected)
		}
		for _, pkg := range packages {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if pkg.Package != "" && pkg.PackageVersion != "" {
				assets = append(assets, purlAsset("pypi", normalizePyPIName(pkg.Package), pkg.PackageVersion, "pipx"))
			} else {
				loss = true
			}
		}
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func parseUV(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assets []model.Asset
	loss := false
	for _, line := range strings.Split(stdout, "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") || len(fields[1]) == 1 {
			loss = true
			continue
		}
		assets = append(assets, purlAsset("pypi", normalizePyPIName(fields[0]), strings.TrimPrefix(fields[1], "v"), "uv"))
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func parseCargo(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assets []model.Asset
	loss := false
	for _, line := range strings.Split(stdout, "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(line, " ") || !strings.HasSuffix(strings.TrimSpace(line), ":") {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, " ") {
				loss = true
			}
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ":"))
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "v") || len(fields[1]) == 1 {
			loss = true
			continue
		}
		assets = append(assets, purlAsset("cargo", fields[0], strings.TrimPrefix(fields[1], "v"), "cargo"))
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func parseGoPath(ctx context.Context, env collector.Environment, stdout string) ([]model.Asset, error) {
	var assets []model.Asset
	accessIncomplete := false
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
			if !errors.Is(err, fs.ErrNotExist) {
				accessIncomplete = true
			}
			continue
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			assets = append(assets, model.Asset{
				ID:     "tool:go:" + escapePURLSegment(name),
				Type:   model.AssetTool,
				Name:   name,
				Path:   filepath.Join(binPath, name),
				Source: "go",
			})
		}
	}
	if accessIncomplete {
		return assets, errFilesystemAccess
	}
	return assets, nil
}

func parseBrew(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assets []model.Asset
	loss := false
	for _, line := range strings.Split(stdout, "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			loss = true
			continue
		}
		for _, version := range fields[1:] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			assets = append(assets, purlAsset("brew", fields[0], version, "homebrew"))
		}
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func parseDocker(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assets []model.Asset
	loss := false
	for _, line := range strings.Split(stdout, "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
			loss = true
			continue
		}
		version := image.Tag
		if version == "" || version == "<none>" {
			version = image.Digest
		}
		if version == "" || version == "<none>" {
			loss = true
			continue
		}
		assets = append(assets, purlAsset("docker", image.Repository, version, "docker"))
	}
	if loss {
		return assets, errParserLoss
	}
	return assets, nil
}

func packageParseError(accessIncomplete, loss bool) error {
	switch {
	case accessIncomplete && loss:
		return errors.Join(errFilesystemAccess, errParserLoss)
	case accessIncomplete:
		return errFilesystemAccess
	case loss:
		return errParserLoss
	default:
		return nil
	}
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
	var normalized strings.Builder
	separator := false
	for _, character := range name {
		if character == '-' || character == '_' || character == '.' {
			if !separator {
				normalized.WriteByte('-')
			}
			separator = true
			continue
		}
		separator = false
		normalized.WriteRune(character)
	}
	return normalized.String()
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}
