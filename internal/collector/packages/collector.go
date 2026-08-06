// Package packages inventories developer packages and tools using fixed probes.
package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
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
	maxPackageEntries                 = 10_000
	packageDirectoryBatchSize         = 128
	maxDockerFailureClassifyBytes     = 8 << 10
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
			if verifyErr == nil && probe.targetID == "packages.docker" && dockerDaemonUnavailable(commandResult, runErr) {
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

func dockerDaemonUnavailable(result platform.CommandResult, runErr error) bool {
	var timeoutErr *platform.TimeoutError
	if errors.As(runErr, &timeoutErr) || errors.Is(runErr, context.DeadlineExceeded) || errors.Is(runErr, context.Canceled) {
		return false
	}
	stderr := result.Stderr
	if len(stderr) > maxDockerFailureClassifyBytes {
		stderr = stderr[:maxDockerFailureClassifyBytes]
	}
	stderr = strings.ToLower(stderr)
	if strings.Contains(stderr, "permission denied while trying to connect to the docker daemon socket") {
		return true
	}
	for _, marker := range []string{
		"cannot connect to the docker daemon",
		"is the docker daemon running",
		"docker daemon is not running",
		"error during connect",
	} {
		if strings.Contains(stderr, marker) {
			return true
		}
	}
	return false
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
	return parseNPMWithEntryLimit(ctx, env, stdout, maxPackageEntries)
}

func parseNPMWithEntryLimit(ctx context.Context, env collector.Environment, stdout string, entryLimit int) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := firstLine(stdout)
	if root == "" {
		return nil, errParserLoss
	}
	rootedFS, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		return nil, errFilesystemAccess
	}
	rootDirectory, err := rootedFS.OpenRoot(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if errors.Is(err, platform.ErrUnsafeRootedPath) {
			return nil, errParserLoss
		}
		return nil, errFilesystemAccess
	}
	defer rootDirectory.Close()
	budget := newPackageEntryBudget(entryLimit)
	entries, truncated, readErr := readPackageDirectory(ctx, rootDirectory, budget)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	assets := make([]model.Asset, 0)
	accessIncomplete := false
	loss := truncated
	markIssue := func(err error) {
		switch {
		case err == nil:
		case errors.Is(err, errParserLoss), errors.Is(err, platform.ErrUnsafeRootedPath), errors.Is(err, fs.ErrNotExist):
			loss = true
		default:
			accessIncomplete = true
		}
	}
	markIssue(readErr)
	appendManifest := func(packageRoot platform.RootedDirectory, location string) {
		contents, readErr := readNPMManifest(ctx, packageRoot)
		if readErr != nil {
			markIssue(readErr)
			return
		}
		var parsed struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(contents, &parsed) != nil || parsed.Name == "" || parsed.Version == "" {
			loss = true
			return
		}
		asset := purlAsset("npm", parsed.Name, parsed.Version, "npm")
		asset.Path = location
		assets = append(assets, asset)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Name() == ".bin" {
			continue
		}
		entryInfo, infoErr := rootDirectory.Lstat(entry.Name())
		if infoErr != nil {
			markIssue(infoErr)
			continue
		}
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			loss = true
			continue
		}
		if !entryInfo.IsDir() {
			continue
		}
		entryPath := filepath.Join(root, entry.Name())
		entryRoot, openErr := platform.OpenVerifiedRoot(ctx, rootDirectory, entry.Name())
		if openErr != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			markIssue(openErr)
			continue
		}
		if strings.HasPrefix(entry.Name(), "@") {
			scoped, scopeTruncated, scopeErr := readPackageDirectory(ctx, entryRoot, budget)
			if err := ctx.Err(); err != nil {
				_ = entryRoot.Close()
				return nil, err
			}
			if scopeTruncated {
				loss = true
			}
			markIssue(scopeErr)
			for _, packageEntry := range scoped {
				if err := ctx.Err(); err != nil {
					_ = entryRoot.Close()
					return nil, err
				}
				packageInfo, infoErr := entryRoot.Lstat(packageEntry.Name())
				if infoErr != nil {
					markIssue(infoErr)
					continue
				}
				if packageInfo.Mode()&fs.ModeSymlink != 0 {
					loss = true
					continue
				}
				if !packageInfo.IsDir() {
					continue
				}
				packageRoot, openErr := platform.OpenVerifiedRoot(ctx, entryRoot, packageEntry.Name())
				if openErr != nil {
					if err := ctx.Err(); err != nil {
						_ = entryRoot.Close()
						return nil, err
					}
					markIssue(openErr)
					continue
				}
				appendManifest(packageRoot, filepath.Join(entryPath, packageEntry.Name()))
				_ = packageRoot.Close()
				if err := ctx.Err(); err != nil {
					_ = entryRoot.Close()
					return nil, err
				}
			}
			_ = entryRoot.Close()
			continue
		}
		appendManifest(entryRoot, entryPath)
		_ = entryRoot.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	return assets, packageParseError(accessIncomplete, loss)
}

func readNPMManifest(ctx context.Context, packageRoot platform.RootedDirectory) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(packageRoot, "package.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, platform.ErrUnsafeRootedPath) {
			return nil, errParserLoss
		}
		return nil, errFilesystemAccess
	}
	defer file.Close()
	if !samePackageFileSnapshot(beforeOpen, opened) {
		return nil, errParserLoss
	}
	if opened.Size() < 0 || opened.Size() > maxPackageManifestBytes {
		return nil, errParserLoss
	}
	contents, err := io.ReadAll(io.LimitReader(&packageContextReader{ctx: ctx, reader: file}, maxPackageManifestBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errFilesystemAccess
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	afterRead, err := file.Stat()
	if err != nil {
		return nil, errFilesystemAccess
	}
	if len(contents) > maxPackageManifestBytes || !samePackageFileSnapshot(opened, afterRead) || int64(len(contents)) != opened.Size() || int64(len(contents)) != afterRead.Size() {
		return nil, errParserLoss
	}
	return contents, nil
}

func parsePip(ctx context.Context, _ collector.Environment, stdout string) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(stdout) == "" {
		return nil, errParserLoss
	}
	var packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(stdout), &packages); err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, errParserLoss
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
		return nil, errParserLoss
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
	if len(listing.Venvs) == 0 {
		return nil, errParserLoss
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
	return parseGoPathWithEntryLimit(ctx, env, stdout, maxPackageEntries)
}

func parseGoPathWithEntryLimit(ctx context.Context, env collector.Environment, stdout string, entryLimit int) ([]model.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(stdout) == "" {
		return nil, errParserLoss
	}
	rootedFS, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		return nil, errFilesystemAccess
	}
	var assets []model.Asset
	accessIncomplete := false
	loss := false
	budget := newPackageEntryBudget(entryLimit)
	usableRoots := 0
	for _, goPath := range filepath.SplitList(strings.TrimRight(stdout, "\r\n")) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(goPath) == "" {
			continue
		}
		usableRoots++
		binPath := filepath.Join(goPath, "bin")
		binRoot, err := rootedFS.OpenRoot(binPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				if errors.Is(err, platform.ErrUnsafeRootedPath) {
					loss = true
				} else {
					accessIncomplete = true
				}
			}
			continue
		}
		entries, truncated, readErr := readPackageDirectory(ctx, binRoot, budget)
		if err := ctx.Err(); err != nil {
			_ = binRoot.Close()
			return nil, err
		}
		if truncated {
			loss = true
		}
		if readErr != nil {
			if errors.Is(readErr, fs.ErrNotExist) || errors.Is(readErr, platform.ErrUnsafeRootedPath) {
				loss = true
			} else {
				accessIncomplete = true
			}
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				_ = binRoot.Close()
				return nil, err
			}
			info, statErr := binRoot.Lstat(entry.Name())
			if statErr != nil {
				if errors.Is(statErr, fs.ErrNotExist) || errors.Is(statErr, platform.ErrUnsafeRootedPath) {
					loss = true
				} else {
					accessIncomplete = true
				}
				continue
			}
			if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
				if !info.IsDir() {
					loss = true
				}
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
		_ = binRoot.Close()
	}
	if usableRoots == 0 {
		loss = true
	}
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	return assets, packageParseError(accessIncomplete, loss)
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
			loss = true
			continue
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

type packageEntryBudget struct {
	remaining int
}

func newPackageEntryBudget(limit int) *packageEntryBudget {
	if limit < 0 {
		limit = 0
	}
	return &packageEntryBudget{remaining: limit}
}

func (b *packageEntryBudget) take() bool {
	if b == nil || b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

func readPackageDirectory(ctx context.Context, root platform.RootedDirectory, budget *packageEntryBudget) ([]os.DirEntry, bool, error) {
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	entries := make([]os.DirEntry, 0)
	for {
		if err := ctx.Err(); err != nil {
			return entries, false, err
		}
		request := packageDirectoryBatchSize
		if budget == nil || budget.remaining < request {
			request = 1
			if budget != nil && budget.remaining > 0 {
				request = budget.remaining + 1
			}
		}
		batch, readErr := directory.ReadDir(request)
		for _, entry := range batch {
			if !budget.take() {
				return nil, true, nil
			}
			entries = append(entries, entry)
		}
		if errors.Is(readErr, io.EOF) {
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, false, nil
		}
		if readErr != nil {
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, false, readErr
		}
		if len(batch) == 0 {
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, false, nil
		}
	}
}

func samePackageFileSnapshot(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() &&
		left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

type packageContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *packageContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
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
