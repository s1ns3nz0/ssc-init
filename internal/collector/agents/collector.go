// Package agents inventories plugins and skills below known AI host roots.
package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
	defaultMaxAgentRoots         = 7
	defaultMaxAgentDepth         = 16
	defaultMaxAgentEntries       = 100_000
	defaultMaxAgentManifests     = 4_096
	defaultMaxAgentManifestBytes = int64(1 << 20)
	maxAgentWalkErrors           = 64
	agentReadDirBatchSize        = 256
)

type walkLimits struct {
	maxRoots         int
	maxDepth         int
	maxEntries       int
	maxManifests     int
	maxManifestBytes int64
}

func defaultWalkLimits() walkLimits {
	return walkLimits{
		maxRoots: defaultMaxAgentRoots, maxDepth: defaultMaxAgentDepth,
		maxEntries: defaultMaxAgentEntries, maxManifests: defaultMaxAgentManifests,
		maxManifestBytes: defaultMaxAgentManifestBytes,
	}
}

func (limits walkLimits) valid() bool {
	return limits.maxRoots > 0 && limits.maxDepth > 0 && limits.maxEntries > 0 && limits.maxManifests > 0 && limits.maxManifestBytes > 0
}

type agentCollector struct {
	limits            walkLimits
	beforeOpen        func(targetID, relative string)
	afterManifestRead func(relative string)
}

// New returns a targeted collector restricted to the immutable AI host catalog.
func New() collector.TargetedCollector {
	return &agentCollector{limits: defaultWalkLimits()}
}

func (*agentCollector) Name() string { return "agents" }

func (*agentCollector) Targets() []model.TargetSpec { return catalogSpecs() }

func (c *agentCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	limits := c.limits
	if !limits.valid() {
		limits = defaultWalkLimits()
	}
	declarations := catalogDeclarations()
	rootedFilesystem, hasRootedFilesystem := env.FS.(platform.RootedFileSystem)
	if !hasRootedFilesystem {
		appendRootedUnavailableTargets(&result, declarations)
		sortAgentResult(&result)
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}
	homeRoot, err := rootedFilesystem.OpenRoot(env.Home)
	if err != nil {
		appendRootedUnavailableTargets(&result, declarations)
		sortAgentResult(&result)
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}
	defer homeRoot.Close()

	rootCount := 0
	for _, declaration := range declarations {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !declaration.supported {
			result.Targets = append(result.Targets, unsupportedAgentTarget(declaration.spec.ID))
			continue
		}
		rootCount++
		if rootCount > limits.maxRoots {
			result.Targets = append(result.Targets, targetWithIssue(declaration.spec.ID, model.TargetPartial, "root_limit", "agent root limit reached", ""))
			continue
		}
		if err := c.collectTarget(ctx, &result, env.Home, homeRoot, declaration, limits); err != nil {
			return result, err
		}
	}

	sortAgentResult(&result)
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func appendRootedUnavailableTargets(result *model.CollectorResult, declarations []targetDeclaration) {
	for _, declaration := range declarations {
		if !declaration.supported {
			result.Targets = append(result.Targets, unsupportedAgentTarget(declaration.spec.ID))
			continue
		}
		result.Targets = append(result.Targets, targetWithIssue(
			declaration.spec.ID, model.TargetUnavailable,
			"rooted_access_unavailable", "rooted agent access is unavailable", "",
		))
	}
}

func (c *agentCollector) collectTarget(ctx context.Context, result *model.CollectorResult, home string, homeRoot platform.RootedDirectory, declaration targetDeclaration, limits walkLimits) error {
	components := strings.Split(filepath.FromSlash(declaration.relativePath), string(filepath.Separator))
	root, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status, code, message := classifyAgentRootError(err)
		target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: status}
		if status != model.TargetNotPresent {
			target.Errors = []model.CoverageError{agentCoverageError(code, message, "$HOME/"+filepath.ToSlash(declaration.relativePath))}
		}
		result.Targets = append(result.Targets, target)
		return nil
	}
	defer root.Close()
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		status := model.TargetUnavailable
		code := "root_unavailable"
		message := "agent root is unavailable"
		if errors.Is(err, platform.ErrUnsafeRootedPath) {
			status = model.TargetPartial
			code = "identity_changed"
			message = "agent root identity changed"
		}
		result.Targets = append(result.Targets, targetWithIssue(
			declaration.spec.ID, status, code, message, "$HOME/"+filepath.ToSlash(declaration.relativePath),
		))
		return nil
	}

	walker := &agentWalker{
		ctx: ctx, declaration: declaration, limits: limits, beforeOpen: c.beforeOpen,
		afterManifestRead: c.afterManifestRead,
		targetRoot:        root,
	}
	_, walkErr := walker.walkDirectory(root, directory, ".", 0)
	closeErr := directory.Close()
	if walkErr != nil {
		return walkErr
	}
	if closeErr != nil {
		walker.addIssue("path_unavailable", "agent directory became unavailable")
	}
	target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetComplete}
	if len(walker.issues) > 0 {
		target.Status = model.TargetPartial
		target.Errors = append(target.Errors, walker.issues...)
	}
	if err := c.buildTargetEvidence(home, root, declaration, walker, result, &target); err != nil {
		return err
	}
	result.Targets = append(result.Targets, target)
	return nil
}

func classifyAgentRootError(err error) (model.TargetStatus, string, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return model.TargetNotPresent, "", ""
	case errors.Is(err, platform.ErrUnsafeRootedPath):
		return model.TargetPartial, "symlink_rejected", "symbolic link or changed root was not followed"
	default:
		return model.TargetUnavailable, "root_unavailable", "agent root is unavailable"
	}
}

type markerCandidate struct {
	kind         markerKind
	relativePath string
	pluginBase   string
	plugin       pluginManifest
	skillName    string
	parseErr     error
	expected     os.FileInfo
	evidence     *agentManifestEvidence
}

// agentManifestEvidence remains in the collector's runtime candidate until a
// sealed target is issued. It is never copied to asset or observation data.
type agentManifestEvidence struct {
	digest      string
	size        int64
	mode        uint32
	fingerprint platform.FileFingerprint
	root        platform.FileFingerprint
	assetRoot   platform.FileFingerprint
	assetPath   string
	maxBytes    int64
}

type agentWalker struct {
	ctx               context.Context
	declaration       targetDeclaration
	limits            walkLimits
	beforeOpen        func(targetID, relative string)
	afterManifestRead func(relative string)
	targetRoot        platform.RootedDirectory
	entries           int
	manifests         int
	plugins           []markerCandidate
	skills            []markerCandidate
	pendingSkills     []markerCandidate
	issues            []model.CoverageError
}

func (walker *agentWalker) walkDirectory(root platform.RootedDirectory, directory platform.RootedFile, relative string, depth int) (bool, error) {
	if err := walker.ctx.Err(); err != nil {
		return true, err
	}
	remaining := walker.limits.maxEntries - walker.entries
	entries, overflow, err := readBoundedAgentDirectory(directory, remaining)
	if err != nil {
		walker.addIssue("path_unavailable", "agent directory is unavailable")
		return false, nil
	}
	if overflow {
		walker.addIssue("entry_limit", "agent entry limit reached")
		return true, nil
	}
	walker.entries += len(entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if err := walker.ctx.Err(); err != nil {
			return true, err
		}
		name := entry.Name()
		entryRelative := name
		if relative != "." {
			entryRelative = filepath.Join(relative, name)
		}
		expected, err := root.Lstat(name)
		if err != nil || expected == nil {
			walker.addIssue("path_unavailable", "agent entry is unavailable")
			continue
		}
		if expected.Mode()&fs.ModeSymlink != 0 {
			walker.addIssue("symlink_rejected", "symbolic link was not followed")
			continue
		}
		if expected.IsDir() {
			if depth+1 > walker.limits.maxDepth {
				walker.addIssue("depth_limit", "agent depth limit reached")
				continue
			}
			walker.invokeBeforeOpen(entryRelative)
			if err := walker.ctx.Err(); err != nil {
				return true, err
			}
			child, err := platform.OpenVerifiedRoot(walker.ctx, root, name)
			if err != nil {
				walker.addIssue(agentIdentityIssueCode(err), "agent directory identity changed")
				continue
			}
			opened, statErr := child.Lstat(".")
			if statErr != nil || opened == nil || !os.SameFile(expected, opened) {
				_ = child.Close()
				walker.addIssue("identity_changed", "agent directory identity changed")
				continue
			}
			childDirectory, err := platform.OpenVerifiedDirectory(child)
			if err != nil {
				_ = child.Close()
				walker.addIssue(agentIdentityIssueCode(err), "agent directory identity changed")
				continue
			}
			stop, walkErr := walker.walkDirectory(child, childDirectory, entryRelative, depth+1)
			_ = childDirectory.Close()
			_ = child.Close()
			if walkErr != nil || stop {
				return stop, walkErr
			}
			continue
		}
		kind, pluginBase, recognized := recognizedAgentMarker(filepath.ToSlash(entryRelative), walker.declaration)
		if !recognized {
			continue
		}
		if !expected.Mode().IsRegular() {
			walker.addIssue("path_unavailable", "agent manifest is unavailable")
			continue
		}
		candidate := markerCandidate{kind: kind, relativePath: filepath.ToSlash(entryRelative), pluginBase: pluginBase}
		if kind == markerSkill && walker.declaration.kind == model.AssetAgentPlugin {
			candidate.expected = expected
			walker.pendingSkills = append(walker.pendingSkills, candidate)
			continue
		}
		if walker.manifests >= walker.limits.maxManifests {
			walker.addIssue("manifest_limit", "agent manifest limit reached")
			return true, nil
		}
		walker.manifests++
		read, readErr := walker.readManifest(root, name, entryRelative, expected)
		if readErr != nil {
			if errors.Is(readErr, errAgentManifestOversized) {
				walker.addIssue("manifest_size_limit", "agent manifest exceeds the size limit")
			} else {
				walker.addIssue(agentIdentityIssueCode(readErr), "agent manifest identity changed")
			}
			continue
		}
		candidate.evidence = &agentManifestEvidence{
			digest: read.digest, size: read.size, mode: read.mode, fingerprint: read.fingerprint, maxBytes: walker.limits.maxManifestBytes,
		}
		if !walker.captureAgentEvidenceAnchor(&candidate) {
			walker.addIssue("identity_changed", "agent evidence anchor identity changed")
			continue
		}
		switch kind {
		case markerClaudePlugin, markerCodexPlugin:
			candidate.plugin, candidate.parseErr = parsePluginManifest(read.contents)
			walker.plugins = append(walker.plugins, candidate)
		case markerSkill:
			fallback := filepath.Base(filepath.Dir(filepath.FromSlash(candidate.relativePath)))
			candidate.skillName, candidate.parseErr = parseSkillManifest(read.contents, fallback)
			walker.skills = append(walker.skills, candidate)
		}
	}
	return false, nil
}

var errAgentManifestOversized = errors.New("agent manifest oversized")

type agentManifestRead struct {
	contents    []byte
	digest      string
	size        int64
	mode        uint32
	fingerprint platform.FileFingerprint
}

func (walker *agentWalker) readManifest(root platform.RootedDirectory, name, relative string, enumerated os.FileInfo) (agentManifestRead, error) {
	if enumerated.Size() < 0 || enumerated.Size() > walker.limits.maxManifestBytes {
		return agentManifestRead{}, errAgentManifestOversized
	}
	walker.invokeBeforeOpen(relative)
	if err := walker.ctx.Err(); err != nil {
		return agentManifestRead{}, err
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		return agentManifestRead{}, err
	}
	defer file.Close()
	if !os.SameFile(enumerated, beforeOpen) || !os.SameFile(enumerated, opened) {
		return agentManifestRead{}, platform.ErrUnsafeRootedPath
	}
	if beforeOpen.Size() < 0 || beforeOpen.Size() > walker.limits.maxManifestBytes || opened.Size() < 0 || opened.Size() > walker.limits.maxManifestBytes {
		return agentManifestRead{}, errAgentManifestOversized
	}
	beforeFingerprint, ok := platform.Fingerprint(opened)
	if !ok {
		return agentManifestRead{}, platform.ErrUnsafeRootedPath
	}
	contents, err := io.ReadAll(io.LimitReader(file, walker.limits.maxManifestBytes+1))
	if err != nil {
		return agentManifestRead{}, err
	}
	if int64(len(contents)) > walker.limits.maxManifestBytes {
		return agentManifestRead{}, errAgentManifestOversized
	}
	postRead, err := file.Stat()
	if err != nil || postRead == nil || !os.SameFile(opened, postRead) {
		return agentManifestRead{}, platform.ErrUnsafeRootedPath
	}
	fingerprint, ok := platform.Fingerprint(postRead)
	if !ok || fingerprint.Size != int64(len(contents)) || fingerprint != beforeFingerprint {
		return agentManifestRead{}, platform.ErrUnsafeRootedPath
	}
	digest := sha256.Sum256(contents)
	return agentManifestRead{contents: contents, digest: hex.EncodeToString(digest[:]), size: int64(len(contents)), mode: uint32(postRead.Mode().Perm()), fingerprint: fingerprint}, nil
}

func readBoundedAgentDirectory(directory platform.RootedFile, remaining int) ([]os.DirEntry, bool, error) {
	if remaining < 0 {
		return nil, true, nil
	}
	entries := make([]os.DirEntry, 0, min(remaining, agentReadDirBatchSize))
	for {
		limit := min(agentReadDirBatchSize, remaining+1-len(entries))
		if limit <= 0 {
			return entries, true, nil
		}
		batch, err := directory.ReadDir(limit)
		entries = append(entries, batch...)
		if len(entries) > remaining {
			return nil, true, nil
		}
		if errors.Is(err, io.EOF) {
			return entries, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

func recognizedAgentMarker(relative string, declaration targetDeclaration) (markerKind, string, bool) {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	if declaration.kind == model.AssetSkill && filepath.Base(filepath.FromSlash(clean)) == "SKILL.md" {
		return markerSkill, "", true
	}
	if declaration.kind != model.AssetAgentPlugin {
		return "", "", false
	}
	markerDirectory := ".claude-plugin"
	if declaration.marker == markerCodexPlugin {
		markerDirectory = ".codex-plugin"
	}
	pluginSuffix := "/" + markerDirectory + "/plugin.json"
	if strings.HasSuffix(clean, pluginSuffix) {
		base := strings.TrimSuffix(clean, pluginSuffix)
		if base == "" {
			base = "."
		}
		return declaration.marker, base, true
	}
	if filepath.Base(filepath.FromSlash(clean)) == "SKILL.md" && strings.Contains("/"+clean, "/skills/") {
		return markerSkill, "", true
	}
	return "", "", false
}

func (walker *agentWalker) invokeBeforeOpen(relative string) {
	if walker.beforeOpen != nil {
		walker.beforeOpen(walker.declaration.spec.ID, filepath.ToSlash(relative))
	}
}

func (walker *agentWalker) addIssue(code, message string) {
	if len(walker.issues) >= maxAgentWalkErrors {
		return
	}
	walker.issues = append(walker.issues, agentCoverageError(code, message, ""))
}

func agentIdentityIssueCode(err error) string {
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		return "identity_changed"
	}
	return "path_unavailable"
}

func (c *agentCollector) buildTargetEvidence(home string, root platform.RootedDirectory, declaration targetDeclaration, walker *agentWalker, result *model.CollectorResult, target *model.TargetCoverage) error {
	sort.Slice(walker.plugins, func(i, j int) bool { return walker.plugins[i].relativePath < walker.plugins[j].relativePath })
	sort.Slice(walker.skills, func(i, j int) bool { return walker.skills[i].relativePath < walker.skills[j].relativePath })
	acceptedPluginBases := make(map[string]struct{})
	for _, candidate := range walker.plugins {
		if candidate.parseErr != nil {
			if errors.Is(candidate.parseErr, errInvalidAgentIdentity) {
				appendAgentTargetIssue(target, "identity_rejected", "agent identity was rejected")
			} else {
				appendAgentTargetIssue(target, "manifest_invalid", "agent manifest is invalid")
			}
			continue
		}
		if observation, accepted := appendAgentObservation(home, declaration, candidate, candidate.plugin.name, candidate.plugin.version, result, target); accepted {
			acceptedPluginBases[filepath.ToSlash(filepath.Clean(filepath.FromSlash(candidate.pluginBase)))] = struct{}{}
			c.issueAgentEvidence(home, declaration, candidate, observation, result, target)
		}
	}
	if declaration.kind == model.AssetAgentPlugin {
		if err := walker.readAcceptedBundledSkills(root, acceptedPluginBases, target); err != nil {
			return err
		}
	}
	for _, candidate := range walker.skills {
		if declaration.kind == model.AssetAgentPlugin && !isBundledSkill(candidate.relativePath, acceptedPluginBases) {
			continue
		}
		if candidate.parseErr != nil {
			appendAgentTargetIssue(target, "manifest_invalid", "agent manifest is invalid")
			continue
		}
		if observation, accepted := appendAgentObservation(home, declaration, candidate, candidate.skillName, "", result, target); accepted {
			c.issueAgentEvidence(home, declaration, candidate, observation, result, target)
		}
	}
	return nil
}

func (walker *agentWalker) readAcceptedBundledSkills(root platform.RootedDirectory, acceptedPluginBases map[string]struct{}, target *model.TargetCoverage) error {
	sort.Slice(walker.pendingSkills, func(i, j int) bool {
		return walker.pendingSkills[i].relativePath < walker.pendingSkills[j].relativePath
	})
	for _, candidate := range walker.pendingSkills {
		if !isBundledSkill(candidate.relativePath, acceptedPluginBases) {
			continue
		}
		if err := walker.ctx.Err(); err != nil {
			return err
		}
		if walker.manifests >= walker.limits.maxManifests {
			appendAgentTargetIssue(target, "manifest_limit", "agent manifest limit reached")
			return nil
		}
		walker.manifests++
		read, err := walker.readStagedManifest(root, candidate)
		if err != nil {
			if ctxErr := walker.ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, errAgentManifestOversized) {
				appendAgentTargetIssue(target, "manifest_size_limit", "agent manifest exceeds the size limit")
			} else {
				appendAgentTargetIssue(target, agentIdentityIssueCode(err), "agent manifest identity changed")
			}
			continue
		}
		candidate.evidence = &agentManifestEvidence{
			digest: read.digest, size: read.size, mode: read.mode, fingerprint: read.fingerprint, maxBytes: walker.limits.maxManifestBytes,
		}
		if !walker.captureAgentEvidenceAnchor(&candidate) {
			appendAgentTargetIssue(target, "identity_changed", "agent evidence anchor identity changed")
			continue
		}
		fallback := filepath.Base(filepath.Dir(filepath.FromSlash(candidate.relativePath)))
		candidate.skillName, candidate.parseErr = parseSkillManifest(read.contents, fallback)
		walker.skills = append(walker.skills, candidate)
	}
	return nil
}

func (walker *agentWalker) readStagedManifest(root platform.RootedDirectory, candidate markerCandidate) (agentManifestRead, error) {
	relative := filepath.Clean(filepath.FromSlash(candidate.relativePath))
	directoryPath := filepath.Dir(relative)
	parent := root
	ownedParent := false
	if directoryPath != "." {
		components := strings.Split(directoryPath, string(filepath.Separator))
		var err error
		parent, err = platform.OpenVerifiedRoot(walker.ctx, root, components...)
		if err != nil {
			return agentManifestRead{}, err
		}
		ownedParent = true
	}
	if ownedParent {
		defer parent.Close()
	}
	name := filepath.Base(relative)
	current, err := parent.Lstat(name)
	if err != nil || current == nil {
		return agentManifestRead{}, err
	}
	if current.Mode()&fs.ModeSymlink != 0 || !current.Mode().IsRegular() || candidate.expected == nil || !os.SameFile(candidate.expected, current) {
		return agentManifestRead{}, platform.ErrUnsafeRootedPath
	}
	return walker.readManifest(parent, name, relative, candidate.expected)
}

func isBundledSkill(relative string, pluginBases map[string]struct{}) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	for base := range pluginBases {
		prefix := "skills/"
		if base != "." {
			prefix = base + "/skills/"
		}
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

func appendAgentEvidence(home string, declaration targetDeclaration, candidate markerCandidate, name, version string, result *model.CollectorResult, target *model.TargetCoverage) bool {
	_, accepted := appendAgentObservation(home, declaration, candidate, name, version, result, target)
	return accepted
}

func appendAgentObservation(home string, declaration targetDeclaration, candidate markerCandidate, name, version string, result *model.CollectorResult, target *model.TargetCoverage) (model.Observation, bool) {
	if invalidAgentIdentity(name, maxAgentNameBytes) || invalidAgentIdentity(version, maxAgentVersionBytes) && version != "" {
		appendAgentTargetIssue(target, "identity_rejected", "agent identity was rejected")
		return model.Observation{}, false
	}
	kind := "agent-plugin"
	assetType := model.AssetAgentPlugin
	if candidate.kind == markerSkill {
		kind = "agent-skill"
		assetType = model.AssetSkill
	}
	assetID := kind + ":" + declaration.spec.Host + ":" + name
	if version != "" {
		assetID += "@" + version
	}
	locationRef := "$HOME/" + filepath.ToSlash(filepath.Join(declaration.relativePath, filepath.FromSlash(candidate.relativePath)))
	metadata := map[string]string{
		"marker_kind":   string(candidate.kind),
		"manifest_path": filepath.ToSlash(candidate.relativePath),
	}
	if version != "" {
		metadata["version"] = version
	}
	if !safeAgentMetadata(metadata) {
		appendAgentTargetIssue(target, "identity_rejected", "agent identity was rejected")
		return model.Observation{}, false
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: assetID, Collector: "agents", Host: declaration.spec.Host,
		Consumers: []string{declaration.spec.Host}, Scope: model.ScopeUser,
		LocationRef: locationRef, Source: declaration.spec.ID, Metadata: metadata,
	})
	if err != nil {
		appendAgentTargetIssue(target, "identity_rejected", "agent identity was rejected")
		return model.Observation{}, false
	}
	result.Assets = append(result.Assets, model.Asset{
		ID: assetID, Type: assetType, Name: name, Version: version, Source: declaration.spec.Host,
	})
	result.Observations = append(result.Observations, observation)
	target.Assets++
	target.Observations++
	return observation, true
}

func invalidAgentIdentity(value string, maxBytes int) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > maxBytes || strings.TrimSpace(value) != value || privacy.ContainsSensitiveValue(value) {
		return true
	}
	for _, character := range value {
		if unicode.IsControl(character) || strings.ContainsRune(`/\\:@`, character) {
			return true
		}
	}
	return false
}

func safeAgentMetadata(metadata map[string]string) bool {
	for key, value := range metadata {
		if key == "" || value == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || privacy.ContainsSensitiveValue(key) || privacy.ContainsSensitiveValue(value) || filepath.IsAbs(value) {
			return false
		}
	}
	return true
}

func appendAgentTargetIssue(target *model.TargetCoverage, code, message string) {
	target.Status = model.TargetPartial
	if len(target.Errors) >= maxAgentWalkErrors {
		return
	}
	target.Errors = append(target.Errors, agentCoverageError(code, message, ""))
}

func unsupportedAgentTarget(id string) model.TargetCoverage {
	return targetWithIssue(id, model.TargetUnsupported, "unsupported_target", "target is not supported", "")
}

func targetWithIssue(id string, status model.TargetStatus, code, message, path string) model.TargetCoverage {
	return model.TargetCoverage{
		TargetID: id, Status: status,
		Errors: []model.CoverageError{agentCoverageError(code, message, path)},
	}
}

func agentCoverageError(code, message, path string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message, Path: path}
}

func sortAgentResult(result *model.CollectorResult) {
	sort.SliceStable(result.Targets, func(i, j int) bool { return result.Targets[i].TargetID < result.Targets[j].TargetID })
	sort.SliceStable(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.SliceStable(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
}
