// Package projects discovers recognized project configuration below explicit,
// bounded filesystem roots.
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
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
)

const (
	projectRootTargetID = "projects.root"
	maxConfiguredRoots  = 32
)

// Root is a canonical configured project root and its persistence-safe
// reference. Path is host-local and must never be copied into model output.
type Root struct {
	Path string
	Ref  string
}

type projectCollector struct {
	roots      []Root
	rootValues []string
	legacyMCP  bool
	limits     walkLimits
	beforeOpen func(string)
}

type rootArgument interface {
	Root | string
}

// ResolveRoots canonicalizes configured roots, applies the default project
// root, and assigns deterministic references without exposing outside-home
// absolute paths.
func ResolveRoots(home string, values []string) ([]Root, error) {
	cleanHome := filepath.Clean(home)
	if home == "" || !filepath.IsAbs(cleanHome) || strings.ContainsRune(cleanHome, '\x00') {
		return nil, errors.New("invalid project roots")
	}
	if len(values) == 0 {
		values = []string{"$HOME/Projects"}
	}
	if len(values) > maxConfiguredRoots {
		return nil, errors.New("invalid project roots")
	}

	homeRoots := make([]Root, 0, len(values))
	externalPaths := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		path, err := resolveRootValue(cleanHome, value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[path]; duplicate {
			return nil, errors.New("invalid project roots")
		}
		seen[path] = struct{}{}
		if ref, ok := homeRootRef(cleanHome, path); ok {
			homeRoots = append(homeRoots, Root{Path: path, Ref: ref})
		} else {
			externalPaths = append(externalPaths, path)
		}
	}
	sort.Slice(homeRoots, func(i, j int) bool { return homeRoots[i].Path < homeRoots[j].Path })
	sort.Strings(externalPaths)
	roots := make([]Root, 0, len(values))
	roots = append(roots, homeRoots...)
	for index, path := range externalPaths {
		roots = append(roots, Root{Path: path, Ref: fmt.Sprintf("external-root-%d", index+1)})
	}
	return roots, nil
}

func resolveRootValue(home, value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid project roots")
	}
	switch {
	case value == "$HOME":
		return home, nil
	case strings.HasPrefix(value, "$HOME/"):
		relative := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(value, "$HOME/")))
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return "", errors.New("invalid project roots")
		}
		return filepath.Clean(filepath.Join(home, relative)), nil
	case filepath.IsAbs(value):
		return filepath.Clean(value), nil
	default:
		return "", errors.New("invalid project roots")
	}
}

func homeRootRef(home, path string) (string, bool) {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", false
	}
	if relative == "." {
		return "$HOME", true
	}
	return filepath.ToSlash(filepath.Join("$HOME", relative)), true
}

// RootRefs returns the deterministic persistence-safe scan scope references.
func RootRefs(roots []Root) []string {
	refs := make([]string, len(roots))
	for index, root := range roots {
		refs[index] = root.Ref
	}
	return refs
}

// New returns the targeted project collector. Production callers pass
// resolved Root values; string values remain accepted for source compatibility
// and are resolved against the injected environment home during collection.
func New[T rootArgument](values []T) collector.TargetedCollector {
	configured := &projectCollector{limits: defaultWalkLimits()}
	for _, value := range values {
		switch typed := any(value).(type) {
		case Root:
			configured.roots = append(configured.roots, typed)
		case string:
			configured.rootValues = append(configured.rootValues, typed)
			configured.legacyMCP = true
		}
	}
	return configured
}

func (*projectCollector) Name() string { return "projects" }

func (*projectCollector) Targets() []model.TargetSpec {
	return []model.TargetSpec{{
		ID: projectRootTargetID, Collector: "projects", Scope: model.ScopeProject,
		Platform: "darwin", Method: model.TargetDirectory,
	}}
}

func (c *projectCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	limits := c.limits
	if !limits.valid() {
		limits = defaultWalkLimits()
	}
	roots := c.roots
	if c.rootValues != nil {
		resolved, err := ResolveRoots(env.Home, c.rootValues)
		if err != nil {
			return result, errors.New("invalid project roots")
		}
		roots = resolved
	}
	if len(roots) == 0 {
		result.Targets = []model.TargetCoverage{{TargetID: projectRootTargetID, Status: model.TargetNotPresent}}
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		walked, err := walkConfiguredRoot(ctx, root, limits, c.beforeOpen)
		if err != nil {
			return result, err
		}
		target := model.TargetCoverage{
			TargetID: projectRootTargetID, InstanceRef: root.Ref,
			Status: walked.status, Errors: append([]model.CoverageError(nil), walked.errors...),
		}
		if walked.status != model.TargetNotPresent && walked.status != model.TargetUnavailable {
			assets, relationships, observations, localTargets, evidenceErrors := buildEvidence(env.Home, root, walked.configs, c.legacyMCP)
			result.Assets = append(result.Assets, assets...)
			result.Relationships = append(result.Relationships, relationships...)
			result.Observations = append(result.Observations, observations...)
			result.LocalTargets = append(result.LocalTargets, localTargets...)
			target.Assets = len(assets)
			target.Observations = len(observations)
			if len(evidenceErrors) > 0 {
				target.Status = model.TargetPartial
				target.Errors = append(target.Errors, evidenceErrors...)
			}
		}
		result.Targets = append(result.Targets, target)
	}

	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].InstanceRef < result.Targets[j].InstanceRef })
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.Slice(result.Relationships, func(i, j int) bool {
		left, right := result.Relationships[i], result.Relationships[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.To != right.To {
			return left.To < right.To
		}
		return left.Kind < right.Kind
	})
	sort.Slice(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
	sort.Slice(result.LocalTargets, func(i, j int) bool {
		if result.LocalTargets[i].Path != result.LocalTargets[j].Path {
			return result.LocalTargets[i].Path < result.LocalTargets[j].Path
		}
		return result.LocalTargets[i].TargetID < result.LocalTargets[j].TargetID
	})
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func buildEvidence(home string, root Root, configs []discoveredConfig, legacyMCP bool) ([]model.Asset, []model.Relationship, []model.Observation, []model.LocalTarget, []model.CoverageError) {
	assets := make([]model.Asset, 0, len(configs)*2)
	relationships := make([]model.Relationship, 0, len(configs))
	observations := make([]model.Observation, 0, len(configs))
	localTargets := make([]model.LocalTarget, 0, len(configs))
	errorsOut := make([]model.CoverageError, 0)
	seenProjects := make(map[string]struct{})
	for _, config := range configs {
		absoluteConfig := filepath.Clean(filepath.Join(root.Path, config.relativePath))
		absoluteProject := filepath.Clean(filepath.Join(root.Path, config.projectRelative))
		locationRef := identity.SafeLocationRef(home, absoluteConfig, root.Ref)
		projectRef := identity.SafeLocationRef(home, absoluteProject, root.Ref)
		projectID := digestID("project", "ssc-init.project.v1", projectRef)
		configID := digestID("project-config", "ssc-init.project-config.v1", locationRef)
		observation, err := identity.FinalizeObservation(model.Observation{
			AssetID: configID, Collector: "projects", Host: config.definition.host,
			Consumers: append([]string(nil), config.definition.consumers...), Scope: model.ScopeProject,
			LocationRef: locationRef, ProjectID: projectID, Source: config.definition.targetID,
			Metadata: map[string]string{"root_ref": root.Ref, "format": config.definition.format},
		})
		if err != nil {
			errorsOut = append(errorsOut, model.CoverageError{Code: "identity_rejected", Message: "project configuration identity was rejected"})
			continue
		}
		if _, exists := seenProjects[projectID]; !exists {
			seenProjects[projectID] = struct{}{}
			assets = append(assets, model.Asset{ID: projectID, Type: model.AssetProject, Name: "project"})
		}
		assets = append(assets, model.Asset{
			ID: configID, Type: model.AssetProject, Name: filepath.ToSlash(config.definition.relativePath), Source: "project-config",
		})
		relationships = append(relationships, model.Relationship{From: projectID, To: configID, Kind: "contains"})
		// Task 5 callers constructed project collectors from unresolved strings
		// and handed this safe, home-redacted asset to the existing MCP follow-up.
		// Keep only that source-compatibility path until Task 7 consumes
		// LocalTargets directly. Resolved Root callers never emit this asset.
		if legacyMCP && config.definition.targetID == "mcp.vscode.project" && strings.HasPrefix(locationRef, "$HOME/") {
			legacyID := "project-file:mcp:" + locationRef
			assets = append(assets, model.Asset{
				ID: legacyID, Type: model.AssetProject, Name: "mcp.json", Path: locationRef, Source: "mcp",
			})
			relationships = append(relationships, model.Relationship{From: projectID, To: legacyID, Kind: "contains"})
		}
		observations = append(observations, observation)
		localTargets = append(localTargets, model.LocalTarget{
			TargetID: config.definition.targetID, InstanceRef: locationRef, Path: absoluteConfig,
			Format: config.definition.format, Host: config.definition.host,
			Consumers: append([]string(nil), config.definition.consumers...),
		})
	}
	return assets, relationships, observations, localTargets, errorsOut
}

func digestID(kind, domain, reference string) string {
	digest := sha256.Sum256([]byte(domain + "\x00" + reference))
	return fmt.Sprintf("%s:sha256:%x", kind, digest)
}

func targetError(code, message string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message}
}

func classifyRootError(err error) model.TargetStatus {
	if errors.Is(err, fs.ErrNotExist) {
		return model.TargetNotPresent
	}
	return model.TargetUnavailable
}
