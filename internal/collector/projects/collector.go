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

	home string
	seal [sha256.Size]byte
}

type projectCollector struct {
	roots      []Root
	invalid    bool
	limits     walkLimits
	beforeOpen func(string)
}

type localTargetProvenance struct {
	owner      *projectCollector
	rootSeal   [sha256.Size]byte
	targetSeal [sha256.Size]byte
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
	for index := range roots {
		roots[index].home = cleanHome
		roots[index].seal = sealRoot(roots[index])
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
	if validateResolvedRoots(roots) != nil {
		return nil
	}
	refs := make([]string, len(roots))
	for index, root := range roots {
		refs[index] = root.Ref
	}
	return refs
}

// New returns a targeted project collector for roots produced by ResolveRoots.
func New(roots []Root) collector.TargetedCollector {
	return &projectCollector{
		roots:   append([]Root(nil), roots...),
		invalid: validateResolvedRoots(roots) != nil,
		limits:  defaultWalkLimits(),
	}
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
	if c.invalid {
		return result, errors.New("invalid project roots")
	}
	limits := c.limits
	if !limits.valid() {
		limits = defaultWalkLimits()
	}
	roots := c.roots
	if validateResolvedRoots(roots) != nil {
		return result, errors.New("invalid project roots")
	}

	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		walked, err := walkConfiguredRoot(ctx, env.FS, root, limits, c.beforeOpen)
		if err != nil {
			return result, err
		}
		target := model.TargetCoverage{
			TargetID: projectRootTargetID, InstanceRef: root.Ref,
			Status: walked.status, Errors: append([]model.CoverageError(nil), walked.errors...),
		}
		if walked.status != model.TargetNotPresent && walked.status != model.TargetUnavailable {
			assets, relationships, observations, localTargets, evidenceErrors := buildEvidence(c, env.Home, root, walked.configs)
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

func sealRoot(root Root) [sha256.Size]byte {
	return sha256.Sum256([]byte("ssc-init.resolved-project-root.v1\x00" + root.home + "\x00" + root.Path + "\x00" + root.Ref))
}

func validateResolvedRoots(roots []Root) error {
	if len(roots) == 0 || len(roots) > maxConfiguredRoots {
		return errors.New("invalid project roots")
	}
	home := roots[0].home
	if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home || strings.ContainsRune(home, '\x00') {
		return errors.New("invalid project roots")
	}
	seenPaths := make(map[string]struct{}, len(roots))
	seenRefs := make(map[string]struct{}, len(roots))
	previousHomePath := ""
	previousExternalPath := ""
	externalIndex := 0
	seenExternal := false
	for _, root := range roots {
		if root.home != home || root.Path == "" || root.Ref == "" || !filepath.IsAbs(root.Path) || filepath.Clean(root.Path) != root.Path || strings.ContainsRune(root.Path, '\x00') || strings.ContainsRune(root.Ref, '\x00') || root.seal != sealRoot(root) {
			return errors.New("invalid project roots")
		}
		if _, duplicate := seenPaths[root.Path]; duplicate {
			return errors.New("invalid project roots")
		}
		if _, duplicate := seenRefs[root.Ref]; duplicate {
			return errors.New("invalid project roots")
		}
		seenPaths[root.Path] = struct{}{}
		seenRefs[root.Ref] = struct{}{}
		if ref, insideHome := homeRootRef(home, root.Path); insideHome {
			if seenExternal || root.Ref != ref || (previousHomePath != "" && root.Path <= previousHomePath) {
				return errors.New("invalid project roots")
			}
			previousHomePath = root.Path
			continue
		}
		seenExternal = true
		externalIndex++
		if root.Ref != fmt.Sprintf("external-root-%d", externalIndex) || (previousExternalPath != "" && root.Path <= previousExternalPath) {
			return errors.New("invalid project roots")
		}
		previousExternalPath = root.Path
	}
	return nil
}

func buildEvidence(owner *projectCollector, home string, root Root, configs []discoveredConfig) ([]model.Asset, []model.Relationship, []model.Observation, []model.LocalTarget, []model.CoverageError) {
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
		observations = append(observations, observation)
		localTarget := model.LocalTarget{
			TargetID: config.definition.targetID, InstanceRef: locationRef, Path: absoluteConfig,
			Format: config.definition.format, Host: config.definition.host,
			Consumers: append([]string(nil), config.definition.consumers...),
		}
		localTarget.Provenance = &localTargetProvenance{
			owner: owner, rootSeal: root.seal, targetSeal: sealLocalTarget(root, &localTarget),
		}
		localTargets = append(localTargets, localTarget)
	}
	return assets, relationships, observations, localTargets, errorsOut
}

func sealLocalTarget(root Root, target *model.LocalTarget) [sha256.Size]byte {
	material := "ssc-init.project-local-target.v1\x00" + string(root.seal[:]) + "\x00" +
		target.TargetID + "\x00" + target.InstanceRef + "\x00" + target.Path + "\x00" +
		target.Format + "\x00" + target.Host + "\x00" + strings.Join(target.Consumers, "\x00")
	return sha256.Sum256([]byte(material))
}

// ValidIssuedLocalTarget authenticates a runtime-only handoff as emitted by a
// project collector over one of its sealed configured roots.
func ValidIssuedLocalTarget(home string, target *model.LocalTarget) bool {
	if target == nil {
		return false
	}
	proof, ok := target.Provenance.(*localTargetProvenance)
	return ok && proof.owner != nil && proof.owner.validLocalTarget(home, target, proof)
}

// ValidLocalTarget authenticates a runtime-only handoff against the exact
// configured project collector that issued it.
func ValidLocalTarget(configured collector.Collector, home string, target *model.LocalTarget) bool {
	if target == nil {
		return false
	}
	owner, ok := configured.(*projectCollector)
	if !ok {
		return false
	}
	proof, ok := target.Provenance.(*localTargetProvenance)
	return ok && proof.owner == owner && owner.validLocalTarget(home, target, proof)
}

func (c *projectCollector) validLocalTarget(home string, target *model.LocalTarget, proof *localTargetProvenance) bool {
	if c == nil || proof.owner != c || validateResolvedRoots(c.roots) != nil || len(c.roots) == 0 || c.roots[0].home != filepath.Clean(home) {
		return false
	}
	for _, root := range c.roots {
		if root.seal != proof.rootSeal {
			continue
		}
		relative, err := filepath.Rel(root.Path, target.Path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return false
		}
		return proof.targetSeal == sealLocalTarget(root, target)
	}
	return false
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
