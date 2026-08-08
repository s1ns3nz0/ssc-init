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
	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
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
	roots              []Root
	invalid            bool
	limits             walkLimits
	beforeOpen         func(string)
	afterWalk          func(string)
	beforeProject      func(string)
	beforeEvidenceHash func(string)
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
		return abortProjectCollection(&result, err)
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
			return abortProjectCollection(&result, err)
		}
		walked, err := walkConfiguredRoot(ctx, env.FS, root, limits, c.beforeOpen)
		if err != nil {
			return abortProjectCollection(&result, err)
		}
		if err := ctx.Err(); err != nil {
			return abortProjectCollection(&result, err)
		}
		if c.afterWalk != nil {
			c.afterWalk(root.Ref)
			if err := ctx.Err(); err != nil {
				return abortProjectCollection(&result, err)
			}
		}
		target := model.TargetCoverage{
			TargetID: projectRootTargetID, InstanceRef: root.Ref,
			Status: walked.status, Errors: append([]model.CoverageError(nil), walked.errors...),
		}
		if walked.status != model.TargetNotPresent && walked.status != model.TargetUnavailable {
			assetStart, observationStart := len(result.Assets), len(result.Observations)
			evidenceErrors, buildErr := buildEvidence(ctx, c, env, root, walked, &result)
			if buildErr != nil {
				return abortProjectCollection(&result, buildErr)
			}
			if err := ctx.Err(); err != nil {
				return abortProjectCollection(&result, err)
			}
			target.Assets = len(result.Assets) - assetStart
			target.Observations = len(result.Observations) - observationStart
			if len(evidenceErrors) > 0 {
				target.Status = model.TargetPartial
				target.Errors = append(target.Errors, evidenceErrors...)
			}
		}
		result.Targets = append(result.Targets, target)
	}
	if err := ctx.Err(); err != nil {
		return abortProjectCollection(&result, err)
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
	sort.SliceStable(result.LocalEvidenceTargets, func(i, j int) bool {
		if result.LocalEvidenceTargets[i].TargetID != result.LocalEvidenceTargets[j].TargetID {
			return result.LocalEvidenceTargets[i].TargetID < result.LocalEvidenceTargets[j].TargetID
		}
		return result.LocalEvidenceTargets[i].ObservationID < result.LocalEvidenceTargets[j].ObservationID
	})
	result.Status = collector.AggregateTargetStatus(result.Targets)
	if err := ctx.Err(); err != nil {
		return abortProjectCollection(&result, err)
	}
	return result, nil
}

func abortProjectCollection(result *model.CollectorResult, err error) (model.CollectorResult, error) {
	if result == nil {
		return model.CollectorResult{Collector: "projects"}, err
	}
	runtime := []model.CollectorResult{*result}
	collector.ClearLocalEvidenceTargets(runtime)
	*result = model.CollectorResult{Collector: "projects"}
	return *result, err
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

func buildEvidence(ctx context.Context, owner *projectCollector, env collector.Environment, root Root, walked rootWalk, result *model.CollectorResult) ([]model.CoverageError, error) {
	errorsOut := make([]model.CoverageError, 0)
	if err := ctx.Err(); err != nil {
		return errorsOut, err
	}
	projectRelatives := make(map[string]struct{}, len(walked.configs)+len(walked.evidence))
	for _, config := range walked.configs {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		projectRelatives[filepath.Clean(config.projectRelative)] = struct{}{}
	}
	for _, item := range walked.evidence {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		projectRelatives[filepath.Clean(item.projectRelative)] = struct{}{}
	}
	orderedProjects := make([]string, 0, len(projectRelatives))
	for relative := range projectRelatives {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		orderedProjects = append(orderedProjects, relative)
	}
	sort.Strings(orderedProjects)
	if err := ctx.Err(); err != nil {
		return errorsOut, err
	}
	projectIDs := make(map[string]string, len(orderedProjects))
	projectObservations := make(map[string]model.Observation, len(orderedProjects))
	for _, projectRelative := range orderedProjects {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		if owner.beforeProject != nil {
			owner.beforeProject(filepath.ToSlash(projectRelative))
			if err := ctx.Err(); err != nil {
				return errorsOut, err
			}
		}
		absoluteProject := filepath.Clean(filepath.Join(root.Path, projectRelative))
		projectRef := identity.SafeLocationRef(env.Home, absoluteProject, root.Ref)
		projectID := digestID("project", "ssc-init.project.v1", projectRef)
		observation, err := identity.FinalizeObservation(model.Observation{
			AssetID: projectID, Collector: "projects", Scope: model.ScopeProject,
			LocationRef: projectRef, ProjectID: projectID, Source: projectRootTargetID,
			Metadata: map[string]string{"root_ref": root.Ref},
		})
		if err != nil {
			errorsOut = append(errorsOut, model.CoverageError{Code: "identity_rejected", Message: "project identity was rejected"})
			continue
		}
		projectIDs[projectRelative] = projectID
		projectObservations[projectRelative] = observation
		result.Assets = append(result.Assets, model.Asset{ID: projectID, Type: model.AssetProject, Name: "project"})
		result.Observations = append(result.Observations, observation)
	}

	for _, config := range walked.configs {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		absoluteConfig := filepath.Clean(filepath.Join(root.Path, config.relativePath))
		locationRef := identity.SafeLocationRef(env.Home, absoluteConfig, root.Ref)
		projectRelative := filepath.Clean(config.projectRelative)
		projectID, exists := projectIDs[projectRelative]
		if !exists {
			continue
		}
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
		result.Assets = append(result.Assets, model.Asset{
			ID: configID, Type: model.AssetProject, Name: filepath.ToSlash(config.definition.relativePath), Source: "project-config",
		})
		result.Relationships = append(result.Relationships, model.Relationship{From: projectID, To: configID, Kind: "contains"})
		result.Observations = append(result.Observations, observation)
		localTarget := model.LocalTarget{
			TargetID: config.definition.targetID, InstanceRef: locationRef, Path: absoluteConfig,
			Format: config.definition.format, Host: config.definition.host,
			Consumers: append([]string(nil), config.definition.consumers...),
		}
		localTarget.Provenance = &localTargetProvenance{
			owner: owner, rootSeal: root.seal, targetSeal: sealLocalTarget(root, &localTarget),
		}
		result.LocalTargets = append(result.LocalTargets, localTarget)
	}

	for _, item := range walked.evidence {
		if err := ctx.Err(); err != nil {
			return errorsOut, err
		}
		projectRelative := filepath.Clean(item.projectRelative)
		projectID, exists := projectIDs[projectRelative]
		observation, observed := projectObservations[projectRelative]
		if !exists || !observed {
			continue
		}
		if err := issueProjectEvidence(ctx, owner, env, root, walked.rootFingerprint, item, projectID, observation, result); err != nil {
			return errorsOut, err
		}
	}
	if err := ctx.Err(); err != nil {
		return errorsOut, err
	}
	return errorsOut, nil
}

func issueProjectEvidence(ctx context.Context, owner *projectCollector, env collector.Environment, configured Root, rootFingerprint platform.FileFingerprint, item discoveredProjectEvidence, projectID string, observation model.Observation, result *model.CollectorResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	base := model.LocalEvidenceTarget{
		TargetID: item.definition.targetID(), AssetID: projectID, ObservationID: observation.ID,
		Kind: model.EvidenceFileSHA256, Subject: item.definition.subject,
	}
	if item.oversize {
		return issueProjectPreset(ctx, result, base, model.EvidenceOversize)
	}
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if !ok || rooted == nil {
		return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
	}
	root, err := rooted.OpenRoot(configured.Path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
	}
	defer root.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	openedRoot, rootOK := projectRootFingerprint(root)
	if !rootOK || openedRoot != rootFingerprint {
		return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
	}
	asset := root
	assetRelative := filepath.Clean(item.projectRelative)
	if assetRelative == "." {
		assetRelative = ""
	}
	if assetRelative != "" {
		components := strings.Split(assetRelative, string(filepath.Separator))
		asset, err = platform.OpenVerifiedRoot(ctx, root, components...)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
		}
		defer asset.Close()
	}
	assetFingerprint, assetOK := projectRootFingerprint(asset)
	if !assetOK || assetFingerprint != item.projectFingerprint {
		return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
	}
	if owner.beforeEvidenceHash != nil {
		owner.beforeEvidenceHash(filepath.ToSlash(item.relativePath))
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	digest, status, _ := evidence.HashVerifiedFile(ctx, root, item.relativePath, item.definition.maxBytes)
	if err := ctx.Err(); err != nil {
		return err
	}
	if status != model.EvidenceComplete || digest.Fingerprint != item.fileFingerprint {
		if status == model.EvidenceOversize {
			return issueProjectPreset(ctx, result, base, model.EvidenceOversize)
		} else {
			return issueProjectPreset(ctx, result, base, model.EvidenceUnavailable)
		}
	}
	base.RootPath = configured.Path
	base.RelativePath = filepath.Clean(item.relativePath)
	anchor := evidence.Anchor{
		Root: rootFingerprint, AssetRoot: assetFingerprint, AssetRelativePath: filepath.ToSlash(assetRelative),
		RelativePath: filepath.Clean(item.relativePath), Digest: digest.SHA256, Size: digest.Size,
		Mode: digest.Fingerprint.Mode & 0o777, Fingerprint: digest.Fingerprint, MaxBytes: item.definition.maxBytes,
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	issuer := evidence.BindCollectorResult(result)
	if issuer != nil {
		result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(base, anchor))
	}
	return ctx.Err()
}

func issueProjectPreset(ctx context.Context, result *model.CollectorResult, target model.LocalEvidenceTarget, status model.EvidenceStatus) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	issuer := evidence.BindCollectorResult(result)
	if issuer == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	target.PresetStatus = status
	result.LocalEvidenceTargets = append(result.LocalEvidenceTargets, issuer.Issue(target, evidence.Anchor{}))
	return ctx.Err()
}

func projectRootFingerprint(root platform.RootedDirectory) (platform.FileFingerprint, bool) {
	if root == nil {
		return platform.FileFingerprint{}, false
	}
	info, err := root.Lstat(".")
	if err != nil || info == nil || !info.IsDir() {
		return platform.FileFingerprint{}, false
	}
	return platform.Fingerprint(info)
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
