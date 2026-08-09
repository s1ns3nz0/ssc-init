// Package surfaces inventories bounded file-backed developer surfaces.
package surfaces

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

type surfaceCollector struct{}

type shellTarget struct {
	id       string
	relative string
}

var shellCatalog = []shellTarget{
	{id: "surfaces.shell.bash-profile", relative: ".bash_profile"},
	{id: "surfaces.shell.bashrc", relative: ".bashrc"},
	{id: "surfaces.shell.fish-config", relative: ".config/fish/config.fish"},
	{id: "surfaces.shell.profile", relative: ".profile"},
	{id: "surfaces.shell.zprofile", relative: ".zprofile"},
	{id: "surfaces.shell.zshrc", relative: ".zshrc"},
}

func New() collector.TargetedCollector { return &surfaceCollector{} }

func (*surfaceCollector) Name() string { return "surfaces" }

func (*surfaceCollector) Targets() []model.TargetSpec {
	targets := make([]model.TargetSpec, 0, len(shellCatalog)+2)
	for _, entry := range shellCatalog {
		targets = append(targets, model.TargetSpec{ID: entry.id, Collector: "surfaces", Scope: model.ScopeUser, Platform: "darwin", Format: "shell", Method: model.TargetFile})
	}
	targets = append(targets,
		model.TargetSpec{ID: "surfaces.git.user-config", Collector: "surfaces", Scope: model.ScopeUser, Platform: "darwin", Format: "git-config", Method: model.TargetFile},
		model.TargetSpec{ID: "surfaces.git.xdg-config", Collector: "surfaces", Scope: model.ScopeUser, Platform: "darwin", Format: "git-config", Method: model.TargetFile},
	)
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}

func (c *surfaceCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	noFollow, ok := env.FS.(platform.NoFollowFileSystem)
	if !ok || noFollow == nil {
		for _, entry := range shellCatalog {
			result.Targets = append(result.Targets, surfaceTargetError(entry.id, model.TargetUnavailable, "filesystem_unavailable", "surface filesystem is unavailable"))
		}
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}
	for _, entry := range shellCatalog {
		if err := ctx.Err(); err != nil {
			collector.ClearLocalEvidenceTargets([]model.CollectorResult{result})
			return model.CollectorResult{Collector: c.Name()}, err
		}
		target := model.TargetCoverage{TargetID: entry.id, Status: model.TargetComplete}
		absolute := filepath.Join(env.Home, filepath.FromSlash(entry.relative))
		info, err := noFollow.Lstat(absolute)
		if errors.Is(err, fs.ErrNotExist) {
			target.Status = model.TargetNotPresent
			result.Targets = append(result.Targets, target)
			continue
		}
		if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
			result.Targets = append(result.Targets, surfaceTargetError(entry.id, model.TargetPartial, "path_unavailable", "surface file is unavailable"))
			continue
		}
		locationRef := "$HOME/" + filepath.ToSlash(filepath.Clean(entry.relative))
		assetID := surfaceID("shell-startup", locationRef)
		observation, err := identity.FinalizeObservation(model.Observation{
			AssetID: assetID, Collector: c.Name(), Scope: model.ScopeUser,
			LocationRef: locationRef, Source: entry.id,
		})
		if err != nil {
			result.Targets = append(result.Targets, surfaceTargetError(entry.id, model.TargetPartial, "identity_rejected", "surface identity was rejected"))
			continue
		}
		result.Assets = append(result.Assets, model.Asset{ID: assetID, Type: model.AssetShellStartup, Name: filepath.Base(entry.relative), Source: "shell-startup"})
		result.Observations = append(result.Observations, observation)
		target.Assets, target.Observations = 1, 1
		status := issueHomeFileEvidence(ctx, env, &result, entry.id, filepath.FromSlash(entry.relative), assetID, observation.ID, model.EvidenceSubjectShellStartup)
		if err := ctx.Err(); err != nil {
			collector.ClearLocalEvidenceTargets([]model.CollectorResult{result})
			return model.CollectorResult{Collector: c.Name()}, err
		}
		if status != model.EvidenceComplete {
			target.Status = model.TargetPartial
			target.Errors = []model.CoverageError{{Code: "evidence_unavailable", Message: "surface evidence is unavailable"}}
		}
		result.Targets = append(result.Targets, target)
	}
	// Credential-helper targets are implemented in the next task and remain
	// truthfully unsupported in this intermediate collector contract.
	result.Targets = append(result.Targets,
		surfaceTargetError("surfaces.git.user-config", model.TargetUnsupported, "unsupported_target", "target is not supported"),
		surfaceTargetError("surfaces.git.xdg-config", model.TargetUnsupported, "unsupported_target", "target is not supported"),
	)
	sort.Slice(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.Slice(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
	sort.Slice(result.Targets, func(i, j int) bool { return result.Targets[i].TargetID < result.Targets[j].TargetID })
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func surfaceID(prefix, value string) string {
	digest := sha256.Sum256([]byte("ssc-init.surface.v1\x00" + prefix + "\x00" + value))
	return fmt.Sprintf("%s:sha256:%x", prefix, digest)
}

func surfaceTargetError(id string, status model.TargetStatus, code, message string) model.TargetCoverage {
	return model.TargetCoverage{TargetID: id, Status: status, Errors: []model.CoverageError{{Code: code, Message: message}}}
}
