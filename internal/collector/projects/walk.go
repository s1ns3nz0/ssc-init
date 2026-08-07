package projects

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	defaultMaxDepth       = 12
	defaultMaxEntries     = 100_000
	defaultMaxConfigs     = 4_096
	defaultMaxConfigBytes = int64(4 << 20)
	maxWalkErrors         = 64
	readDirBatchSize      = 256
)

type walkLimits struct {
	maxDepth       int
	maxEntries     int
	maxConfigs     int
	maxConfigBytes int64
}

func defaultWalkLimits() walkLimits {
	return walkLimits{
		maxDepth: defaultMaxDepth, maxEntries: defaultMaxEntries,
		maxConfigs: defaultMaxConfigs, maxConfigBytes: defaultMaxConfigBytes,
	}
}

func (limits walkLimits) valid() bool {
	return limits.maxDepth > 0 && limits.maxEntries > 0 && limits.maxConfigs > 0 && limits.maxConfigBytes > 0
}

type configDefinition struct {
	relativePath string
	targetID     string
	host         string
	consumers    []string
	format       string
}

var recognizedConfigs = []configDefinition{
	{relativePath: ".codex/config.toml", targetID: "mcp.codex.project", host: "codex", consumers: []string{"codex"}, format: "toml"},
	{relativePath: ".cursor/mcp.json", targetID: "mcp.cursor.project", host: "cursor", consumers: []string{"cursor"}, format: "json"},
	{relativePath: ".mcp.json", targetID: "mcp.shared.project", host: "shared", consumers: []string{"claude-code", "vscode"}, format: "json"},
	{relativePath: ".vscode/mcp.json", targetID: "mcp.vscode.project", host: "vscode", consumers: []string{"vscode"}, format: "json"},
}

type discoveredConfig struct {
	relativePath    string
	projectRelative string
	definition      configDefinition
}

type discoveredProjectEvidence struct {
	relativePath       string
	projectRelative    string
	definition         projectEvidenceDefinition
	fileFingerprint    platform.FileFingerprint
	projectFingerprint platform.FileFingerprint
}

type rootWalk struct {
	status          model.TargetStatus
	rootFingerprint platform.FileFingerprint
	configs         []discoveredConfig
	evidence        []discoveredProjectEvidence
	errors          []model.CoverageError
}

type rootWalker struct {
	ctx        context.Context
	limits     walkLimits
	beforeOpen func(string)
	entries    int
	configs    []discoveredConfig
	evidence   []discoveredProjectEvidence
	errors     []model.CoverageError
}

func walkConfiguredRoot(ctx context.Context, fileSystem platform.FileSystem, configured Root, limits walkLimits, beforeOpen func(string)) (rootWalk, error) {
	if err := ctx.Err(); err != nil {
		return rootWalk{}, err
	}
	noFollowFileSystem, hasNoFollow := fileSystem.(platform.NoFollowFileSystem)
	rootedFileSystem, hasRooted := fileSystem.(platform.RootedFileSystem)
	if !hasNoFollow || !hasRooted {
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	expected, err := noFollowFileSystem.Lstat(configured.Path)
	if err != nil {
		status := classifyRootError(err)
		if status == model.TargetNotPresent {
			return rootWalk{status: status}, nil
		}
		return rootWalk{status: status, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	if expected != nil && expected.Mode()&fs.ModeSymlink != 0 {
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("symlink_rejected", "symbolic link was not followed")}}, nil
	}
	if expected == nil || !expected.IsDir() {
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	root, err := rootedFileSystem.OpenRoot(configured.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, platform.ErrUnsafeRootedPath) {
			return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("identity_changed", "project directory identity changed")}}, nil
		}
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	defer root.Close()
	rootIdentity, err := root.Lstat(".")
	if err != nil || rootIdentity == nil || !rootIdentity.IsDir() || !os.SameFile(expected, rootIdentity) {
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("identity_changed", "project directory identity changed")}}, nil
	}
	rootFingerprint, ok := platform.Fingerprint(rootIdentity)
	if !ok {
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("identity_changed", "project directory identity changed")}}, nil
	}
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError(identityErrorCode(err), "project directory identity changed")}}, nil
	}

	walker := &rootWalker{ctx: ctx, limits: limits, beforeOpen: beforeOpen}
	stop, walkErr := walker.walkDirectory(root, directory, ".", 0)
	_ = stop
	if closeErr := directory.Close(); walkErr == nil && closeErr != nil {
		walker.addError("path_unavailable", "project directory became unavailable")
	}
	if walkErr != nil {
		return rootWalk{}, walkErr
	}
	sort.Slice(walker.configs, func(i, j int) bool { return walker.configs[i].relativePath < walker.configs[j].relativePath })
	sort.Slice(walker.evidence, func(i, j int) bool { return walker.evidence[i].relativePath < walker.evidence[j].relativePath })
	status := model.TargetComplete
	if len(walker.errors) > 0 {
		status = model.TargetPartial
	}
	return rootWalk{status: status, rootFingerprint: rootFingerprint, configs: walker.configs, evidence: walker.evidence, errors: walker.errors}, nil
}

func (walker *rootWalker) walkDirectory(root platform.RootedDirectory, directory platform.RootedFile, relative string, depth int) (bool, error) {
	if err := walker.ctx.Err(); err != nil {
		return true, err
	}
	remaining := walker.limits.maxEntries - walker.entries
	entries, overflow, err := readBoundedDirectory(directory, remaining)
	if err != nil {
		walker.addError("path_unavailable", "project directory is unavailable")
		return false, nil
	}
	if overflow {
		walker.addError("entry_limit", "project root entry limit reached")
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
		if err != nil {
			walker.addError("path_unavailable", "project entry is unavailable")
			continue
		}
		if expected == nil {
			walker.addError("path_unavailable", "project entry is unavailable")
			continue
		}
		if expected.Mode()&fs.ModeSymlink != 0 {
			walker.addError("symlink_rejected", "symbolic link was not followed")
			continue
		}
		if expected.IsDir() {
			if excludedDirectory(entryRelative) {
				continue
			}
			if depth+1 >= walker.limits.maxDepth {
				walker.addError("depth_limit", "project root depth limit reached")
				continue
			}
			if walker.beforeOpen != nil {
				walker.beforeOpen(filepath.ToSlash(entryRelative))
			}
			childRoot, childDirectory, err := openVerifiedDirectory(root, name, expected)
			if err != nil {
				walker.addError(identityErrorCode(err), "project directory identity changed")
				continue
			}
			stop, walkErr := walker.walkDirectory(childRoot, childDirectory, entryRelative, depth+1)
			_ = childDirectory.Close()
			_ = childRoot.Close()
			if walkErr != nil || stop {
				return stop, walkErr
			}
			continue
		}
		definition, projectRelative, recognized := recognizeConfig(filepath.ToSlash(entryRelative))
		evidenceDefinition, evidenceRecognized := evidenceCatalog[name]
		if !recognized && !evidenceRecognized {
			continue
		}
		if !expected.Mode().IsRegular() {
			walker.addError("path_unavailable", "project file is unavailable")
			continue
		}
		if recognized && (expected.Size() < 0 || expected.Size() > walker.limits.maxConfigBytes) {
			walker.addError("config_size_limit", "project configuration exceeds the size limit")
			continue
		}
		if len(walker.configs)+len(walker.evidence) >= walker.limits.maxConfigs {
			walker.addError("config_limit", "project configuration limit reached")
			return true, nil
		}
		var enumeratedFile, enumeratedProject platform.FileFingerprint
		if evidenceRecognized {
			var fileOK, projectOK bool
			enumeratedFile, fileOK = platform.Fingerprint(expected)
			projectInfo, projectErr := directory.Stat()
			enumeratedProject, projectOK = platform.Fingerprint(projectInfo)
			if !fileOK || projectErr != nil || projectInfo == nil || !projectInfo.IsDir() || !projectOK {
				walker.addError("identity_changed", "project evidence identity changed")
				continue
			}
		}
		if walker.beforeOpen != nil {
			walker.beforeOpen(filepath.ToSlash(entryRelative))
		}
		file, opened, err := openVerifiedFile(root, name, expected)
		if err != nil {
			if evidenceRecognized {
				walker.evidence = append(walker.evidence, discoveredProjectEvidence{
					relativePath: filepath.Clean(entryRelative), projectRelative: filepath.Clean(relative), definition: evidenceDefinition,
					fileFingerprint: enumeratedFile, projectFingerprint: enumeratedProject,
				})
				walker.addError(identityErrorCode(err), "project evidence identity changed")
				continue
			}
			walker.addError(identityErrorCode(err), "project configuration identity changed")
			continue
		}
		_ = file.Close()
		if recognized && (opened.Size() < 0 || opened.Size() > walker.limits.maxConfigBytes) {
			walker.addError("config_size_limit", "project configuration exceeds the size limit")
			continue
		}
		if recognized {
			walker.configs = append(walker.configs, discoveredConfig{
				relativePath: filepath.Clean(entryRelative), projectRelative: projectRelative, definition: definition,
			})
			continue
		}
		fileFingerprint, fileOK := platform.Fingerprint(opened)
		if !fileOK || fileFingerprint != enumeratedFile {
			walker.addError("identity_changed", "project evidence identity changed")
			continue
		}
		projectRelative = filepath.Clean(relative)
		walker.evidence = append(walker.evidence, discoveredProjectEvidence{
			relativePath: filepath.Clean(entryRelative), projectRelative: projectRelative, definition: evidenceDefinition,
			fileFingerprint: fileFingerprint, projectFingerprint: enumeratedProject,
		})
	}
	return false, nil
}

func readBoundedDirectory(directory platform.RootedFile, remaining int) ([]os.DirEntry, bool, error) {
	if remaining < 0 {
		return nil, true, nil
	}
	entries := make([]os.DirEntry, 0, min(remaining, readDirBatchSize))
	for {
		limit := min(readDirBatchSize, remaining+1-len(entries))
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

func openVerifiedDirectory(parent platform.RootedDirectory, name string, expected os.FileInfo) (platform.RootedDirectory, platform.RootedFile, error) {
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, err
	}
	directory, err := child.Open(".")
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	opened, err := directory.Stat()
	if err != nil || opened == nil || !opened.IsDir() || !os.SameFile(expected, opened) {
		_ = directory.Close()
		_ = child.Close()
		return nil, nil, errIdentityChanged
	}
	return child, directory, nil
}

func openVerifiedFile(parent platform.RootedDirectory, name string, expected os.FileInfo) (platform.RootedFile, os.FileInfo, error) {
	file, err := parent.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || opened == nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		_ = file.Close()
		return nil, nil, errIdentityChanged
	}
	return file, opened, nil
}

var errIdentityChanged = errors.New("filesystem identity changed")

func identityErrorCode(err error) string {
	if errors.Is(err, errIdentityChanged) || errors.Is(err, platform.ErrUnsafeRootedPath) {
		return "identity_changed"
	}
	return "path_unavailable"
}

func recognizeConfig(relative string) (configDefinition, string, bool) {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	for _, definition := range recognizedConfigs {
		if clean != definition.relativePath && !strings.HasSuffix(clean, "/"+definition.relativePath) {
			continue
		}
		prefix := strings.TrimSuffix(clean, definition.relativePath)
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix == "" {
			prefix = "."
		}
		return definition, filepath.FromSlash(prefix), true
	}
	return configDefinition{}, "", false
}

func (walker *rootWalker) addError(code, message string) {
	if len(walker.errors) >= maxWalkErrors {
		return
	}
	walker.errors = append(walker.errors, targetError(code, message))
}
