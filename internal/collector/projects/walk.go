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
	"golang.org/x/sys/unix"
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

type rootWalk struct {
	status  model.TargetStatus
	configs []discoveredConfig
	errors  []model.CoverageError
}

type rootWalker struct {
	ctx        context.Context
	limits     walkLimits
	beforeOpen func(string)
	entries    int
	configs    []discoveredConfig
	errors     []model.CoverageError
}

func walkConfiguredRoot(ctx context.Context, configured Root, limits walkLimits, beforeOpen func(string)) (rootWalk, error) {
	if err := ctx.Err(); err != nil {
		return rootWalk{}, err
	}
	expected, err := os.Lstat(configured.Path)
	if err != nil {
		status := classifyRootError(err)
		if status == model.TargetNotPresent {
			return rootWalk{status: status}, nil
		}
		return rootWalk{status: status, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	if expected.Mode()&fs.ModeSymlink != 0 {
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("symlink_rejected", "symbolic link was not followed")}}, nil
	}
	if !expected.IsDir() {
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}

	root, err := os.OpenRoot(configured.Path)
	if err != nil {
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return rootWalk{status: model.TargetUnavailable, errors: []model.CoverageError{targetError("root_unavailable", "configured project root is unavailable")}}, nil
	}
	opened, statErr := directory.Stat()
	if statErr != nil || opened == nil || !os.SameFile(expected, opened) {
		_ = directory.Close()
		return rootWalk{status: model.TargetPartial, errors: []model.CoverageError{targetError("identity_changed", "project directory identity changed")}}, nil
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
	status := model.TargetComplete
	if len(walker.errors) > 0 {
		status = model.TargetPartial
	}
	return rootWalk{status: status, configs: walker.configs, errors: walker.errors}, nil
}

func (walker *rootWalker) walkDirectory(root *os.Root, directory *os.File, relative string, depth int) (bool, error) {
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
		var expected unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), name, &expected, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			walker.addError("path_unavailable", "project entry is unavailable")
			continue
		}
		modeType := expected.Mode & unix.S_IFMT
		if modeType == unix.S_IFLNK {
			walker.addError("symlink_rejected", "symbolic link was not followed")
			continue
		}
		if modeType == unix.S_IFDIR {
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
		if !recognized {
			continue
		}
		if modeType != unix.S_IFREG {
			walker.addError("path_unavailable", "project configuration is unavailable")
			continue
		}
		if int64(expected.Size) < 0 || int64(expected.Size) > walker.limits.maxConfigBytes {
			walker.addError("config_size_limit", "project configuration exceeds the size limit")
			continue
		}
		if len(walker.configs) >= walker.limits.maxConfigs {
			walker.addError("config_limit", "project configuration limit reached")
			return true, nil
		}
		if walker.beforeOpen != nil {
			walker.beforeOpen(filepath.ToSlash(entryRelative))
		}
		file, opened, err := openVerifiedFile(root, name, expected)
		if err != nil {
			walker.addError(identityErrorCode(err), "project configuration identity changed")
			continue
		}
		_ = file.Close()
		if int64(opened.Size) < 0 || int64(opened.Size) > walker.limits.maxConfigBytes {
			walker.addError("config_size_limit", "project configuration exceeds the size limit")
			continue
		}
		walker.configs = append(walker.configs, discoveredConfig{
			relativePath: filepath.Clean(entryRelative), projectRelative: projectRelative, definition: definition,
		})
	}
	return false, nil
}

func readBoundedDirectory(directory *os.File, remaining int) ([]os.DirEntry, bool, error) {
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

func openVerifiedDirectory(parent *os.Root, name string, expected unix.Stat_t) (*os.Root, *os.File, error) {
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, err
	}
	directory, err := child.Open(".")
	if err != nil {
		_ = child.Close()
		return nil, nil, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &opened); err != nil || !sameFileIdentity(expected, opened) || opened.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = directory.Close()
		_ = child.Close()
		return nil, nil, errIdentityChanged
	}
	return child, directory, nil
}

func openVerifiedFile(parent *os.Root, name string, expected unix.Stat_t) (*os.File, unix.Stat_t, error) {
	file, err := parent.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil || !sameFileIdentity(expected, opened) || opened.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return nil, unix.Stat_t{}, errIdentityChanged
	}
	return file, opened, nil
}

var errIdentityChanged = errors.New("filesystem identity changed")

func sameFileIdentity(expected, opened unix.Stat_t) bool {
	return expected.Dev == opened.Dev && expected.Ino == opened.Ino && expected.Mode&unix.S_IFMT == opened.Mode&unix.S_IFMT
}

func identityErrorCode(err error) string {
	if errors.Is(err, errIdentityChanged) {
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
