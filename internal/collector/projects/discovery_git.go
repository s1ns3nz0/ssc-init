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

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const (
	gitDiscoveryMaxDepth      = 12
	gitDiscoveryMaxEntries    = 100000
	gitDiscoveryBatchSize     = 256
	gitDiscoveryMaxWorktrees  = 64
	gitDiscoveryMetadataBytes = 4 * 1024
)

// discoverGitWorktrees finds linked worktrees using Git administration
// metadata only. It never invokes Git and never persists metadata paths.
func discoverGitWorktrees(ctx context.Context, env collector.Environment, seeds []discoveryCandidate) ([]discoveryCandidate, []model.TargetCoverage, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if env.Home == "" || !filepath.IsAbs(env.Home) || filepath.Clean(env.Home) != env.Home || !validMetadataText(env.Home) {
		return nil, nil, errors.New("invalid project discovery home")
	}
	rooted, ok := env.FS.(platform.RootedFileSystem)
	if env.FS == nil || !ok {
		return nil, nil, errors.New("project discovery filesystem unavailable")
	}
	homeRoot, err := rooted.OpenRoot(env.Home)
	if err != nil {
		return nil, nil, errors.New("project discovery home unavailable")
	}
	defer homeRoot.Close()

	issues := map[string]map[string]struct{}{}
	addIssue := func(code string) {
		if code == "" {
			return
		}
		if issues[discoveryGitTargetID] == nil {
			issues[discoveryGitTargetID] = map[string]struct{}{}
		}
		issues[discoveryGitTargetID][code] = struct{}{}
	}
	var out []discoveryCandidate
	clearAndFail := func(err error) ([]discoveryCandidate, []model.TargetCoverage, error) {
		clearDiscoveryCandidates(out)
		return nil, nil, err
	}
	entryCount := 0
	seen := map[string]struct{}{}
	for _, seed := range seeds {
		if err := ctx.Err(); err != nil {
			return clearAndFail(err)
		}
		components, inside := discoveryRelativeComponents(env.Home, seed.path)
		if !inside {
			addIssue("outside_home")
			continue
		}
		seedRoot, openErr := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
		clearStrings(components)
		if openErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return clearAndFail(ctxErr)
			}
			addIssue(discoverySourceErrorCode(openErr))
			continue
		}
		if seed.identity != nil {
			opened, identityErr := seedRoot.Lstat(".")
			if identityErr != nil || opened == nil || !os.SameFile(seed.identity, opened) {
				_ = seedRoot.Close()
				addIssue("identity_changed")
				continue
			}
		}
		walkErr := walkGitMetadata(ctx, env.Home, homeRoot, seedRoot, seed.path, 0, &entryCount, addIssue, func(candidate string) {
			if _, exists := seen[candidate]; exists {
				return
			}
			seen[candidate] = struct{}{}
			out = append(out, discoveryCandidate{path: strings.Clone(candidate), source: discoveryGitTargetID, priority: 5})
		})
		_ = seedRoot.Close()
		if walkErr != nil {
			return clearAndFail(walkErr)
		}
		if entryCount >= gitDiscoveryMaxEntries {
			addIssue("root_limit")
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, discoveryIssueCoverage(issues), nil
}

func walkGitMetadata(ctx context.Context, home string, homeRoot, root platform.RootedDirectory, path string, depth int, entries *int, addIssue func(string), emit func(string)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gitInfo, gitErr := root.Lstat(".git")
	if gitErr == nil && gitInfo != nil {
		if gitInfo.Mode()&fs.ModeSymlink != 0 {
			addIssue("symlink_rejected")
			return nil
		}
		if gitInfo.IsDir() {
			discoverMainWorktree(ctx, home, homeRoot, root, path, addIssue, emit)
			return ctx.Err()
		}
		if gitInfo.Mode().IsRegular() {
			candidate, code := validateLinkedSeed(ctx, home, homeRoot, root, path)
			addIssue(code)
			if candidate != "" {
				emit(candidate)
			}
			return ctx.Err()
		}
	}
	if gitErr != nil && !errors.Is(gitErr, fs.ErrNotExist) {
		addIssue("metadata_unavailable")
	}
	if depth >= gitDiscoveryMaxDepth {
		addIssue("root_limit")
		return nil
	}
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		addIssue(discoverySourceErrorCode(err))
		return nil
	}
	defer directory.Close()
	var listed []os.DirEntry
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, readErr := directory.ReadDir(gitDiscoveryBatchSize)
		listed = append(listed, batch...)
		*entries += len(batch)
		if *entries >= gitDiscoveryMaxEntries {
			addIssue("root_limit")
			return nil
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			addIssue("metadata_unavailable")
			break
		}
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name() < listed[j].Name() })
	for _, entry := range listed {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !validDiscoveryComponent(name) {
			addIssue("identity_changed")
			continue
		}
		info, err := root.Lstat(name)
		if err != nil || info == nil {
			addIssue("metadata_unavailable")
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if !info.IsDir() || excludedDirectory(filepath.Join(path, name)) {
			continue
		}
		child, err := platform.OpenVerifiedRoot(ctx, root, name)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			addIssue(discoverySourceErrorCode(err))
			continue
		}
		err = walkGitMetadata(ctx, home, homeRoot, child, filepath.Join(path, name), depth+1, entries, addIssue, emit)
		_ = child.Close()
		if err != nil {
			return err
		}
		if *entries >= gitDiscoveryMaxEntries {
			return nil
		}
	}
	return nil
}

func discoverMainWorktree(ctx context.Context, home string, homeRoot, repoRoot platform.RootedDirectory, repoPath string, addIssue func(string), emit func(string)) {
	gitRoot, err := platform.OpenVerifiedRoot(ctx, repoRoot, ".git", "worktrees")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			addIssue(discoverySourceErrorCode(err))
		}
		return
	}
	defer gitRoot.Close()
	entries, code, readErr := readDiscoveryDirectory(ctx, gitRoot, gitDiscoveryMaxWorktrees)
	if readErr != nil {
		return
	}
	addIssue(code)
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		name := entry.Name()
		info, statErr := gitRoot.Lstat(name)
		if statErr != nil || info == nil {
			addIssue("metadata_unavailable")
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			addIssue("symlink_rejected")
			continue
		}
		if !info.IsDir() {
			continue
		}
		admin, openErr := platform.OpenVerifiedRoot(ctx, gitRoot, name)
		if openErr != nil {
			addIssue(discoverySourceErrorCode(openErr))
			continue
		}
		candidate, candidateCode := validateAdminBacklink(ctx, home, homeRoot, admin, filepath.Join(repoPath, ".git", "worktrees", name))
		_ = admin.Close()
		addIssue(candidateCode)
		if candidate != "" {
			emit(candidate)
		}
	}
}

func validateLinkedSeed(ctx context.Context, home string, homeRoot, linkedRoot platform.RootedDirectory, linkedPath string) (string, string) {
	contents, code := readGitPathFile(ctx, linkedRoot, ".git", true)
	if code != "" {
		return "", code
	}
	adminPath := strings.TrimPrefix(contents, "gitdir: ")
	if adminPath == contents || !canonicalGitAdminPath(adminPath) {
		return "", "metadata_malformed"
	}
	components, inside := discoveryRelativeComponents(home, adminPath)
	if !inside {
		return "", "outside_home"
	}
	admin, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	clearStrings(components)
	if err != nil {
		return "", discoverySourceErrorCode(err)
	}
	defer admin.Close()
	target, targetCode := readGitPathFile(ctx, admin, "gitdir", false)
	if targetCode != "" {
		return "", targetCode
	}
	if target != filepath.Join(linkedPath, ".git") {
		return "", "metadata_malformed"
	}
	currentBacklink, backlinkCode := readGitPathFile(ctx, linkedRoot, ".git", true)
	if backlinkCode != "" {
		return "", backlinkCode
	}
	currentTarget, targetCode := readGitPathFile(ctx, admin, "gitdir", false)
	if targetCode != "" {
		return "", targetCode
	}
	if currentBacklink != contents || currentTarget != target {
		return "", "identity_changed"
	}
	return linkedPath, ""
}

func validateAdminBacklink(ctx context.Context, home string, homeRoot, admin platform.RootedDirectory, adminPath string) (string, string) {
	target, code := readGitPathFile(ctx, admin, "gitdir", false)
	if code != "" {
		return "", code
	}
	if !canonicalGitPath(target) || filepath.Base(target) != ".git" {
		return "", "metadata_malformed"
	}
	linkedPath := filepath.Dir(target)
	components, inside := discoveryRelativeComponents(home, linkedPath)
	if !inside {
		return "", "outside_home"
	}
	linked, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	clearStrings(components)
	if err != nil {
		return "", discoverySourceErrorCode(err)
	}
	defer linked.Close()
	backlink, backlinkCode := readGitPathFile(ctx, linked, ".git", true)
	if backlinkCode != "" {
		return "", backlinkCode
	}
	backlink = strings.TrimPrefix(backlink, "gitdir: ")
	if !canonicalGitPath(backlink) || backlink != adminPath {
		return "", "metadata_malformed"
	}
	currentTarget, targetCode := readGitPathFile(ctx, admin, "gitdir", false)
	if targetCode != "" {
		return "", targetCode
	}
	currentBacklink, backlinkCode := readGitPathFile(ctx, linked, ".git", true)
	if backlinkCode != "" {
		return "", backlinkCode
	}
	if currentTarget != target || currentBacklink != "gitdir: "+backlink {
		return "", "identity_changed"
	}
	return linkedPath, ""
}

func readGitPathFile(ctx context.Context, root platform.RootedDirectory, name string, requirePrefix bool) (string, string) {
	metadata, code, err := readDiscoveryMetadata(ctx, root, name, gitDiscoveryMetadataBytes)
	if err != nil {
		return "", discoverySourceErrorCode(err)
	}
	if code != "" {
		return "", code
	}
	if metadata == nil {
		return "", "metadata_unavailable"
	}
	defer metadata.clearAndClose()
	if !metadata.identityMatches(root) {
		return "", "identity_changed"
	}
	value := strings.TrimSpace(string(metadata.contents))
	if !validMetadataText(value) || strings.ContainsAny(value, "\r\n\t") {
		return "", "metadata_malformed"
	}
	if requirePrefix && !strings.HasPrefix(value, "gitdir: ") {
		return "", "metadata_malformed"
	}
	return value, ""
}

func canonicalGitPath(path string) bool {
	return path != "" && validMetadataText(path) && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func canonicalGitAdminPath(path string) bool {
	if !canonicalGitPath(path) {
		return false
	}
	worktrees := filepath.Dir(path)
	gitDir := filepath.Dir(worktrees)
	return filepath.Base(path) != "." && filepath.Base(path) != ".." &&
		filepath.Base(worktrees) == "worktrees" && filepath.Base(gitDir) == ".git"
}
