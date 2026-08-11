package projects

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

const (
	discoveryVSCodeTargetID    = "projects.discovery.vscode"
	discoveryCursorTargetID    = "projects.discovery.cursor"
	discoveryWindsurfTargetID  = "projects.discovery.windsurf"
	discoveryJetBrainsTargetID = "projects.discovery.jetbrains"
	discoveryGitTargetID       = "projects.discovery.git-worktrees"
)

var discoveryTargetOrder = []string{
	discoveryVSCodeTargetID,
	discoveryCursorTargetID,
	discoveryWindsurfTargetID,
	discoveryJetBrainsTargetID,
	discoveryGitTargetID,
}

// Discovery contains sealed project roots and privacy-safe source coverage.
type Discovery struct {
	Roots    []Root                 `json:"roots,omitempty"`
	Coverage []model.TargetCoverage `json:"coverage,omitempty"`
}

type discoveryCandidate struct {
	path     string
	source   string
	priority int
}

type verifiedDiscoveryCandidate struct {
	path     string
	ref      string
	source   string
	priority int
	identity os.FileInfo
}

// finalizeDiscoveredRoots validates ephemeral candidates, removes duplicate
// and nested roots, then seals a deterministic bounded root set.
func finalizeDiscoveredRoots(home string, fileSystem platform.FileSystem, candidates []discoveryCandidate) (Discovery, error) {
	cleanHome := filepath.Clean(home)
	if home == "" || cleanHome != home || !filepath.IsAbs(cleanHome) || !validMetadataText(cleanHome) {
		return Discovery{}, errors.New("invalid project discovery home")
	}
	noFollow, noFollowOK := fileSystem.(platform.NoFollowFileSystem)
	rooted, rootedOK := fileSystem.(platform.RootedFileSystem)
	if fileSystem == nil || !noFollowOK || !rootedOK {
		return Discovery{}, errors.New("project discovery filesystem unavailable")
	}

	issues := make(map[string]map[string]struct{}, len(discoveryTargetOrder))
	addIssue := func(source, code string) {
		codes := issues[source]
		if codes == nil {
			codes = make(map[string]struct{})
			issues[source] = codes
		}
		codes[code] = struct{}{}
	}

	ordered := append([]discoveryCandidate(nil), candidates...)
	for index := range ordered {
		source, ok := normalizeDiscoverySource(ordered[index].source)
		if !ok {
			return Discovery{}, errors.New("invalid project discovery candidate")
		}
		ordered[index].source = source
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftRef, _ := homeRootRef(cleanHome, ordered[i].path)
		rightRef, _ := homeRootRef(cleanHome, ordered[j].path)
		if leftRef == "$HOME/Projects" || rightRef == "$HOME/Projects" {
			return leftRef == "$HOME/Projects" && rightRef != "$HOME/Projects"
		}
		if ordered[i].priority != ordered[j].priority {
			return ordered[i].priority < ordered[j].priority
		}
		if leftRef != rightRef {
			return leftRef < rightRef
		}
		return ordered[i].source < ordered[j].source
	})

	verified := make([]verifiedDiscoveryCandidate, 0, len(ordered))
	seenPaths := make(map[string]struct{}, len(ordered))
	for _, candidate := range ordered {
		ref, identity, code := validateDiscoveryCandidate(cleanHome, noFollow, rooted, candidate.path)
		if code != "" {
			addIssue(candidate.source, code)
			continue
		}
		if _, duplicate := seenPaths[candidate.path]; duplicate {
			continue
		}
		seenPaths[candidate.path] = struct{}{}
		verified = append(verified, verifiedDiscoveryCandidate{
			path: candidate.path, ref: ref, source: candidate.source,
			priority: candidate.priority, identity: identity,
		})
	}

	minimal := make([]verifiedDiscoveryCandidate, 0, len(verified))
	for index, candidate := range verified {
		nested := false
		for otherIndex, other := range verified {
			if index != otherIndex && strictPathAncestor(other.path, candidate.path) {
				nested = true
				break
			}
		}
		if !nested {
			minimal = append(minimal, candidate)
		}
	}
	sort.Slice(minimal, func(i, j int) bool { return discoveredCandidateLess(minimal[i], minimal[j]) })

	selected := make([]verifiedDiscoveryCandidate, 0, len(minimal))
	for _, candidate := range minimal {
		duplicate := false
		for _, existing := range selected {
			if os.SameFile(existing.identity, candidate.identity) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			selected = append(selected, candidate)
		}
	}
	if len(selected) > maxConfiguredRoots {
		for _, omitted := range selected[maxConfiguredRoots:] {
			addIssue(omitted.source, "root_limit")
		}
		selected = selected[:maxConfiguredRoots]
	}

	result := Discovery{Roots: make([]Root, 0, len(selected))}
	for _, candidate := range selected {
		final, err := noFollow.Lstat(candidate.path)
		if err != nil || final == nil || !os.SameFile(candidate.identity, final) {
			addIssue(candidate.source, "identity_changed")
			continue
		}
		root := Root{
			Path: candidate.path, Ref: candidate.ref, home: cleanHome,
			automatic: true, discoveryPriority: candidate.priority,
		}
		root.seal = sealRoot(root)
		result.Roots = append(result.Roots, root)
	}
	if len(result.Roots) > 0 {
		if err := validateResolvedRoots(result.Roots); err != nil {
			return Discovery{}, errors.New("invalid discovered project roots")
		}
	}
	result.Coverage = discoveryIssueCoverage(issues)
	return result, nil
}

func validateDiscoveryCandidate(home string, noFollow platform.NoFollowFileSystem, rooted platform.RootedFileSystem, path string) (string, os.FileInfo, string) {
	if path == "" || !validMetadataText(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, "outside_home"
	}
	ref, insideHome := homeRootRef(home, path)
	if !insideHome || ref == "$HOME" || excludedDiscoveryCandidate(home, path) {
		return "", nil, "outside_home"
	}
	expected, err := noFollow.Lstat(path)
	if err != nil || expected == nil {
		return "", nil, "metadata_unavailable"
	}
	if expected.Mode()&fs.ModeSymlink != 0 {
		return "", nil, "symlink_rejected"
	}
	if !expected.IsDir() {
		return "", nil, "metadata_unavailable"
	}
	root, err := rooted.OpenRoot(path)
	if err != nil {
		if errors.Is(err, platform.ErrUnsafeRootedPath) {
			return "", nil, "identity_changed"
		}
		return "", nil, "metadata_unavailable"
	}
	defer root.Close()
	opened, err := root.Lstat(".")
	if err != nil || opened == nil || !os.SameFile(expected, opened) {
		return "", nil, "identity_changed"
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", nil, "identity_changed"
	}
	openedDescriptor, statErr := directory.Stat()
	if statErr != nil || openedDescriptor == nil || !os.SameFile(expected, openedDescriptor) {
		_ = directory.Close()
		return "", nil, "identity_changed"
	}
	if localFile, ok := directory.(platform.LocalRootedFile); ok {
		if local, known := localFile.LocalFilesystem(); known && !local {
			_ = directory.Close()
			return "", nil, "outside_home"
		}
	}
	if err := directory.Close(); err != nil {
		return "", nil, "identity_changed"
	}
	return ref, expected, ""
}

func excludedDiscoveryCandidate(home, path string) bool {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		if _, excluded := excludedDirectoryNames[component]; excluded {
			return true
		}
		switch strings.ToLower(component) {
		case ".trash", "caches", "backups", "backups.backupdb":
			return true
		}
		if index == 0 {
			switch strings.ToLower(component) {
			case "downloads", "movies", "music", "pictures":
				return true
			}
			if strings.HasPrefix(component, ".") {
				return true
			}
		}
	}
	return false
}

func strictPathAncestor(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func discoveredCandidateLess(left, right verifiedDiscoveryCandidate) bool {
	if left.ref == "$HOME/Projects" || right.ref == "$HOME/Projects" {
		return left.ref == "$HOME/Projects" && right.ref != "$HOME/Projects"
	}
	if left.priority != right.priority {
		return left.priority < right.priority
	}
	return left.ref < right.ref
}

func normalizeDiscoverySource(source string) (string, bool) {
	switch source {
	case discoveryVSCodeTargetID, "code", "vscode", "Code":
		return discoveryVSCodeTargetID, true
	case discoveryCursorTargetID, "cursor", "Cursor":
		return discoveryCursorTargetID, true
	case discoveryWindsurfTargetID, "windsurf", "Windsurf":
		return discoveryWindsurfTargetID, true
	case discoveryJetBrainsTargetID, "jetbrains", "JetBrains":
		return discoveryJetBrainsTargetID, true
	case discoveryGitTargetID, "git", "Git", "git-worktrees":
		return discoveryGitTargetID, true
	default:
		return "", false
	}
}

func discoveryIssueCoverage(issues map[string]map[string]struct{}) []model.TargetCoverage {
	coverage := make([]model.TargetCoverage, 0, len(issues))
	for _, targetID := range discoveryTargetOrder {
		codes := issues[targetID]
		if len(codes) == 0 {
			continue
		}
		orderedCodes := make([]string, 0, len(codes))
		for code := range codes {
			orderedCodes = append(orderedCodes, code)
		}
		sort.Strings(orderedCodes)
		target := model.TargetCoverage{TargetID: targetID, Status: model.TargetPartial}
		for _, code := range orderedCodes {
			target.Errors = append(target.Errors, model.CoverageError{Code: code, Message: discoveryIssueMessage(code)})
		}
		coverage = append(coverage, target)
	}
	return coverage
}

func discoveryIssueMessage(code string) string {
	switch code {
	case "identity_changed":
		return "project candidate identity changed"
	case "metadata_unavailable":
		return "project candidate metadata is unavailable"
	case "outside_home":
		return "project candidate is outside the permitted home scope"
	case "root_limit":
		return "project root limit reached"
	case "symlink_rejected":
		return "symbolic link candidate was rejected"
	default:
		return "project discovery candidate was rejected"
	}
}
