package projects

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
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

const maxDiscoveredRoots = maxConfiguredRoots - 1

const (
	maxVSCodeDiscoveryChildren = 256
	maxVSCodeMetadataBytes     = 64 * 1024
	maxJetBrainsProducts       = 32
	maxJetBrainsMetadataBytes  = 256 * 1024
)

type vscodeDiscoverySource struct {
	product  string
	targetID string
	priority int
}

var vscodeDiscoverySources = []vscodeDiscoverySource{
	{product: "Code", targetID: discoveryVSCodeTargetID, priority: 1},
	{product: "Cursor", targetID: discoveryCursorTargetID, priority: 2},
	{product: "Windsurf", targetID: discoveryWindsurfTargetID, priority: 3},
}

var excludedDiscoveryMediaExtensions = map[string]struct{}{
	".avi": {}, ".flac": {}, ".gif": {}, ".heic": {}, ".jpeg": {},
	".jpg": {}, ".m4a": {}, ".m4v": {}, ".mkv": {}, ".mov": {},
	".mp3": {}, ".mp4": {}, ".png": {}, ".raw": {}, ".wav": {},
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
	identity os.FileInfo
}

type verifiedDiscoveryCandidate struct {
	path     string
	ref      string
	source   string
	priority int
	identity os.FileInfo
}

// DiscoverRoots performs the bounded automatic project discovery prepass.
// The conventional root is retained as a scope placeholder even when absent.
func DiscoverRoots(ctx context.Context, env collector.Environment) (Discovery, error) {
	if err := ctx.Err(); err != nil {
		return Discovery{}, err
	}
	conventional, err := ResolveRoots(env.Home, nil)
	if err != nil {
		return Discovery{}, err
	}
	if len(conventional) != 1 || conventional[0].Ref != "$HOME/Projects" {
		return Discovery{}, errors.New("invalid conventional project root")
	}

	ideCandidates, ideCoverage, sourcePresence, err := discoverIDERootsWithPresence(ctx, env)
	if err != nil {
		clearDiscoveryCandidates(ideCandidates)
		return Discovery{}, err
	}
	defer clearDiscoveryCandidates(ideCandidates)
	verifiedIDE, err := verifyDiscoverySeeds(ctx, env.Home, env.FS, ideCandidates)
	if err != nil {
		return Discovery{}, err
	}
	defer clearDiscoveryCandidates(verifiedIDE)
	bindVerifiedDiscoveryIdentities(ideCandidates, verifiedIDE)

	seeds := make([]discoveryCandidate, 0, len(verifiedIDE)+1)
	allCandidates := make([]discoveryCandidate, 0, len(ideCandidates)+1)
	if info, statErr := discoveryConventionalRootInfo(env.FS, conventional[0].Path); statErr == nil && info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
		seed := discoveryCandidate{path: conventional[0].Path, source: discoveryGitTargetID, priority: 0, identity: info}
		seeds = append(seeds, seed)
		allCandidates = append(allCandidates, seed)
	}
	seeds = append(seeds, verifiedIDE...)
	defer clearDiscoveryCandidates(seeds)

	gitCandidates, gitCoverage, err := discoverGitWorktrees(ctx, env, seeds)
	if err != nil {
		clearDiscoveryCandidates(gitCandidates)
		clearDiscoveryCandidates(allCandidates)
		return Discovery{}, err
	}
	defer clearDiscoveryCandidates(gitCandidates)
	if len(gitCandidates) > 0 {
		sourcePresence[discoveryGitTargetID] = true
	}
	allCandidates = append(allCandidates, ideCandidates...)
	allCandidates = append(allCandidates, gitCandidates...)
	defer clearDiscoveryCandidates(allCandidates)

	finalized, err := finalizeDiscoveredRoots(env.Home, env.FS, allCandidates)
	if err != nil {
		return Discovery{}, err
	}
	if err := ctx.Err(); err != nil {
		clearDiscoveryRoots(finalized.Roots)
		return Discovery{}, err
	}

	if len(finalized.Roots) > 0 && finalized.Roots[0].Ref == "$HOME/Projects" {
		finalized.Roots[0] = conventional[0]
	} else {
		roots := make([]Root, 0, len(finalized.Roots)+1)
		roots = append(roots, conventional[0])
		roots = append(roots, finalized.Roots...)
		finalized.Roots = roots
	}
	finalized.Coverage = mergeDiscoveryCoverage(sourcePresence, ideCoverage, gitCoverage, finalized.Coverage)
	return finalized, nil
}

func bindVerifiedDiscoveryIdentities(candidates, verified []discoveryCandidate) {
	byPath := make(map[string]os.FileInfo, len(verified))
	for _, candidate := range verified {
		byPath[candidate.path] = candidate.identity
	}
	for index := range candidates {
		candidates[index].identity = byPath[candidates[index].path]
	}
}

func verifyDiscoverySeeds(ctx context.Context, home string, fileSystem platform.FileSystem, candidates []discoveryCandidate) ([]discoveryCandidate, error) {
	noFollow, noFollowOK := fileSystem.(platform.NoFollowFileSystem)
	rooted, rootedOK := fileSystem.(platform.RootedFileSystem)
	if fileSystem == nil || !noFollowOK || !rootedOK {
		return nil, errors.New("project discovery filesystem unavailable")
	}
	homeRoot, _, homeDevice, err := openDiscoveryHome(home, noFollow, rooted)
	if err != nil {
		return nil, err
	}
	defer homeRoot.Close()
	verified := make([]discoveryCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			clearDiscoveryCandidates(verified)
			return nil, err
		}
		_, identity, code := validateDiscoveryCandidate(home, homeRoot, homeDevice, candidate.path)
		if code != "" || !recheckDiscoveryCandidate(home, homeRoot, homeDevice, candidate.path, identity) {
			continue
		}
		candidate.identity = identity
		verified = append(verified, candidate)
	}
	return verified, nil
}

func discoveryConventionalRootInfo(fileSystem platform.FileSystem, path string) (os.FileInfo, error) {
	noFollow, ok := fileSystem.(platform.NoFollowFileSystem)
	if fileSystem == nil || !ok {
		return nil, errors.New("project discovery filesystem unavailable")
	}
	return noFollow.Lstat(path)
}

func mergeDiscoveryCoverage(present map[string]bool, groups ...[]model.TargetCoverage) []model.TargetCoverage {
	issues := make(map[string]map[string]struct{}, len(discoveryTargetOrder))
	for _, group := range groups {
		for _, target := range group {
			if !isDiscoveryTargetID(target.TargetID) {
				continue
			}
			for _, issue := range target.Errors {
				if issues[target.TargetID] == nil {
					issues[target.TargetID] = make(map[string]struct{})
				}
				issues[target.TargetID][normalizeDiscoveryIssueCode(issue.Code)] = struct{}{}
			}
		}
	}
	return discoveryCatalogCoverage(present, issues)
}

func normalizeDiscoveryIssueCode(code string) string {
	switch code {
	case "identity_changed":
		return "identity_changed"
	case "metadata_malformed":
		return "metadata_malformed"
	case "metadata_oversize":
		return "metadata_oversize"
	case "metadata_unavailable":
		return "metadata_unavailable"
	case "outside_home":
		return "outside_home"
	case "root_limit":
		return "root_limit"
	case "remote_unsupported":
		return "remote_unsupported"
	case "symlink_rejected":
		return "symlink_rejected"
	default:
		return "metadata_malformed"
	}
}

func clearDiscoveryRoots(roots []Root) {
	for index := range roots {
		roots[index] = Root{}
	}
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
	homeRoot, homeIdentity, homeDevice, err := openDiscoveryHome(cleanHome, noFollow, rooted)
	if err != nil {
		return Discovery{}, err
	}
	defer homeRoot.Close()

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
		ref, identity, code := validateDiscoveryCandidate(cleanHome, homeRoot, homeDevice, candidate.path)
		if code != "" {
			addIssue(candidate.source, code)
			continue
		}
		if candidate.identity != nil && !os.SameFile(candidate.identity, identity) {
			addIssue(candidate.source, "identity_changed")
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
	selectionLimit := maxDiscoveredRoots
	if len(selected) > 0 && selected[0].ref == "$HOME/Projects" {
		selectionLimit = maxConfiguredRoots
	}
	if len(selected) > selectionLimit {
		for _, omitted := range selected[selectionLimit:] {
			addIssue(omitted.source, "root_limit")
		}
		selected = selected[:selectionLimit]
	}

	result := Discovery{Roots: make([]Root, 0, len(selected))}
	for _, candidate := range selected {
		if !recheckDiscoveryCandidate(cleanHome, homeRoot, homeDevice, candidate.path, candidate.identity) {
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
	finalHome, err := noFollow.Lstat(cleanHome)
	if err != nil || finalHome == nil || !os.SameFile(homeIdentity, finalHome) {
		return Discovery{}, errors.New("project discovery home identity changed")
	}
	if len(result.Roots) > 0 {
		if err := validateResolvedRoots(result.Roots); err != nil {
			return Discovery{}, errors.New("invalid discovered project roots")
		}
	}
	result.Coverage = discoveryIssueCoverage(issues)
	return result, nil
}

func openDiscoveryHome(home string, noFollow platform.NoFollowFileSystem, rooted platform.RootedFileSystem) (platform.RootedDirectory, os.FileInfo, uint64, error) {
	expected, err := noFollow.Lstat(home)
	if err != nil || expected == nil || expected.Mode()&fs.ModeSymlink != 0 || !expected.IsDir() {
		return nil, nil, 0, errors.New("project discovery home unavailable")
	}
	root, err := rooted.OpenRoot(home)
	if err != nil {
		return nil, nil, 0, errors.New("project discovery home unavailable")
	}
	opened, err := root.Lstat(".")
	if err != nil || opened == nil || !os.SameFile(expected, opened) {
		_ = root.Close()
		return nil, nil, 0, errors.New("project discovery home identity changed")
	}
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		_ = root.Close()
		return nil, nil, 0, errors.New("project discovery home identity changed")
	}
	descriptorInfo, statErr := directory.Stat()
	if statErr != nil || descriptorInfo == nil || !os.SameFile(expected, descriptorInfo) {
		_ = directory.Close()
		_ = root.Close()
		return nil, nil, 0, errors.New("project discovery home identity changed")
	}
	if localFile, ok := directory.(platform.LocalRootedFile); ok {
		if local, known := localFile.LocalFilesystem(); known && !local {
			_ = directory.Close()
			_ = root.Close()
			return nil, nil, 0, errors.New("project discovery home is not local")
		}
	}
	device, ok := discoveryFilesystemDevice(root, descriptorInfo)
	if closeErr := directory.Close(); closeErr != nil || !ok {
		_ = root.Close()
		return nil, nil, 0, errors.New("project discovery home device unavailable")
	}
	return root, expected, device, nil
}

func validateDiscoveryCandidate(home string, homeRoot platform.RootedDirectory, homeDevice uint64, path string) (string, os.FileInfo, string) {
	if path == "" || !validMetadataText(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, "outside_home"
	}
	ref, insideHome := homeRootRef(home, path)
	if !insideHome || ref == "$HOME" || excludedDiscoveryCandidate(home, path) {
		return "", nil, "outside_home"
	}
	components, ok := discoveryRelativeComponents(home, path)
	if !ok {
		return "", nil, "outside_home"
	}
	root, code := openAnchoredDiscoveryCandidate(homeRoot, components)
	if code != "" {
		return "", nil, code
	}
	defer root.Close()
	expected, err := root.Lstat(".")
	if err != nil || expected == nil || !expected.IsDir() {
		return "", nil, "identity_changed"
	}
	directory, err := platform.OpenVerifiedDirectory(root)
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
	device, deviceOK := discoveryFilesystemDevice(root, openedDescriptor)
	if !deviceOK || device != homeDevice {
		_ = directory.Close()
		return "", nil, "outside_home"
	}
	if err := directory.Close(); err != nil {
		return "", nil, "identity_changed"
	}
	return ref, expected, ""
}

func openAnchoredDiscoveryCandidate(homeRoot platform.RootedDirectory, components []string) (platform.RootedDirectory, string) {
	if len(components) == 0 {
		return nil, "outside_home"
	}
	current := homeRoot
	owned := false
	closeOwned := func() {
		if owned {
			_ = current.Close()
		}
	}
	for _, component := range components {
		observed, err := current.Lstat(component)
		if err != nil || observed == nil {
			closeOwned()
			return nil, "metadata_unavailable"
		}
		if observed.Mode()&fs.ModeSymlink != 0 {
			closeOwned()
			return nil, "symlink_rejected"
		}
		if !observed.IsDir() {
			closeOwned()
			return nil, "metadata_unavailable"
		}
		child, err := platform.OpenVerifiedRoot(context.Background(), current, component)
		if err != nil {
			closeOwned()
			return nil, "identity_changed"
		}
		if owned {
			_ = current.Close()
		}
		current = child
		owned = true
	}
	return current, ""
}

func recheckDiscoveryCandidate(home string, homeRoot platform.RootedDirectory, homeDevice uint64, path string, expected os.FileInfo) bool {
	components, ok := discoveryRelativeComponents(home, path)
	if !ok {
		return false
	}
	root, code := openAnchoredDiscoveryCandidate(homeRoot, components)
	if code != "" {
		return false
	}
	defer root.Close()
	current, err := root.Lstat(".")
	if err != nil || current == nil || !os.SameFile(expected, current) {
		return false
	}
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return false
	}
	descriptorInfo, statErr := directory.Stat()
	if statErr != nil || descriptorInfo == nil || !os.SameFile(expected, descriptorInfo) {
		_ = directory.Close()
		return false
	}
	if localFile, ok := directory.(platform.LocalRootedFile); ok {
		if local, known := localFile.LocalFilesystem(); known && !local {
			_ = directory.Close()
			return false
		}
	}
	device, deviceOK := discoveryFilesystemDevice(root, descriptorInfo)
	return directory.Close() == nil && deviceOK && device == homeDevice
}

func discoveryRelativeComponents(home, path string) ([]string, bool) {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, false
	}
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, false
		}
	}
	return components, true
}

type discoveryDeviceEvidence interface {
	filesystemDevice() (uint64, bool)
}

func discoveryFilesystemDevice(source any, info os.FileInfo) (uint64, bool) {
	if evidence, ok := source.(discoveryDeviceEvidence); ok {
		return evidence.filesystemDevice()
	}
	if info == nil || info.Sys() == nil {
		return 0, false
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	device := value.FieldByName("Dev")
	if !device.IsValid() {
		return 0, false
	}
	switch device.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return uint64(device.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return device.Uint(), true
	default:
		return 0, false
	}
}

func excludedDiscoveryCandidate(home, path string) bool {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		for excluded := range excludedDirectoryNames {
			if strings.EqualFold(component, excluded) {
				return true
			}
		}
		switch strings.ToLower(component) {
		case "library", ".trash", "caches", "backups", "backups.backupdb":
			return true
		}
		if _, media := excludedDiscoveryMediaExtensions[strings.ToLower(filepath.Ext(component))]; media {
			return true
		}
		if index == 0 {
			switch strings.ToLower(component) {
			case "movies", "music", "pictures":
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
	var coverage []model.TargetCoverage
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

func discoveryCatalogCoverage(present map[string]bool, issues map[string]map[string]struct{}) []model.TargetCoverage {
	coverage := make([]model.TargetCoverage, 0, len(discoveryTargetOrder))
	for _, targetID := range discoveryTargetOrder {
		codes := issues[targetID]
		status := model.TargetNotPresent
		if present[targetID] {
			status = model.TargetComplete
		}
		target := model.TargetCoverage{TargetID: targetID, Status: status}
		if len(codes) > 0 {
			target.Status = model.TargetPartial
			orderedCodes := make([]string, 0, len(codes))
			for code := range codes {
				orderedCodes = append(orderedCodes, code)
			}
			sort.Strings(orderedCodes)
			for _, code := range orderedCodes {
				target.Errors = append(target.Errors, model.CoverageError{Code: code, Message: discoveryIssueMessage(code)})
			}
		}
		coverage = append(coverage, target)
	}
	return coverage
}

func discoveryIssueMessage(code string) string {
	switch code {
	case "identity_changed":
		return "project candidate identity changed"
	case "metadata_malformed":
		return "project discovery metadata is malformed"
	case "metadata_oversize":
		return "project discovery metadata exceeds the size limit"
	case "metadata_unavailable":
		return "project candidate metadata is unavailable"
	case "outside_home":
		return "project candidate is outside the permitted home scope"
	case "root_limit":
		return "project root limit reached"
	case "remote_unsupported":
		return "remote project metadata is unsupported"
	case "symlink_rejected":
		return "symbolic link candidate was rejected"
	default:
		return "project discovery candidate was rejected"
	}
}
