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

var jetBrainsDiscoveryComponents = []string{"Library", "Application Support", "JetBrains"}

// discoverIDERoots reads only the fixed IDE metadata catalog below env.Home.
// Returned candidate paths are runtime-only and must pass final validation
// before they are sealed or persisted.
func discoverIDERoots(ctx context.Context, env collector.Environment) ([]discoveryCandidate, []model.TargetCoverage, error) {
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

	issues := make(map[string]map[string]struct{}, len(vscodeDiscoverySources)+1)
	addIssue := func(targetID, code string) {
		if code == "" {
			return
		}
		if issues[targetID] == nil {
			issues[targetID] = make(map[string]struct{})
		}
		issues[targetID][code] = struct{}{}
	}
	var candidates []discoveryCandidate
	clearOnError := func(err error) ([]discoveryCandidate, []model.TargetCoverage, error) {
		clearDiscoveryCandidates(candidates)
		return nil, nil, err
	}

	for _, source := range vscodeDiscoverySources {
		components := []string{"Library", "Application Support", source.product, "User", "workspaceStorage"}
		found, sourceIssues, sourceErr := discoverVSCodeSource(ctx, homeRoot, components, source)
		clearStrings(components)
		if sourceErr != nil {
			return clearOnError(sourceErr)
		}
		candidates = append(candidates, found...)
		for _, code := range sourceIssues {
			addIssue(source.targetID, code)
		}
	}
	found, sourceIssues, sourceErr := discoverJetBrainsSource(ctx, homeRoot, env.Home)
	if sourceErr != nil {
		return clearOnError(sourceErr)
	}
	candidates = append(candidates, found...)
	for _, code := range sourceIssues {
		addIssue(discoveryJetBrainsTargetID, code)
	}
	if err := ctx.Err(); err != nil {
		return clearOnError(err)
	}
	return candidates, discoveryIssueCoverage(issues), nil
}

func discoverVSCodeSource(ctx context.Context, homeRoot platform.RootedDirectory, components []string, source vscodeDiscoverySource) ([]discoveryCandidate, []string, error) {
	sourceRoot, expectedSource, code, err := openDiscoverySource(ctx, homeRoot, components)
	if err != nil || sourceRoot == nil {
		return nil, issueSlice(code), err
	}
	defer sourceRoot.Close()

	entries, readCode, err := readDiscoveryDirectory(ctx, sourceRoot, maxVSCodeDiscoveryChildren)
	if err != nil {
		return nil, nil, err
	}
	issues := issueSlice(readCode)
	var candidates []discoveryCandidate
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			clearDiscoveryCandidates(candidates)
			return nil, nil, err
		}
		name := entry.Name()
		if !validDiscoveryComponent(name) {
			issues = append(issues, "identity_changed")
			continue
		}
		expectedChild, statErr := sourceRoot.Lstat(name)
		if statErr != nil || expectedChild == nil {
			issues = append(issues, "metadata_unavailable")
			continue
		}
		if expectedChild.Mode()&fs.ModeSymlink != 0 {
			issues = append(issues, "symlink_rejected")
			continue
		}
		if !expectedChild.IsDir() {
			continue
		}
		childRoot, openErr := platform.OpenVerifiedRoot(ctx, sourceRoot, name)
		if openErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				clearDiscoveryCandidates(candidates)
				return nil, nil, ctxErr
			}
			issues = append(issues, discoverySourceErrorCode(openErr))
			continue
		}
		openedChild, childStatErr := childRoot.Lstat(".")
		if childStatErr != nil || openedChild == nil || !os.SameFile(expectedChild, openedChild) {
			_ = childRoot.Close()
			issues = append(issues, "identity_changed")
			continue
		}

		metadata, metadataCode, metadataErr := readDiscoveryMetadata(ctx, childRoot, "workspace.json", maxVSCodeMetadataBytes)
		if metadataErr != nil {
			_ = childRoot.Close()
			clearDiscoveryCandidates(candidates)
			return nil, nil, metadataErr
		}
		if metadata == nil {
			_ = childRoot.Close()
			if metadataCode != "" {
				issues = append(issues, metadataCode)
			}
			continue
		}
		path, kind, parseErr := parseVSCodeWorkspace(metadata.contents)
		childComponents := appendDiscoveryComponent(components, name)
		identityOK := metadata.identityMatches(childRoot) &&
			discoveryRootIdentityMatches(ctx, homeRoot, components, expectedSource) &&
			discoveryRootIdentityMatches(ctx, homeRoot, childComponents, expectedChild)
		clearStrings(childComponents)
		metadata.clearAndClose()
		_ = childRoot.Close()
		if !identityOK {
			path = ""
			issues = append(issues, "identity_changed")
			continue
		}
		if parseErr != nil {
			path = ""
			if errors.Is(parseErr, errRemoteUnsupported) {
				continue
			}
			issues = append(issues, "metadata_malformed")
			continue
		}
		if kind == candidateWorkspaceFile {
			path = filepath.Dir(path)
		}
		candidates = append(candidates, discoveryCandidate{path: strings.Clone(path), source: source.targetID, priority: source.priority})
		path = ""
	}
	if !discoveryRootIdentityMatches(ctx, homeRoot, components, expectedSource) {
		clearDiscoveryCandidates(candidates)
		return nil, append(issues, "identity_changed"), nil
	}
	return candidates, issues, nil
}

func discoverJetBrainsSource(ctx context.Context, homeRoot platform.RootedDirectory, home string) ([]discoveryCandidate, []string, error) {
	sourceRoot, expectedSource, code, err := openDiscoverySource(ctx, homeRoot, jetBrainsDiscoveryComponents)
	if err != nil || sourceRoot == nil {
		return nil, issueSlice(code), err
	}
	defer sourceRoot.Close()

	entries, readCode, err := readDiscoveryDirectory(ctx, sourceRoot, maxJetBrainsProducts)
	if err != nil {
		return nil, nil, err
	}
	issues := issueSlice(readCode)
	var candidates []discoveryCandidate
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			clearDiscoveryCandidates(candidates)
			return nil, nil, err
		}
		product := entry.Name()
		if !validDiscoveryComponent(product) {
			issues = append(issues, "identity_changed")
			continue
		}
		expectedProduct, statErr := sourceRoot.Lstat(product)
		if statErr != nil || expectedProduct == nil {
			issues = append(issues, "metadata_unavailable")
			continue
		}
		if expectedProduct.Mode()&fs.ModeSymlink != 0 {
			issues = append(issues, "symlink_rejected")
			continue
		}
		if !expectedProduct.IsDir() {
			continue
		}
		productRoot, openErr := platform.OpenVerifiedRoot(ctx, sourceRoot, product)
		if openErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				clearDiscoveryCandidates(candidates)
				return nil, nil, ctxErr
			}
			issues = append(issues, discoverySourceErrorCode(openErr))
			continue
		}
		openedProduct, productStatErr := productRoot.Lstat(".")
		if productStatErr != nil || openedProduct == nil || !os.SameFile(expectedProduct, openedProduct) {
			_ = productRoot.Close()
			issues = append(issues, "identity_changed")
			continue
		}
		optionsRoot, optionsErr := platform.OpenVerifiedRoot(ctx, productRoot, "options")
		if optionsErr != nil {
			_ = productRoot.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				clearDiscoveryCandidates(candidates)
				return nil, nil, ctxErr
			}
			if !errors.Is(optionsErr, fs.ErrNotExist) {
				issues = append(issues, discoverySourceErrorCode(optionsErr))
			}
			continue
		}
		expectedOptions, optionsStatErr := optionsRoot.Lstat(".")
		if optionsStatErr != nil || expectedOptions == nil {
			_ = optionsRoot.Close()
			_ = productRoot.Close()
			issues = append(issues, "identity_changed")
			continue
		}

		metadata, metadataCode, metadataErr := readDiscoveryMetadata(ctx, optionsRoot, "recentProjects.xml", maxJetBrainsMetadataBytes)
		if metadataErr != nil {
			_ = optionsRoot.Close()
			_ = productRoot.Close()
			clearDiscoveryCandidates(candidates)
			return nil, nil, metadataErr
		}
		if metadata == nil {
			_ = optionsRoot.Close()
			_ = productRoot.Close()
			if metadataCode != "" {
				issues = append(issues, metadataCode)
			}
			continue
		}
		paths, parseErr := parseJetBrainsRecent(metadata.contents)
		productComponents := appendDiscoveryComponent(jetBrainsDiscoveryComponents, product)
		optionsComponents := appendDiscoveryComponent(productComponents, "options")
		identityOK := metadata.identityMatches(optionsRoot) &&
			discoveryRootIdentityMatches(ctx, homeRoot, jetBrainsDiscoveryComponents, expectedSource) &&
			discoveryRootIdentityMatches(ctx, homeRoot, productComponents, expectedProduct) &&
			discoveryRootIdentityMatches(ctx, homeRoot, optionsComponents, expectedOptions)
		clearStrings(productComponents)
		clearStrings(optionsComponents)
		metadata.clearAndClose()
		_ = optionsRoot.Close()
		_ = productRoot.Close()
		if !identityOK {
			clearStrings(paths)
			issues = append(issues, "identity_changed")
			continue
		}
		if parseErr != nil {
			clearStrings(paths)
			issues = append(issues, "metadata_malformed")
			continue
		}
		for index := range paths {
			expanded := expandJetBrainsDiscoveryPath(home, paths[index])
			candidates = append(candidates, discoveryCandidate{path: strings.Clone(expanded), source: discoveryJetBrainsTargetID, priority: 4})
			expanded = ""
		}
		clearStrings(paths)
	}
	if !discoveryRootIdentityMatches(ctx, homeRoot, jetBrainsDiscoveryComponents, expectedSource) {
		clearDiscoveryCandidates(candidates)
		return nil, append(issues, "identity_changed"), nil
	}
	return candidates, issues, nil
}

func openDiscoverySource(ctx context.Context, homeRoot platform.RootedDirectory, components []string) (platform.RootedDirectory, os.FileInfo, string, error) {
	root, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, "", ctxErr
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, "", nil
		}
		return nil, nil, discoverySourceErrorCode(err), nil
	}
	expected, statErr := root.Lstat(".")
	if statErr != nil || expected == nil {
		_ = root.Close()
		return nil, nil, "identity_changed", nil
	}
	return root, expected, "", nil
}

func readDiscoveryDirectory(ctx context.Context, root platform.RootedDirectory, limit int) ([]os.DirEntry, string, error) {
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return nil, discoverySourceErrorCode(err), nil
	}
	defer directory.Close()
	entries := make([]os.DirEntry, 0, limit+1)
	for len(entries) <= limit {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		request := min(128, limit+1-len(entries))
		batch, readErr := directory.ReadDir(request)
		entries = append(entries, batch...)
		if len(entries) > limit {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries[:limit], "entry_limit", nil
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, "metadata_unavailable", nil
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, "", nil
}

type discoveryMetadata struct {
	file     platform.RootedFile
	expected os.FileInfo
	opened   os.FileInfo
	contents []byte
	limit    int64
	name     string
}

func readDiscoveryMetadata(ctx context.Context, root platform.RootedDirectory, name string, limit int64) (*discoveryMetadata, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	file, expected, opened, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", nil
		}
		return nil, discoverySourceErrorCode(err), nil
	}
	metadata := &discoveryMetadata{file: file, expected: expected, opened: opened, limit: limit, name: name}
	if expected.Size() < 0 || opened.Size() < 0 || expected.Size() > limit || opened.Size() > limit {
		metadata.clearAndClose()
		return nil, "metadata_oversized", nil
	}
	contents, readErr := io.ReadAll(io.LimitReader(&discoveryContextReader{ctx: ctx, reader: file}, limit+1))
	if readErr != nil {
		clearBytes(contents)
		metadata.clearAndClose()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, "metadata_unavailable", nil
	}
	if int64(len(contents)) > limit {
		clearBytes(contents)
		metadata.clearAndClose()
		return nil, "metadata_oversized", nil
	}
	metadata.contents = contents
	return metadata, "", nil
}

func (m *discoveryMetadata) identityMatches(root platform.RootedDirectory) bool {
	if m == nil || m.file == nil || m.expected == nil || m.opened == nil {
		return false
	}
	current, pathErr := root.Lstat(m.name)
	postRead, statErr := m.file.Stat()
	if pathErr != nil || statErr != nil || current == nil || postRead == nil {
		return false
	}
	return sameDiscoverySnapshot(m.expected, m.opened) &&
		sameDiscoverySnapshot(m.opened, postRead) &&
		sameDiscoverySnapshot(m.expected, current) &&
		int64(len(m.contents)) == postRead.Size()
}

func (m *discoveryMetadata) clearAndClose() {
	if m == nil {
		return
	}
	clearBytes(m.contents)
	m.contents = nil
	m.expected = nil
	m.opened = nil
	m.name = ""
	if m.file != nil {
		_ = m.file.Close()
		m.file = nil
	}
}

func sameDiscoverySnapshot(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Size() == right.Size() && left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

func discoveryRootIdentityMatches(ctx context.Context, homeRoot platform.RootedDirectory, components []string, expected os.FileInfo) bool {
	if expected == nil || ctx.Err() != nil {
		return false
	}
	root, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		return false
	}
	defer root.Close()
	current, err := root.Lstat(".")
	return err == nil && current != nil && os.SameFile(expected, current)
}

func expandJetBrainsDiscoveryPath(home, path string) string {
	const userHome = "$USER_HOME$/"
	if strings.HasPrefix(path, userHome) {
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(path, userHome)))
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(path, "~/")))
	}
	return path
}

func discoverySourceErrorCode(err error) string {
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		return "symlink_rejected"
	}
	return "metadata_unavailable"
}

func validDiscoveryComponent(component string) bool {
	return component != "" && component != "." && component != ".." &&
		filepath.Base(component) == component && !strings.ContainsRune(component, filepath.Separator) &&
		!strings.ContainsRune(component, '\x00') && validMetadataText(component)
}

func appendDiscoveryComponent(components []string, component string) []string {
	result := make([]string, len(components)+1)
	copy(result, components)
	result[len(components)] = component
	return result
}

func issueSlice(code string) []string {
	if code == "" {
		return nil
	}
	return []string{code}
}

func clearBytes(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}

func clearStrings(values []string) {
	for index := range values {
		values[index] = ""
	}
}

func clearDiscoveryCandidates(candidates []discoveryCandidate) {
	for index := range candidates {
		candidates[index].path = ""
		candidates[index].source = ""
		candidates[index].priority = 0
	}
}

type discoveryContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *discoveryContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
