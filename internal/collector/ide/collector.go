// Package ide inventories extensions from fixed IDE manifest locations without
// starting an IDE or loading extension code.
package ide

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const (
	maxManifestBytes    = 4 << 20
	maxVSCodeEntries    = 10_000
	maxJetBrainsEntries = 10_000
	maxIDEErrors        = 128
	jetBrainsRootPath   = "Library/Application Support/JetBrains"
)

var errDirectoryEntryLimit = errors.New("directory entry limit reached")

type ideCollector struct {
	beforeOpen        func(targetID, relative string)
	afterManifestRead func(targetID, relative string)
}

type entryBudget struct {
	remaining int
}

func newEntryBudget(limit int) *entryBudget {
	return &entryBudget{remaining: limit}
}

func (b *entryBudget) charge(entries int) bool {
	if entries < 0 || entries > b.remaining {
		return false
	}
	b.remaining -= entries
	return true
}

func (b *entryBudget) readDirectory(ctx context.Context, root platform.RootedDirectory) ([]os.DirEntry, error) {
	entries, err := readDirectory(ctx, root, b.remaining)
	if !b.charge(len(entries)) {
		return nil, errDirectoryEntryLimit
	}
	return entries, err
}

// New returns a targeted collector restricted to the immutable local IDE
// extension catalog.
func New() collector.TargetedCollector { return &ideCollector{} }

func (*ideCollector) Name() string { return "ide" }

func (*ideCollector) Targets() []model.TargetSpec { return catalogSpecs() }

func (c *ideCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	declarations := catalogDeclarations()
	rootedFilesystem, ok := env.FS.(platform.RootedFileSystem)
	if !ok {
		c.appendUnavailableCatalog(&result, declarations)
		result.Errors = append(result.Errors, ideCoverageError("rooted_access_unavailable", "rooted IDE access is unavailable", ""))
		sortIDEResult(&result)
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}
	homeRoot, err := rootedFilesystem.OpenRoot(env.Home)
	if err != nil {
		c.appendUnavailableCatalog(&result, declarations)
		result.Errors = append(result.Errors, ideCoverageError("rooted_access_unavailable", "rooted IDE access is unavailable", ""))
		sortIDEResult(&result)
		result.Status = collector.AggregateTargetStatus(result.Targets)
		return result, nil
	}
	defer homeRoot.Close()

	for _, declaration := range declarations {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !declaration.supported {
			result.Targets = append(result.Targets, unsupportedIDETarget(declaration.spec.ID))
			continue
		}
		if declaration.expanded {
			if err := c.collectJetBrains(ctx, homeRoot, env.Home, declaration, &result); err != nil {
				return result, err
			}
			continue
		}
		if err := c.collectVSCodeTarget(ctx, homeRoot, env.Home, declaration, &result); err != nil {
			return result, err
		}
	}

	sortIDEResult(&result)
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func (*ideCollector) appendUnavailableCatalog(result *model.CollectorResult, declarations []targetDeclaration) {
	for _, declaration := range declarations {
		if !declaration.supported {
			result.Targets = append(result.Targets, unsupportedIDETarget(declaration.spec.ID))
			continue
		}
		result.Targets = append(result.Targets, ideTargetWithIssue(
			declaration.spec.ID, "", model.TargetUnavailable,
			"rooted_access_unavailable", "rooted IDE access is unavailable", "",
		))
	}
}

func (c *ideCollector) collectVSCodeTarget(ctx context.Context, homeRoot platform.RootedDirectory, home string, declaration targetDeclaration, result *model.CollectorResult) error {
	target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetComplete}
	components := splitRelativePath(declaration.relativePath)
	rootPath := filepath.Join(home, filepath.FromSlash(declaration.relativePath))
	extensionsRoot, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status, code, message := classifyIDERootError(err, "IDE extension root")
		target.Status = status
		if status != model.TargetNotPresent && code != "" {
			c.addIssue(result, &target, status, code, message, redactPath(home, rootPath))
		}
		result.Targets = append(result.Targets, target)
		return nil
	}
	defer extensionsRoot.Close()

	entries, readErr := readDirectory(ctx, extensionsRoot, maxVSCodeEntries)
	if readErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status := model.TargetPartial
		code, message := "path_unavailable", "IDE extension root is unavailable"
		if errors.Is(readErr, errDirectoryEntryLimit) {
			code, message = "entry_limit", "IDE extension entry limit reached"
		} else if len(entries) == 0 {
			status = model.TargetUnavailable
		}
		c.addIssue(result, &target, status, code, message, redactPath(home, rootPath))
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeIDEComponent(entry.Name()) {
			c.addIssue(result, &target, model.TargetPartial, "identity_rejected", "IDE installation identity was rejected", "")
			continue
		}
		entryPath := filepath.Join(rootPath, entry.Name())
		info, err := extensionsRoot.Lstat(entry.Name())
		if err != nil {
			c.addIssue(result, &target, model.TargetPartial, "path_unavailable", "IDE extension path is unavailable", redactPath(home, entryPath))
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			c.addIssue(result, &target, model.TargetPartial, "symlink_rejected", "symbolic link was not followed", redactPath(home, entryPath))
			continue
		}
		if !info.IsDir() {
			continue
		}
		c.invokeBeforeOpen(declaration.spec.ID, entry.Name())
		if err := ctx.Err(); err != nil {
			return err
		}
		extensionRoot, err := platform.OpenVerifiedRoot(ctx, extensionsRoot, entry.Name())
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			c.addIssue(result, &target, model.TargetPartial, ideIdentityIssueCode(err), "IDE extension identity changed", redactPath(home, entryPath))
			continue
		}
		opened, statErr := extensionRoot.Lstat(".")
		if statErr != nil || opened == nil || !os.SameFile(info, opened) {
			_ = extensionRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, "identity_changed", "IDE extension identity changed", redactPath(home, entryPath))
			continue
		}
		manifestRelative := filepath.ToSlash(filepath.Join(entry.Name(), declaration.manifestPath))
		manifest, code := readManifest(ctx, extensionRoot, declaration.manifestPath, func() {
			c.invokeAfterManifestRead(declaration.spec.ID, manifestRelative)
		})
		if err := ctx.Err(); err != nil {
			_ = extensionRoot.Close()
			return err
		}
		manifestPath := filepath.Join(entryPath, declaration.manifestPath)
		if code != "" {
			_ = extensionRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, code, manifestErrorMessage(code), redactPath(home, manifestPath))
			continue
		}
		parsed, err := parseVSCodeManifest(manifest.contents, declaration.spec.Host, home)
		if err != nil {
			_ = extensionRoot.Close()
			code, message := "manifest_invalid", "IDE extension manifest is invalid"
			if errors.Is(err, errRejectedIDEIdentity) {
				code, message = "identity_rejected", "IDE extension identity was rejected"
			}
			c.addIssue(result, &target, model.TargetPartial, code, message, "")
			continue
		}
		manifestAnchor, anchored := captureIDEManifestAnchor(extensionsRoot, extensionRoot, entry.Name(), manifestRelative, manifest)
		if !anchored {
			_ = extensionRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, "identity_changed", "IDE extension evidence anchor identity changed", redactPath(home, entryPath))
			continue
		}
		if !c.appendEvidence(rootPath, home, declaration, "", entryPath, manifestRelative, parsed, result, &target, manifestAnchor) {
			_ = extensionRoot.Close()
			continue
		}
		_ = extensionRoot.Close()
	}
	result.Targets = append(result.Targets, target)
	return nil
}

func (c *ideCollector) collectJetBrains(ctx context.Context, homeRoot platform.RootedDirectory, home string, declaration targetDeclaration, result *model.CollectorResult) error {
	components := splitRelativePath(jetBrainsRootPath)
	rootPath := filepath.Join(home, filepath.FromSlash(jetBrainsRootPath))
	jetBrainsRoot, err := platform.OpenVerifiedRoot(ctx, homeRoot, components...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status, code, message := classifyIDERootError(err, "JetBrains product root")
		target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: status}
		if status != model.TargetNotPresent && code != "" {
			c.addIssue(result, &target, status, code, message, redactPath(home, rootPath))
		}
		result.Targets = append(result.Targets, target)
		return nil
	}
	defer jetBrainsRoot.Close()

	budget := newEntryBudget(maxJetBrainsEntries)
	products, readErr := budget.readDirectory(ctx, jetBrainsRoot)
	var expansionTarget *model.TargetCoverage
	ensureExpansionIssue := func(status model.TargetStatus, code, message, path string) {
		if expansionTarget == nil {
			target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetComplete}
			expansionTarget = &target
		}
		c.addIssue(result, expansionTarget, status, code, message, path)
	}
	if readErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status := model.TargetPartial
		code, message := "path_unavailable", "JetBrains product root is unavailable"
		if errors.Is(readErr, errDirectoryEntryLimit) {
			code, message = "entry_limit", "JetBrains plugin entry limit reached"
		} else if len(products) == 0 {
			status = model.TargetUnavailable
		}
		ensureExpansionIssue(status, code, message, redactPath(home, rootPath))
	}
	if len(products) == 0 && expansionTarget == nil {
		result.Targets = append(result.Targets, model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetComplete})
		return nil
	}

	initialTargetCount := len(result.Targets)
	for productIndex, product := range products {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeIDEComponent(product.Name()) {
			ensureExpansionIssue(model.TargetPartial, "identity_rejected", "JetBrains product identity was rejected", "")
			continue
		}
		if budget.remaining == 0 {
			for _, remaining := range products[productIndex:] {
				if safeIDEComponent(remaining.Name()) && remaining.IsDir() {
					target := ideTargetWithIssue(declaration.spec.ID, remaining.Name(), model.TargetPartial, "entry_limit", "JetBrains plugin entry limit reached", "")
					result.Targets = append(result.Targets, target)
				}
			}
			ensureExpansionIssue(model.TargetPartial, "entry_limit", "JetBrains plugin entry limit reached", redactPath(home, rootPath))
			break
		}
		info, statErr := jetBrainsRoot.Lstat(product.Name())
		if statErr == nil && info != nil && !info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			continue
		}
		if err := c.collectJetBrainsProduct(ctx, jetBrainsRoot, home, rootPath, product.Name(), declaration, budget, result); err != nil {
			return err
		}
	}
	if expansionTarget != nil {
		result.Targets = append(result.Targets, *expansionTarget)
	} else if len(result.Targets) == initialTargetCount {
		result.Targets = append(result.Targets, model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetComplete})
	}
	return nil
}

func (c *ideCollector) collectJetBrainsProduct(ctx context.Context, jetBrainsRoot platform.RootedDirectory, home, rootPath, product string, declaration targetDeclaration, budget *entryBudget, result *model.CollectorResult) error {
	target := model.TargetCoverage{TargetID: declaration.spec.ID, InstanceRef: product, Status: model.TargetComplete}
	productPath := filepath.Join(rootPath, product)
	info, err := jetBrainsRoot.Lstat(product)
	if err != nil {
		c.addIssue(result, &target, model.TargetUnavailable, "path_unavailable", "JetBrains product is unavailable", redactPath(home, productPath))
		result.Targets = append(result.Targets, target)
		return nil
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		c.addIssue(result, &target, model.TargetPartial, "symlink_rejected", "symbolic link was not followed", redactPath(home, productPath))
		result.Targets = append(result.Targets, target)
		return nil
	}
	if !info.IsDir() {
		return nil
	}
	c.invokeBeforeOpen(declaration.spec.ID, product)
	if err := ctx.Err(); err != nil {
		return err
	}
	productRoot, err := platform.OpenVerifiedRoot(ctx, jetBrainsRoot, product)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status := model.TargetUnavailable
		if errors.Is(err, platform.ErrUnsafeRootedPath) {
			status = model.TargetPartial
		}
		c.addIssue(result, &target, status, ideIdentityIssueCode(err), "JetBrains product identity changed", redactPath(home, productPath))
		result.Targets = append(result.Targets, target)
		return nil
	}
	openedProduct, statErr := productRoot.Lstat(".")
	if statErr != nil || openedProduct == nil || !os.SameFile(info, openedProduct) {
		_ = productRoot.Close()
		c.addIssue(result, &target, model.TargetPartial, "identity_changed", "JetBrains product identity changed", redactPath(home, productPath))
		result.Targets = append(result.Targets, target)
		return nil
	}
	pluginsRoot, err := platform.OpenVerifiedRoot(ctx, productRoot, "plugins")
	_ = productRoot.Close()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			target.Status = model.TargetNotPresent
		case errors.Is(err, platform.ErrUnsafeRootedPath):
			c.addIssue(result, &target, model.TargetPartial, "symlink_rejected", "symbolic link or changed plugin root was not followed", redactPath(home, filepath.Join(productPath, "plugins")))
		default:
			c.addIssue(result, &target, model.TargetUnavailable, "path_unavailable", "JetBrains plugin root is unavailable", redactPath(home, filepath.Join(productPath, "plugins")))
		}
		result.Targets = append(result.Targets, target)
		return nil
	}
	defer pluginsRoot.Close()

	plugins, readErr := budget.readDirectory(ctx, pluginsRoot)
	if readErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		status := model.TargetPartial
		code, message := "path_unavailable", "JetBrains plugin root is unavailable"
		if errors.Is(readErr, errDirectoryEntryLimit) {
			code, message = "entry_limit", "JetBrains plugin entry limit reached"
		} else if len(plugins) == 0 {
			status = model.TargetUnavailable
		}
		c.addIssue(result, &target, status, code, message, redactPath(home, filepath.Join(productPath, "plugins")))
	}
	for _, plugin := range plugins {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !safeIDEComponent(plugin.Name()) {
			c.addIssue(result, &target, model.TargetPartial, "identity_rejected", "JetBrains plugin location was rejected", "")
			continue
		}
		pluginPath := filepath.Join(productPath, "plugins", plugin.Name())
		info, err := pluginsRoot.Lstat(plugin.Name())
		if err != nil {
			c.addIssue(result, &target, model.TargetPartial, "path_unavailable", "JetBrains plugin path is unavailable", redactPath(home, pluginPath))
			continue
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			c.addIssue(result, &target, model.TargetPartial, "symlink_rejected", "symbolic link was not followed", redactPath(home, pluginPath))
			continue
		}
		if !info.IsDir() {
			continue
		}
		c.invokeBeforeOpen(declaration.spec.ID, filepath.ToSlash(filepath.Join(product, "plugins", plugin.Name())))
		if err := ctx.Err(); err != nil {
			return err
		}
		pluginRoot, err := platform.OpenVerifiedRoot(ctx, pluginsRoot, plugin.Name())
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			c.addIssue(result, &target, model.TargetPartial, ideIdentityIssueCode(err), "JetBrains plugin identity changed", redactPath(home, pluginPath))
			continue
		}
		openedPlugin, statErr := pluginRoot.Lstat(".")
		if statErr != nil || openedPlugin == nil || !os.SameFile(info, openedPlugin) {
			_ = pluginRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, "identity_changed", "JetBrains plugin identity changed", redactPath(home, pluginPath))
			continue
		}
		metaRoot, err := platform.OpenVerifiedRoot(ctx, pluginRoot, "META-INF")
		if err != nil {
			_ = pluginRoot.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			c.addIssue(result, &target, model.TargetPartial, ideIdentityIssueCode(err), "JetBrains plugin manifest path is unavailable", redactPath(home, filepath.Join(pluginPath, "META-INF")))
			continue
		}
		manifestRelative := filepath.ToSlash(filepath.Join(plugin.Name(), "META-INF", "plugin.xml"))
		manifest, code := readManifest(ctx, metaRoot, "plugin.xml", func() {
			c.invokeAfterManifestRead(declaration.spec.ID, filepath.ToSlash(filepath.Join(product, "plugins", manifestRelative)))
		})
		_ = metaRoot.Close()
		if err := ctx.Err(); err != nil {
			_ = pluginRoot.Close()
			return err
		}
		manifestPath := filepath.Join(pluginPath, "META-INF", "plugin.xml")
		if code != "" {
			_ = pluginRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, code, manifestErrorMessage(code), redactPath(home, manifestPath))
			continue
		}
		parsed, err := parseJetBrainsManifest(manifest.contents)
		if err != nil {
			_ = pluginRoot.Close()
			code, message := "manifest_invalid", "IDE extension manifest is invalid"
			if errors.Is(err, errRejectedIDEIdentity) {
				code, message = "identity_rejected", "IDE extension identity was rejected"
			}
			c.addIssue(result, &target, model.TargetPartial, code, message, "")
			continue
		}
		manifestAnchor, anchored := captureIDEManifestAnchor(pluginsRoot, pluginRoot, plugin.Name(), manifestRelative, manifest)
		if !anchored {
			_ = pluginRoot.Close()
			c.addIssue(result, &target, model.TargetPartial, "identity_changed", "IDE extension evidence anchor identity changed", redactPath(home, pluginPath))
			continue
		}
		c.appendEvidence(filepath.Join(productPath, "plugins"), home, declaration, product, pluginPath, manifestRelative, parsed, result, &target, manifestAnchor)
		_ = pluginRoot.Close()
	}
	result.Targets = append(result.Targets, target)
	return nil
}

func (c *ideCollector) appendEvidence(rootPath, home string, declaration targetDeclaration, product, locationPath, manifestRelative string, evidence manifestEvidence, result *model.CollectorResult, target *model.TargetCoverage, manifestAnchor ideEvidenceAnchor) bool {
	metadata := make(map[string]string, len(evidence.metadata)+3)
	for key, value := range evidence.metadata {
		if value != "" {
			metadata[key] = value
		}
	}
	metadata["manifest_path"] = filepath.ToSlash(manifestRelative)
	metadata["source_target"] = declaration.spec.ID
	if product != "" {
		metadata["product_instance"] = product
	}
	locationRef := identity.SafeLocationRef(home, locationPath, "external-ide")
	if !safeIDEMetadata(metadata) || !utf8.ValidString(locationRef) || privacy.ContainsSensitiveValue(locationRef) {
		c.addIssue(result, target, model.TargetPartial, "identity_rejected", "IDE extension identity was rejected", "")
		return false
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: evidence.asset.ID, Collector: "ide", Host: declaration.spec.Host,
		Consumers: []string{declaration.spec.Host}, Scope: model.ScopeIDEProfile,
		LocationRef: locationRef, Source: declaration.spec.ID, Metadata: metadata,
	})
	if err != nil {
		c.addIssue(result, target, model.TargetPartial, "identity_rejected", "IDE extension identity was rejected", "")
		return false
	}
	result.Assets = append(result.Assets, evidence.asset)
	result.Observations = append(result.Observations, observation)
	target.Assets++
	target.Observations++
	c.issueIDEManifestTargets(rootPath, declaration, evidence, observation, result, target, manifestAnchor)
	return true
}

func (*ideCollector) addIssue(result *model.CollectorResult, target *model.TargetCoverage, status model.TargetStatus, code, message, path string) {
	if target.Status == model.TargetComplete || target.Status == model.TargetNotPresent || status == model.TargetPartial {
		target.Status = status
	}
	issue := ideCoverageError(code, message, path)
	if len(target.Errors) < maxIDEErrors {
		target.Errors = append(target.Errors, issue)
	}
	if len(result.Errors) < maxIDEErrors {
		result.Errors = append(result.Errors, issue)
	}
}

func classifyIDERootError(err error, subject string) (model.TargetStatus, string, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return model.TargetNotPresent, "", ""
	case errors.Is(err, platform.ErrUnsafeRootedPath):
		return model.TargetPartial, "symlink_rejected", "symbolic link or changed " + subject + " was not followed"
	default:
		return model.TargetUnavailable, "path_unavailable", subject + " is unavailable"
	}
}

func ideIdentityIssueCode(err error) string {
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		return "identity_changed"
	}
	return "path_unavailable"
}

func (c *ideCollector) invokeBeforeOpen(targetID, relative string) {
	if c.beforeOpen != nil {
		c.beforeOpen(targetID, filepath.ToSlash(relative))
	}
}

func (c *ideCollector) invokeAfterManifestRead(targetID, relative string) {
	if c.afterManifestRead != nil {
		c.afterManifestRead(targetID, filepath.ToSlash(relative))
	}
}

func safeIDEComponent(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > maxIdentityLength || !utf8.ValidString(value) || strings.TrimSpace(value) != value || privacy.ContainsSensitiveValue(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func safeIDEMetadata(metadata map[string]string) bool {
	for key, value := range metadata {
		if key == "" || value == "" || !utf8.ValidString(key) || !utf8.ValidString(value) || privacy.ContainsSensitiveValue(key) || sensitiveIDEMetadata(value) || filepath.IsAbs(value) {
			return false
		}
	}
	return true
}

func splitRelativePath(relative string) []string {
	return strings.Split(filepath.FromSlash(relative), string(filepath.Separator))
}

func readDirectory(ctx context.Context, root platform.RootedDirectory, limit int) ([]os.DirEntry, error) {
	directory, err := platform.OpenVerifiedDirectory(root)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	var entries []os.DirEntry
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batchSize := 128
		if limit >= 0 {
			remainingWithSentinel := limit + 1 - len(entries)
			if remainingWithSentinel < batchSize {
				batchSize = remainingWithSentinel
			}
		}
		batch, err := directory.ReadDir(batchSize)
		entries = append(entries, batch...)
		if limit >= 0 && len(entries) > limit {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries[:limit], errDirectoryEntryLimit
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			return entries, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

type ideManifestRead struct {
	contents    []byte
	digest      string
	size        int64
	mode        uint32
	fingerprint platform.FileFingerprint
}

func readManifest(ctx context.Context, root platform.RootedDirectory, name string, afterRead func()) (ideManifestRead, string) {
	if err := ctx.Err(); err != nil {
		return ideManifestRead{}, "manifest_unavailable"
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(root, name)
	if err != nil {
		return ideManifestRead{}, "manifest_unavailable"
	}
	defer file.Close()
	if beforeOpen.Size() < 0 || beforeOpen.Size() > maxManifestBytes || opened.Size() < 0 || opened.Size() > maxManifestBytes {
		return ideManifestRead{}, "manifest_oversized"
	}
	if !sameManifestSnapshot(beforeOpen, opened) {
		return ideManifestRead{}, "manifest_changed"
	}
	contents, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maxManifestBytes+1))
	if afterRead != nil {
		afterRead()
	}
	if err != nil {
		return ideManifestRead{}, "manifest_unavailable"
	}
	postRead, statErr := file.Stat()
	if statErr != nil || postRead == nil {
		return ideManifestRead{}, "manifest_unavailable"
	}
	if postRead.Size() < 0 || postRead.Size() > maxManifestBytes || len(contents) > maxManifestBytes {
		return ideManifestRead{}, "manifest_oversized"
	}
	if !sameManifestSnapshot(opened, postRead) || int64(len(contents)) != opened.Size() || int64(len(contents)) != postRead.Size() {
		return ideManifestRead{}, "manifest_changed"
	}
	fingerprint, ok := platform.Fingerprint(postRead)
	if !ok {
		return ideManifestRead{}, "manifest_changed"
	}
	digest := sha256.Sum256(contents)
	return ideManifestRead{contents: contents, digest: hex.EncodeToString(digest[:]), size: int64(len(contents)), mode: uint32(postRead.Mode().Perm()), fingerprint: fingerprint}, ""
}

func sameManifestSnapshot(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) &&
		left.Size() == right.Size() && left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func manifestErrorMessage(code string) string {
	message := "IDE extension manifest is unavailable"
	if code == "manifest_invalid" {
		message = "IDE extension manifest is invalid"
	}
	if code == "manifest_oversized" {
		message = "IDE extension manifest exceeds the size limit"
	}
	if code == "manifest_changed" {
		message = "IDE extension manifest changed while being read"
	}
	return message
}

func unsupportedIDETarget(id string) model.TargetCoverage {
	return ideTargetWithIssue(id, "", model.TargetUnsupported, "unsupported_target", "target is not supported", "")
}

func ideTargetWithIssue(id, instance string, status model.TargetStatus, code, message, path string) model.TargetCoverage {
	return model.TargetCoverage{
		TargetID: id, InstanceRef: instance, Status: status,
		Errors: []model.CoverageError{ideCoverageError(code, message, path)},
	}
}

func ideCoverageError(code, message, path string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message, Path: path}
}

func sortIDEResult(result *model.CollectorResult) {
	sort.SliceStable(result.Targets, func(i, j int) bool {
		if result.Targets[i].TargetID == result.Targets[j].TargetID {
			return result.Targets[i].InstanceRef < result.Targets[j].InstanceRef
		}
		return result.Targets[i].TargetID < result.Targets[j].TargetID
	})
	sort.SliceStable(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.SliceStable(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}

var _ collector.TargetedCollector = (*ideCollector)(nil)
var _ platform.RootedFileSystem = platform.OSFileSystem{}
