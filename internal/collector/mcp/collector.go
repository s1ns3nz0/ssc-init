// Package mcp inventories MCP servers from the immutable local target catalog.
package mcp

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/privacy"
)

const maxMCPConfigBytes = maxJSONConfigBytes

const redactedValue = "[redacted]"

const maxMCPSemanticFieldBytes = 4096

type mcpCollector struct {
	projectTargets []model.LocalTarget
	projectOnly    bool
}

// New returns a catalog-targeted collector. Raw project paths are retained only
// for the lifetime of this single-use collector and are never included in model output.
func New(projectTargets ...model.LocalTarget) collector.TargetedCollector {
	return &mcpCollector{projectTargets: projectTargets}
}

// NewProjectOnly parses only the sealed project targets supplied by the
// project collector. It never opens or advertises the user MCP catalog.
func NewProjectOnly(projectTargets ...model.LocalTarget) collector.TargetedCollector {
	return &mcpCollector{projectTargets: projectTargets, projectOnly: true}
}

func (*mcpCollector) Name() string { return "mcp" }

func (c *mcpCollector) Targets() []model.TargetSpec {
	if !c.projectOnly {
		return catalogSpecs()
	}
	allowed := c.projectTargetIDs()
	result := make([]model.TargetSpec, 0, len(allowed))
	for _, spec := range catalogSpecs() {
		if allowed[spec.ID] {
			result = append(result, spec)
		}
	}
	return result
}

func (c *mcpCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	defer c.clearProjectTargets()
	if err := ctx.Err(); err != nil {
		return result, err
	}

	rootedFilesystem, hasRootedFilesystem := env.FS.(platform.RootedFileSystem)
	var homeRoot platform.RootedDirectory
	if hasRootedFilesystem && !c.projectOnly {
		var err error
		homeRoot, err = rootedFilesystem.OpenRoot(env.Home)
		if err != nil {
			homeRoot = nil
		}
	}
	if homeRoot != nil {
		defer homeRoot.Close()
	}

	projectTargets, invalidProjectTargets := c.validatedProjectTargets(env.Home)
	allowedProjectTargets := c.projectTargetIDs()
	declarations := catalogDeclarations()
	for phase := 0; phase < 2; phase++ {
		for _, declaration := range declarations {
			if c.projectOnly && !allowedProjectTargets[declaration.spec.ID] {
				continue
			}
			isExpandableProject := declaration.spec.Scope == model.ScopeProject && declaration.relativePath != ""
			if isExpandableProject != (phase == 1) {
				continue
			}
			if err := ctx.Err(); err != nil {
				return result, err
			}
			switch declaration.spec.Scope {
			case model.ScopeProject:
				if declaration.relativePath == "" {
					result.Targets = append(result.Targets, unsupportedTarget(declaration.spec.ID))
					continue
				}
				instances := projectTargets[declaration.spec.ID]
				if len(instances) == 0 {
					target := model.TargetCoverage{TargetID: declaration.spec.ID, Status: model.TargetNotPresent}
					if invalidProjectTargets[declaration.spec.ID] {
						target.Status = model.TargetPartial
						target.Errors = []model.CoverageError{coverageError("invalid_local_target", "project target was rejected", "")}
					}
					result.Targets = append(result.Targets, target)
					continue
				}
				for _, instanceIndex := range instances {
					if err := c.collectProjectTarget(ctx, &result, env, rootedFilesystem, hasRootedFilesystem, declaration, &c.projectTargets[instanceIndex]); err != nil {
						return result, err
					}
				}
			case model.ScopeUser:
				if declaration.relativePath == "" || !declaration.supported {
					result.Targets = append(result.Targets, unsupportedTarget(declaration.spec.ID))
					continue
				}
				if !hasRootedFilesystem || homeRoot == nil {
					result.Targets = append(result.Targets, unavailableTarget(declaration.spec.ID, "rooted_access_unavailable", "rooted MCP access is unavailable"))
					continue
				}
				if err := c.collectUserTarget(ctx, &result, env.Home, homeRoot, declaration); err != nil {
					return result, err
				}
			default:
				result.Targets = append(result.Targets, unsupportedTarget(declaration.spec.ID))
			}
		}
	}

	sortResult(&result)
	result.Status = collector.AggregateTargetStatus(result.Targets)
	return result, nil
}

func (c *mcpCollector) projectTargetIDs() map[string]bool {
	result := make(map[string]bool, len(c.projectTargets))
	for _, target := range c.projectTargets {
		if target.TargetID != "" {
			result[target.TargetID] = true
		}
	}
	return result
}

func (c *mcpCollector) clearProjectTargets() {
	clearLocalTargets(c.projectTargets)
	c.projectTargets = nil
}

func clearLocalTargets(targets []model.LocalTarget) {
	for index := range targets {
		clear(targets[index].Consumers)
		targets[index] = model.LocalTarget{}
	}
}

func (c *mcpCollector) collectUserTarget(ctx context.Context, result *model.CollectorResult, home string, homeRoot platform.RootedDirectory, declaration targetDeclaration) error {
	locationRef := "$HOME/" + filepath.ToSlash(declaration.relativePath)
	read := readUserConfig(ctx, homeRoot, declaration)
	if err := ctx.Err(); err != nil {
		return err
	}
	collectReadEvidence(result, home, locationRef, declaration, read)
	return nil
}

func (c *mcpCollector) collectProjectTarget(ctx context.Context, result *model.CollectorResult, env collector.Environment, rootedFilesystem platform.RootedFileSystem, hasRootedFilesystem bool, declaration targetDeclaration, instance *model.LocalTarget) error {
	if !declaration.supported {
		target := unsupportedTarget(declaration.spec.ID)
		target.InstanceRef = instance.InstanceRef
		result.Targets = append(result.Targets, target)
		return nil
	}
	if !hasRootedFilesystem {
		target := unavailableTarget(declaration.spec.ID, "rooted_access_unavailable", "rooted MCP access is unavailable")
		target.InstanceRef = instance.InstanceRef
		result.Targets = append(result.Targets, target)
		return nil
	}
	read := readProjectConfig(ctx, rootedFilesystem, instance.Path)
	if err := ctx.Err(); err != nil {
		return err
	}
	collectReadEvidence(result, env.Home, instance.InstanceRef, declaration, read)
	return nil
}

func collectReadEvidence(result *model.CollectorResult, home, locationRef string, declaration targetDeclaration, read configRead) {
	target := model.TargetCoverage{
		TargetID: declaration.spec.ID, InstanceRef: projectInstanceRef(declaration, locationRef), Status: read.status,
	}
	if read.issue != nil {
		issue := *read.issue
		issue.Path = locationRef
		target.Errors = append(target.Errors, issue)
	}
	if read.status != model.TargetComplete {
		result.Targets = append(result.Targets, target)
		return
	}

	parsed, err := parseConfig(read.contents, declaration)
	if err != nil {
		target.Status = model.TargetPartial
		target.Errors = append(target.Errors, coverageError("config_invalid", "MCP configuration is invalid", locationRef))
		result.Targets = append(result.Targets, target)
		return
	}
	for _, issue := range parsed.Issues {
		target.Status = model.TargetPartial
		target.Errors = append(target.Errors, serverIssue(issue, locationRef))
	}
	for _, server := range parsed.Servers {
		asset, observation, evidenceErr := buildServerEvidence(home, locationRef, declaration, server)
		if evidenceErr != nil {
			target.Status = model.TargetPartial
			issue := rejectedEvidenceError(evidenceErr)
			issue.Path = locationRef
			target.Errors = append(target.Errors, issue)
			continue
		}
		result.Assets = append(result.Assets, asset)
		result.Observations = append(result.Observations, observation)
		target.Assets++
		target.Observations++
		if !issueMCPSemanticEvidence(result, declaration, observation) {
			target.Status = model.TargetPartial
			target.Errors = append(target.Errors, coverageError("identity_changed", "MCP evidence issuer is unavailable", ""))
		}
	}
	result.Targets = append(result.Targets, target)
}

func parseConfig(contents []byte, declaration targetDeclaration) (ParseResult, error) {
	switch declaration.spec.Format {
	case "json":
		return parseJSONContainer(contents, declaration.container)
	case "toml":
		return ParseTOML(contents)
	default:
		return ParseResult{}, errInvalidConfig
	}
}

func projectInstanceRef(declaration targetDeclaration, locationRef string) string {
	if declaration.spec.Scope == model.ScopeProject {
		return locationRef
	}
	return ""
}

func (c *mcpCollector) validatedProjectTargets(home string) (map[string][]int, map[string]bool) {
	valid := make(map[string][]int)
	invalid := make(map[string]bool)
	seen := make(map[string]struct{})
	for index := range c.projectTargets {
		target := &c.projectTargets[index]
		declaration, known := declarationByID(target.TargetID)
		if !known || declaration.spec.Scope != model.ScopeProject {
			continue
		}
		if !validProjectTarget(home, target, declaration) {
			invalid[target.TargetID] = true
			continue
		}
		key := target.TargetID + "\x00" + target.InstanceRef
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		valid[target.TargetID] = append(valid[target.TargetID], index)
	}
	for id := range valid {
		sort.Slice(valid[id], func(i, j int) bool {
			return c.projectTargets[valid[id][i]].InstanceRef < c.projectTargets[valid[id][j]].InstanceRef
		})
	}
	return valid, invalid
}

func validProjectTarget(home string, target *model.LocalTarget, declaration targetDeclaration) bool {
	if !projects.ValidIssuedLocalTarget(home, target) {
		return false
	}
	if target.TargetID != declaration.spec.ID || target.Format != declaration.spec.Format || target.Host != declaration.spec.Host || !slices.Equal(target.Consumers, declaration.consumers) {
		return false
	}
	if home == "" || !filepath.IsAbs(home) || target.Path == "" || !filepath.IsAbs(target.Path) || filepath.Clean(target.Path) != target.Path || target.InstanceRef == "" {
		return false
	}
	slashPath := filepath.ToSlash(target.Path)
	if !strings.HasSuffix(slashPath, "/"+declaration.relativePath) {
		return false
	}
	if strings.HasPrefix(target.InstanceRef, "$HOME/") {
		return identity.SafeLocationRef(home, target.Path, "external-root") == target.InstanceRef
	}
	label, digest, found := strings.Cut(target.InstanceRef, "/path-sha256:")
	if !found || len(digest) != 64 || !validExternalRootLabel(label) {
		return false
	}
	for _, character := range digest {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return identity.SafeLocationRef(home, target.Path, label) == target.InstanceRef
}

// ValidProjectTarget reports whether a memory-only project handoff exactly
// matches the immutable catalog and its persistence-safe instance identity.
// It never returns or formats the raw path.
func ValidProjectTarget(home string, target *model.LocalTarget) bool {
	if target == nil {
		return false
	}
	declaration, known := declarationByID(target.TargetID)
	return known && declaration.spec.Scope == model.ScopeProject && declaration.relativePath != "" && validProjectTarget(home, target, declaration)
}

func validExternalRootLabel(value string) bool {
	if !strings.HasPrefix(value, "external-root-") {
		return false
	}
	number := strings.TrimPrefix(value, "external-root-")
	if number == "" || number[0] == '0' {
		return false
	}
	for _, character := range number {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

type configRead struct {
	contents []byte
	status   model.TargetStatus
	issue    *model.CoverageError
}

func readUserConfig(ctx context.Context, root platform.RootedDirectory, declaration targetDeclaration) configRead {
	components := strings.Split(filepath.FromSlash(declaration.relativePath), string(filepath.Separator))
	parent := root
	ownedParent := false
	if len(components) > 1 {
		var err error
		parent, err = platform.OpenVerifiedRoot(ctx, root, components[:len(components)-1]...)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return configRead{status: model.TargetNotPresent}
			}
			return readAccessFailure(err)
		}
		ownedParent = true
	}
	if ownedParent {
		defer parent.Close()
	}
	return readConfigFile(ctx, parent, components[len(components)-1])
}

func readProjectConfig(ctx context.Context, rootedFilesystem platform.RootedFileSystem, path string) configRead {
	parent, err := rootedFilesystem.OpenRoot(filepath.Dir(path))
	if err != nil {
		return configRead{status: model.TargetPartial, issue: errorPointer(coverageError("config_unavailable", "MCP configuration is unavailable", ""))}
	}
	defer parent.Close()
	read := readConfigFile(ctx, parent, filepath.Base(path))
	if read.status == model.TargetNotPresent || read.status == model.TargetUnavailable {
		read.status = model.TargetPartial
		read.issue = errorPointer(coverageError("config_unavailable", "MCP configuration is unavailable", ""))
	}
	return read
}

func readConfigFile(ctx context.Context, parent platform.RootedDirectory, name string) configRead {
	if err := ctx.Err(); err != nil {
		return configRead{}
	}
	file, beforeOpen, opened, err := platform.OpenVerifiedFile(parent, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return configRead{status: model.TargetNotPresent}
		}
		return readAccessFailure(err)
	}
	defer file.Close()
	if beforeOpen.Size() < 0 || beforeOpen.Size() > maxMCPConfigBytes || opened.Size() < 0 || opened.Size() > maxMCPConfigBytes {
		return configRead{status: model.TargetPartial, issue: errorPointer(coverageError("config_oversized", "MCP configuration exceeds the size limit", ""))}
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxMCPConfigBytes+1))
	if err != nil {
		return configRead{status: model.TargetUnavailable, issue: errorPointer(coverageError("config_unavailable", "MCP configuration is unavailable", ""))}
	}
	if len(contents) > maxMCPConfigBytes {
		return configRead{status: model.TargetPartial, issue: errorPointer(coverageError("config_oversized", "MCP configuration exceeds the size limit", ""))}
	}
	return configRead{contents: contents, status: model.TargetComplete}
}

func readAccessFailure(err error) configRead {
	status := model.TargetUnavailable
	if errors.Is(err, platform.ErrUnsafeRootedPath) {
		status = model.TargetPartial
	}
	return configRead{status: status, issue: errorPointer(coverageError("config_unavailable", "MCP configuration is unavailable", ""))}
}

func unsupportedTarget(id string) model.TargetCoverage {
	return model.TargetCoverage{
		TargetID: id, Status: model.TargetUnsupported,
		Errors: []model.CoverageError{coverageError("unsupported_target", "target is not supported", "")},
	}
}

func unavailableTarget(id, code, message string) model.TargetCoverage {
	return model.TargetCoverage{
		TargetID: id, Status: model.TargetUnavailable,
		Errors: []model.CoverageError{coverageError(code, message, "")},
	}
}

func coverageError(code, message, path string) model.CoverageError {
	return model.CoverageError{Code: code, Message: message, Path: path}
}

func errorPointer(value model.CoverageError) *model.CoverageError { return &value }

func sortResult(result *model.CollectorResult) {
	sort.SliceStable(result.Targets, func(i, j int) bool {
		if result.Targets[i].TargetID == result.Targets[j].TargetID {
			return result.Targets[i].InstanceRef < result.Targets[j].InstanceRef
		}
		return result.Targets[i].TargetID < result.Targets[j].TargetID
	})
	sort.SliceStable(result.Assets, func(i, j int) bool { return result.Assets[i].ID < result.Assets[j].ID })
	sort.SliceStable(result.Observations, func(i, j int) bool { return result.Observations[i].ID < result.Observations[j].ID })
	sort.SliceStable(result.LocalEvidenceTargets, func(i, j int) bool {
		if result.LocalEvidenceTargets[i].TargetID != result.LocalEvidenceTargets[j].TargetID {
			return result.LocalEvidenceTargets[i].TargetID < result.LocalEvidenceTargets[j].TargetID
		}
		return result.LocalEvidenceTargets[i].ObservationID < result.LocalEvidenceTargets[j].ObservationID
	})
}

func buildServerEvidence(home, locationRef string, declaration targetDeclaration, server ServerConfig) (model.Asset, model.Observation, error) {
	if invalidServerName(server.Name) || privacy.ContainsSensitiveValue(server.Name) {
		return model.Asset{}, model.Observation{}, identity.ErrRejectedIdentity
	}
	if !validServerSemanticLists(server) {
		return model.Asset{}, model.Observation{}, errors.New("unsafe MCP metadata")
	}
	asset := model.Asset{
		ID:   "mcp:" + declaration.spec.Host + ":" + server.Name,
		Type: model.AssetMCP, Name: server.Name, Source: declaration.spec.Host,
	}
	metadata, metadataOK := observationMetadata(home, declaration.spec.ID, server)
	if !metadataOK || !safeMetadata(metadata) {
		return model.Asset{}, model.Observation{}, errors.New("unsafe MCP metadata")
	}
	observation, err := identity.FinalizeObservation(model.Observation{
		AssetID: asset.ID, Collector: "mcp", Host: declaration.spec.Host,
		Consumers: append([]string(nil), declaration.consumers...), Scope: declaration.spec.Scope,
		LocationRef: locationRef, Source: declaration.spec.ID, Metadata: metadata,
	})
	if err != nil {
		return model.Asset{}, model.Observation{}, err
	}
	return asset, observation, nil
}

func invalidServerName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, `/\\:`) {
		return true
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func observationMetadata(home, sourceTarget string, server ServerConfig) (map[string]string, bool) {
	args, argsOK := sanitizeArgs(home, server.Args)
	if !argsOK {
		return nil, false
	}
	metadata := map[string]string{
		"transport":     server.Transport,
		"source_target": sourceTarget,
	}
	putMetadata(metadata, "command", sanitizeCommand(home, server.Command))
	putMetadata(metadata, "args", strings.Join(args, "\x1f"))
	putMetadata(metadata, "url_shape", sanitizeURLShape(server.URL))
	putMetadata(metadata, "cwd_ref", sanitizeCWD(home, server.CWD))
	if server.Enabled != nil {
		metadata["enabled"] = strconv.FormatBool(*server.Enabled)
	}
	putMetadata(metadata, "env_keys", strings.Join(server.EnvKeys, ","))
	putMetadata(metadata, "header_keys", strings.Join(server.HeaderKeys, ","))
	putMetadata(metadata, "enabled_tools", strings.Join(server.EnabledTools, ","))
	putMetadata(metadata, "disabled_tools", strings.Join(server.DisabledTools, ","))
	putMetadata(metadata, "unknown_fields", strings.Join(server.UnknownFields, ","))
	return metadata, true
}

func putMetadata(metadata map[string]string, key, value string) {
	if value != "" {
		metadata[key] = value
	}
}

func safeMetadata(metadata map[string]string) bool {
	for key, value := range metadata {
		if key == "" || value == "" || privacy.ContainsSensitiveValue(key) || containsSensitiveMetadataValue(key, value) || containsRawAbsolutePath(value) {
			return false
		}
	}
	return true
}

func containsSensitiveMetadataValue(key, value string) bool {
	if key != "args" {
		return privacy.ContainsSensitiveValue(value)
	}
	for _, item := range strings.Split(value, "\x1f") {
		if privacy.ContainsSensitiveValue(item) {
			return true
		}
	}
	return false
}

func validServerSemanticLists(server ServerConfig) bool {
	return validServerSemanticList(server.EnvKeys, validMCPEnvKey) &&
		validServerSemanticList(server.HeaderKeys, validMCPHeaderKey) &&
		validServerSemanticList(server.EnabledTools, validMCPToolName) &&
		validServerSemanticList(server.DisabledTools, validMCPToolName)
}

func validServerSemanticList(values []string, validItem func(string) bool) bool {
	total := 0
	previous := ""
	for _, value := range values {
		if !validItem(value) || (previous != "" && value <= previous) {
			return false
		}
		total += len(value)
		previous = value
	}
	if len(values) > 1 {
		total += len(values) - 1
	}
	return total <= maxMCPSemanticFieldBytes
}

func validMCPEnvKey(value string) bool {
	if value == "" || !(value[0] == '_' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !(character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validMCPHeaderKey(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func validMCPToolName(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func sanitizeCommand(home, command string) string {
	if command == "" {
		return ""
	}
	if privacy.IsRedactedPlaceholder(command) {
		return redactedValue
	}
	fields := strings.Fields(command)
	for _, field := range fields {
		key := field
		if before, _, found := strings.Cut(field, "="); found {
			key = before
		}
		if credentialFlag(key) || sensitiveName(key) {
			return redactedValue
		}
		if _, _, sensitive := combinedCredentialFlag(field); sensitive {
			return redactedValue
		}
		if _, sensitive := sensitiveTextPrefix(field); sensitive {
			return redactedValue
		}
	}
	if absoluteURL(command) {
		return sanitizeURLShape(command)
	}
	if filepath.IsAbs(command) {
		return identity.SafeLocationRef(home, command, "external-command")
	}
	if privacy.ContainsSensitiveValue(command) || containsRawAbsolutePath(command) {
		return redactedValue
	}
	return redactHomeText(home, command)
}

func containsRawAbsolutePath(value string) bool {
	for index, character := range value {
		if character != '/' {
			continue
		}
		if mcpURLSchemeSlashes(value, index) {
			continue
		}
		if mcpHTTPAuthorityRootSlash(value, index) {
			continue
		}
		if index == 0 {
			return true
		}
		previous, _ := utf8.DecodeLastRuneInString(value[:index])
		if !(unicode.IsLetter(previous) || unicode.IsDigit(previous) || strings.ContainsRune("-._~", previous)) {
			return true
		}
	}
	return false
}

func mcpURLSchemeSlashes(value string, slash int) bool {
	for _, scheme := range []string{"http:", "https:"} {
		start := slash - len(scheme)
		if start >= 0 && value[start:slash] == scheme && (start == 0 || !mcpPathSafeByte(value[start-1])) && slash+1 < len(value) && value[slash+1] == '/' {
			return true
		}
		start = slash - len(scheme) - 1
		if start >= 0 && value[start:slash+1] == scheme+"//" && (start == 0 || !mcpPathSafeByte(value[start-1])) {
			return true
		}
	}
	return false
}

func mcpHTTPAuthorityRootSlash(value string, slash int) bool {
	prefix := value[:slash]
	for _, scheme := range []string{"http://", "https://"} {
		start := strings.LastIndex(prefix, scheme)
		if start < 0 || start > 0 && mcpPathSafeByte(value[start-1]) {
			continue
		}
		parsed, err := url.Parse(prefix[start:])
		if err == nil && parsed.Scheme+"://" == scheme && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
			return true
		}
	}
	return false
}

func mcpPathSafeByte(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", rune(character))
}

func sanitizeArgs(home string, args []string) ([]string, bool) {
	result := make([]string, len(args))
	redactNext := false
	for index, arg := range args {
		if redactNext {
			if credentialShapedArgument(arg) {
				return nil, false
			}
			result[index] = redactedValue
			redactNext = false
			continue
		}
		if privacy.IsRedactedPlaceholder(arg) {
			result[index] = redactedValue
			continue
		}
		if prefix, ok := sensitiveTextPrefix(arg); ok {
			result[index] = prefix + redactedValue
			if standaloneSensitiveTextFlag(arg) {
				redactNext = true
			}
			continue
		}
		if prefix, consumeNext, ok := combinedCredentialFlag(arg); ok {
			result[index] = prefix + redactedValue
			redactNext = consumeNext
			continue
		}
		if credentialFlag(arg) {
			result[index] = arg
			redactNext = true
			continue
		}
		if key, value, found := strings.Cut(arg, "="); found {
			switch {
			case sensitiveName(key):
				result[index] = key + "=" + redactedValue
			case absoluteURL(value):
				result[index] = key + "=" + sanitizeURLShape(value)
			case filepath.IsAbs(value):
				result[index] = redactedValue
			case privacy.ContainsSensitiveValue(value):
				result[index] = key + "=" + redactedValue
			case containsRawAbsolutePath(arg):
				result[index] = redactedValue
			default:
				result[index] = redactHomeText(home, arg)
			}
			continue
		}
		switch {
		case absoluteURL(arg):
			result[index] = sanitizeURLShape(arg)
		case filepath.IsAbs(arg):
			result[index] = identity.SafeLocationRef(home, arg, "external-arg")
		case privacy.ContainsSensitiveValue(arg), containsRawAbsolutePath(arg):
			result[index] = redactedValue
		default:
			result[index] = redactHomeText(home, arg)
		}
	}
	if redactNext {
		return nil, false
	}
	return result, true
}

func credentialShapedArgument(value string) bool {
	if _, _, sensitive := combinedCredentialFlag(value); sensitive {
		return true
	}
	if credentialFlag(value) {
		return true
	}
	if _, sensitive := sensitiveTextPrefix(value); sensitive {
		return true
	}
	trimmed := strings.TrimSpace(value)
	return strings.EqualFold(trimmed, "bearer") || strings.EqualFold(trimmed, "authorization") || strings.EqualFold(trimmed, "proxy-authorization")
}

func sanitizeURLShape(raw string) string {
	if raw == "" {
		return ""
	}
	if privacy.IsRedactedPlaceholder(raw) {
		return redactedValue
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || !safeMCPURLPath(parsed) {
		return redactedValue
	}
	parsed.User = nil
	shape := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return redactedValue
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		if !safeMCPURLQueryKey(key) {
			return redactedValue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		shape += "?query_keys=" + strings.Join(keys, ",")
	}
	if len(shape) > maxMCPSemanticFieldBytes {
		return redactedValue
	}
	return shape
}

func safeMCPURLPath(parsed *url.URL) bool {
	escaped := parsed.EscapedPath()
	lowerEscaped := strings.ToLower(escaped)
	if strings.Contains(lowerEscaped, "%2f") || strings.Contains(lowerEscaped, "%5c") {
		return false
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil || containsMCPValidPercentEscape(decoded) || len(decoded) > maxMCPSemanticFieldBytes || !utf8.ValidString(decoded) || strings.ContainsRune(decoded, '\\') || privacy.ContainsSensitiveValue(decoded) {
		return false
	}
	for _, character := range decoded {
		if unicode.IsControl(character) {
			return false
		}
	}
	segments := strings.Split(decoded, "/")
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if separator := strings.IndexAny(segment, "=:"); separator > 0 && sensitiveName(segment[:separator]) {
			return false
		}
	}
	return true
}

func containsMCPValidPercentEscape(value string) bool {
	for index := 0; index+2 < len(value); index++ {
		if value[index] == '%' && isMCPASCIIHex(value[index+1]) && isMCPASCIIHex(value[index+2]) {
			return true
		}
	}
	return false
}

func isMCPASCIIHex(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F'
}

func safeMCPURLQueryKey(value string) bool {
	if value == "" || len(value) > maxMCPSemanticFieldBytes || !utf8.ValidString(value) || privacy.ContainsSensitiveValue(value) {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-' || character == '.') {
			return false
		}
	}
	return true
}

func sanitizeCWD(home, cwd string) string {
	if cwd == "" {
		return ""
	}
	if privacy.IsRedactedPlaceholder(cwd) {
		return redactedValue
	}
	if filepath.IsAbs(cwd) {
		return identity.SafeLocationRef(home, cwd, "external-cwd")
	}
	redacted := redactHomeText(home, cwd)
	if redacted == "$HOME" {
		return redacted
	}
	if strings.HasPrefix(redacted, "$HOME/") {
		if !safeMCPRelativeRef(strings.TrimPrefix(redacted, "$HOME/")) {
			return redactedValue
		}
		return filepath.ToSlash(redacted)
	}
	if !safeMCPRelativeRef(cwd) {
		return redactedValue
	}
	return "config-relative/" + filepath.ToSlash(cwd)
}

func safeMCPRelativeRef(value string) bool {
	if value == "" || len(value) > maxMCPSemanticFieldBytes || !utf8.ValidString(value) || strings.ContainsRune(value, '\\') || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func absoluteURL(value string) bool {
	if !strings.Contains(value, "://") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != ""
}

func credentialFlag(value string) bool {
	return value == "-H" || value == "-e" || sensitiveLongFlag(value)
}

func combinedCredentialFlag(value string) (prefix string, consumeNext, sensitive bool) {
	lower := strings.ToLower(value)
	if (strings.HasPrefix(value, "-H") || strings.HasPrefix(value, "-e")) && len(value) > 2 {
		prefix = value[:2]
		if value[2] == ':' || value[2] == '=' {
			prefix += value[2:3]
			return prefix, len(value) == 3, true
		}
		if privacy.IsRedactedPlaceholder(value[2:]) || mcpLongFlagCharacter(value[2]) {
			return prefix, false, true
		}
		return "", false, true
	}
	if prefix, attached := attachedSensitiveLongFlag(value); attached {
		return prefix, prefix != "" && len(prefix) == len(value), true
	}
	if separator := strings.IndexAny(value, "=:"); separator > 2 {
		key := value[:separator]
		if sensitiveLongFlag(key) || sensitiveName(key) {
			return value[:separator+1], separator+1 == len(value), true
		}
	}
	for _, flag := range []string{"--api-key", "--apikey", "--token"} {
		if strings.HasPrefix(lower, flag) && len(value) > len(flag) {
			if flag == "--token" && strings.HasPrefix(lower[len(flag):], "izer") {
				return "", false, false
			}
			return value[:len(flag)], false, true
		}
	}
	return "", false, false
}

func sensitiveLongFlag(value string) bool {
	if !validMCPLongFlag(value) {
		return false
	}
	name := strings.TrimPrefix(value, "--")
	for _, exact := range []string{"header", "headers", "env", "bearer", "signature"} {
		if strings.EqualFold(name, exact) {
			return true
		}
	}
	return hasSensitiveComponent(name)
}

func attachedSensitiveLongFlag(value string) (canonicalPrefix string, attached bool) {
	if !strings.HasPrefix(value, "--") {
		return "", false
	}
	end := 2
	for end < len(value) && mcpLongFlagCharacter(value[end]) {
		end++
	}
	if end == len(value) || end == 2 || !sensitiveLongFlag(value[:end]) {
		return "", false
	}
	if value[end] == ':' || value[end] == '=' {
		return value[:end+1], true
	}
	return "", true
}

func validMCPLongFlag(value string) bool {
	if len(value) <= 2 || !strings.HasPrefix(value, "--") {
		return false
	}
	for index := 2; index < len(value); index++ {
		if !mcpLongFlagCharacter(value[index]) {
			return false
		}
	}
	return true
}

func mcpLongFlagCharacter(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_'
}

func sensitiveTextPrefix(value string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(lower, "authorization:"):
		return "Authorization: ", true
	case strings.HasPrefix(lower, "proxy-authorization:"):
		return "Proxy-Authorization: ", true
	case strings.HasPrefix(lower, "bearer "):
		return "Bearer ", true
	}
	return "", false
}

func standaloneSensitiveTextFlag(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.EqualFold(trimmed, "authorization:") || strings.EqualFold(trimmed, "proxy-authorization:")
}

func sensitiveName(value string) bool {
	return hasSensitiveComponent(strings.TrimLeft(value, "-"))
}

func hasSensitiveComponent(value string) bool {
	return privacy.ContainsCredentialComponent(value)
}

func redactHomeText(home, value string) string {
	cleanHome := strings.TrimRight(filepath.Clean(home), string(filepath.Separator))
	if cleanHome == "" || cleanHome == "." {
		return value
	}
	if value == cleanHome {
		return "$HOME"
	}
	return strings.ReplaceAll(value, cleanHome+string(filepath.Separator), "$HOME/")
}

func rejectedEvidenceError(err error) model.CoverageError {
	code := "rejected_metadata"
	message := "MCP server metadata was rejected"
	if errors.Is(err, identity.ErrRejectedIdentity) {
		code = "rejected_identity"
		message = "MCP server identity was rejected"
	}
	return coverageError(code, message, "")
}

func serverIssue(issue ParseIssue, locationRef string) model.CoverageError {
	if issue.Code == "unknown_server_field" {
		return coverageError("unknown_server_field", "MCP server contains an unknown field", locationRef)
	}
	return coverageError("invalid_server", "MCP server entry is invalid", locationRef)
}
