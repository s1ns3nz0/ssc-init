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

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/privacy"
)

const maxMCPConfigBytes = maxJSONConfigBytes

const redactedValue = "[redacted]"

type mcpCollector struct {
	projectTargets []model.LocalTarget
}

// New returns a catalog-targeted collector. Raw project paths are retained only
// for the lifetime of this single-use collector and are never included in model output.
func New(projectTargets ...model.LocalTarget) collector.TargetedCollector {
	return &mcpCollector{projectTargets: projectTargets}
}

func (*mcpCollector) Name() string { return "mcp" }

func (*mcpCollector) Targets() []model.TargetSpec { return catalogSpecs() }

func (c *mcpCollector) Collect(ctx context.Context, env collector.Environment) (model.CollectorResult, error) {
	result := model.CollectorResult{Collector: c.Name()}
	defer c.clearProjectTargets()
	if err := ctx.Err(); err != nil {
		return result, err
	}

	rootedFilesystem, hasRootedFilesystem := env.FS.(platform.RootedFileSystem)
	var homeRoot platform.RootedDirectory
	if hasRootedFilesystem {
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
	declarations := catalogDeclarations()
	for phase := 0; phase < 2; phase++ {
		for _, declaration := range declarations {
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
		target.Errors = append(target.Errors, serverIssue(issue.Code, locationRef))
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
	asset := model.Asset{
		ID:   "mcp:" + declaration.spec.Host + ":" + server.Name,
		Type: model.AssetMCP, Name: server.Name, Source: declaration.spec.Host,
	}
	metadata := observationMetadata(home, declaration.spec.ID, server)
	if !safeMetadata(metadata) {
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

func observationMetadata(home, sourceTarget string, server ServerConfig) map[string]string {
	metadata := map[string]string{
		"transport":     server.Transport,
		"source_target": sourceTarget,
	}
	putMetadata(metadata, "command", sanitizeCommand(home, server.Command))
	putMetadata(metadata, "args", strings.Join(sanitizeArgs(home, server.Args), "\x1f"))
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
	return metadata
}

func putMetadata(metadata map[string]string, key, value string) {
	if value != "" {
		metadata[key] = value
	}
}

func safeMetadata(metadata map[string]string) bool {
	for key, value := range metadata {
		if key == "" || value == "" || privacy.ContainsSensitiveValue(key) || privacy.ContainsSensitiveValue(value) || containsRawAbsolutePath(value) {
			return false
		}
	}
	return true
}

func sanitizeCommand(home, command string) string {
	if command == "" {
		return ""
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
		if _, sensitive := combinedCredentialFlag(field); sensitive {
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
	if privacy.ContainsSensitiveValue(command) {
		return redactedValue
	}
	return redactHomeText(home, command)
}

func containsRawAbsolutePath(value string) bool {
	for _, field := range strings.FieldsFunc(value, func(character rune) bool {
		return character == '\x1f' || character == ',' || character == '=' || unicode.IsSpace(character)
	}) {
		if filepath.IsAbs(field) {
			return true
		}
	}
	return false
}

func sanitizeArgs(home string, args []string) []string {
	result := make([]string, len(args))
	redactNext := false
	for index, arg := range args {
		if redactNext {
			result[index] = redactedValue
			redactNext = false
			continue
		}
		if credentialFlag(arg) {
			result[index] = arg
			redactNext = true
			continue
		}
		if prefix, ok := combinedCredentialFlag(arg); ok {
			result[index] = prefix + redactedValue
			continue
		}
		if prefix, ok := sensitiveTextPrefix(arg); ok {
			result[index] = prefix + redactedValue
			continue
		}
		if key, value, found := strings.Cut(arg, "="); found {
			switch {
			case sensitiveName(key):
				result[index] = key + "=" + redactedValue
			case absoluteURL(value):
				result[index] = key + "=" + sanitizeURLShape(value)
			case filepath.IsAbs(value):
				result[index] = key + "=" + identity.SafeLocationRef(home, value, "external-arg")
			case privacy.ContainsSensitiveValue(value):
				result[index] = key + "=" + redactedValue
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
		case privacy.ContainsSensitiveValue(arg):
			result[index] = redactedValue
		default:
			result[index] = redactHomeText(home, arg)
		}
	}
	return result
}

func sanitizeURLShape(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return redactedValue
	}
	parsed.User = nil
	shape := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	keys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		shape += "?query_keys=" + strings.Join(keys, ",")
	}
	return shape
}

func sanitizeCWD(home, cwd string) string {
	if cwd == "" {
		return ""
	}
	if filepath.IsAbs(cwd) {
		return identity.SafeLocationRef(home, cwd, "external-cwd")
	}
	redacted := redactHomeText(home, cwd)
	if strings.HasPrefix(redacted, "$HOME") {
		return filepath.ToSlash(redacted)
	}
	return "config-relative/" + filepath.ToSlash(filepath.Clean(cwd))
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

func combinedCredentialFlag(value string) (string, bool) {
	lower := strings.ToLower(value)
	if strings.HasPrefix(value, "-H") && len(value) > 2 {
		return value[:2], true
	}
	for _, flag := range []string{"--api-key", "--apikey", "--token"} {
		if strings.HasPrefix(lower, flag) && len(value) > len(flag) {
			if flag == "--token" && strings.HasPrefix(lower[len(flag):], "izer") {
				return "", false
			}
			return value[:len(flag)], true
		}
	}
	return "", false
}

func sensitiveLongFlag(value string) bool {
	if !strings.HasPrefix(value, "--") {
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

func sensitiveName(value string) bool {
	return hasSensitiveComponent(strings.TrimLeft(value, "-"))
}

func hasSensitiveComponent(value string) bool {
	if value == "authorizationHelper" || value == "AuthorizationHelper" {
		return false
	}
	if strings.EqualFold(value, "authorizationhelper") {
		return true
	}
	for _, component := range semanticComponents(value) {
		switch component {
		case "token", "secret", "password", "passwd", "credential", "credentials",
			"apikey", "accesskey", "privatekey", "clientsecret", "bearer", "signature", "key",
			"authorization", "auth", "header", "headers", "env":
			return true
		}
	}
	return false
}

func semanticComponents(value string) []string {
	runes := []rune(value)
	components := make([]string, 0, 4)
	for start := 0; start < len(runes); {
		for start < len(runes) && !unicode.IsLetter(runes[start]) && !unicode.IsDigit(runes[start]) {
			start++
		}
		if start == len(runes) {
			break
		}
		end := start
		for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end])) {
			end++
		}
		word := runes[start:end]
		wordStart := 0
		for index := 1; index < len(word); index++ {
			lowerToUpper := (unicode.IsLower(word[index-1]) || unicode.IsDigit(word[index-1])) && unicode.IsUpper(word[index])
			acronymToWord := unicode.IsUpper(word[index-1]) && unicode.IsUpper(word[index]) && index+1 < len(word) && unicode.IsLower(word[index+1])
			if lowerToUpper || acronymToWord {
				components = append(components, strings.ToLower(string(word[wordStart:index])))
				wordStart = index
			}
		}
		components = append(components, strings.ToLower(string(word[wordStart:])))
		start = end
	}
	return components
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

func serverIssue(code, locationRef string) model.CoverageError {
	message := "MCP server entry is invalid"
	if code == "unknown_server_field" {
		message = "MCP server contains an unknown field"
	}
	return coverageError(code, message, locationRef)
}
