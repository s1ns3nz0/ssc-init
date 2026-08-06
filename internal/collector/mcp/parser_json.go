package mcp

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/privacy"
)

const (
	maxJSONConfigBytes = 4 << 20
	maxJSONServers     = 4_096
	maxJSONFields      = 128
	maxJSONCollection  = 4_096
	maxJSONStringBytes = 64 << 10
)

// ServerConfig is the value-only-safe normalized representation shared by the
// JSON parser and the Task 8 TOML parser.
type ServerConfig struct {
	Name          string   `json:"name"`
	Command       string   `json:"command,omitempty"`
	Args          []string `json:"args,omitempty"`
	URL           string   `json:"url,omitempty"`
	Transport     string   `json:"transport,omitempty"`
	CWD           string   `json:"cwd,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	EnvKeys       []string `json:"envKeys,omitempty"`
	HeaderKeys    []string `json:"headerKeys,omitempty"`
	EnabledTools  []string `json:"enabledTools,omitempty"`
	DisabledTools []string `json:"disabledTools,omitempty"`
	UnknownFields []string `json:"unknownFields,omitempty"`
}

// ParseIssue records only a stable issue code. It deliberately omits server
// names and values so callers cannot accidentally persist hostile input.
type ParseIssue struct {
	Code string `json:"code"`
}

// ParseResult retains valid siblings when another server entry is malformed.
type ParseResult struct {
	Servers []ServerConfig `json:"servers,omitempty"`
	Issues  []ParseIssue   `json:"issues,omitempty"`
}

// ParseJSON strictly normalizes either official JSON MCP container.
func ParseJSON(contents []byte) (ParseResult, error) {
	return parseJSONContainer(contents, "")
}

func parseJSONContainer(contents []byte, expectedContainer string) (ParseResult, error) {
	if len(contents) > maxJSONConfigBytes || !startsJSONObject(contents) {
		return ParseResult{}, errInvalidConfig
	}
	if err := validateJSONObjectKeys(contents); err != nil {
		return ParseResult{}, errInvalidConfig
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(contents, &document); err != nil || document == nil {
		return ParseResult{}, errInvalidConfig
	}

	containers := []string{"mcpServers", "servers"}
	if expectedContainer != "" {
		otherContainer := "mcpServers"
		if expectedContainer == otherContainer {
			otherContainer = "servers"
		}
		if _, wrongEquivalent := document[otherContainer]; wrongEquivalent {
			return ParseResult{}, errInvalidConfig
		}
		containers = []string{expectedContainer}
	}
	var container json.RawMessage
	found := 0
	for _, name := range containers {
		if raw, exists := document[name]; exists {
			container = raw
			found++
		}
	}
	if expectedContainer == "" && found > 1 {
		return ParseResult{}, errInvalidConfig
	}
	if found == 0 {
		return ParseResult{}, nil
	}
	if !startsJSONObject(container) {
		return ParseResult{}, errInvalidConfig
	}
	var rawServers map[string]json.RawMessage
	if err := json.Unmarshal(container, &rawServers); err != nil || rawServers == nil || len(rawServers) > maxJSONServers {
		return ParseResult{}, errInvalidConfig
	}

	names := make([]string, 0, len(rawServers))
	for name := range rawServers {
		names = append(names, name)
	}
	sort.Strings(names)
	result := ParseResult{Servers: make([]ServerConfig, 0, len(names))}
	for _, name := range names {
		server, unknown, ok := normalizeJSONServer(name, rawServers[name])
		if !ok {
			result.Issues = append(result.Issues, ParseIssue{Code: "invalid_server"})
			continue
		}
		result.Servers = append(result.Servers, server)
		if unknown {
			result.Issues = append(result.Issues, ParseIssue{Code: "unknown_server_field"})
		}
	}
	return result, nil
}

func normalizeJSONServer(name string, raw json.RawMessage) (ServerConfig, bool, bool) {
	if len(name) > maxJSONStringBytes || !startsJSONObject(raw) {
		return ServerConfig{}, false, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil || len(fields) > maxJSONFields {
		return ServerConfig{}, false, false
	}
	server := ServerConfig{Name: name}
	hasUnknown := false
	known := map[string]bool{
		"command": true, "args": true, "url": true, "type": true, "transport": true,
		"cwd": true, "enabled": true, "disabled": true, "env": true,
		"headers": true, "httpHeaders": true, "enabledTools": true, "disabledTools": true,
	}
	for field := range fields {
		if !known[field] {
			hasUnknown = true
			if safeNormalizedFieldName(field) {
				server.UnknownFields = append(server.UnknownFields, field)
			}
		}
	}
	sort.Strings(server.UnknownFields)

	if !decodeOptionalString(fields, "command", &server.Command) ||
		!decodeOptionalString(fields, "url", &server.URL) ||
		!decodeOptionalString(fields, "cwd", &server.CWD) ||
		!decodeOptionalStringSlice(fields, "args", &server.Args) ||
		!decodeOptionalStringSlice(fields, "enabledTools", &server.EnabledTools) ||
		!decodeOptionalStringSlice(fields, "disabledTools", &server.DisabledTools) {
		return ServerConfig{}, false, false
	}
	server.EnabledTools = uniqueSortedStrings(server.EnabledTools)
	server.DisabledTools = uniqueSortedStrings(server.DisabledTools)

	typeValue, hasType, typeOK := decodeStringField(fields, "type")
	transport, hasTransport, transportOK := decodeStringField(fields, "transport")
	if !typeOK || !transportOK || (hasType && hasTransport) {
		return ServerConfig{}, false, false
	}
	if hasType {
		server.Transport = typeValue
	} else if hasTransport {
		server.Transport = transport
	}

	enabled, hasEnabled, enabledOK := decodeBoolField(fields, "enabled")
	disabled, hasDisabled, disabledOK := decodeBoolField(fields, "disabled")
	if !enabledOK || !disabledOK || (hasEnabled && hasDisabled) {
		return ServerConfig{}, false, false
	}
	if hasEnabled {
		server.Enabled = &enabled
	} else if hasDisabled {
		enabled = !disabled
		server.Enabled = &enabled
	}

	envKeys, envOK := decodeKeyMap(fields, "env")
	headerKeys, headersOK := decodeAliasedKeyMap(fields, "headers", "httpHeaders")
	if !envOK || !headersOK {
		return ServerConfig{}, false, false
	}
	server.EnvKeys = envKeys
	server.HeaderKeys = headerKeys

	hasCommand := server.Command != ""
	hasURL := server.URL != ""
	if hasCommand == hasURL {
		return ServerConfig{}, false, false
	}
	if server.Transport == "" {
		if hasCommand {
			server.Transport = "stdio"
		} else {
			server.Transport = "http"
		}
	}
	return server, hasUnknown, true
}

func decodeOptionalString(fields map[string]json.RawMessage, name string, destination *string) bool {
	value, exists, ok := decodeStringField(fields, name)
	if !ok {
		return false
	}
	if exists {
		*destination = value
	}
	return true
}

func decodeStringField(fields map[string]json.RawMessage, name string) (string, bool, bool) {
	raw, exists := fields[name]
	if !exists {
		return "", false, true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || len(value) > maxJSONStringBytes {
		return "", true, false
	}
	return value, true, true
}

func decodeBoolField(fields map[string]json.RawMessage, name string) (bool, bool, bool) {
	raw, exists := fields[name]
	if !exists {
		return false, false, true
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, true, false
	}
	return value, true, true
}

func decodeOptionalStringSlice(fields map[string]json.RawMessage, name string, destination *[]string) bool {
	raw, exists := fields[name]
	if !exists {
		return true
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) > maxJSONCollection {
		return false
	}
	for _, value := range values {
		if len(value) > maxJSONStringBytes {
			return false
		}
	}
	*destination = values
	return true
}

func decodeAliasedKeyMap(fields map[string]json.RawMessage, first, second string) ([]string, bool) {
	_, hasFirst := fields[first]
	_, hasSecond := fields[second]
	if hasFirst && hasSecond {
		return nil, false
	}
	if hasFirst {
		return decodeKeyMap(fields, first)
	}
	return decodeKeyMap(fields, second)
}

func decodeKeyMap(fields map[string]json.RawMessage, name string) ([]string, bool) {
	raw, exists := fields[name]
	if !exists {
		return nil, true
	}
	if !startsJSONObject(raw) {
		return nil, false
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil || len(values) > maxJSONCollection {
		return nil, false
	}
	keys := make([]string, 0, len(values))
	for key, rawValue := range values {
		var ignored string
		if len(key) > maxJSONStringBytes || json.Unmarshal(rawValue, &ignored) != nil {
			return nil, false
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, true
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func startsJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func safeNormalizedFieldName(value string) bool {
	if value == "" || strings.ContainsAny(value, `/\\`) || privacy.ContainsSensitiveValue(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
