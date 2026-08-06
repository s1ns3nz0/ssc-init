package mcp

import (
	"sort"

	"github.com/pelletier/go-toml/v2"
)

var knownTOMLServerFields = map[string]struct{}{
	"command": {}, "args": {}, "url": {}, "cwd": {}, "enabled": {},
	"env": {}, "env_vars": {}, "http_headers": {}, "env_http_headers": {},
	"bearer_token_env_var": {}, "enabled_tools": {}, "disabled_tools": {},
}

type tomlDocument struct {
	MCPServers map[string]map[string]any `toml:"mcp_servers"`
}

// ParseTOML strictly normalizes the official Codex mcp_servers table. Values
// from direct environment and header maps are deliberately discarded during
// normalization; only key names and environment-variable references survive.
func ParseTOML(contents []byte) (ParseResult, error) {
	if len(contents) > maxJSONConfigBytes {
		return ParseResult{}, errInvalidConfig
	}
	var document tomlDocument
	if err := toml.Unmarshal(contents, &document); err != nil {
		return ParseResult{}, errInvalidConfig
	}
	if len(document.MCPServers) > maxJSONServers {
		return ParseResult{}, errInvalidConfig
	}

	names := make([]string, 0, len(document.MCPServers))
	for name := range document.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)

	result := ParseResult{Servers: make([]ServerConfig, 0, len(names))}
	for _, name := range names {
		server, unknown, ok := normalizeTOMLServer(name, document.MCPServers[name])
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

func normalizeTOMLServer(name string, fields map[string]any) (ServerConfig, bool, bool) {
	if name == "" || len(name) > maxJSONStringBytes || fields == nil || len(fields) > maxJSONFields {
		return ServerConfig{}, false, false
	}
	server := ServerConfig{Name: name}
	hasUnknown := false
	for field := range fields {
		if _, known := knownTOMLServerFields[field]; known {
			continue
		}
		hasUnknown = true
		if safeNormalizedFieldName(field) {
			server.UnknownFields = append(server.UnknownFields, field)
		}
	}
	sort.Strings(server.UnknownFields)

	if !decodeTOMLOptionalString(fields, "command", &server.Command) ||
		!decodeTOMLOptionalString(fields, "url", &server.URL) ||
		!decodeTOMLOptionalString(fields, "cwd", &server.CWD) ||
		!decodeTOMLOptionalStrings(fields, "args", &server.Args) ||
		!decodeTOMLOptionalStrings(fields, "enabled_tools", &server.EnabledTools) ||
		!decodeTOMLOptionalStrings(fields, "disabled_tools", &server.DisabledTools) {
		return ServerConfig{}, false, false
	}
	server.EnabledTools = uniqueSortedStrings(server.EnabledTools)
	server.DisabledTools = uniqueSortedStrings(server.DisabledTools)

	if raw, exists := fields["enabled"]; exists {
		enabled, ok := raw.(bool)
		if !ok {
			return ServerConfig{}, false, false
		}
		server.Enabled = &enabled
	}

	envKeys, _, envOK := decodeTOMLKeyMap(fields, "env")
	headerKeys, _, headersOK := decodeTOMLKeyMap(fields, "http_headers")
	envHeaderKeys, envHeaderRefs, envHeadersOK := decodeTOMLKeyMap(fields, "env_http_headers")
	envRefs, envVarsOK := decodeTOMLEnvVars(fields)
	bearerRef, hasBearerRef, bearerOK := decodeTOMLString(fields, "bearer_token_env_var")
	if !envOK || !headersOK || !envHeadersOK || !envVarsOK || !bearerOK {
		return ServerConfig{}, false, false
	}
	server.EnvKeys = append(append(envKeys, envRefs...), envHeaderRefs...)
	if hasBearerRef {
		server.EnvKeys = append(server.EnvKeys, bearerRef)
	}
	server.EnvKeys = uniqueSortedStrings(server.EnvKeys)
	server.HeaderKeys = uniqueSortedStrings(append(headerKeys, envHeaderKeys...))

	hasCommand := server.Command != ""
	hasURL := server.URL != ""
	if hasCommand == hasURL {
		return ServerConfig{}, false, false
	}
	if hasCommand {
		server.Transport = "stdio"
	} else {
		server.Transport = "http"
	}
	return server, hasUnknown, true
}

func decodeTOMLOptionalString(fields map[string]any, name string, destination *string) bool {
	value, exists, ok := decodeTOMLString(fields, name)
	if !ok {
		return false
	}
	if exists {
		*destination = value
	}
	return true
}

func decodeTOMLString(fields map[string]any, name string) (string, bool, bool) {
	raw, exists := fields[name]
	if !exists {
		return "", false, true
	}
	value, ok := raw.(string)
	if !ok || len(value) > maxJSONStringBytes {
		return "", true, false
	}
	return value, true, true
}

func decodeTOMLOptionalStrings(fields map[string]any, name string, destination *[]string) bool {
	raw, exists := fields[name]
	if !exists {
		return true
	}
	values, ok := tomlStringSlice(raw)
	if !ok {
		return false
	}
	*destination = values
	return true
}

func tomlStringSlice(raw any) ([]string, bool) {
	switch values := raw.(type) {
	case []string:
		if len(values) > maxJSONCollection {
			return nil, false
		}
		result := append([]string(nil), values...)
		for _, value := range result {
			if len(value) > maxJSONStringBytes {
				return nil, false
			}
		}
		return result, true
	case []any:
		if len(values) > maxJSONCollection {
			return nil, false
		}
		result := make([]string, 0, len(values))
		for _, rawValue := range values {
			value, ok := rawValue.(string)
			if !ok || len(value) > maxJSONStringBytes {
				return nil, false
			}
			result = append(result, value)
		}
		return result, true
	default:
		return nil, false
	}
}

func decodeTOMLKeyMap(fields map[string]any, name string) ([]string, []string, bool) {
	raw, exists := fields[name]
	if !exists {
		return nil, nil, true
	}
	values, ok := raw.(map[string]any)
	if !ok || values == nil || len(values) > maxJSONCollection {
		return nil, nil, false
	}
	keys := make([]string, 0, len(values))
	references := make([]string, 0, len(values))
	for key, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || len(key) > maxJSONStringBytes || len(value) > maxJSONStringBytes {
			return nil, nil, false
		}
		keys = append(keys, key)
		references = append(references, value)
	}
	sort.Strings(keys)
	sort.Strings(references)
	return keys, references, true
}

func decodeTOMLEnvVars(fields map[string]any) ([]string, bool) {
	raw, exists := fields["env_vars"]
	if !exists {
		return nil, true
	}
	values, ok := raw.([]any)
	if !ok || len(values) > maxJSONCollection {
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, rawValue := range values {
		switch value := rawValue.(type) {
		case string:
			if len(value) > maxJSONStringBytes {
				return nil, false
			}
			result = append(result, value)
		case map[string]any:
			if len(value) == 0 || len(value) > 2 {
				return nil, false
			}
			name, hasName := value["name"].(string)
			if !hasName || name == "" || len(name) > maxJSONStringBytes {
				return nil, false
			}
			for field := range value {
				if field != "name" && field != "source" {
					return nil, false
				}
			}
			if source, hasSource := value["source"]; hasSource {
				sourceName, sourceOK := source.(string)
				if !sourceOK || (sourceName != "local" && sourceName != "remote") {
					return nil, false
				}
			}
			result = append(result, name)
		default:
			return nil, false
		}
	}
	return uniqueSortedStrings(result), true
}
