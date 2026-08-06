package agents

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	maxAgentNameBytes    = 256
	maxAgentVersionBytes = 128
)

var errInvalidAgentManifest = errors.New("invalid agent manifest")

type pluginManifest struct {
	name    string
	version string
}

func parsePluginManifest(contents []byte) (pluginManifest, error) {
	if len(contents) > int(defaultMaxAgentManifestBytes) || validateAgentJSONKeys(contents) != nil {
		return pluginManifest{}, errInvalidAgentManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return pluginManifest{}, errInvalidAgentManifest
	}
	seen := make(map[string]struct{})
	manifest := pluginManifest{}
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return pluginManifest{}, errInvalidAgentManifest
		}
		if _, duplicate := seen[key]; duplicate {
			return pluginManifest{}, errInvalidAgentManifest
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return pluginManifest{}, errInvalidAgentManifest
		}
		switch key {
		case "name":
			if err := json.Unmarshal(raw, &manifest.name); err != nil {
				return pluginManifest{}, errInvalidAgentManifest
			}
		case "version":
			if err := json.Unmarshal(raw, &manifest.version); err != nil {
				return pluginManifest{}, errInvalidAgentManifest
			}
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return pluginManifest{}, errInvalidAgentManifest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return pluginManifest{}, errInvalidAgentManifest
	}
	if manifest.name == "" || len(manifest.name) > maxAgentNameBytes || len(manifest.version) > maxAgentVersionBytes {
		return pluginManifest{}, errInvalidAgentManifest
	}
	return manifest, nil
}

func validateAgentJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	tokens := 0
	if err := readAgentJSONValue(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidAgentManifest
	}
	return nil
}

func readAgentJSONValue(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > 64 || *tokens > int(defaultMaxAgentManifestBytes) {
		return errInvalidAgentManifest
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	*tokens = *tokens + 1
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errInvalidAgentManifest
			}
			if _, duplicate := seen[key]; duplicate {
				return errInvalidAgentManifest
			}
			seen[key] = struct{}{}
			if err := readAgentJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidAgentManifest
		}
	case '[':
		for decoder.More() {
			if err := readAgentJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidAgentManifest
		}
	default:
		return errInvalidAgentManifest
	}
	return nil
}

func parseSkillManifest(contents []byte, fallback string) (string, error) {
	normalized := strings.ReplaceAll(string(contents), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return fallback, nil
	}
	end := -1
	for index := 1; index < len(lines); index++ {
		if lines[index] == "---" {
			end = index
			break
		}
	}
	if end < 0 {
		return "", errInvalidAgentManifest
	}
	name := ""
	seenName := false
	for _, line := range lines[1:end] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(trimmed, ":")
		if !found || strings.TrimSpace(key) != "name" {
			continue
		}
		if seenName {
			return "", errInvalidAgentManifest
		}
		seenName = true
		var err error
		name, err = parseFrontmatterScalar(strings.TrimSpace(rawValue))
		if err != nil {
			return "", errInvalidAgentManifest
		}
	}
	if name == "" {
		name = fallback
	}
	if len(name) > maxAgentNameBytes {
		return "", errInvalidAgentManifest
	}
	return name, nil
}

func parseFrontmatterScalar(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, `"`) {
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return parsed, nil
	}
	if strings.HasPrefix(value, "'") {
		if len(value) < 2 || !strings.HasSuffix(value, "'") {
			return "", errInvalidAgentManifest
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
	}
	if value == "|" || value == ">" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errInvalidAgentManifest
	}
	return strings.TrimSpace(value), nil
}
