package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errInvalidConfig = errors.New("invalid MCP configuration")

type serverConfig struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

type configDocument struct {
	MCPServers map[string]serverConfig `json:"mcpServers"`
	Servers    map[string]serverConfig `json:"servers"`
}

func parseConfig(contents []byte) (map[string]serverConfig, error) {
	if err := validateJSONObjectKeys(contents); err != nil {
		return nil, errInvalidConfig
	}
	var document configDocument
	if err := json.Unmarshal(contents, &document); err != nil {
		return nil, errInvalidConfig
	}
	servers := make(map[string]serverConfig, len(document.MCPServers)+len(document.Servers))
	for name, config := range document.MCPServers {
		servers[name] = config
	}
	for name, config := range document.Servers {
		servers[name] = config
	}
	return servers, nil
}

func validateJSONObjectKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := readJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errInvalidConfig
		}
		return err
	}
	return nil
}

func readJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidConfig
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%w: duplicate object key", errInvalidConfig)
			}
			seen[key] = struct{}{}
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidConfig
		}
	case '[':
		for decoder.More() {
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidConfig
		}
	default:
		return errInvalidConfig
	}
	return nil
}
