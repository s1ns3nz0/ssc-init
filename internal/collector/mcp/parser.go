package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var errInvalidConfig = errors.New("invalid MCP configuration")

func validateJSONObjectKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	tokens := 0
	if err := readJSONValue(decoder, 0, &tokens); err != nil {
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

func readJSONValue(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > 64 || *tokens > maxJSONConfigBytes {
		return errInvalidConfig
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	*tokens++
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
			if err := readJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidConfig
		}
	case '[':
		for decoder.More() {
			if err := readJSONValue(decoder, depth+1, tokens); err != nil {
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
