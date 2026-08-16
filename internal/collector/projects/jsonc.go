package projects

import (
	"bytes"
	"encoding/json"
	"io"
)

func validLaunchJSONC(raw []byte) bool {
	normalized, ok := normalizeLaunchJSONC(raw)
	if !ok {
		return false
	}
	defer clear(normalized)
	if !json.Valid(normalized) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	if !consumeUniqueLaunchJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func normalizeLaunchJSONC(raw []byte) ([]byte, bool) {
	result := append([]byte(nil), raw...)
	const (
		normal = iota
		quoted
		lineComment
		blockComment
	)
	state := normal
	escaped := false
	for index := 0; index < len(result); index++ {
		current := result[index]
		switch state {
		case normal:
			switch {
			case current == '"':
				state = quoted
			case current == '/' && index+1 < len(result) && result[index+1] == '/':
				result[index], result[index+1], state = ' ', ' ', lineComment
				index++
			case current == '/' && index+1 < len(result) && result[index+1] == '*':
				result[index], result[index+1], state = ' ', ' ', blockComment
				index++
			}
		case quoted:
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				state = normal
			}
		case lineComment:
			if current == '\n' || current == '\r' {
				state = normal
			} else {
				result[index] = ' '
			}
		case blockComment:
			if current == '*' && index+1 < len(result) && result[index+1] == '/' {
				result[index], result[index+1], state = ' ', ' ', normal
				index++
			} else if current != '\n' && current != '\r' {
				result[index] = ' '
			}
		}
	}
	if state == blockComment || state == quoted {
		clear(result)
		return nil, false
	}

	state, escaped = normal, false
	for index := 0; index < len(result); index++ {
		current := result[index]
		if state == quoted {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				state = normal
			}
			continue
		}
		if current == '"' {
			state = quoted
			continue
		}
		if current != ',' {
			continue
		}
		next := index + 1
		for next < len(result) && (result[next] == ' ' || result[next] == '\t' || result[next] == '\r' || result[next] == '\n') {
			next++
		}
		if next < len(result) && (result[next] == '}' || result[next] == ']') {
			result[index] = ' '
		}
	}
	return result, true
}

func consumeUniqueLaunchJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := keys[key]; duplicate {
				return false
			}
			keys[key] = struct{}{}
			if !consumeUniqueLaunchJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueLaunchJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
