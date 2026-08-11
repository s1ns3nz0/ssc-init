package projects

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errMetadataMalformed = errors.New("project metadata malformed")
	errRemoteUnsupported = errors.New("remote project metadata unsupported")
)

type candidateKind uint8

const (
	candidateFolder candidateKind = iota + 1
	candidateWorkspaceFile
)

// parseVSCodeWorkspace parses the single local location recorded by VS Code
// family products. It deliberately does not open a workspace file.
func parseVSCodeWorkspace(contents []byte) (string, candidateKind, error) {
	if !utf8.Valid(contents) {
		return "", 0, errMetadataMalformed
	}

	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	token, err := decoder.Token()
	if err != nil {
		return "", 0, errMetadataMalformed
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return "", 0, errMetadataMalformed
	}

	seen := make(map[string]struct{}, 1)
	var field, value string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", 0, errMetadataMalformed
		}
		key, ok := token.(string)
		if !ok {
			return "", 0, errMetadataMalformed
		}
		if _, duplicate := seen[key]; duplicate {
			return "", 0, errMetadataMalformed
		}
		seen[key] = struct{}{}
		if key != "folder" && key != "workspace" {
			return "", 0, errMetadataMalformed
		}
		if err := decoder.Decode(&value); err != nil {
			return "", 0, errMetadataMalformed
		}
		field = key
	}
	if token, err := decoder.Token(); err != nil {
		return "", 0, errMetadataMalformed
	} else if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return "", 0, errMetadataMalformed
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		return "", 0, errMetadataMalformed
	}
	if len(seen) != 1 || value == "" || !validMetadataText(value) {
		return "", 0, errMetadataMalformed
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return "", 0, errMetadataMalformed
	}
	if parsed.Scheme != "file" {
		if parsed.Scheme == "" {
			return "", 0, errMetadataMalformed
		}
		return "", 0, errRemoteUnsupported
	}
	if parsed.Opaque != "" || parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !validMetadataText(parsed.Path) {
		return "", 0, errMetadataMalformed
	}
	path := filepath.Clean(parsed.Path)
	if !filepath.IsAbs(path) || !validMetadataText(path) {
		return "", 0, errMetadataMalformed
	}
	if field == "workspace" {
		return path, candidateWorkspaceFile, nil
	}
	return path, candidateFolder, nil
}

func validMetadataText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}
