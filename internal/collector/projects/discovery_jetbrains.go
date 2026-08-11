package projects

import (
	"bytes"
	"encoding/xml"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxJetBrainsRecentTokens = 4096

// parseJetBrainsRecent extracts only the closed recent-project list hierarchy
// from JetBrains' application settings. Path expansion belongs to discovery,
// not to this parser.
func parseJetBrainsRecent(contents []byte) ([]string, error) {
	if !utf8.Valid(contents) || bytes.Contains(contents, []byte("&")) {
		return nil, errMetadataMalformed
	}

	decoder := xml.NewDecoder(bytes.NewReader(contents))
	var paths []string
	var stack []xml.StartElement
	seenRoot := false
	seenDeclaration := false
	for tokens := 0; ; {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 || !seenRoot {
				return nil, errMetadataMalformed
			}
			return paths, nil
		}
		if err != nil {
			return nil, errMetadataMalformed
		}
		tokens++
		if tokens > maxJetBrainsRecentTokens {
			return nil, errMetadataMalformed
		}

		switch token := token.(type) {
		case xml.Directive:
			return nil, errMetadataMalformed
		case xml.ProcInst:
			if token.Target != "xml" || seenDeclaration || seenRoot || len(stack) != 0 {
				return nil, errMetadataMalformed
			}
			seenDeclaration = true
		case xml.StartElement:
			if token.Name.Space != "" || !hasOnlyUnqualifiedAttributes(token) {
				return nil, errMetadataMalformed
			}
			if len(stack) == 0 {
				if seenRoot || token.Name.Space != "" || token.Name.Local != "application" {
					return nil, errMetadataMalformed
				}
				seenRoot = true
			} else if err := validateJetBrainsStart(stack, token, &paths); err != nil {
				return nil, errMetadataMalformed
			}
			stack = append(stack, token)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].Name != token.Name {
				return nil, errMetadataMalformed
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if strings.TrimSpace(string(token)) != "" {
				return nil, errMetadataMalformed
			}
		}
	}
}

func hasOnlyUnqualifiedAttributes(element xml.StartElement) bool {
	seen := make(map[string]struct{}, len(element.Attr))
	for _, attribute := range element.Attr {
		if attribute.Name.Space != "" {
			return false
		}
		if _, duplicate := seen[attribute.Name.Local]; duplicate {
			return false
		}
		seen[attribute.Name.Local] = struct{}{}
	}
	return true
}

func validateJetBrainsStart(stack []xml.StartElement, current xml.StartElement, paths *[]string) error {
	parent := stack[len(stack)-1]
	if parent.Name.Local != "application" {
		if isJetBrainsRecentComponent(stack) {
			return validateJetBrainsRecentChild(stack, current, paths)
		}
		return nil
	}
	if current.Name.Local == "component" && isRecentComponent(current) {
		return nil
	}
	return nil
}

func isJetBrainsRecentComponent(stack []xml.StartElement) bool {
	return len(stack) >= 2 && stack[1].Name.Local == "component" && isRecentComponent(stack[1])
}

func isRecentComponent(element xml.StartElement) bool {
	name, ok := xmlAttribute(element, "name")
	return ok && (name == "RecentProjectsManager" || name == "RecentDirectoryProjectsManager")
}

func validateJetBrainsRecentChild(stack []xml.StartElement, current xml.StartElement, paths *[]string) error {
	depth := len(stack)
	switch depth {
	case 2: // application/component
		if current.Name.Local != "option" {
			return errMetadataMalformed
		}
		return nil
	case 3: // application/component/option
		if name, ok := xmlAttribute(stack[2], "name"); ok && name == "recentPaths" {
			if current.Name.Local != "list" {
				return errMetadataMalformed
			}
		}
		return nil
	case 4: // application/component/option/list
		if name, ok := xmlAttribute(stack[2], "name"); ok && name == "recentPaths" {
			if current.Name.Local != "option" {
				return errMetadataMalformed
			}
			value, ok := xmlAttribute(current, "value")
			if !ok || !validJetBrainsRecentPath(value) {
				return errMetadataMalformed
			}
			*paths = append(*paths, strings.Clone(value))
		}
		return nil
	default:
		if name, ok := xmlAttribute(stack[2], "name"); ok && name == "recentPaths" {
			return errMetadataMalformed
		}
		return nil
	}
}

func xmlAttribute(element xml.StartElement, name string) (string, bool) {
	for _, attribute := range element.Attr {
		if attribute.Name.Space == "" && attribute.Name.Local == name {
			return attribute.Value, true
		}
	}
	return "", false
}

func validJetBrainsRecentPath(path string) bool {
	if !validMetadataText(path) {
		return false
	}
	if strings.HasPrefix(path, "$USER_HOME$/") {
		return len(path) > len("$USER_HOME$/")
	}
	if strings.HasPrefix(path, "~/") {
		return len(path) > len("~/")
	}
	return filepath.IsAbs(path)
}
