package provenance

import (
	"bufio"
	"bytes"
	"strings"
)

var ignoredRequirementOptions = map[string]struct{}{
	"-i": {}, "--index-url": {}, "--extra-index-url": {}, "-f": {}, "--find-links": {},
	"--trusted-host": {}, "-c": {}, "--constraint": {}, "-r": {}, "--requirement": {},
}

func parseRequirements(contents []byte) ([]Record, error) {
	lines, ok := requirementLines(contents)
	if !ok {
		return nil, ErrMalformed
	}
	seen := make(map[string]Record)
	for _, line := range lines {
		record, skip, ok := parseRequirement(line)
		if !ok {
			return nil, ErrMalformed
		}
		if skip {
			continue
		}
		if err := addRecord(seen, record); err != nil {
			return nil, err
		}
	}
	records := make([]Record, 0, len(seen))
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}

func requirementLines(contents []byte) ([]string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 4096), len(contents)+1)
	lines := make([]string, 0)
	var current string
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(strings.TrimRight(line, " \t"), "\\")
		if continued {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\")
		}
		if len(current)+len(line) > len(contents) {
			return nil, false
		}
		current += line
		if continued {
			continue
		}
		if current != "" {
			lines = append(lines, current)
		}
		current = ""
	}
	return lines, scanner.Err() == nil && current == ""
}

func parseRequirement(line string) (Record, bool, bool) {
	line = strings.TrimSpace(stripRequirementComment(line))
	if line == "" {
		return Record{}, true, true
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Record{}, true, true
	}
	option := fields[0]
	editableSource := ""
	if base, value, found := strings.Cut(option, "="); found {
		option = base
		if option == "--editable" {
			editableSource = value
		}
	}
	if _, ignored := ignoredRequirementOptions[option]; ignored {
		return Record{}, true, true
	}
	if option == "-e" || option == "--editable" {
		if editableSource == "" && len(fields) < 2 {
			return Record{}, false, false
		}
		if editableSource == "" {
			editableSource = strings.Join(fields[1:], " ")
		}
		name := editableRequirementName(editableSource)
		if name == "" {
			return Record{}, true, true
		}
		record, ok := pythonRecord(name, "", true, nil)
		return record, false, ok
	}

	withoutMarker := stripRequirementMarker(line)
	fields = strings.Fields(strings.TrimSpace(withoutMarker))
	if len(fields) == 0 {
		return Record{}, true, true
	}
	hashes := make([]string, 0)
	parts := make([]string, 0, len(fields))
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if hash, found := strings.CutPrefix(field, "--hash="); found {
			hashes = append(hashes, hash)
			continue
		}
		if field == "--hash" {
			if index+1 == len(fields) {
				return Record{}, false, false
			}
			index++
			hashes = append(hashes, fields[index])
			continue
		}
		parts = append(parts, field)
	}
	value := strings.Join(parts, " ")
	if name, source, direct := strings.Cut(value, " @ "); direct {
		if source == "" {
			return Record{}, false, false
		}
		record, ok := pythonRecord(stripPythonExtras(name), "", true, hashes)
		return record, false, ok
	}
	if strings.HasPrefix(value, ".") || strings.HasPrefix(value, "/") || strings.Contains(value, "://") || strings.HasPrefix(value, "git+") {
		return Record{}, true, true
	}
	name, version := splitPythonRequirement(value)
	if name == "" {
		return Record{}, false, false
	}
	record, ok := pythonRecord(stripPythonExtras(name), version, false, hashes)
	return record, false, ok
}

func stripRequirementComment(value string) string {
	for index := 0; index < len(value); index++ {
		if value[index] == '#' && (index == 0 || value[index-1] == ' ' || value[index-1] == '\t') {
			return value[:index]
		}
	}
	return value
}

func stripRequirementMarker(value string) string {
	marker := strings.IndexByte(value, ';')
	if marker < 0 {
		return value
	}
	hash := strings.Index(value[marker:], "--hash")
	if hash < 0 {
		return value[:marker]
	}
	return value[:marker] + " " + value[marker+hash:]
}

func editableRequirementName(value string) string {
	_, fragment, found := strings.Cut(value, "#")
	if !found {
		return ""
	}
	for _, part := range strings.Split(fragment, "&") {
		if name, found := strings.CutPrefix(part, "egg="); found {
			return name
		}
	}
	return ""
}

func stripPythonExtras(name string) string {
	base, _, _ := strings.Cut(name, "[")
	return base
}

func splitPythonRequirement(value string) (string, string) {
	for index := 0; index < len(value); index++ {
		if strings.ContainsRune("<>=!~", rune(value[index])) {
			name := strings.TrimSpace(value[:index])
			version := strings.TrimSpace(value[index:])
			if strings.HasPrefix(version, "==") {
				return name, strings.TrimPrefix(version, "==")
			}
			return name, version
		}
	}
	return strings.TrimSpace(value), ""
}
