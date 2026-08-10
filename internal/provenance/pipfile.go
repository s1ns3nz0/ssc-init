package provenance

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

type pipfileEntry struct {
	Version  string   `json:"version"`
	Hashes   []string `json:"hashes"`
	Path     string   `json:"path"`
	File     string   `json:"file"`
	Git      string   `json:"git"`
	Editable bool     `json:"editable"`
}

func parsePipfile(contents []byte) ([]Record, error) {
	if !uniqueJSONKeys(contents) {
		return nil, ErrMalformed
	}
	var root map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&root); err != nil || root == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrMalformed
	}
	seen := make(map[string]Record)
	for _, section := range []string{"default", "develop"} {
		raw, exists := root[section]
		if !exists {
			continue
		}
		var dependencies map[string]json.RawMessage
		if !jsonObject(raw) || json.Unmarshal(raw, &dependencies) != nil || dependencies == nil {
			return nil, ErrMalformed
		}
		for name, rawEntry := range dependencies {
			if !jsonObject(rawEntry) {
				return nil, ErrMalformed
			}
			var entry pipfileEntry
			if err := json.Unmarshal(rawEntry, &entry); err != nil {
				return nil, ErrMalformed
			}
			version := entry.Version
			if strings.HasPrefix(version, "==") {
				version = strings.TrimPrefix(version, "==")
			}
			mutable := entry.Path != "" || entry.File != "" || entry.Git != "" || entry.Editable
			record, ok := pythonRecord(name, version, mutable, entry.Hashes)
			if !ok {
				return nil, ErrMalformed
			}
			if mutable {
				record.Version = ""
			}
			if err := addRecord(seen, record); err != nil {
				return nil, err
			}
		}
	}
	records := make([]Record, 0, len(seen))
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}

func jsonObject(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '{'
}
