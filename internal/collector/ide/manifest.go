package ide

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
)

const (
	maxIdentityLength   = 512
	maxMetadataLength   = 4096
	maxMetadataItems    = 1024
	metadataListDivider = "\x1f"
)

var errInvalidManifest = errors.New("invalid IDE extension manifest")

type vscodeManifest struct {
	Name             string                     `json:"name"`
	Publisher        string                     `json:"publisher"`
	Version          string                     `json:"version"`
	Main             string                     `json:"main"`
	Browser          string                     `json:"browser"`
	ActivationEvents []string                   `json:"activationEvents"`
	Capabilities     map[string]json.RawMessage `json:"capabilities"`
	Contributes      map[string]json.RawMessage `json:"contributes"`
}

type jetBrainsManifest struct {
	ID      string `xml:"id"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

func parseVSCodeManifest(contents []byte, host, home, path string) (model.Asset, error) {
	var manifest vscodeManifest
	if err := decodeJSON(contents, &manifest); err != nil {
		return model.Asset{}, errInvalidManifest
	}
	name, ok := normalizeIdentity(manifest.Name)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	publisher, ok := normalizeIdentity(manifest.Publisher)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	version, ok := normalizeIdentity(manifest.Version)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	entryPoint := strings.TrimSpace(manifest.Main)
	if entryPoint == "" {
		entryPoint = strings.TrimSpace(manifest.Browser)
	}
	entryPoint, ok = normalizeMetadata(entryPoint)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	entryPoint = redactHomeText(home, entryPoint)

	activationEvents, ok := normalizeList(manifest.ActivationEvents)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	capabilityNames := make([]string, 0, len(manifest.Capabilities)+len(manifest.Contributes))
	for capability := range manifest.Capabilities {
		capabilityNames = append(capabilityNames, capability)
	}
	for capability := range manifest.Contributes {
		capabilityNames = append(capabilityNames, capability)
	}
	capabilities, ok := normalizeList(capabilityNames)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}

	return model.Asset{
		ID:      "ide-extension:" + host + ":" + publisher + "." + name + "@" + version,
		Type:    model.AssetIDEExtension,
		Name:    name,
		Version: version,
		Path:    redactPath(home, path),
		Source:  host,
		Metadata: map[string]string{
			"publisher":         publisher,
			"entry_point":       entryPoint,
			"activation_events": strings.Join(activationEvents, metadataListDivider),
			"capabilities":      strings.Join(capabilities, metadataListDivider),
		},
	}, nil
}

func parseJetBrainsManifest(contents []byte, home, path string) (model.Asset, error) {
	var manifest jetBrainsManifest
	if err := decodeXML(contents, &manifest); err != nil {
		return model.Asset{}, errInvalidManifest
	}
	id, ok := normalizeIdentity(manifest.ID)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	version, ok := normalizeIdentity(manifest.Version)
	if !ok {
		return model.Asset{}, errInvalidManifest
	}
	name, ok := normalizeMetadata(manifest.Name)
	if !ok || name == "" {
		return model.Asset{}, errInvalidManifest
	}
	publisher := id
	if index := strings.LastIndexByte(id, '.'); index > 0 {
		publisher = id[:index]
	}

	return model.Asset{
		ID:      "ide-extension:jetbrains:" + id + "@" + version,
		Type:    model.AssetIDEExtension,
		Name:    name,
		Version: version,
		Path:    redactPath(home, path),
		Source:  "jetbrains",
		Metadata: map[string]string{
			"publisher":         publisher,
			"entry_point":       "",
			"activation_events": "",
			"capabilities":      "",
		},
	}, nil
}

func decodeJSON(contents []byte, destination any) error {
	if err := validateUniqueJSONKeys(contents); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidManifest
	}
	return nil
}

func validateUniqueJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := readJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidManifest
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
				return errInvalidManifest
			}
			if _, exists := seen[key]; exists {
				return errInvalidManifest
			}
			seen[key] = struct{}{}
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidManifest
		}
	case '[':
		for decoder.More() {
			if err := readJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidManifest
		}
	default:
		return errInvalidManifest
	}
	return nil
}

func decodeXML(contents []byte, destination any) error {
	decoder := xml.NewDecoder(bytes.NewReader(contents))
	decoder.Strict = true
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		characters, ok := token.(xml.CharData)
		if !ok || strings.TrimSpace(string(characters)) != "" {
			return errInvalidManifest
		}
	}
}

func normalizeIdentity(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxIdentityLength {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) || strings.ContainsRune(":@/\\", character) {
			return "", false
		}
	}
	return value, true
}

func normalizeMetadata(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) > maxMetadataLength {
		return "", false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return value, true
}

func normalizeList(values []string) ([]string, bool) {
	if len(values) > maxMetadataItems {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized, ok := normalizeMetadata(value)
		if !ok {
			return nil, false
		}
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result, true
}

func redactHomeText(home, value string) string {
	if home == "" || value == "" {
		return value
	}
	return strings.ReplaceAll(value, filepath.Clean(home), "$HOME")
}

func redactPath(home, path string) string {
	return filepath.ToSlash(platform.RedactHome(filepath.Clean(home), filepath.Clean(path)))
}
