// Package provenance parses bounded local lockfile facts without network access.
package provenance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type Format string

const (
	FormatNPM          Format = "npm"
	FormatCargo        Format = "cargo"
	FormatGoSum        Format = "go.sum"
	FormatRequirements Format = "requirements.txt"
	FormatPipfile      Format = "Pipfile.lock"
	FormatPoetry       Format = "poetry.lock"
	FormatUV           Format = "uv.lock"
)

var (
	ErrOversize  = errors.New("lockfile exceeds provenance parsing bound")
	ErrMalformed = errors.New("lockfile provenance is malformed")
)

// Record contains only a normalized package coordinate and closed provenance
// facts. SourceIntegrity holds an approved non-SHA-256 lockfile fact (currently
// Go h1) which must not be mislabeled as Asset.Provenance.Integrity.
type Record struct {
	Ecosystem       string
	Name            string
	Version         string
	Provenance      model.Provenance
	SourceIntegrity string
}

func Parse(ctx context.Context, format Format, source io.Reader, maxBytes int64) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || maxBytes <= 0 {
		return nil, ErrMalformed
	}
	contents, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: source}, maxBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrMalformed
	}
	if int64(len(contents)) > maxBytes {
		return nil, ErrOversize
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var records []Record
	switch format {
	case FormatNPM:
		records, err = parseNPM(contents)
	case FormatCargo:
		records, err = parseCargo(contents)
	case FormatGoSum:
		records, err = parseGoSum(contents)
	case FormatRequirements:
		records, err = parseRequirements(contents)
	case FormatPipfile:
		records, err = parsePipfile(contents)
	case FormatPoetry:
		records, err = parsePoetry(contents)
	case FormatUV:
		records, err = parseUV(contents)
	default:
		err = ErrMalformed
	}
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Version < records[j].Version
	})
	return records, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func parseNPM(contents []byte) ([]Record, error) {
	if !uniqueJSONKeys(contents) {
		return nil, ErrMalformed
	}
	var lock struct {
		Packages map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&lock); err != nil || lock.Packages == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrMalformed
	}
	records := make([]Record, 0, len(lock.Packages))
	seen := make(map[string]Record)
	for path, entry := range lock.Packages {
		if path == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			name = npmNameFromPath(path)
		}
		record, ok := packageRecord("npm", name, entry.Version)
		if !ok {
			return nil, ErrMalformed
		}
		if entry.Integrity != "" {
			digest, ok := decodeSHA256SRI(entry.Integrity)
			if !ok {
				return nil, ErrMalformed
			}
			record.Provenance.Status = model.ProvenanceImmutable
			record.Provenance.Integrity = "sha256:" + digest
		}
		if err := addRecord(seen, record); err != nil {
			return nil, err
		}
	}
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}

func npmNameFromPath(path string) string {
	index := strings.LastIndex(path, "node_modules/")
	if index < 0 {
		return ""
	}
	return path[index+len("node_modules/"):]
}

func decodeSHA256SRI(value string) (string, bool) {
	encoded, ok := strings.CutPrefix(value, "sha256-")
	if !ok || strings.ContainsAny(encoded, " \t\r\n") {
		return "", false
	}
	digest, err := base64.StdEncoding.DecodeString(encoded)
	return hex.EncodeToString(digest), err == nil && len(digest) == 32
}

func parseCargo(contents []byte) ([]Record, error) {
	var lock struct {
		Packages []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Checksum string `toml:"checksum"`
		} `toml:"package"`
	}
	decoder := toml.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&lock); err != nil {
		return nil, ErrMalformed
	}
	seen := make(map[string]Record)
	for _, entry := range lock.Packages {
		record, ok := packageRecord("cargo", entry.Name, entry.Version)
		if !ok {
			return nil, ErrMalformed
		}
		if entry.Checksum != "" {
			if !lowercaseSHA256(entry.Checksum) {
				return nil, ErrMalformed
			}
			record.Provenance.Status = model.ProvenanceImmutable
			record.Provenance.Integrity = "sha256:" + entry.Checksum
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

func parseGoSum(contents []byte) ([]Record, error) {
	seen := make(map[string]Record)
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 4096), len(contents)+1)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return nil, ErrMalformed
		}
		if strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		name, version, integrity := fields[0], fields[1], fields[2]
		record, ok := packageRecord("go", name, version)
		if !ok || !validH1(integrity) {
			return nil, ErrMalformed
		}
		record.SourceIntegrity = integrity
		if err := addRecord(seen, record); err != nil {
			return nil, err
		}
	}
	if scanner.Err() != nil {
		return nil, ErrMalformed
	}
	records := make([]Record, 0, len(seen))
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}

func packageRecord(ecosystem, name, version string) (Record, bool) {
	if !safeCoordinate(name) || version != "" && !safeCoordinate(version) {
		return Record{}, false
	}
	status := model.ProvenanceUnknown
	lowerVersion := strings.ToLower(version)
	if version == "" || lowerVersion == "latest" || strings.HasPrefix(lowerVersion, "git+") || strings.HasPrefix(lowerVersion, "http:") || strings.HasPrefix(lowerVersion, "https:") || strings.HasPrefix(lowerVersion, "file:") || strings.HasPrefix(lowerVersion, "link:") || strings.HasPrefix(lowerVersion, "workspace:") {
		status = model.ProvenanceMutable
	}
	return Record{Ecosystem: ecosystem, Name: name, Version: version, Provenance: model.Provenance{Status: status, Ecosystem: ecosystem, Source: "lockfile"}}, true
}

func uniqueJSONKeys(contents []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if !consumeUniqueJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeUniqueJSONValue(decoder *json.Decoder) bool {
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
			if !consumeUniqueJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueJSONValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

func safeCoordinate(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validH1(value string) bool {
	encoded, ok := strings.CutPrefix(value, "h1:")
	if !ok {
		return false
	}
	digest, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(digest) == 32
}

func lowercaseSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32
}

func addRecord(seen map[string]Record, record Record) error {
	key := record.Ecosystem + "\x00" + record.Name + "\x00" + record.Version
	if existing, ok := seen[key]; ok && existing != record {
		return ErrMalformed
	}
	seen[key] = record
	return nil
}
