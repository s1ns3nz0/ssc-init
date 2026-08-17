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
// facts. SourceIntegrity holds an approved non-SHA-256 lockfile fact (Go h1 or
// npm SHA-384/SHA-512) which must not be mislabeled as
// Asset.Provenance.Integrity.
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
	type npmPackageEntry struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Integrity string `json:"integrity"`
		Link      bool   `json:"link"`
	}
	type npmV1Entry struct {
		Version      string                `json:"version"`
		Integrity    string                `json:"integrity"`
		Dependencies map[string]npmV1Entry `json:"dependencies"`
	}
	var lock struct {
		Packages     map[string]npmPackageEntry `json:"packages"`
		Dependencies map[string]npmV1Entry      `json:"dependencies"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&lock); err != nil || decoder.Decode(&struct{}{}) != io.EOF || lock.Packages == nil && lock.Dependencies == nil {
		return nil, ErrMalformed
	}
	records := make([]Record, 0, len(lock.Packages)+len(lock.Dependencies))
	seen := make(map[string]Record)
	if lock.Packages != nil {
		for path, entry := range lock.Packages {
			if path == "" || entry.Link {
				continue
			}
			name := entry.Name
			if name == "" {
				name = npmNameFromPath(path)
			}
			if name == "" {
				continue
			}
			if err := addNPMRecord(seen, name, entry.Version, entry.Integrity); err != nil {
				return nil, err
			}
		}
	} else {
		type namedEntry struct {
			name  string
			entry npmV1Entry
		}
		stack := make([]namedEntry, 0, len(lock.Dependencies))
		for name, entry := range lock.Dependencies {
			stack = append(stack, namedEntry{name: name, entry: entry})
		}
		for len(stack) > 0 {
			last := len(stack) - 1
			current := stack[last]
			stack = stack[:last]
			if err := addNPMRecord(seen, current.name, current.entry.Version, current.entry.Integrity); err != nil {
				return nil, err
			}
			for name, entry := range current.entry.Dependencies {
				stack = append(stack, namedEntry{name: name, entry: entry})
			}
		}
	}
	for _, record := range seen {
		records = append(records, record)
	}
	return records, nil
}

func addNPMRecord(seen map[string]Record, name, version, integrity string) error {
	record, ok := packageRecord("npm", name, version)
	if !ok {
		return ErrMalformed
	}
	if integrity != "" {
		algorithm, digest, ok := decodeNpmSRI(integrity)
		if !ok {
			return ErrMalformed
		}
		if algorithm == "sha256" {
			record.Provenance.Status = model.ProvenanceImmutable
			record.Provenance.Integrity = algorithm + ":" + digest
		} else {
			if algorithm != "sha1" {
				record.Provenance.Status = model.ProvenanceImmutable
			}
			record.SourceIntegrity = algorithm + ":" + digest
		}
	}
	key := record.Ecosystem + "\x00" + record.Name + "\x00" + record.Version
	existing, exists := seen[key]
	if !exists || existing == record {
		seen[key] = record
		return nil
	}
	existingHasIntegrity := existing.Provenance.Integrity != "" || existing.SourceIntegrity != ""
	recordHasIntegrity := record.Provenance.Integrity != "" || record.SourceIntegrity != ""
	if !existingHasIntegrity && recordHasIntegrity {
		seen[key] = record
		return nil
	}
	if existingHasIntegrity && !recordHasIntegrity {
		return nil
	}
	if existingHasIntegrity && recordHasIntegrity {
		existingRank := npmIntegrityRank(existing)
		recordRank := npmIntegrityRank(record)
		if existingRank != recordRank {
			if recordRank > existingRank {
				seen[key] = record
			}
			return nil
		}
	}
	return ErrMalformed
}

func npmIntegrityRank(record Record) int {
	value := record.SourceIntegrity
	if value == "" {
		value = record.Provenance.Integrity
	}
	algorithm, _, _ := strings.Cut(value, ":")
	return map[string]int{"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}[algorithm]
}

func npmNameFromPath(path string) string {
	index := strings.LastIndex(path, "node_modules/")
	if index < 0 {
		return ""
	}
	return path[index+len("node_modules/"):]
}

func decodeNpmSRI(value string) (string, string, bool) {
	if strings.ContainsAny(value, " \t\r\n") {
		return "", "", false
	}
	algorithm, encoded, ok := strings.Cut(value, "-")
	wantBytes := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
	if !ok || wantBytes == 0 || encoded == "" {
		return "", "", false
	}
	digest, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(digest) != wantBytes {
		clear(digest)
		return "", "", false
	}
	result := hex.EncodeToString(digest)
	clear(digest)
	return algorithm, result, true
}

func parseCargo(contents []byte) ([]Record, error) {
	var lock struct {
		Packages []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Source   string `toml:"source"`
			Checksum string `toml:"checksum"`
		} `toml:"package"`
	}
	decoder := toml.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(&lock); err != nil {
		return nil, ErrMalformed
	}
	type cargoRecord struct {
		record Record
		source string
	}
	seen := make(map[string]cargoRecord)
	for _, entry := range lock.Packages {
		record, ok := packageRecord("cargo", entry.Name, entry.Version)
		if !ok || !validCargoSource(entry.Source) {
			return nil, ErrMalformed
		}
		if strings.HasPrefix(entry.Source, "git+") {
			record.Provenance.Status, record.SourceIntegrity = cargoGitSourceFact(entry.Source)
		}
		if entry.Checksum != "" {
			if !lowercaseSHA256(entry.Checksum) {
				return nil, ErrMalformed
			}
			record.Provenance.Status = model.ProvenanceImmutable
			record.Provenance.Integrity = "sha256:" + entry.Checksum
		}
		key := record.Ecosystem + "\x00" + record.Name + "\x00" + record.Version
		candidate := cargoRecord{record: record, source: entry.Source}
		if existing, exists := seen[key]; exists {
			merged, mergeOK := mergeCargoRecord(existing, candidate)
			if !mergeOK {
				return nil, ErrMalformed
			}
			seen[key] = merged
		} else {
			seen[key] = candidate
		}
	}
	records := make([]Record, 0, len(seen))
	for _, entry := range seen {
		records = append(records, entry.record)
	}
	return records, nil
}

func cargoGitSourceFact(source string) (model.ProvenanceStatus, string) {
	_, revision, found := strings.Cut(source, "#")
	if !found || !lowercaseHex(revision, 40) {
		return model.ProvenanceMutable, ""
	}
	return model.ProvenanceUnknown, "git-sha1:" + revision
}

func lowercaseHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validCargoSource(value string) bool {
	return value == "" || safeCoordinate(value) && (strings.HasPrefix(value, "registry+") || strings.HasPrefix(value, "sparse+") || strings.HasPrefix(value, "git+"))
}

func mergeCargoRecord(left, right struct {
	record Record
	source string
}) (struct {
	record Record
	source string
}, bool) {
	if left.source == right.source {
		return left, left.record == right.record
	}
	if left.source == "" && right.source != "" && right.record.Provenance.Integrity != "" {
		return right, true
	}
	if right.source == "" && left.source != "" && left.record.Provenance.Integrity != "" {
		return left, true
	}
	return left, false
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
