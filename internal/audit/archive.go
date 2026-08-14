package audit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const (
	maxArchiveBytes             int64 = 256 << 20
	maxArchiveEntries                 = 8
	maxEntryBytes               int64 = 64 << 20
	maxExpandedBytes            int64 = 128 << 20
	maxCompressionRatio         int64 = 100
	maxIntelligenceReceiptBytes int64 = 1024
)

type EntryDigest struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion  string        `json:"schemaVersion"`
	Run            Run           `json:"run"`
	Profile        Profile       `json:"profile"`
	State          State         `json:"state"`
	Authentication string        `json:"authentication"`
	Entries        []EntryDigest `json:"entries"`
}

type Verified struct {
	Manifest  Manifest
	Record    Record
	ZIPSHA256 string
	SafePath  string `json:"-"`
}

type coveragePayload struct {
	Collectors []model.CollectorResult `json:"collectors"`
	Evidence   *model.EvidenceCoverage `json:"evidence,omitempty"`
}

type archiveEntry struct {
	name string
	data []byte
}

func Encode(record Record, reportText []byte) ([]byte, error) {
	if err := Validate(record); err != nil {
		return nil, err
	}
	if !validReportText(reportText) || int64(len(reportText)) > maxEntryBytes {
		return nil, errors.New("invalid audit report")
	}
	entries, err := recordEntries(record, reportText)
	if err != nil {
		return nil, err
	}
	manifest := Manifest{
		SchemaVersion:  schemaVersion,
		Run:            record.Run,
		Profile:        record.Profile,
		State:          record.State,
		Authentication: "unsigned",
		Entries:        make([]EntryDigest, 0, len(entries)),
	}
	for _, entry := range entries {
		digest := sha256.Sum256(entry.data)
		manifest.Entries = append(manifest.Entries, EntryDigest{Name: entry.name, Size: int64(len(entry.data)), SHA256: hex.EncodeToString(digest[:])})
	}
	manifestJSON, err := canonicalJSON(manifest)
	if err != nil {
		return nil, err
	}
	all := make([]archiveEntry, 0, len(entries)+1)
	all = append(all, archiveEntry{name: "manifest.json", data: manifestJSON})
	all = append(all, entries...)
	encoded, err := encodeZIP(all)
	if err != nil {
		return nil, err
	}
	if _, err := Verify(bytes.NewReader(encoded), int64(len(encoded))); err != nil {
		return nil, errors.New("encoded audit archive failed verification")
	}
	return encoded, nil
}

func recordEntries(record Record, reportText []byte) ([]archiveEntry, error) {
	if !validReportText(reportText) {
		return nil, errors.New("invalid audit report")
	}
	summary, err := canonicalJSON(record.Summary)
	if err != nil {
		return nil, err
	}
	entries := []archiveEntry{{name: "summary.json", data: summary}, {name: "report.txt", data: bytes.Clone(reportText)}}
	if record.State == StateFailed {
		failure, err := canonicalJSON(record.Failure)
		if err != nil {
			return nil, err
		}
		return append(entries, archiveEntry{name: "failure.json", data: failure}), nil
	}
	if record.Intelligence != nil {
		intelligence, err := canonicalJSON(record.Intelligence)
		if err != nil || int64(len(intelligence)) > maxIntelligenceReceiptBytes {
			return nil, errors.New("invalid intelligence receipt")
		}
		entries = append(entries, archiveEntry{name: "intelligence.json", data: intelligence})
	}
	payloads := []struct {
		name  string
		value any
	}{
		{name: "inventory.json", value: record.Inventory},
		{name: "findings.json", value: record.Findings},
		{name: "coverage.json", value: coveragePayload{Collectors: record.Coverage, Evidence: record.EvidenceCoverage}},
		{name: "changes.json", value: record.Changes},
	}
	for _, payload := range payloads {
		encoded, err := canonicalJSON(payload.value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, archiveEntry{name: payload.name, data: encoded})
	}
	return entries, nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func encodeZIP(entries []archiveEntry) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate, Flags: 0x800}
		header.SetModTime(time.Unix(0, 0).UTC())
		header.SetMode(0o600)
		destination, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := destination.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if int64(buffer.Len()) > maxArchiveBytes {
		return nil, errors.New("audit archive too large")
	}
	return buffer.Bytes(), nil
}

func Verify(reader io.ReaderAt, size int64) (Verified, error) {
	if reader == nil || size <= 0 || size > maxArchiveBytes {
		return Verified{}, errors.New("invalid audit archive size")
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return Verified{}, errors.New("invalid audit ZIP")
	}
	if len(archive.File) < 1 || len(archive.File) > maxArchiveEntries {
		return Verified{}, errors.New("invalid audit entry count")
	}
	files := make(map[string]*zip.File, len(archive.File))
	var expanded uint64
	for _, file := range archive.File {
		if !validArchiveEntryName(file.Name) || files[file.Name] != nil || file.Method != zip.Deflate || file.FileInfo().Mode()&os.ModeType != 0 || file.Mode().Perm() != 0o600 {
			return Verified{}, errors.New("invalid audit ZIP entry")
		}
		if file.UncompressedSize64 > uint64(maxEntryBytes) {
			return Verified{}, errors.New("audit ZIP entry too large")
		}
		if file.Name == "intelligence.json" && file.UncompressedSize64 > uint64(maxIntelligenceReceiptBytes) {
			return Verified{}, errors.New("intelligence receipt too large")
		}
		if file.UncompressedSize64 > 0 && (file.CompressedSize64 == 0 || file.UncompressedSize64 > file.CompressedSize64*uint64(maxCompressionRatio)) {
			return Verified{}, errors.New("invalid audit ZIP compression ratio")
		}
		if expanded > uint64(maxExpandedBytes)-file.UncompressedSize64 {
			return Verified{}, errors.New("audit ZIP expanded size exceeded")
		}
		expanded += file.UncompressedSize64
		files[file.Name] = file
	}
	contents := make(map[string][]byte, len(files))
	for _, file := range archive.File {
		content, err := readZIPEntry(file)
		if err != nil {
			return Verified{}, err
		}
		contents[file.Name] = content
	}
	manifestBytes, ok := contents["manifest.json"]
	if !ok {
		return Verified{}, errors.New("missing audit manifest")
	}
	manifest, err := decodeCanonical[Manifest](manifestBytes)
	if err != nil {
		return Verified{}, errors.New("invalid audit manifest")
	}
	catalog, err := catalogForManifest(manifest)
	if err != nil || !sameZIPOrder(archive.File, catalog) || manifest.SchemaVersion != schemaVersion || manifest.Authentication != "unsigned" || len(manifest.Entries) != len(catalog)-1 {
		return Verified{}, errors.New("invalid audit manifest contract")
	}
	for index, expectedName := range catalog[1:] {
		entry := manifest.Entries[index]
		content := contents[expectedName]
		digest := sha256.Sum256(content)
		if entry.Name != expectedName || entry.Size != int64(len(content)) || entry.SHA256 != hex.EncodeToString(digest[:]) {
			return Verified{}, errors.New("audit entry digest mismatch")
		}
	}
	if !validReportText(contents["report.txt"]) {
		return Verified{}, errors.New("invalid audit report")
	}
	record, err := decodeRecord(manifest, contents)
	if err != nil {
		return Verified{}, err
	}
	if err := Validate(record); err != nil {
		return Verified{}, err
	}
	zipDigest := sha256.New()
	if _, err := io.Copy(zipDigest, io.NewSectionReader(reader, 0, size)); err != nil {
		return Verified{}, errors.New("cannot hash audit ZIP")
	}
	return Verified{Manifest: manifest, Record: record, ZIPSHA256: hex.EncodeToString(zipDigest.Sum(nil))}, nil
}

func validReportText(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			return false
		}
	}
	return true
}

func validArchiveEntryName(name string) bool {
	switch name {
	case "manifest.json", "summary.json", "report.txt", "intelligence.json", "inventory.json", "findings.json", "coverage.json", "changes.json", "failure.json":
		return true
	default:
		return false
	}
}

func readZIPEntry(file *zip.File) ([]byte, error) {
	source, err := file.Open()
	if err != nil {
		return nil, errors.New("invalid audit ZIP entry")
	}
	content, readErr := io.ReadAll(io.LimitReader(source, maxEntryBytes+1))
	closeErr := source.Close()
	if readErr != nil || closeErr != nil || int64(len(content)) > maxEntryBytes || uint64(len(content)) != file.UncompressedSize64 {
		return nil, errors.New("invalid audit ZIP entry data")
	}
	return content, nil
}

func catalogForState(state State) ([]string, error) {
	switch state {
	case StateComplete, StatePartial:
		return []string{"manifest.json", "summary.json", "report.txt", "inventory.json", "findings.json", "coverage.json", "changes.json"}, nil
	case StateFailed:
		return []string{"manifest.json", "summary.json", "report.txt", "failure.json"}, nil
	default:
		return nil, errors.New("invalid audit state")
	}
}

func catalogForManifest(manifest Manifest) ([]string, error) {
	catalog, err := catalogForState(manifest.State)
	if err != nil || manifest.State == StateFailed {
		return catalog, err
	}
	if len(manifest.Entries) == len(catalog) && len(manifest.Entries) > 2 && manifest.Entries[2].Name == "intelligence.json" {
		return []string{"manifest.json", "summary.json", "report.txt", "intelligence.json", "inventory.json", "findings.json", "coverage.json", "changes.json"}, nil
	}
	return catalog, nil
}

func sameZIPOrder(files []*zip.File, names []string) bool {
	if len(files) != len(names) {
		return false
	}
	for index := range names {
		if files[index].Name != names[index] {
			return false
		}
	}
	return true
}

func decodeRecord(manifest Manifest, contents map[string][]byte) (Record, error) {
	summary, err := decodeCanonical[Summary](contents["summary.json"])
	if err != nil {
		return Record{}, errors.New("invalid audit summary")
	}
	record := Record{SchemaVersion: manifest.SchemaVersion, Profile: manifest.Profile, State: manifest.State, Run: manifest.Run, Summary: summary}
	if manifest.State == StateFailed {
		failure, err := decodeCanonical[Failure](contents["failure.json"])
		if err != nil {
			return Record{}, errors.New("invalid audit failure")
		}
		record.Failure = &failure
		return record, nil
	}
	if content, present := contents["intelligence.json"]; present {
		intelligence, err := decodeCanonical[IntelligenceUpdate](content)
		if err != nil {
			return Record{}, errors.New("invalid intelligence receipt")
		}
		record.Intelligence = &intelligence
	}
	if record.Inventory, err = decodeCanonical[model.Inventory](contents["inventory.json"]); err != nil {
		return Record{}, errors.New("invalid audit inventory")
	}
	if record.Findings, err = decodeCanonical[[]model.Finding](contents["findings.json"]); err != nil {
		return Record{}, errors.New("invalid audit findings")
	}
	coverage, err := decodeCanonical[coveragePayload](contents["coverage.json"])
	if err != nil {
		return Record{}, errors.New("invalid audit coverage")
	}
	record.Coverage, record.EvidenceCoverage = coverage.Collectors, coverage.Evidence
	if record.Changes, err = decodeCanonical[model.Delta](contents["changes.json"]); err != nil {
		return Record{}, errors.New("invalid audit changes")
	}
	return record, nil
}

func decodeCanonical[T any](content []byte) (T, error) {
	var value T
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return value, errors.New("trailing JSON data")
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(canonical, content) {
		return value, fmt.Errorf("non-canonical JSON")
	}
	return value, nil
}
