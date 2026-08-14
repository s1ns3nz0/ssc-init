package audit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEncodeIsByteIdenticalAndUsesClosedCatalog(t *testing.T) {
	first, err := Encode(validRecord(), []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode(validRecord(), []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("archive is nondeterministic")
	}
	assertZIPNames(t, first, "manifest.json", "summary.json", "report.txt", "inventory.json", "findings.json", "coverage.json", "changes.json")
}

func TestEncodeFailureUsesFailureCatalogOnly(t *testing.T) {
	record, err := BuildFailure(validRun(), StageCollect, CodeCollectorFailed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(record, []byte("failed\n"))
	if err != nil {
		t.Fatal(err)
	}
	assertZIPNames(t, encoded, "manifest.json", "summary.json", "report.txt", "failure.json")
}

func assertZIPNames(t *testing.T, encoded []byte, want ...string) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(reader.File))
	for index, file := range reader.File {
		got[index] = file.Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ZIP names = %q, want %q", got, want)
	}
}

func TestVerifyRoundTripsEncodedRecord(t *testing.T) {
	record := validRecord()
	encoded, err := Encode(record, []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified.Record, record) || verified.Manifest.Authentication != "unsigned" || verified.ZIPSHA256 == "" {
		t.Fatalf("Verify result = %#v", verified)
	}
}

func TestEncodeRoundTripsCanonicalIntelligenceReceipt(t *testing.T) {
	record := validRecord()
	record.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("d", 64), KeyID: "ti-prod-1", RecordedAt: record.Run.FinishedAt}
	encoded, err := Encode(record, []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	assertZIPNames(t, encoded, "manifest.json", "summary.json", "report.txt", "intelligence.json", "inventory.json", "findings.json", "coverage.json", "changes.json")
	verified, err := Verify(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified.Record.Intelligence, record.Intelligence) {
		t.Fatalf("receipt=%+v want=%+v", verified.Record.Intelligence, record.Intelligence)
	}
}

func TestVerifyRejectsMalformedOversizedAndPrivateIntelligenceReceipt(t *testing.T) {
	record := validRecord()
	record.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("d", 64), KeyID: "ti-prod-1", RecordedAt: record.Run.FinishedAt}
	encoded, err := Encode(record, []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"duplicate": []byte(`{"family":"ti","family":"ti","status":"updated","freshness":"fresh","sequence":42,"digest":"` + strings.Repeat("d", 64) + `","keyId":"ti-prod-1","recordedAt":"2026-08-11T16:02:03Z"}` + "\n"),
		"unknown":   []byte(`{"family":"ti","status":"updated","freshness":"fresh","sequence":42,"digest":"` + strings.Repeat("d", 64) + `","keyId":"ti-prod-1","recordedAt":"2026-08-11T16:02:03Z","sourceUrl":"https://private.example"}` + "\n"),
		"oversized": append([]byte(`{"family":"ti","status":"updated","freshness":"fresh","sequence":42,"digest":"`+strings.Repeat("d", 64)+`","keyId":"`), append(bytes.Repeat([]byte("x"), 2048), []byte(`","recordedAt":"2026-08-11T16:02:03Z"}`+"\n")...)...),
	} {
		t.Run(name, func(t *testing.T) {
			assertVerifyError(t, replaceSignedArchiveEntry(t, encoded, "intelligence.json", value))
		})
	}
	private := record
	private.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("d", 64), KeyID: "/Users/alice/private-key", RecordedAt: private.Run.FinishedAt}
	assertVerifyError(t, archiveFromUncheckedRecord(t, private, []byte("report\n")))
}

func replaceSignedArchiveEntry(t *testing.T, encoded []byte, name string, value []byte) []byte {
	t.Helper()
	entries := unzipEntries(t, encoded)
	entries[name] = value
	manifest, err := decodeCanonical[Manifest](entries["manifest.json"])
	if err != nil {
		t.Fatal(err)
	}
	for index := range manifest.Entries {
		if manifest.Entries[index].Name == name {
			digest := sha256.Sum256(value)
			manifest.Entries[index].Size = int64(len(value))
			manifest.Entries[index].SHA256 = hex.EncodeToString(digest[:])
		}
	}
	entries["manifest.json"], err = canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return zipEntries(t, zipNames(encoded, t), entries)
}

func TestVerifyRejectsChecksumMutation(t *testing.T) {
	encoded := validArchive(t)
	entries := unzipEntries(t, encoded)
	entries["report.txt"] = []byte("tamper\n")
	assertVerifyError(t, zipEntries(t, zipNames(encoded, t), entries))
}

func TestVerifyRejectsDuplicateTraversalAndUnknownEntries(t *testing.T) {
	for name, encoded := range map[string][]byte{
		"duplicate": zipNamedContents(t, []string{"manifest.json", "manifest.json"}),
		"traversal": zipNamedContents(t, []string{"../secret"}),
		"nested":    zipNamedContents(t, []string{"nested/manifest.json"}),
		"unknown":   zipNamedContents(t, []string{"unknown.json"}),
	} {
		t.Run(name, func(t *testing.T) { assertVerifyError(t, encoded) })
	}
}

func TestVerifyRejectsMissingReorderedLinkAndNonContractHeaders(t *testing.T) {
	valid := validArchive(t)
	entries := unzipEntries(t, valid)
	names := zipNames(valid, t)
	withoutChanges := append([]string(nil), names[:len(names)-1]...)
	reordered := append([]string(nil), names...)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	for name, encoded := range map[string][]byte{
		"missing":        zipEntries(t, withoutChanges, entries),
		"reordered":      zipEntries(t, reordered, entries),
		"symlink":        zipWithHeader(t, "manifest.json", zip.Deflate, 0o600|0o120000),
		"world-readable": zipWithHeader(t, "manifest.json", zip.Deflate, 0o644),
		"stored":         zipWithHeader(t, "manifest.json", zip.Store, 0o600),
	} {
		t.Run(name, func(t *testing.T) { assertVerifyError(t, encoded) })
	}
}

func TestVerifyRejectsNonCanonicalAndTrailingJSON(t *testing.T) {
	valid := validArchive(t)
	entries := unzipEntries(t, valid)
	names := zipNames(valid, t)
	entries["manifest.json"] = append(entries["manifest.json"], ' ')
	assertVerifyError(t, zipEntries(t, names, entries))

	entries = unzipEntries(t, valid)
	entries["summary.json"] = append(entries["summary.json"], []byte("{}\n")...)
	manifest, err := decodeCanonical[Manifest](entries["manifest.json"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(entries["summary.json"])
	manifest.Entries[0].Size = int64(len(entries["summary.json"]))
	manifest.Entries[0].SHA256 = hex.EncodeToString(digest[:])
	entries["manifest.json"], err = canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	assertVerifyError(t, zipEntries(t, names, entries))
}

func TestVerifyRejectsOuterEntryExpansionAndRatioLimits(t *testing.T) {
	valid := validArchive(t)
	for name, input := range map[string]struct {
		reader io.ReaderAt
		size   int64
	}{
		"outer":    {reader: bytes.NewReader(nil), size: maxArchiveBytes + 1},
		"entries":  {reader: bytes.NewReader(zipNamedContents(t, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"})), size: int64(len(zipNamedContents(t, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"})))},
		"entry":    archiveWithCentralSizes(t, valid, 1, uint32(maxEntryBytes+1)),
		"expanded": archiveWithAllCentralSizes(t, valid, 1, 22<<20),
		"ratio":    archiveWithCentralSizes(t, valid, 1, 101),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(input.reader, input.size); err == nil {
				t.Fatal("Verify accepted bounded archive violation")
			}
		})
	}
}

func TestVerifyRejectsPrivacyInvalidDecodedRecords(t *testing.T) {
	record := validRecord()
	record.Run.Label = "/Users/alice/private"
	assertVerifyError(t, archiveFromUncheckedRecord(t, record, []byte("report\n")))
}

func validArchive(t *testing.T) []byte {
	t.Helper()
	encoded, err := Encode(validRecord(), []byte("report\n"))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertVerifyError(t *testing.T, encoded []byte) {
	t.Helper()
	if _, err := Verify(bytes.NewReader(encoded), int64(len(encoded))); err == nil {
		t.Fatal("Verify accepted invalid archive")
	}
}

func unzipEntries(t *testing.T, encoded []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		source, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(source)
		closeErr := source.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read %q: %v / close: %v", file.Name, err, closeErr)
		}
		entries[file.Name] = data
	}
	return entries
}

func zipNames(encoded []byte, t *testing.T) []string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(reader.File))
	for index, file := range reader.File {
		names[index] = file.Name
	}
	return names
}

func zipNamedContents(t *testing.T, names []string) []byte {
	t.Helper()
	entries := make(map[string][]byte, len(names))
	for _, name := range names {
		entries[name] = []byte("x")
	}
	return zipEntries(t, names, entries)
}

func zipEntries(t *testing.T, names []string, entries map[string][]byte) []byte {
	t.Helper()
	ordered := make([]archiveEntry, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, archiveEntry{name: name, data: entries[name]})
	}
	encoded, err := encodeZIP(ordered)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func zipWithHeader(t *testing.T, name string, method uint16, mode uint32) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: name, Method: method}
	header.SetMode(os.FileMode(mode))
	destination, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func archiveWithCentralSizes(t *testing.T, encoded []byte, compressed, expanded uint32) struct {
	reader io.ReaderAt
	size   int64
} {
	t.Helper()
	mutated := bytes.Clone(encoded)
	offset := bytes.Index(mutated, []byte{'P', 'K', 1, 2})
	if offset < 0 {
		t.Fatal("central directory not found")
	}
	binary.LittleEndian.PutUint32(mutated[offset+20:offset+24], compressed)
	binary.LittleEndian.PutUint32(mutated[offset+24:offset+28], expanded)
	return struct {
		reader io.ReaderAt
		size   int64
	}{bytes.NewReader(mutated), int64(len(mutated))}
}

func archiveWithAllCentralSizes(t *testing.T, encoded []byte, compressed, expanded uint32) struct {
	reader io.ReaderAt
	size   int64
} {
	t.Helper()
	mutated := bytes.Clone(encoded)
	for offset := 0; ; {
		index := bytes.Index(mutated[offset:], []byte{'P', 'K', 1, 2})
		if index < 0 {
			break
		}
		offset += index
		binary.LittleEndian.PutUint32(mutated[offset+20:offset+24], compressed)
		binary.LittleEndian.PutUint32(mutated[offset+24:offset+28], expanded)
		offset += 4
	}
	return struct {
		reader io.ReaderAt
		size   int64
	}{bytes.NewReader(mutated), int64(len(mutated))}
}

func archiveFromUncheckedRecord(t *testing.T, record Record, report []byte) []byte {
	t.Helper()
	entries, err := recordEntries(record, report)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: schemaVersion, Run: record.Run, Profile: record.Profile, State: record.State, Authentication: "unsigned"}
	for _, entry := range entries {
		digest := sha256.Sum256(entry.data)
		manifest.Entries = append(manifest.Entries, EntryDigest{Name: entry.name, Size: int64(len(entry.data)), SHA256: hex.EncodeToString(digest[:])})
	}
	manifestJSON, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return zipEntries(t, append([]string{"manifest.json"}, zipEntryNames(entries)...), mergeEntryData(entries, manifestJSON))
}

func zipEntryNames(entries []archiveEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.name
	}
	return names
}

func mergeEntryData(entries []archiveEntry, manifest []byte) map[string][]byte {
	result := map[string][]byte{"manifest.json": manifest}
	for _, entry := range entries {
		result[entry.name] = entry.data
	}
	return result
}
