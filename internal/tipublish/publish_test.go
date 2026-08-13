package tipublish

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	versionmatch "github.com/s1ns3nz0/ssc-init/internal/analyzer/version"
	"github.com/s1ns3nz0/ssc-init/internal/bundle"
)

var fixtureTime = time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

func TestBuildSeparatesMaliciousFromVulnerableClassification(t *testing.T) {
	input := fixtureInput(t)
	raw, report, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, envelope.TI.Records, "MAL-2026-1#001", "pkg:npm/evil", "osv:ecosystem:=1.0.0", "known-malicious", "high")
	assertRecord(t, envelope.TI.Records, "MAL-2026-1#002", "pkg:npm/evil", "osv:ecosystem:=1.0.1", "known-malicious", "high")
	assertRecord(t, envelope.TI.Records, "GHSA-2026-1", "pkg:pypi/requests", "osv:ecosystem:>=2.0.0 <2.5.0", "needs-review", "medium")
	assertRecord(t, envelope.TI.Records, "GO-2026-1", "pkg:golang/example.com/mod", "osv:semver:<1.2.3", "suspicious", "high")
	if report.Malicious != 2 || report.Vulnerable != 2 || report.Records != 4 {
		t.Fatalf("report=%+v", report)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("bundle must use one trailing newline: %q", raw)
	}
}

func TestBuildUsesExactCVSSNineThreshold(t *testing.T) {
	document := `[
{"id":"CVSS-8.9","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"lower"},"ranges":[],"versions":["1.0.0"]}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L"}],"references":[]},
{"id":"CVSS-9.0","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"threshold"},"ranges":[],"versions":["1.0.0"]}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"references":[]}
]`
	input := inputForDocument(t, document, false, "CC-BY-4.0")
	raw, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, envelope.TI.Records, "CVSS-8.9", "pkg:npm/lower", "osv:ecosystem:=1.0.0", "needs-review", "medium")
	assertRecord(t, envelope.TI.Records, "CVSS-9.0", "pkg:npm/threshold", "osv:ecosystem:=1.0.0", "suspicious", "high")
}

func TestBuildUsesAffectedLevelCVSSWhenTopLevelSeverityIsAbsent(t *testing.T) {
	document := `[{"schema_version":"1.7.4","id":"AFFECTED-CVSS","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"threshold"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"versions":["1.0.0"]}],"references":[]}]`
	input := inputForDocument(t, document, false, "CC-BY-4.0")
	raw, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, envelope.TI.Records, "AFFECTED-CVSS", "pkg:cargo/threshold", "osv:ecosystem:=1.0.0", "suspicious", "high")
}

func TestBuildAcceptsOneOSVRecordPerPinnedSourceFile(t *testing.T) {
	document := `{"schema_version":"1.7.4","id":"MAL-SINGLE","modified":"2026-08-13T00:00:00Z","published":"2026-08-12T00:00:00Z","summary":"Malicious package record","details":"Pinned source file.","affected":[{"package":{"ecosystem":"npm","name":"single-file"},"versions":["1.0.0"]}],"references":[],"database_specific":{"origin":"fixture"}}`
	input := inputForDocument(t, document, true, "Apache-2.0")
	raw, report, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if report.Malicious != 1 || len(envelope.TI.Records) != 1 || envelope.TI.Records[0].ID != "MAL-SINGLE" || envelope.TI.Records[0].License != "Apache-2.0" {
		t.Fatalf("report=%+v records=%+v", report, envelope.TI.Records)
	}
}

func TestBuildAcceptsBoundedPublicOSVReferencesWithQueries(t *testing.T) {
	document := `[{"id":"QUERY-REFERENCE","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"query-reference"},"versions":["1.0.0"]}],"references":[{"type":"WEB","url":"https://example.test/advisory?id=QUERY-REFERENCE#details"}]}]`
	input := inputForDocument(t, document, false, "CC-BY-4.0")
	if _, _, err := Build(input); err != nil {
		t.Fatal(err)
	}
}

func TestBuildConvertsInclusiveAndOpenRangeBoundariesExactly(t *testing.T) {
	document := `[
{"id":"LAST-AFFECTED","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"inclusive"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.1.214"}]}]}]},
{"id":"OPEN-RANGE","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"open-range"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"limit":"*"}]}]}]}
]`
	input := inputForDocument(t, document, false, "CC-BY-4.0")
	raw, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, envelope.TI.Records, "LAST-AFFECTED", "pkg:cargo/inclusive", "osv:ecosystem:<=2.1.214", "needs-review", "medium")
	assertRecord(t, envelope.TI.Records, "OPEN-RANGE", "pkg:npm/open-range", "osv:semver:>=1.0.0", "needs-review", "medium")
}

func TestBuildPreservesPyPIEcosystemOrderingAtMatchTime(t *testing.T) {
	document := `[{"id":"PYPI-POST","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"post-boundary"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0-1"}]}]}]}]`
	input := inputForDocument(t, document, true, "Apache-2.0")
	raw, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.TI.Records) != 1 || envelope.TI.Records[0].Verdict != "known-malicious" {
		t.Fatalf("records=%+v", envelope.TI.Records)
	}
	matched, supported := versionmatch.Match(envelope.TI.Records[0].AssetID, "1.0", envelope.TI.Records[0].VersionRange)
	if !supported || matched {
		t.Fatalf("unaffected PyPI 1.0 matched %q: matched=%v supported=%v", envelope.TI.Records[0].VersionRange, matched, supported)
	}
	matched, supported = versionmatch.Match(envelope.TI.Records[0].AssetID, "1.0.post1", envelope.TI.Records[0].VersionRange)
	if !supported || !matched {
		t.Fatalf("affected PyPI 1.0.post1 did not match %q: matched=%v supported=%v", envelope.TI.Records[0].VersionRange, matched, supported)
	}
}

func TestBuildRetainsWithdrawnRecordsWithoutChangingTheirClassification(t *testing.T) {
	document := `[{
"id":"MAL-WITHDRAWN","modified":"2026-08-13T00:00:00Z","withdrawn":"2026-08-13T12:00:00Z",
"affected":[{"package":{"ecosystem":"crates.io","name":"bad-crate"},"ranges":[],"versions":["3.2.1"]}],
"severity":[],"references":[]
}]`
	input := inputForDocument(t, document, true, "CC-BY-4.0")
	raw, report, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.TI.Records) != 1 || !envelope.TI.Records[0].Withdrawn || envelope.TI.Records[0].Verdict != "known-malicious" || report.Withdrawn != 1 {
		t.Fatalf("record=%+v report=%+v", envelope.TI.Records, report)
	}
}

func TestBuildKeepsMaliciousFalsePositiveVersionsOutOfRange(t *testing.T) {
	document := `[{
"id":"MAL-EXACT","modified":"2026-08-13T00:00:00Z",
"affected":[{"package":{"ecosystem":"PyPI","name":"Bad_Package"},"ranges":[],"versions":["1.0.0","1.2.0"]}],
"severity":[],"references":[]
}]`
	input := inputForDocument(t, document, true, "CC-BY-4.0")
	raw, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, envelope.TI.Records, "MAL-EXACT#001", "pkg:pypi/bad-package", "osv:ecosystem:=1.0.0", "known-malicious", "high")
	assertRecord(t, envelope.TI.Records, "MAL-EXACT#002", "pkg:pypi/bad-package", "osv:ecosystem:=1.2.0", "known-malicious", "high")
	for _, record := range envelope.TI.Records {
		if strings.Contains(record.VersionRange, ">=") {
			t.Fatalf("malicious explicit versions were broadened: %q", record.VersionRange)
		}
	}
}

func TestBuildSplitsLargeValidOSVShapesWithoutTruncation(t *testing.T) {
	t.Run("84 affected packages", func(t *testing.T) {
		var affected strings.Builder
		for index := 0; index < 84; index++ {
			if index > 0 {
				affected.WriteByte(',')
			}
			fmt.Fprintf(&affected, `{"package":{"ecosystem":"npm","name":"workspace-%02d"},"versions":["1.0.0"]}`, index)
		}
		document := `[{"id":"GHSA-MANY-AFFECTED","modified":"2026-08-13T00:00:00Z","affected":[` + affected.String() + `]}]`
		input := inputForDocument(t, document, false, "CC-BY-4.0")
		raw, report, err := Build(input)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := bundle.Load(raw, input.GeneratedAt)
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope.TI.Records) != 84 || report.Records != 84 || report.Vulnerable != 84 {
			t.Fatalf("records=%d report=%+v", len(envelope.TI.Records), report)
		}
		if envelope.TI.Records[0].ID != "GHSA-MANY-AFFECTED#001" || envelope.TI.Records[83].ID != "GHSA-MANY-AFFECTED#084" {
			t.Fatalf("non-deterministic child ids: first=%q last=%q", envelope.TI.Records[0].ID, envelope.TI.Records[83].ID)
		}
	})

	t.Run("range plus 56 explicit versions", func(t *testing.T) {
		versions := make([]string, 56)
		for index := range versions {
			versions[index] = fmt.Sprintf("1.0.post%d", index+1)
		}
		encodedVersions, err := json.Marshal(versions)
		if err != nil {
			t.Fatal(err)
		}
		document := `[{"id":"GHSA-MANY-VERSIONS","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"many-versions"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}],"versions":` + string(encodedVersions) + `}]}]`
		input := inputForDocument(t, document, false, "CC-BY-4.0")
		raw, report, err := Build(input)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := bundle.Load(raw, input.GeneratedAt)
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope.TI.Records) != 57 || report.Records != 57 {
			t.Fatalf("records=%d report=%+v", len(envelope.TI.Records), report)
		}
		for _, record := range envelope.TI.Records {
			if record.AssetID != "pkg:pypi/many-versions" || !strings.HasPrefix(record.ID, "GHSA-MANY-VERSIONS#") {
				t.Fatalf("record=%+v", record)
			}
		}
	})
}

func TestBuildRejectsOnlyUnrepresentableAffectedSibling(t *testing.T) {
	document := `[{"id":"MIXED-AFFECTED","modified":"2026-08-13T00:00:00Z","affected":[
{"package":{"ecosystem":"npm","name":"representable"},"versions":["1.0.0"]},
{"package":{"ecosystem":"PyPI","name":"requires-git"},"ranges":[{"type":"GIT","repo":"https://example.test/repo.git","events":[{"introduced":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}
]}]`
	input := inputForDocument(t, document, false, "CC-BY-4.0")
	raw, report, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.TI.Records) != 1 || envelope.TI.Records[0].AssetID != "pkg:npm/representable" || report.RejectedAffected != 1 {
		t.Fatalf("records=%+v report=%+v", envelope.TI.Records, report)
	}
}

func TestBuildMergesOSVAggregateAndAuthoritativeOpenSSFOverlap(t *testing.T) {
	osvDocument := `[{"schema_version":"1.7.4","id":"MAL-2025-191840","modified":"2026-05-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"python-doenv"},"versions":["0.1.0"]}]}]`
	openSSFDocument := `{"schema_version":"1.7.4","id":"MAL-2025-191840","modified":"2026-05-02T00:00:00Z","published":"2025-12-01T00:00:00Z","summary":"Malicious code in python-doenv (PyPI)","details":"Pinned overlap shape.","affected":[{"package":{"ecosystem":"PyPI","name":"python-doenv"},"versions":["0.1.0"]}],"database_specific":{"malicious-packages-origins":[{"id":"pypi/fixture/python-doenv","source":"fixture","versions":["0.1.0"]}]}}`
	input := fixtureInput(t)
	input.OSV = []Source{{Path: writeDocument(t, osvDocument), License: "CC-BY-4.0", PublicURLBase: "https://osv.dev/vulnerability/"}}
	input.OpenSSF = []Source{{Path: writeDocument(t, openSSFDocument), License: "Apache-2.0", PublicURLBase: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/"}}
	raw, report, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.TI.Records) != 1 {
		t.Fatalf("records=%+v", envelope.TI.Records)
	}
	record := envelope.TI.Records[0]
	if record.ID != "MAL-2025-191840" || record.AssetID != "pkg:pypi/python-doenv" || record.Verdict != "known-malicious" || record.Confidence != "high" || record.License != "Apache-2.0 AND CC-BY-4.0" || strings.Join(record.SourceURLs, ",") != "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/MAL-2025-191840,https://osv.dev/vulnerability/MAL-2025-191840" {
		t.Fatalf("record=%+v", record)
	}
	if report.Records != 1 || report.Malicious != 1 || report.Vulnerable != 0 || len(report.Attributions) != 2 || report.Attributions[0].Category != "malicious" || report.Attributions[1].Category != "vulnerable" {
		t.Fatalf("report=%+v", report)
	}

	input.OpenSSF = nil
	raw, _, err = Build(input)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err = bundle.Load(raw, input.GeneratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.TI.Records[0].Verdict != "needs-review" {
		t.Fatalf("OSV-only MAL record self-promoted: %+v", envelope.TI.Records[0])
	}
}

func TestBuildRejectsIncompatibleOSVOpenSSFOverlapSelectors(t *testing.T) {
	osvDocument := `[{"id":"MAL-CONFLICT","modified":"2026-05-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"overlap"},"versions":["1.0.0"]}]}]`
	openSSFDocument := `[{"id":"MAL-CONFLICT","modified":"2026-05-02T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"overlap"},"versions":["2.0.0"]}]}]`
	input := fixtureInput(t)
	input.OSV = []Source{{Path: writeDocument(t, osvDocument), License: "CC-BY-4.0", PublicURLBase: "https://osv.dev/vulnerability/"}}
	input.OpenSSF = []Source{{Path: writeDocument(t, openSSFDocument), License: "Apache-2.0", PublicURLBase: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/"}}
	assertBuildError(t, input, "conflicting duplicate")
}

func TestBuildRejectsUnsupportedEcosystem(t *testing.T) {
	document := `[{"id":"MAVEN-1","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"example"},"ranges":[],"versions":["1.0.0"]}],"severity":[],"references":[]}]`
	assertBuildError(t, inputForDocument(t, document, false, "CC-BY-4.0"), "unsupported ecosystem")
}

func TestBuildRejectsAbsentOrDisallowedSourceLicense(t *testing.T) {
	document := `[{"id":"LICENSE-1","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[],"versions":["1.0.0"]}],"severity":[],"references":[]}]`
	for _, license := range []string{"", "Proprietary", "GPL-3.0-only"} {
		t.Run(license, func(t *testing.T) {
			assertBuildError(t, inputForDocument(t, document, false, license), "redistributable license")
		})
	}
}

func TestBuildRejectsMalformedOrLossyRanges(t *testing.T) {
	documents := map[string]string{
		"fixed without introduced": `[{"id":"BAD-RANGE-1","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"SEMVER","events":[{"fixed":"2.0.0"}]}],"versions":[]}],"severity":[],"references":[]}]`,
		"unsupported git range":    `[{"id":"BAD-RANGE-2","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}],"versions":[]}],"severity":[],"references":[]}]`,
		"unclosed event":           `[{"id":"BAD-RANGE-3","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"introduced":"2.0.0"}]}],"versions":[]}],"severity":[],"references":[]}]`,
		"unknown field":            `[{"id":"BAD-RANGE-4","modified":"2026-08-13T00:00:00Z","affected":[],"severity":[],"references":[],"unrecognized":"not in the closed subset"}]`,
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			assertBuildError(t, inputForDocument(t, document, false, "CC-BY-4.0"), "source record")
		})
	}
}

func TestBuildDeduplicatesRecordsAndIsByteIdenticalWhenSourcesAreShuffled(t *testing.T) {
	input := fixtureInput(t)
	input.OSV = append(input.OSV, input.OSV[0])
	input.OpenSSF = append(input.OpenSSF, input.OpenSSF[0])
	first, firstReport, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	input.OSV[0], input.OSV[1] = input.OSV[1], input.OSV[0]
	input.OpenSSF[0], input.OpenSSF[1] = input.OpenSSF[1], input.OpenSSF[0]
	second, secondReport, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("shuffled output differs\nfirst=%s\nsecond=%s", first, second)
	}
	if !reflect.DeepEqual(firstReport, secondReport) || firstReport.Records != 4 || firstReport.Duplicates != 3 {
		t.Fatalf("first=%+v second=%+v", firstReport, secondReport)
	}
}

func TestBuildRejectsConflictingDuplicateRecordIDs(t *testing.T) {
	input := fixtureInput(t)
	document := `[{"id":"GHSA-2026-1","modified":"2026-08-13T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"different"},"ranges":[],"versions":["1.0.0"]}],"severity":[],"references":[]}]`
	path := writeDocument(t, document)
	input.OSV = append(input.OSV, Source{Path: path, License: "CC-BY-4.0", PublicURLBase: "https://osv.dev/vulnerability/"})
	assertBuildError(t, input, "conflicting duplicate")
}

func TestBuildRejectsInvalidMetadataAndPublicSourceConfiguration(t *testing.T) {
	input := fixtureInput(t)
	input.Sequence = 0
	assertBuildError(t, input, "metadata")

	input = fixtureInput(t)
	input.OSV[0].PublicURLBase = "http://osv.dev/vulnerability/"
	assertBuildError(t, input, "public source")

	input = fixtureInput(t)
	input.OSV[0].Path = filepath.Join(t.TempDir(), "missing.json")
	assertBuildError(t, input, "read source")
}

func fixtureInput(t *testing.T) Input {
	t.Helper()
	return Input{
		OSV: []Source{{
			Path:          filepath.Join("testdata", "osv-vulnerable.json"),
			License:       "CC-BY-4.0",
			PublicURLBase: "https://osv.dev/vulnerability/",
		}},
		OpenSSF: []Source{{
			Path:          filepath.Join("testdata", "openssf-malicious.json"),
			License:       "CC-BY-4.0",
			PublicURLBase: "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/",
		}},
		Version:     "2026.08.14",
		Sequence:    42,
		KeyID:       "ti-production-2026",
		GeneratedAt: fixtureTime,
		ValidFrom:   fixtureTime.Add(-time.Hour),
		ValidUntil:  fixtureTime.Add(7 * 24 * time.Hour),
	}
}

func inputForDocument(t *testing.T, document string, malicious bool, license string) Input {
	t.Helper()
	input := fixtureInput(t)
	input.OSV = nil
	input.OpenSSF = nil
	source := Source{Path: writeDocument(t, document), License: license, PublicURLBase: "https://example.test/records/"}
	if malicious {
		input.OpenSSF = []Source{source}
	} else {
		input.OSV = []Source{source}
	}
	return input
}

func writeDocument(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertBuildError(t *testing.T, input Input, contains string) {
	t.Helper()
	if _, _, err := Build(input); err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("error=%v, want containing %q", err, contains)
	}
}

func assertRecord(t *testing.T, records []bundle.TIRecord, id, assetID, versionRange, verdict, confidence string) {
	t.Helper()
	for _, record := range records {
		if record.ID != id {
			continue
		}
		if record.AssetID != assetID || record.VersionRange != versionRange || record.Verdict != verdict || record.Confidence != confidence || record.License != "CC-BY-4.0" || !record.Redistributable || len(record.SourceURLs) != 1 {
			t.Fatalf("record=%+v", record)
		}
		return
	}
	t.Fatalf("missing record %q in %+v", id, records)
}

func TestReportJSONIsClosedAndStable(t *testing.T) {
	_, report, err := Build(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Version      string `json:"version"`
		Sequence     uint64 `json:"sequence"`
		Records      int    `json:"records"`
		Sources      int    `json:"sources"`
		Attributions []struct {
			ID         string     `json:"id"`
			Category   string     `json:"category"`
			License    string     `json:"license"`
			PublicURL  string     `json:"publicUrl"`
			Severities []Severity `json:"severities"`
		} `json:"attributions"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Version != "2026.08.14" || decoded.Sequence != 42 || decoded.Records != 4 || decoded.Sources != 2 || len(decoded.Attributions) != 4 || decoded.Attributions[0].ID != "GHSA-2026-1" || decoded.Attributions[0].Severities[0].Type != "CVSS_V3" {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
}
