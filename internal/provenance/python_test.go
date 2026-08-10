package provenance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestParseRequirementsNormalizesAndRedactsInput(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := "Foo_Bar==1.2.3 ; python_version >= \"3.11\" \\\n+    --hash=sha256:" + digest + "\n" +
		"--index-url https://user:secret@example.invalid/simple\n" +
		"-r private-requirements.txt\n"
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	record := records[0]
	if record.Ecosystem != "pypi" || record.Name != "foo-bar" || record.Version != "1.2.3" ||
		record.Provenance.Status != model.ProvenanceImmutable || record.Provenance.Integrity != "sha256:"+digest {
		t.Fatalf("record=%+v", record)
	}
	formatted := record.Name + "@" + record.Version + " " + record.Provenance.Integrity + " " + errString(err)
	for _, secret := range []string{"https://", "secret", "python_version", "private-requirements"} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("sensitive input retained in %q", formatted)
		}
	}
}

func TestParseRequirementsClassifiesHashesAndMutableReferences(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	input := "hashless==1.0.0\n" +
		"multi==2.0 --hash=sha256:" + a + " --hash=sha256:" + b + "\n" +
		"direct @ https://user:secret@example.invalid/direct.whl\n" +
		"--editable=git+https://user:secret@example.invalid/editable.git#egg=editable\n" +
		"ranged>=1.0\n" +
		"../private-package\n" +
		"hashless==1.0.0\n"
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 5 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	want := map[string]model.ProvenanceStatus{
		"hashless\x001.0.0": model.ProvenanceUnknown,
		"multi\x002.0":      model.ProvenanceUnknown,
		"direct\x00":        model.ProvenanceMutable,
		"editable\x00":      model.ProvenanceMutable,
		"ranged\x00":        model.ProvenanceMutable,
	}
	for _, record := range records {
		key := record.Name + "\x00" + record.Version
		status, found := want[key]
		if !found || record.Provenance.Status != status || record.Provenance.Integrity != "" {
			t.Fatalf("record=%+v want=%v", record, want)
		}
		if strings.Contains(record.Version, "secret") {
			t.Fatalf("mutable source retained: %+v", record)
		}
	}
}

func TestParseRequirementsRejectsUnsafeOrConflictingEntries(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, input := range []string{
		"demo==1.0 --hash=sha256:" + strings.Repeat("a", 63) + "\n",
		"demo==1.0\ndemo==1.0 --hash=sha256:" + digest + "\n",
		"--no-binary demo\n",
	} {
		if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestParseRequirementsHandlesCRLFBoundsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, FormatRequirements, strings.NewReader("demo==1.0\r\n"), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
	if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader("demo==1.0\r\n"), 5); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize err=%v", err)
	}
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader("demo==1.0\r\n"), 100)
	if err != nil || len(records) != 1 || records[0].Name != "demo" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParsePipfileCombinesSectionsAndSorts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := `{
  "_meta": {"sources": [{"url": "https://user:secret@example.invalid/simple"}]},
  "develop": {"Zoo": {"version": "==3.0.0"}},
  "default": {
    "Foo_Bar": {"version": "==1.2.3", "hashes": ["sha256:` + digest + `"]},
    "direct": {"version": "==9.0.0", "file": "https://user:secret@example.invalid/direct.whl"}
  }
}`
	records, err := Parse(context.Background(), FormatPipfile, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 3 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if records[0].Name != "direct" || records[0].Version != "" || records[0].Provenance.Status != model.ProvenanceMutable ||
		records[1].Name != "foo-bar" || records[1].Version != "1.2.3" || records[1].Provenance.Integrity != "sha256:"+digest ||
		records[2].Name != "zoo" || records[2].Version != "3.0.0" {
		t.Fatalf("records=%+v", records)
	}
	if strings.Contains(records[0].Version, "secret") {
		t.Fatalf("mutable source retained: %+v", records[0])
	}
}

func TestParsePipfileClassifiesAndRejectsInvalidShapes(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	valid := `{"default":{"hashless":{"version":"==1.0"},"multi":{"version":"==2.0","hashes":["sha256:` + a + `","sha256:` + b + `"]},"git":{"git":"https://example.invalid/repo.git","editable":true},"path":{"path":"../private-package"},"range":{"version":">=3"}},"develop":{}}`
	records, err := Parse(context.Background(), FormatPipfile, strings.NewReader(valid), 1<<20)
	if err != nil || len(records) != 5 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	for _, record := range records {
		if record.Name == "hashless" || record.Name == "multi" {
			if record.Provenance.Status != model.ProvenanceUnknown {
				t.Fatalf("record=%+v", record)
			}
		} else if record.Provenance.Status != model.ProvenanceMutable {
			t.Fatalf("record=%+v", record)
		}
	}
	for _, input := range []string{
		`{"default":[]}`, `{"default":{"demo":"==1.0"}}`, `{"default":{"demo":{"version":"==1.0","hashes":["sha256:` + strings.Repeat("a", 63) + `"]}}}`,
		`{"default":{"Foo":{"version":"==1.0"},"foo":{"version":"==1.0","hashes":["sha256:` + a + `"]}}}`, `{"default":{"demo":{"version":"==1.0"}},"default":{}}`, `{"default":{}} trailing`,
	} {
		if _, err := Parse(context.Background(), FormatPipfile, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestPythonRecordClassifiesIntegrityConservatively(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	tests := []struct {
		name, version string
		mutable       bool
		hashes        []string
		wantName      string
		wantStatus    model.ProvenanceStatus
		wantIntegrity string
		ok            bool
	}{
		{"Foo__..Bar", "1.2.3", false, []string{"sha256:" + a}, "foo-bar", model.ProvenanceImmutable, "sha256:" + a, true},
		{"demo", "1.2.3", false, nil, "demo", model.ProvenanceUnknown, "", true},
		{"demo", "1.2.3", false, []string{"sha256:" + a, "sha256:" + b}, "demo", model.ProvenanceUnknown, "", true},
		{"demo", "1.2.3", true, []string{"sha256:" + a}, "demo", model.ProvenanceMutable, "", true},
		{"/private/demo", "1.2.3", false, nil, "", "", "", false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name+"/"+testCase.version, func(t *testing.T) {
			got, ok := pythonRecord(testCase.name, testCase.version, testCase.mutable, testCase.hashes)
			if ok != testCase.ok {
				t.Fatalf("ok=%v want=%v record=%+v", ok, testCase.ok, got)
			}
			if !ok {
				return
			}
			if got.Name != testCase.wantName || got.Version != testCase.version ||
				got.Ecosystem != "pypi" || got.Provenance.Ecosystem != "pypi" ||
				got.Provenance.Source != "lockfile" || got.Provenance.Status != testCase.wantStatus ||
				got.Provenance.Integrity != testCase.wantIntegrity {
				t.Fatalf("record=%+v", got)
			}
		})
	}
}

func TestPythonRecordDeduplicatesIdenticalSHA256(t *testing.T) {
	digest := strings.Repeat("a", 64)
	got, ok := pythonRecord("demo", "1.2.3", false, []string{"sha256:" + digest, "sha256:" + digest})
	if !ok || got.Provenance.Status != model.ProvenanceImmutable || got.Provenance.Integrity != "sha256:"+digest {
		t.Fatalf("record=%+v ok=%v", got, ok)
	}
}

func TestPythonRecordIgnoresValidNonSHA256Hashes(t *testing.T) {
	got, ok := pythonRecord("demo", "1.2.3", false, []string{"sha512:" + strings.Repeat("a", 128)})
	if !ok || got.Provenance.Status != model.ProvenanceUnknown || got.Provenance.Integrity != "" {
		t.Fatalf("record=%+v ok=%v", got, ok)
	}
}

func TestPythonRecordRejectsMalformedDeclaredSHA256(t *testing.T) {
	for _, hash := range []string{
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
	} {
		t.Run(hash[:12], func(t *testing.T) {
			if got, ok := pythonRecord("demo", "1.2.3", false, []string{hash}); ok {
				t.Fatalf("malformed hash accepted: %+v", got)
			}
		})
	}
}

func TestPythonRecordTreatsFixedPythonVersionsAsExact(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, version := range []string{"1.2.3", "1.2.3.post1", "1!2.0"} {
		t.Run(version, func(t *testing.T) {
			got, ok := pythonRecord("demo", version, false, []string{"sha256:" + digest})
			if !ok || got.Provenance.Status != model.ProvenanceImmutable || got.Provenance.Integrity != "sha256:"+digest {
				t.Fatalf("record=%+v ok=%v", got, ok)
			}
		})
	}
}

func TestPythonRecordMarksSelectorsAndSourcesMutable(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, version := range []string{"", "*", ">=1", "~=1.2", "https://example.test/demo.whl", "git+https://example.test/demo.git", "../demo", "workspace:*"} {
		t.Run(version, func(t *testing.T) {
			got, ok := pythonRecord("demo", version, false, []string{"sha256:" + digest})
			if !ok || got.Provenance.Status != model.ProvenanceMutable || got.Provenance.Integrity != "" {
				t.Fatalf("record=%+v ok=%v", got, ok)
			}
		})
	}
}

func TestPythonRecordDoesNotRetainMutableSourceText(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, version := range []string{"https://example.test/demo.whl", "git+https://example.test/demo.git", "../demo", "workspace:*"} {
		t.Run(version, func(t *testing.T) {
			got, ok := pythonRecord("demo", version, false, []string{"sha256:" + digest})
			if !ok || got.Version != "" || got.Provenance.Status != model.ProvenanceMutable || got.Provenance.Integrity != "" {
				t.Fatalf("record=%+v ok=%v", got, ok)
			}
		})
	}
}

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"Foo__..Bar", "foo-bar", true},
		{"demo", "demo", true},
		{"demo---package", "demo-package", true},
		{"/private/demo", "", false},
		{"demo/child", "", false},
		{"demo-", "", false},
		{"démo", "", false},
	}
	for _, testCase := range tests {
		t.Run(testCase.input, func(t *testing.T) {
			got, ok := normalizePyPIName(testCase.input)
			if got != testCase.want || ok != testCase.ok {
				t.Fatalf("name=%q ok=%v want=%q wantOk=%v", got, ok, testCase.want, testCase.ok)
			}
		})
	}
}
