package provenance

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestParseRequirementsNormalizesAndRedactsInput(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := "Foo_Bar==1.2.3 ; python_version >= \"3.11\" \\\n    --hash=sha256:" + digest + "\n" +
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

func TestParseRequirementsAcceptsPEP508WhitespaceMarkersAndComments(t *testing.T) {
	input := `jinja2 >= 3.1.0  # minimum runtime
resolvelib >= 0.8.0, < 2.0.0  # bounded dependency
bcrypt < 5 ; python_version >= '3.13'
typing_extensions; python_version < '3.11'
`
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 4 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	want := []string{"bcrypt", "jinja2", "resolvelib", "typing-extensions"}
	for index, record := range records {
		if record.Name != want[index] || record.Version != "" || record.Provenance.Status != model.ProvenanceMutable {
			t.Fatalf("record[%d]=%+v want name=%q mutable", index, record, want[index])
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

func TestParseRequirementsRejectsContinuationInterruptedByComment(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := "demo==1.0 \\\n# interrupted continuation\n" +
		"--hash=sha256:" + digest + "\n"
	if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("interrupted continuation accepted: %v", err)
	}
}

func TestRequirementLinesBuildsManyContinuationsWithBoundedAllocations(t *testing.T) {
	const continuations = 4096
	contents := []byte(strings.Repeat("x\\\n", continuations) + "x\n")
	wantLength := continuations + 1

	allocations := testing.AllocsPerRun(3, func() {
		lines, ok := requirementLines(contents)
		if !ok || len(lines) != 1 || len(lines[0]) != wantLength {
			panic("many-continuation requirement was not assembled")
		}
	})
	if allocations > 64 {
		t.Fatalf("requirementLines allocations=%.0f want<=64", allocations)
	}
}

func TestParseRequirementsIgnoresAttachedIncludeOptions(t *testing.T) {
	input := "-rprivate-requirements.txt\n-cprivate-constraints.txt\nsafe==1.0\n"
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "safe" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if strings.Contains(recordText(records), "private") {
		t.Fatalf("attached include target retained: %+v", records)
	}
}

func TestParseRequirementsRejectsMalformedHashesForMutableEntries(t *testing.T) {
	for _, input := range []string{
		"ranged>=1 --hash=sha256:" + strings.Repeat("a", 63) + "\n",
		"direct @ https://user:secret@example.invalid/demo.whl --hash=sha512:not-hex\n",
	} {
		if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("mutable requirement accepted malformed hash: %v", err)
		}
	}
}

func TestParseRequirementsAcceptsValidHashForEditableEntry(t *testing.T) {
	digest := strings.Repeat("a", 64)
	validEditable := "-e git+https://user:secret@example.invalid/demo.git#egg=demo --hash=sha256:" + digest + "\n"
	records, err := Parse(context.Background(), FormatRequirements, strings.NewReader(validEditable), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "demo" || records[0].Provenance.Status != model.ProvenanceMutable || records[0].Provenance.Integrity != "" {
		t.Fatalf("valid editable records=%+v err=%v", records, err)
	}
}

func TestParseRequirementsRejectsMalformedHashesForEditableAndSkippedEntries(t *testing.T) {
	for _, input := range []string{
		"--editable=git+https://user:secret@example.invalid/demo.git#egg=demo --hash=sha256:" + strings.Repeat("a", 63) + "\n",
		"https://user:secret@example.invalid/demo.whl --hash=sha256:" + strings.Repeat("a", 63) + "\n",
		"git+https://user:secret@example.invalid/demo.git --hash=sha512:not-hex\n",
		"../private-demo --hash=sha256:" + strings.Repeat("a", 63) + "\n",
	} {
		if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("editable or skipped requirement accepted malformed hash: %v", err)
		}
	}
}

func TestPythonParsersRejectCaseVariantSHA256Algorithms(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		format Format
		input  string
	}{
		{FormatRequirements, "demo>=1 --hash=SHA256:" + digest + "\n"},
		{FormatPipfile, `{"default":{"demo":{"version":"==1.0","path":"../private","hashes":["SHA256:` + digest + `"]}}}`},
	}
	for _, testCase := range tests {
		if _, err := Parse(context.Background(), testCase.format, strings.NewReader(testCase.input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("format %q accepted SHA256 case variant: %v", testCase.format, err)
		}
	}
}

func TestParseRequirementsRejectsUnsupportedTrailingTokens(t *testing.T) {
	for _, input := range []string{
		"demo==1.0 unexpected\n",
		"demo==1.0 --unsupported-option\n",
		"demo>=1 trailing\n",
		"demo @ https://example.invalid/demo.whl unexpected\n",
	} {
		if _, err := Parse(context.Background(), FormatRequirements, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("requirement with trailing token accepted: %q err=%v", input, err)
		}
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
	if records[0].Name != "direct" || records[0].Version != "9.0.0" || records[0].Provenance.Status != model.ProvenanceMutable ||
		records[1].Name != "foo-bar" || records[1].Version != "1.2.3" || records[1].Provenance.Integrity != "sha256:"+digest ||
		records[2].Name != "zoo" || records[2].Version != "3.0.0" {
		t.Fatalf("records=%+v", records)
	}
	if strings.Contains(records[0].Version, "secret") {
		t.Fatalf("mutable source retained: %+v", records[0])
	}
}

func TestParsePipfileRejectsMalformedHashesForMutableEntries(t *testing.T) {
	for _, input := range []string{
		`{"default":{"path-source":{"version":"==1.0","path":"../private","hashes":["sha256:` + strings.Repeat("a", 63) + `"]}}}`,
		`{"default":{"git-source":{"version":"==1.0","git":"https://user:secret@example.invalid/repo.git","hashes":["sha512:not-hex"]}}}`,
	} {
		if _, err := Parse(context.Background(), FormatPipfile, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("mutable Pipfile entry accepted malformed hash: %v", err)
		}
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

func TestParsePoetryClassifiesRegistryHashesAndRedactsMetadata(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	input := `[[package]]
name = "Foo__Bar"
version = "1.2.3"
groups = ["main", "dev"]
markers = "python_version >= '3.11'"
extras = ["private-extra"]
files = [{ file = "private-wheel.whl", hash = "sha256:` + a + `" }]

[[package]]
name = "multi"
version = "2.0.0"
files = [{ file = "first.whl", hash = "sha256:` + a + `" }, { file = "second.whl", hash = "sha256:` + b + `" }]

[[package]]
name = "hashless"
version = "3.0.0"

[metadata]
content-hash = "private-content-hash"
`
	records, err := Parse(context.Background(), FormatPoetry, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 3 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	want := map[string]struct {
		status    model.ProvenanceStatus
		integrity string
	}{
		"foo-bar\x001.2.3":  {model.ProvenanceImmutable, "sha256:" + a},
		"multi\x002.0.0":    {model.ProvenanceUnknown, ""},
		"hashless\x003.0.0": {model.ProvenanceUnknown, ""},
	}
	for _, record := range records {
		got, ok := want[record.Name+"\x00"+record.Version]
		if !ok || record.Provenance.Status != got.status || record.Provenance.Integrity != got.integrity {
			t.Fatalf("record=%+v want=%+v", record, want)
		}
	}
	for _, private := range []string{"private-wheel", "first.whl", "private-content-hash", "python_version", "private-extra"} {
		if strings.Contains(recordText(records), private) {
			t.Fatalf("private TOML field retained in records: %q", private)
		}
	}
}

func TestParsePoetryMarksNonLegacySourcesAndDevelopMutable(t *testing.T) {
	input := `[[package]]
name = "directory"
version = "1.0.0"
source = { type = "directory", url = "../private-directory" }

[[package]]
name = "file"
version = "1.0.0"
source = { type = "file", url = "https://user:secret@example.invalid/private.whl" }

[[package]]
name = "url"
version = "1.0.0"
source = { type = "url", url = "https://user:secret@example.invalid/private.whl" }

[[package]]
name = "git"
version = "1.0.0"
source = { type = "git", url = "https://user:secret@example.invalid/private.git" }

[[package]]
name = "develop"
version = "1.0.0"
develop = true
source = { type = "legacy" }
`
	records, err := Parse(context.Background(), FormatPoetry, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 5 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	for _, record := range records {
		if record.Provenance.Status != model.ProvenanceMutable || record.Provenance.Integrity != "" {
			t.Fatalf("record=%+v", record)
		}
	}
	if strings.Contains(recordText(records), "secret") || strings.Contains(recordText(records), "private") {
		t.Fatalf("mutable source text retained: %+v", records)
	}
}

func TestParsePoetryRejectsMalformedEntries(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, input := range []string{
		"package = []\n",
		"[[package]]\nversion = \"1.0.0\"\n",
		"[[package]]\nname = \"Foo\"\nversion = \"1.0.0\"\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\nfiles = [{ hash = \"sha256:" + digest + "\" }]\n",
		"[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nfiles = [{ hash = \"sha256:" + strings.Repeat("a", 63) + "\" }]\n",
		"[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nfiles = [{ hash = \"\" }]\n",
	} {
		if _, err := Parse(context.Background(), FormatPoetry, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestParsePoetryRejectsMalformedHashForMutableSource(t *testing.T) {
	input := "[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = { type = \"directory\", url = \"../private-directory\" }\nfiles = [{ hash = \"sha256:" + strings.Repeat("a", 63) + "\" }]\n"
	if _, err := Parse(context.Background(), FormatPoetry, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("mutable package accepted malformed hash: %v", err)
	}
}

func TestParseUVClassifiesArtifactHashesAndRedactsLocations(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	input := `[[package]]
name = "Foo__Bar"
version = "1.2.3"
source = { registry = "https://user:secret@example.invalid/simple" }
sdist = { url = "https://user:secret@example.invalid/private.tar.gz", hash = "sha256:` + a + `" }

[[package]]
name = "multi"
version = "2.0.0"
source = { registry = "https://example.invalid/simple" }
sdist = { url = "https://example.invalid/private.tar.gz", hash = "sha256:` + a + `" }
wheels = [{ url = "https://example.invalid/private.whl", hash = "sha256:` + b + `" }]

[[package]]
name = "hashless"
version = "3.0.0"
source = { registry = "https://example.invalid/simple" }
`
	records, err := Parse(context.Background(), FormatUV, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 3 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	want := map[string]struct {
		status    model.ProvenanceStatus
		integrity string
	}{
		"foo-bar\x001.2.3":  {model.ProvenanceImmutable, "sha256:" + a},
		"multi\x002.0.0":    {model.ProvenanceUnknown, ""},
		"hashless\x003.0.0": {model.ProvenanceUnknown, ""},
	}
	for _, record := range records {
		got, ok := want[record.Name+"\x00"+record.Version]
		if !ok || record.Provenance.Status != got.status || record.Provenance.Integrity != got.integrity {
			t.Fatalf("record=%+v want=%+v", record, want)
		}
	}
	for _, private := range []string{"https://", "secret", "private.tar", "private.whl"} {
		if strings.Contains(recordText(records), private) {
			t.Fatalf("private artifact field retained in records: %q", private)
		}
	}
}

func TestParseUVMarksNonRegistryAndMissingVersionMutable(t *testing.T) {
	input := `[[package]]
name = "git"
version = "1.0.0"
source = { git = "https://user:secret@example.invalid/private.git" }

[[package]]
name = "editable"
version = "1.0.0"
source = { editable = "../private-editable" }

[[package]]
name = "virtual"
version = "1.0.0"
source = { virtual = "." }

[[package]]
name = "path"
version = "1.0.0"
source = { path = "../private-path" }

[[package]]
name = "missing-version"
source = { registry = "https://example.invalid/simple" }
`
	records, err := Parse(context.Background(), FormatUV, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 4 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	for _, record := range records {
		if record.Provenance.Status != model.ProvenanceMutable || record.Provenance.Integrity != "" {
			t.Fatalf("record=%+v", record)
		}
	}
	if strings.Contains(recordText(records), "secret") || strings.Contains(recordText(records), "private") {
		t.Fatalf("mutable source text retained: %+v", records)
	}
}

func TestParseUVOmitsVirtualWorkspacePackages(t *testing.T) {
	input := `[[package]]
name = "registry"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "workspace-root"
version = "0.0.0"
source = { virtual = "." }

[[package]]
name = "path-dependency"
version = "2.0.0"
source = { path = "../private-path" }
`
	records, err := Parse(context.Background(), FormatUV, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 2 || records[0].Name != "path-dependency" || records[1].Name != "registry" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if records[0].Provenance.Status != model.ProvenanceMutable || records[1].Provenance.Status != model.ProvenanceUnknown {
		t.Fatalf("records=%+v", records)
	}
}

func TestParseUVRejectsMalformedEntries(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, input := range []string{
		"package = []\n",
		"[[package]]\nversion = \"1.0.0\"\nsource = { registry = \"https://example.invalid/simple\" }\n",
		"[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = []\n",
		"[[package]]\nname = \"Foo\"\nversion = \"1.0.0\"\nsource = { registry = \"https://example.invalid/simple\" }\n[[package]]\nname = \"foo\"\nversion = \"1.0.0\"\nsource = { registry = \"https://example.invalid/simple\" }\nsdist = { hash = \"sha256:" + digest + "\" }\n",
		"[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = { registry = \"https://example.invalid/simple\" }\nsdist = { hash = \"sha256:" + strings.Repeat("a", 63) + "\" }\n",
		"[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = { registry = \"https://example.invalid/simple\" }\nsdist = { hash = \"\" }\n",
	} {
		if _, err := Parse(context.Background(), FormatUV, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted %q: %v", input, err)
		}
	}
}

func TestParseUVRejectsMalformedHashForMutableSource(t *testing.T) {
	input := "[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\nsource = { git = \"https://user:secret@example.invalid/private.git\" }\nwheels = [{ hash = \"sha256:" + strings.Repeat("a", 63) + "\" }]\n"
	if _, err := Parse(context.Background(), FormatUV, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("mutable package accepted malformed hash: %v", err)
	}
}

func recordText(records []Record) string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		values = append(values, record.Ecosystem+" "+record.Name+" "+record.Version+" "+record.Provenance.Integrity)
	}
	return strings.Join(values, "\n")
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

func TestPythonRecordRejectsMalformedUnsupportedHashSyntax(t *testing.T) {
	for _, hash := range []string{
		"sha512:not-hex",
		"sha512:" + strings.Repeat("A", 128),
		"sha512:abc",
		"sha 512:" + strings.Repeat("a", 128),
		"_sha512:" + strings.Repeat("a", 128),
		"sha512_:" + strings.Repeat("a", 128),
	} {
		if got, ok := pythonRecord("demo", "1.2.3", true, []string{hash}); ok {
			t.Fatalf("malformed unsupported hash %q accepted: %+v", hash, got)
		}
	}
}

func TestDistinctPythonSHA256ReturnsSortedDigests(t *testing.T) {
	hashes := []string{
		"sha256:" + strings.Repeat("f", 64),
		"sha256:" + strings.Repeat("1", 64),
		"sha256:" + strings.Repeat("d", 64),
		"sha256:" + strings.Repeat("3", 64),
		"sha256:" + strings.Repeat("b", 64),
		"sha256:" + strings.Repeat("5", 64),
	}
	for attempt := 0; attempt < 20; attempt++ {
		got, ok := distinctPythonSHA256(hashes)
		if !ok || !sort.StringsAreSorted(got) {
			t.Fatalf("digests=%q valid=%v", got, ok)
		}
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
