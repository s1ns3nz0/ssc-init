package provenance

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

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
