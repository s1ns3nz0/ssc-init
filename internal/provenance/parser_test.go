package provenance

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestParseNpmSRIUsesExactApprovedDigestAlgorithms(t *testing.T) {
	for _, test := range []struct {
		algorithm string
		size      int
	}{
		{algorithm: "sha256", size: 32},
		{algorithm: "sha384", size: 48},
		{algorithm: "sha512", size: 64},
	} {
		t.Run(test.algorithm, func(t *testing.T) {
			digest := []byte(strings.Repeat("x", test.size))
			integrity := test.algorithm + "-" + base64.StdEncoding.EncodeToString(digest)
			input := `{"lockfileVersion":3,"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"` + integrity + `"}}}`
			records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
			if err != nil || len(records) != 1 || records[0].Provenance.Status != model.ProvenanceImmutable {
				t.Fatalf("records=%+v err=%v", records, err)
			}
			want := test.algorithm + ":" + hex.EncodeToString(digest)
			if test.algorithm == "sha256" {
				if records[0].Provenance.Integrity != want || records[0].SourceIntegrity != "" {
					t.Fatalf("record=%+v want integrity=%q", records[0], want)
				}
			} else if records[0].Provenance.Integrity != "" || records[0].SourceIntegrity != want {
				t.Fatalf("record=%+v want source integrity=%q", records[0], want)
			}
		})
	}
}

func TestParseNpmSRIRejectsUnapprovedMalformedAndWrongLengthValues(t *testing.T) {
	values := []string{
		"sha1-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 19))),
		"sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 63))),
		"sha384-not-base64",
		"sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 64))) + " sha256-extra",
	}
	for _, integrity := range values {
		input := `{"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"` + integrity + `"}}}`
		if _, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("integrity=%q err=%v", integrity, err)
		}
	}
}

func TestParseNPMSkipsWorkspaceLinksWithoutDroppingPackages(t *testing.T) {
	input := `{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/demo-workspace": {"resolved":"packages/demo", "link":true},
			"node_modules/real-package": {"version":"1.2.3", "integrity":"sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}
		}
	}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "real-package" || records[0].Version != "1.2.3" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseNPMSkipsNamedWorkspacePathsWithoutExternalCoordinates(t *testing.T) {
	input := `{
		"lockfileVersion":3,
		"packages":{
			"packages/local-workspace":{"version":"0.1.0"},
			"node_modules/real-package":{"version":"1.2.3"}
		}
	}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "real-package" || records[0].Version != "1.2.3" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseNPMV3IgnoresPackageDependencyMetadata(t *testing.T) {
	input := `{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.2.3","dependencies":{"child":"^2.0.0"}}}}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "demo" || records[0].Version != "1.2.3" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseNPMMergesDuplicateCoordinateWithSourceIntegrity(t *testing.T) {
	input := `{
		"lockfileVersion":3,
		"packages":{
			"node_modules/parent/node_modules/tslib":{"version":"2.8.1"},
			"node_modules/tslib":{"version":"2.8.1","integrity":"sha512-oJFu94HQb+KVduSUQL7wnpmqnfmLsOA/nAh6b6EH0wCEoK0/mPeXU6c3wKDV83MkOuHPRHtSXKKU99IBazS/2w=="}
		}
	}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "tslib" || records[0].Version != "2.8.1" || records[0].SourceIntegrity != "sha512:a0916ef781d06fe29576e49440bef09e99aa9df98bb0e03f9c087a6fa107d30084a0ad3f98f79753a737c0a0d5f373243ae1cf447b525ca294f7d2016b34bfdb" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseNPMMergesDifferentIntegrityAlgorithmsDeterministically(t *testing.T) {
	sha1 := "sha1-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 20)))
	sha512 := "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 64)))
	for _, test := range []struct {
		name   string
		first  string
		second string
	}{
		{name: "sha1 then sha512", first: sha1, second: sha512},
		{name: "sha512 then sha1", first: sha512, second: sha1},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `{"lockfileVersion":3,"packages":{` +
				`"node_modules/parent/node_modules/demo":{"version":"1.0.0","integrity":"` + test.first + `"},` +
				`"node_modules/demo":{"version":"1.0.0","integrity":"` + test.second + `"}` +
				`}}`
			records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
			want := "sha512:" + strings.Repeat("62", 64)
			if err != nil || len(records) != 1 || records[0].SourceIntegrity != want || records[0].Provenance.Integrity != "" {
				t.Fatalf("records=%+v err=%v want source integrity=%q", records, err, want)
			}
		})
	}
}

func TestParseNPMRejectsSameAlgorithmDigestConflict(t *testing.T) {
	first := "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64)))
	second := "sha512-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 64)))
	input := `{"lockfileVersion":3,"packages":{` +
		`"node_modules/parent/node_modules/demo":{"version":"1.0.0","integrity":"` + first + `"},` +
		`"node_modules/demo":{"version":"1.0.0","integrity":"` + second + `"}` +
		`}}`
	if _, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("conflicting SHA-512 digests accepted: %v", err)
	}
}

func TestParseNPMV1FlattensNestedDependencies(t *testing.T) {
	input := `{
		"lockfileVersion": 1,
		"dependencies": {
			"parent": {
				"version": "1.0.0",
				"integrity": "sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
				"dependencies": {
					"child": {"version": "2.0.0"}
				}
			}
		}
	}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 2 || records[0].Name != "child" || records[0].Version != "2.0.0" || records[1].Name != "parent" || records[1].Version != "1.0.0" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseNPMRetainsExactSHA1AsSourceIntegrity(t *testing.T) {
	digest := []byte(strings.Repeat("s", 20))
	integrity := "sha1-" + base64.StdEncoding.EncodeToString(digest)
	input := `{"lockfileVersion":2,"packages":{"node_modules/demo":{"version":"1.2.3","integrity":"` + integrity + `"}}}`
	records, err := Parse(context.Background(), FormatNPM, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	want := "sha1:" + hex.EncodeToString(digest)
	if records[0].Provenance.Status != model.ProvenanceUnknown || records[0].Provenance.Integrity != "" || records[0].SourceIntegrity != want {
		t.Fatalf("record=%+v want source integrity=%q", records[0], want)
	}
}

func TestParseCargoMergesLocalAndRegistryDuplicate(t *testing.T) {
	digest := strings.Repeat("a", 64)
	input := `[[package]]
name = "clap"
version = "4.6.6"

[[package]]
name = "clap"
version = "4.6.6"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "` + digest + `"
`
	records, err := Parse(context.Background(), FormatCargo, strings.NewReader(input), 1<<20)
	if err != nil || len(records) != 1 || records[0].Name != "clap" || records[0].Version != "4.6.6" || records[0].Provenance.Status != model.ProvenanceImmutable || records[0].Provenance.Integrity != "sha256:"+digest {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestParseCargoDistinguishesPinnedAndFloatingGitSources(t *testing.T) {
	pinned := strings.Repeat("a", 40)
	for _, test := range []struct {
		name           string
		source         string
		wantStatus     model.ProvenanceStatus
		wantSourceFact string
	}{
		{name: "exact commit", source: "git+https://github.com/example/demo?rev=" + pinned + "#" + pinned, wantStatus: model.ProvenanceUnknown, wantSourceFact: "git-sha1:" + pinned},
		{name: "branch with resolved commit", source: "git+https://github.com/example/demo?branch=main#" + pinned, wantStatus: model.ProvenanceUnknown, wantSourceFact: "git-sha1:" + pinned},
		{name: "floating branch", source: "git+https://github.com/example/demo?branch=main", wantStatus: model.ProvenanceMutable},
		{name: "short revision", source: "git+https://github.com/example/demo#" + strings.Repeat("b", 39), wantStatus: model.ProvenanceMutable},
		{name: "uppercase revision", source: "git+https://github.com/example/demo#" + strings.Repeat("A", 40), wantStatus: model.ProvenanceMutable},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `[[package]]
name = "demo"
version = "1.2.3"
source = "` + test.source + `"
`
			records, err := Parse(context.Background(), FormatCargo, strings.NewReader(input), 1<<20)
			if err != nil || len(records) != 1 {
				t.Fatalf("records=%+v err=%v", records, err)
			}
			if records[0].Provenance.Status != test.wantStatus || records[0].Provenance.Integrity != "" || records[0].SourceIntegrity != test.wantSourceFact {
				t.Fatalf("record=%+v want status=%q sourceFact=%q", records[0], test.wantStatus, test.wantSourceFact)
			}
		})
	}
}

func TestParseCargoRejectsConflictingDuplicateSourcesAndChecksums(t *testing.T) {
	for name, input := range map[string]string{
		"checksum": `[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "` + strings.Repeat("a", 64) + `"
[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "` + strings.Repeat("b", 64) + `"
`,
		"registry source": `[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://registry-one.example/index"
checksum = "` + strings.Repeat("a", 64) + `"
[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://registry-two.example/index"
checksum = "` + strings.Repeat("a", 64) + `"
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(context.Background(), FormatCargo, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestParseSupportedLockfiles(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		format Format
		input  string
		want   Record
	}{
		{FormatNPM, `{"lockfileVersion":3,"packages":{"node_modules/demo":{"name":"demo","version":"1.2.3","integrity":"sha256-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}}}`, Record{Ecosystem: "npm", Name: "demo", Version: "1.2.3", Provenance: model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "npm", Source: "lockfile", Integrity: "sha256:" + strings.Repeat("aa", 32)}}},
		{FormatCargo, `[[package]]
name = "demo"
version = "1.2.3"
checksum = "` + digest + `"
`, Record{Ecosystem: "cargo", Name: "demo", Version: "1.2.3", Provenance: model.Provenance{Status: model.ProvenanceImmutable, Ecosystem: "cargo", Source: "lockfile", Integrity: "sha256:" + digest}}},
		{FormatGoSum, "example.com/demo v1.2.3 h1:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=\n", Record{Ecosystem: "go", Name: "example.com/demo", Version: "v1.2.3", Provenance: model.Provenance{Status: model.ProvenanceUnknown, Ecosystem: "go", Source: "lockfile"}, SourceIntegrity: "h1:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="}},
	}
	for _, testCase := range tests {
		t.Run(string(testCase.format), func(t *testing.T) {
			got, err := Parse(context.Background(), testCase.format, strings.NewReader(testCase.input), 1<<20)
			if err != nil || len(got) != 1 || got[0] != testCase.want {
				t.Fatalf("records=%+v err=%v want=%+v", got, err, testCase.want)
			}
		})
	}
}

func TestParseMarksMutableAndUnknownEntries(t *testing.T) {
	got, err := Parse(context.Background(), FormatNPM, strings.NewReader(`{"packages":{"node_modules/latest":{"name":"latest","version":"latest"},"node_modules/missing":{"name":"missing"},"node_modules/plain":{"name":"plain","version":"1.0.0"}}}`), 1<<20)
	if err != nil || len(got) != 3 {
		t.Fatalf("records=%+v err=%v", got, err)
	}
	if got[0].Provenance.Status != model.ProvenanceMutable || got[1].Provenance.Status != model.ProvenanceMutable || got[2].Provenance.Status != model.ProvenanceUnknown {
		t.Fatalf("records=%+v", got)
	}
}

func TestParseFailsClosedOnBoundsCancellationDuplicatesAndHostileValues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Parse(ctx, FormatGoSum, strings.NewReader("example.com/x v1.0.0 h1:x\n"), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
	if _, err := Parse(context.Background(), FormatGoSum, strings.NewReader(strings.Repeat("x", 101)), 100); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize err=%v", err)
	}
	for _, input := range []string{
		"example.com/x v1.0.0 h1:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=\nexample.com/x v1.0.0 h1:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=\n",
		"/Users/private v1.0.0 h1:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=\n",
	} {
		if _, err := Parse(context.Background(), FormatGoSum, strings.NewReader(input), 1<<20); !errors.Is(err, ErrMalformed) {
			t.Fatalf("input accepted: %q err=%v", input, err)
		}
	}
	if _, err := Parse(context.Background(), FormatNPM, strings.NewReader(`{"packages":{},"packages":{}}`), 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate JSON key accepted: %v", err)
	}
}
