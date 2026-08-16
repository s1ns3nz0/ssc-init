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
		"sha1-" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 20))),
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
