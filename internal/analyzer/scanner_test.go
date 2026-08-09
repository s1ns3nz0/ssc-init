package analyzer

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type scannerContent struct{ *bytes.Reader }

func newScannerContent(value string) scannerContent {
	return scannerContent{bytes.NewReader([]byte(value))}
}
func (scannerContent) AssetID() string     { return "tool:fixture" }
func (scannerContent) EvidenceID() string  { return "evidence:fixture" }
func (scannerContent) Subject() string     { return model.EvidenceSubjectEntrypointMain }
func (content scannerContent) Size() int64 { return content.Reader.Size() }

var _ io.Reader = scannerContent{}

func TestScannerDetectsRealAPIsAndIgnoresCommentedAndQuotedTwins(t *testing.T) {
	real := `const token = process.env.API_TOKEN; fetch(endpoint); child_process.exec(command); eval(code)`
	facts, err := (Scanner{}).Analyze(context.Background(), newScannerContent(real))
	if err != nil || len(facts) != 5 {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	commented := `// process.env.API_TOKEN; fetch(endpoint); eval(code)
const docs = "child_process.exec(command)"; /* requests.post(secret) */`
	facts, err = (Scanner{}).Analyze(context.Background(), newScannerContent(commented))
	if err != nil || len(facts) != 0 {
		t.Fatalf("commented facts=%+v err=%v", facts, err)
	}
}

func TestScannerRejectsOversizeInput(t *testing.T) {
	content := scannerContent{bytes.NewReader(bytes.Repeat([]byte("a"), 1<<20+1))}
	if _, err := (Scanner{}).Analyze(context.Background(), content); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestScannerDetectsOnlyForwardBoundedCredentialEgressFlow(t *testing.T) {
	facts, err := (Scanner{}).Analyze(context.Background(), newScannerContent(`const secret = process.env.TOKEN; fetch(endpoint, secret)`))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fact := range facts {
		if fact.Category == model.AnalyzerCredentialEgress {
			found = true
		}
	}
	if !found {
		t.Fatalf("facts=%+v", facts)
	}
	for _, source := range []string{`fetch(endpoint); const secret = process.env.TOKEN`, `const secret = process.env.TOKEN; ` + strings.Repeat(" ", 4097) + `fetch(endpoint)`, `// process.env.TOKEN; fetch(endpoint)`} {
		facts, err := (Scanner{}).Analyze(context.Background(), newScannerContent(source))
		if err != nil {
			t.Fatal(err)
		}
		for _, fact := range facts {
			if fact.Category == model.AnalyzerCredentialEgress {
				t.Fatalf("unsupported flow matched: %+v", facts)
			}
		}
	}
}
