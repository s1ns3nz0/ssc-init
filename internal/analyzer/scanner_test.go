package analyzer

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type scannerContent struct {
	*bytes.Reader
	subject string
}

func newScannerContent(value string) scannerContent {
	return scannerContent{Reader: bytes.NewReader([]byte(value)), subject: model.EvidenceSubjectEntrypointMain}
}
func (scannerContent) AssetID() string    { return "tool:fixture" }
func (scannerContent) EvidenceID() string { return "evidence:fixture" }
func (content scannerContent) Subject() string {
	return content.subject
}
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

func TestScannerSkipsGenericBehaviorRulesForDependencyEvidence(t *testing.T) {
	tests := []struct {
		subject string
		raw     string
	}{
		{subject: "project-lockfile:Cargo.lock", raw: `checksum = "` + strings.Repeat("a", 64) + `"`},
		{subject: "project-lockfile:go.sum", raw: "github.com/aws/aws-sdk-go-v2/credentials v1.0.0 h1:" + strings.Repeat("A", 44)},
		{subject: "project-manifest:go.mod", raw: "require github.com/docker/docker-credential-helpers v0.9.3"},
	}
	for _, test := range tests {
		content := scannerContent{Reader: bytes.NewReader([]byte(test.raw)), subject: test.subject}
		facts, err := (Scanner{}).Analyze(context.Background(), content)
		if err != nil || len(facts) != 0 {
			t.Fatalf("subject=%q facts=%+v err=%v", test.subject, facts, err)
		}
	}

	facts, err := (Scanner{}).Analyze(context.Background(), newScannerContent(`const secret = os.getenv("TOKEN"); fetch(endpoint, secret)`))
	if err != nil || len(facts) == 0 {
		t.Fatalf("source facts=%+v err=%v", facts, err)
	}
}

func TestScannerRejectsOversizeInput(t *testing.T) {
	content := scannerContent{Reader: bytes.NewReader(bytes.Repeat([]byte("a"), 1<<20+1)), subject: model.EvidenceSubjectEntrypointMain}
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
