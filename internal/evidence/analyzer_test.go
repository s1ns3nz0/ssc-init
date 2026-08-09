package evidence

import (
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type analyzerFunc func(context.Context, SealedContent) ([]model.AnalyzerFact, error)

func (f analyzerFunc) Analyze(ctx context.Context, content SealedContent) ([]model.AnalyzerFact, error) {
	return f(ctx, content)
}

func TestRunContentAnalyzerExposesNoPathAndClearsSourceBytes(t *testing.T) {
	raw := []byte("private source bytes")
	candidate := &issuedCandidate{target: model.LocalEvidenceTarget{AssetID: "tool:fixture", RootPath: "/private/root", RelativePath: "secret.js", Subject: model.EvidenceSubjectEntrypointMain}, evidenceID: "evidence:fixture"}
	var methods []string
	analyzer := analyzerFunc(func(_ context.Context, content SealedContent) ([]model.AnalyzerFact, error) {
		typeOf := reflect.TypeOf(content)
		for index := 0; index < typeOf.NumMethod(); index++ {
			methods = append(methods, typeOf.Method(index).Name)
		}
		got, err := io.ReadAll(content)
		if err != nil || string(got) != "private source bytes" || content.AssetID() != candidate.target.AssetID || content.EvidenceID() != candidate.evidenceID {
			t.Fatalf("content mismatch")
		}
		return []model.AnalyzerFact{{ID: "analyzer:fixture", AssetID: content.AssetID(), EvidenceID: content.EvidenceID(), RuleID: "ssc-init/test", Category: model.AnalyzerDynamicExecution, Confidence: model.ConfidenceHigh, Occurrences: 1}}, nil
	})
	facts, coverage := runContentAnalyzer(context.Background(), analyzer, candidate, raw)
	if len(facts) != 1 || coverage.Status != model.CoverageComplete || coverage.FilesRead != 1 {
		t.Fatalf("facts=%+v coverage=%+v", facts, coverage)
	}
	for _, method := range methods {
		if method == "Path" || method == "RootPath" || method == "RelativePath" {
			t.Fatalf("path method exposed: %v", methods)
		}
	}
	for _, value := range raw {
		if value != 0 {
			t.Fatalf("source bytes not cleared: %q", raw)
		}
	}
}

func TestRunContentAnalyzerContainsPanicAsFailedCoverage(t *testing.T) {
	candidate := &issuedCandidate{target: model.LocalEvidenceTarget{AssetID: "tool:fixture"}, evidenceID: "evidence:fixture"}
	facts, coverage := runContentAnalyzer(context.Background(), analyzerFunc(func(context.Context, SealedContent) ([]model.AnalyzerFact, error) { panic("private source") }), candidate, []byte("secret"))
	if len(facts) != 0 || coverage.Status != model.CoverageFailed || !reflect.DeepEqual(coverage.SkippedRules, []string{"analyzer-failed"}) {
		t.Fatalf("facts=%+v coverage=%+v", facts, coverage)
	}
}

func TestRunContentAnalyzerSkipsBinaryWithoutInvokingAnalyzer(t *testing.T) {
	candidate := &issuedCandidate{target: model.LocalEvidenceTarget{AssetID: "tool:fixture"}, evidenceID: "evidence:fixture"}
	called := false
	raw := []byte{'e', 'v', 'a', 'l', '(', 0, ')'}
	facts, coverage := runContentAnalyzer(context.Background(), analyzerFunc(func(context.Context, SealedContent) ([]model.AnalyzerFact, error) {
		called = true
		return nil, nil
	}), candidate, raw)
	if called || len(facts) != 0 || coverage.Status != model.CoverageSkipped || !reflect.DeepEqual(coverage.SkippedRules, []string{"binary-content"}) {
		t.Fatalf("called=%v facts=%+v coverage=%+v", called, facts, coverage)
	}
	for _, value := range raw {
		if value != 0 {
			t.Fatalf("binary bytes not cleared: %q", raw)
		}
	}
}
