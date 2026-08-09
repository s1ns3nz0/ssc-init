package evidence

import (
	"bytes"
	"context"
	"io"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

const maxAnalyzerFileBytes = 1 << 20

type SealedContent interface {
	io.Reader
	AssetID() string
	EvidenceID() string
	Subject() string
	Size() int64
}

type ContentAnalyzer interface {
	Analyze(context.Context, SealedContent) ([]model.AnalyzerFact, error)
}

type sealedContent struct {
	assetID, evidenceID, subject string
	size                         int64
	reader                       *bytes.Reader
}

func (c *sealedContent) Read(buffer []byte) (int, error) { return c.reader.Read(buffer) }
func (c *sealedContent) AssetID() string                 { return c.assetID }
func (c *sealedContent) EvidenceID() string              { return c.evidenceID }
func (c *sealedContent) Subject() string                 { return c.subject }
func (c *sealedContent) Size() int64                     { return c.size }

func runContentAnalyzer(ctx context.Context, analyzer ContentAnalyzer, candidate *issuedCandidate, raw []byte) (facts []model.AnalyzerFact, coverage model.AnalyzerCoverage) {
	coverage.Status = model.CoverageComplete
	if analyzer == nil {
		return nil, model.AnalyzerCoverage{}
	}
	if raw == nil {
		coverage.Status = model.CoverageSkipped
		coverage.SkippedRules = []string{"oversize-or-unsupported"}
		return nil, coverage
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		clear(raw)
		coverage.Status = model.CoverageSkipped
		coverage.SkippedRules = []string{"binary-content"}
		return nil, coverage
	}
	coverage.FilesRead, coverage.BytesRead = 1, int64(len(raw))
	content := &sealedContent{assetID: candidate.target.AssetID, evidenceID: candidate.evidenceID, subject: candidate.target.Subject, size: int64(len(raw)), reader: bytes.NewReader(raw)}
	defer func() {
		clear(raw)
		content.assetID, content.evidenceID, content.subject, content.size, content.reader = "", "", "", 0, bytes.NewReader(nil)
		if recover() != nil {
			facts = nil
			coverage = model.AnalyzerCoverage{Status: model.CoverageFailed, SkippedRules: []string{"analyzer-failed"}}
		}
	}()
	facts, err := analyzer.Analyze(ctx, content)
	if err != nil || ctx.Err() != nil {
		return nil, model.AnalyzerCoverage{Status: model.CoverageFailed, SkippedRules: []string{"analyzer-failed"}}
	}
	for _, fact := range facts {
		if !fact.Valid() || fact.AssetID != candidate.target.AssetID || fact.EvidenceID != candidate.evidenceID {
			return nil, model.AnalyzerCoverage{Status: model.CoverageFailed, SkippedRules: []string{"analyzer-invalid"}}
		}
	}
	return facts, coverage
}
