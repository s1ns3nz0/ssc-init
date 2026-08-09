package finding

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type activeReaderStub struct {
	value bundle.ActiveBundle
	err   error
}

func (s activeReaderStub) Active(context.Context) (bundle.ActiveBundle, error) { return s.value, s.err }

func TestServiceReportsUnavailableIntelligenceWithoutInventingFindings(t *testing.T) {
	got, err := (Service{TI: activeReaderStub{err: bundle.ErrActiveUnavailable}}).Evaluate(context.Background(), model.Inventory{})
	if err != nil || got.Intelligence != "unavailable" || len(got.Findings) != 0 {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestServiceReducesConfidenceForStaleVerifiedIntelligence(t *testing.T) {
	asset := model.Asset{ID: "tool:bad", Type: model.AssetTool, Name: "bad"}
	active := activeTI([]bundle.TIRecord{{ID: "ti:bad", AssetID: asset.ID, Verdict: "known-malicious", Confidence: "high"}})
	active.Status.Freshness = bundle.FreshnessStale
	got, err := (Service{TI: activeReaderStub{value: active}, Now: func() time.Time { return time.Unix(1, 0) }}).Evaluate(context.Background(), model.Inventory{Assets: []model.Asset{asset}})
	if err != nil || got.Intelligence != "stale" || len(got.Findings) != 1 || got.Findings[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestServicePropagatesUnexpectedBundleFailure(t *testing.T) {
	_, err := (Service{TI: activeReaderStub{err: errors.New("storage failed")}}).Evaluate(context.Background(), model.Inventory{})
	if err == nil {
		t.Fatal("error=nil")
	}
}
