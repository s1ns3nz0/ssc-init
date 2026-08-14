package audit

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestServiceCompleteArchivesExactModelUsedForRendering(t *testing.T) {
	manager := newTestManager(t)
	service := Service{Manager: manager, Product: "ssc-init", Version: "dev", DeviceID: validRun().DeviceID, Now: func() time.Time { return validRun().FinishedAt }}
	outcome := service.Complete(context.Background(), validRun(), model.ScanResult{ScanID: validRun().ScanID, Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil)
	if outcome.Stored == nil || outcome.ArchiveErrorCode != "" {
		t.Fatalf("Outcome = %#v", outcome)
	}
	verified, err := manager.Open(context.Background(), outcome.Stored.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(outcome.Record, verified.Record) {
		t.Fatalf("render/archive records differ:\n%#v\n%#v", outcome.Record, verified.Record)
	}
}

func TestServiceCompleteWithIntelligencePersistsClosedReceipt(t *testing.T) {
	manager := newTestManager(t)
	service := Service{Manager: manager, Product: "ssc-init", Version: "dev", DeviceID: validRun().DeviceID, Now: func() time.Time { return validRun().FinishedAt }}
	receipt := &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 42, Digest: strings.Repeat("a", 64), KeyID: "ti-prod-1", Records: 4, Malicious: 1, Vulnerable: 3, RecordedAt: validRun().FinishedAt.UTC()}
	outcome := service.CompleteWithIntelligence(context.Background(), validRun(), model.ScanResult{ScanID: validRun().ScanID, Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, receipt)
	if outcome.Stored == nil || outcome.Record.Intelligence == nil || outcome.Record.Intelligence.Sequence != 42 || outcome.Record.Intelligence.Records != 4 {
		t.Fatalf("outcome=%+v", outcome)
	}
}

func TestServiceArchiveFailurePreservesCompleteOrPartialScanState(t *testing.T) {
	for _, status := range []model.ScanStatus{model.ScanComplete, model.ScanPartial} {
		t.Run(string(status), func(t *testing.T) {
			home := t.TempDir()
			manager := &Manager{Root: home + "/wrong", Home: home, Now: time.Now, Random: zeroReader{}, Render: ReportText}
			outcome := (Service{Manager: manager, Product: "ssc-init", Version: "dev", DeviceID: validRun().DeviceID, Now: func() time.Time { return validRun().FinishedAt }}).Complete(context.Background(), validRun(), model.ScanResult{ScanID: validRun().ScanID, Status: status}, model.Inventory{}, model.Delta{}, nil)
			if outcome.Record.State != State(status) || outcome.Stored != nil || outcome.ArchiveErrorCode != CodeAuditUnavailable {
				t.Fatalf("Outcome = %#v", outcome)
			}
		})
	}
}

func TestServicePrunesOnlyAfterVerifiedPublication(t *testing.T) {
	manager := newTestManager(t)
	manager.retentionBytes = 1
	service := Service{Manager: manager, Product: "ssc-init", Version: "dev", DeviceID: validRun().DeviceID, Now: func() time.Time { return validRun().FinishedAt }}
	outcome := service.Complete(context.Background(), validRun(), model.ScanResult{ScanID: validRun().ScanID, Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil)
	if outcome.Stored == nil {
		t.Fatalf("Outcome = %#v", outcome)
	}
	if _, err := manager.Open(context.Background(), outcome.Stored.RunID); err != nil {
		t.Fatalf("newest verified publication was pruned: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(value []byte) (int, error) {
	clear(value)
	return len(value), nil
}
