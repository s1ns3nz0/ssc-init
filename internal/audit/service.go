package audit

import (
	"context"
	"io"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type Service struct {
	Manager  *Manager
	Product  string
	Version  string
	DeviceID string
	Now      func() time.Time
	Random   io.Reader
}

type Outcome struct {
	Record           Record
	Stored           *Stored
	ArchiveErrorCode string
}

func (s Service) Complete(ctx context.Context, run Run, scan model.ScanResult, inventory model.Inventory, delta model.Delta, findings []model.Finding) Outcome {
	return s.CompleteWithIntelligence(ctx, run, scan, inventory, delta, findings, nil)
}

// CompleteWithIntelligence archives the scan and the closed result of an
// explicit pre-scan TI update as one audit record.
func (s Service) CompleteWithIntelligence(ctx context.Context, run Run, scan model.ScanResult, inventory model.Inventory, delta model.Delta, findings []model.Finding, intelligence *IntelligenceUpdate) Outcome {
	run = s.finishRun(run)
	run.ScanID = scan.ScanID
	if intelligence != nil {
		value := *intelligence
		value.RecordedAt = run.FinishedAt
		intelligence = &value
	}
	record, err := Build(scan, inventory, delta, findings, run, intelligence)
	if err != nil {
		return Outcome{ArchiveErrorCode: CodeAuditUnavailable}
	}
	outcome := Outcome{Record: record}
	if s.Manager == nil {
		outcome.ArchiveErrorCode = CodeAuditUnavailable
		return outcome
	}
	stored, err := s.Manager.Save(ctx, record)
	if err != nil {
		outcome.ArchiveErrorCode = CodeAuditUnavailable
		return outcome
	}
	outcome.Stored = &stored
	return outcome
}

func (s Service) Fail(ctx context.Context, run Run, stage Stage, code string) Outcome {
	run = s.finishRun(run)
	record, err := BuildFailure(run, stage, code)
	if err != nil {
		return Outcome{ArchiveErrorCode: CodeAuditUnavailable}
	}
	outcome := Outcome{Record: record}
	if s.Manager == nil {
		outcome.ArchiveErrorCode = CodeAuditUnavailable
		return outcome
	}
	stored, err := s.Manager.Save(ctx, record)
	if err != nil {
		outcome.ArchiveErrorCode = CodeAuditUnavailable
		return outcome
	}
	outcome.Stored = &stored
	return outcome
}

func (s Service) finishRun(run Run) Run {
	run.Product, run.Version, run.DeviceID = s.Product, s.Version, s.DeviceID
	if s.Now != nil {
		run.FinishedAt = s.Now().UTC()
	}
	return run
}
