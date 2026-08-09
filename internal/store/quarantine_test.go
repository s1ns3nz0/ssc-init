package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/quarantine"
)

func TestQuarantineRecordPersistsOnlyValidForwardTransitions(t *testing.T) {
	s := openTestStore(t)
	now := time.Unix(10, 0).UTC()
	requested := quarantine.Record{ID: "quarantine:fixture", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: "$HOME/tool", SHA256: strings.Repeat("a", 64), OriginalMode: 0o755, State: quarantine.StateRequested, RequestedAt: now}
	if err := s.SaveQuarantineRecord(context.Background(), requested); err != nil {
		t.Fatal(err)
	}
	quarantined := requested
	quarantined.State, quarantined.QuarantinedAt = quarantine.StateQuarantined, now.Add(time.Second)
	if err := s.SaveQuarantineRecord(context.Background(), quarantined); err != nil {
		t.Fatal(err)
	}
	got, err := s.QuarantineRecords(context.Background())
	if err != nil || !reflect.DeepEqual(got, []quarantine.Record{quarantined}) {
		t.Fatalf("records=%+v err=%v", got, err)
	}
	if err := s.SaveQuarantineRecord(context.Background(), requested); !errors.Is(err, ErrInvalidQuarantineTransition) {
		t.Fatalf("backward transition err=%v", err)
	}
}

func TestQuarantineRecordRequiresRequestedStateFirst(t *testing.T) {
	s := openTestStore(t)
	record := quarantine.Record{ID: "quarantine:fixture", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: "$HOME/tool", SHA256: strings.Repeat("a", 64), OriginalMode: 0o755, State: quarantine.StateQuarantined, RequestedAt: time.Unix(10, 0).UTC(), QuarantinedAt: time.Unix(11, 0).UTC()}
	if err := s.SaveQuarantineRecord(context.Background(), record); !errors.Is(err, ErrInvalidQuarantineTransition) {
		t.Fatalf("direct quarantine err=%v", err)
	}
}
