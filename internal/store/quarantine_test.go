package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

func TestConcurrentQuarantineOperationsHaveOneDurableWinner(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, "Library", "Application Support", "SSC Init")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	source := filepath.Join(home, ".tools", "fixture")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("fixture bytes")
	if err := os.WriteFile(source, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	record := quarantine.Record{ID: "quarantine:concurrent", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: "$HOME/.tools/fixture", SHA256: fmt.Sprintf("%x", digest), OriginalMode: 0o755}

	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, operationErr := (quarantine.Manager{Home: home, Recorder: s}).Quarantine(context.Background(), record)
			results <- operationErr
		}()
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	for operationErr := range results {
		if operationErr == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
	records, err := s.QuarantineRecords(context.Background())
	if err != nil || len(records) != 1 || records[0].State != quarantine.StateQuarantined {
		t.Fatalf("records=%+v err=%v", records, err)
	}
}

func TestQuarantineRecordRequiresRequestedStateFirst(t *testing.T) {
	s := openTestStore(t)
	record := quarantine.Record{ID: "quarantine:fixture", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: "$HOME/tool", SHA256: strings.Repeat("a", 64), OriginalMode: 0o755, State: quarantine.StateQuarantined, RequestedAt: time.Unix(10, 0).UTC(), QuarantinedAt: time.Unix(11, 0).UTC()}
	if err := s.SaveQuarantineRecord(context.Background(), record); !errors.Is(err, ErrInvalidQuarantineTransition) {
		t.Fatalf("direct quarantine err=%v", err)
	}
}
