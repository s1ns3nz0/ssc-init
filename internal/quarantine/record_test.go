package quarantine

import (
	"strings"
	"testing"
	"time"
)

func TestRecordAcceptsOnlyClosedStateTransitionsAndTokenizedOrigin(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	valid := Record{
		ID: "quarantine:sha256:" + strings.Repeat("a", 64), AssetID: "tool:fixture", ObservationID: "observation:fixture",
		EvidenceID: "evidence:fixture", OriginalRef: "$HOME/.tools/fixture", SHA256: strings.Repeat("b", 64),
		OriginalMode: 0o755, State: StateQuarantined, RequestedAt: now, QuarantinedAt: now.Add(time.Second),
	}
	if !valid.Valid() {
		t.Fatal("valid record rejected")
	}
	for name, mutate := range map[string]func(*Record){
		"state":       func(v *Record) { v.State = "deleted" },
		"absolute":    func(v *Record) { v.OriginalRef = "/Users/private/tool" },
		"traversal":   func(v *Record) { v.OriginalRef = "$HOME/../private/tool" },
		"digest":      func(v *Record) { v.SHA256 = "short" },
		"mode":        func(v *Record) { v.OriginalMode = 0o100755 },
		"ordering":    func(v *Record) { v.QuarantinedAt = now.Add(-time.Second) },
		"restored-at": func(v *Record) { v.RestoredAt = now.Add(time.Second) },
		"failure":     func(v *Record) { v.FailureCode = "raw /private/path" },
		"secret":      func(v *Record) { v.AssetID = "ghp_" + strings.Repeat("a", 36) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if candidate.Valid() {
				t.Fatalf("invalid record accepted: %+v", candidate)
			}
		})
	}
}

func TestRestoredAndFailedRecordsRequireExactStateFields(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	base := Record{ID: "quarantine:fixture", AssetID: "tool:fixture", ObservationID: "observation:fixture", EvidenceID: "evidence:fixture", OriginalRef: "$HOME/tool", SHA256: strings.Repeat("b", 64), OriginalMode: 0o644, RequestedAt: now}
	restored := base
	restored.State, restored.QuarantinedAt, restored.RestoredAt = StateRestored, now.Add(time.Second), now.Add(2*time.Second)
	if !restored.Valid() {
		t.Fatal("restored record rejected")
	}
	failed := base
	failed.State, failed.FailureCode = StateFailed, FailureIdentityChanged
	if !failed.Valid() {
		t.Fatal("failed record rejected")
	}
	failed.FailureCode = "private-value"
	if failed.Valid() {
		t.Fatal("open failure code accepted")
	}
}
