package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestPolicyPinsSurviveSnapshotPruning(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pin := policy.Pin{AssetID: "agent-plugin:claude:helpful-utils@1.0.0", Kind: "tree-sha256", Subject: "payload-tree", Digest: strings.Repeat("1", 64)}
	if err := s.SavePins(ctx, []policy.Pin{pin}, base); err != nil {
		t.Fatal(err)
	}
	saveSnapshotAt(t, s, "policy-old", base.Add(-90*24*time.Hour), base)
	saveSnapshotAt(t, s, "policy-new", base.Add(-time.Hour), base)
	pins, err := s.Pins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 1 || pins[0] != pin {
		t.Fatalf("snapshot pruning changed pins: %+v", pins)
	}
}

func TestPolicyRowsRejectRawPathsAndSecrets(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	badPin := policy.Pin{AssetID: "asset", Kind: "kind", Subject: "subject", Digest: "/Users/someone/private"}
	if err := s.SavePins(ctx, []policy.Pin{badPin}, time.Now()); err == nil || strings.Contains(err.Error(), badPin.Digest) {
		t.Fatalf("unsafe digest error = %v", err)
	}
	secret := "AKIAIOSFODNN7EXAMPLE"
	exception := policy.Exception{RuleID: "unpinned", Scope: policy.ScopeRun, Reason: secret, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveExceptions(ctx, []policy.Exception{exception}, time.Now()); !errors.Is(err, ErrSensitiveSnapshot) || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret exception error = %v", err)
	}
}

func TestPolicyDecisionsKeepFirstSeenAndAdvanceLastSeen(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	first := time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)
	violation := policy.Violation{RuleID: "unpinned", AssetID: "asset", Level: 5}
	if err := s.RecordDecisions(ctx, []policy.Violation{violation}, first); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordDecisions(ctx, []policy.Violation{violation}, first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	decisions, err := s.Decisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || !decisions[0].FirstSeenAt.Equal(first) || !decisions[0].LastSeenAt.Equal(first.Add(time.Hour)) {
		t.Fatalf("decisions=%+v", decisions)
	}
}

func TestMigrationSevenAddsPolicyTablesWithoutForeignKeys(t *testing.T) {
	path := createDatabaseAtMigration(t, len(migrations)-1)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, table := range []string{"policy_pins", "policy_exceptions", "policy_decisions"} {
		assertTableExists(t, s.db, table)
		var foreignKeys int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_foreign_key_list(?)`, table).Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 0 {
			t.Fatalf("%s has %d foreign keys", table, foreignKeys)
		}
	}
}
