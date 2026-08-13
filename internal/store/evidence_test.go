package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func finalizeTestObservation(t *testing.T, value model.Observation) model.Observation {
	t.Helper()
	finalized, err := identity.FinalizeObservation(value)
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}

func finalizeTestEvidence(t *testing.T, value model.ContentEvidence) model.ContentEvidence {
	t.Helper()
	finalized, err := identity.FinalizeEvidence(value)
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}

func TestValidEvidenceKindSubjectAcceptsSurfaceProducerPairs(t *testing.T) {
	for _, testCase := range []struct {
		kind    model.EvidenceKind
		subject string
	}{
		{model.EvidenceFileSHA256, model.EvidenceSubjectShellStartup},
		{model.EvidenceFileSHA256, model.EvidenceSubjectGitHook},
		{model.EvidenceFileSHA256, model.EvidenceSubjectLaunchConfig},
		{model.EvidenceSemanticSHA256, model.EvidenceSubjectCredentialConfig},
	} {
		if !validEvidenceKindSubject(testCase.kind, testCase.subject) {
			t.Errorf("producer pair kind=%q subject=%q rejected", testCase.kind, testCase.subject)
		}
	}
}

// validV3Snapshot builds a v3-shaped snapshot containing complete, partial,
// unsupported, and skipped evidence with nil-error, populated-error,
// empty-error, nil-metadata, populated-metadata, and empty-metadata shapes.
// It also carries at least one row for every table keyed by scan_id, so
// retention tests that assert no table is left behind cannot pass vacuously.
func validV3Snapshot(t *testing.T, scanID string) (model.ScanResult, model.Inventory) {
	t.Helper()
	obsManifest := finalizeTestObservation(t, model.Observation{
		AssetID: "asset-one", Collector: "plugins", Scope: model.ScopeUser, LocationRef: "$HOME/.plugins/one/manifest.json",
	})
	obsTree := finalizeTestObservation(t, model.Observation{
		AssetID: "asset-one", Collector: "plugins", Scope: model.ScopeUser, LocationRef: "$HOME/.plugins/one/payload",
	})
	obsPackage := finalizeTestObservation(t, model.Observation{
		AssetID: "asset-two", Collector: "packages", Scope: model.ScopeToolEnvironment, LocationRef: "probe-target:packages.npm",
	})
	obsContainer := finalizeTestObservation(t, model.Observation{
		AssetID: "asset-two", Collector: "packages", Scope: model.ScopeToolEnvironment, LocationRef: "probe-target:packages.docker",
	})
	complete := finalizeTestEvidence(t, model.ContentEvidence{
		AssetID: "asset-one", ObservationID: obsManifest.ID,
		Kind: model.EvidenceFileSHA256, Subject: model.EvidenceSubjectManifest, Status: model.EvidenceComplete,
		Algorithm: "sha256", Digest: strings.Repeat("a", 64), Size: 42,
		Metadata: map[string]string{"completeness": "complete"},
	})
	partial := finalizeTestEvidence(t, model.ContentEvidence{
		AssetID: "asset-one", ObservationID: obsTree.ID,
		Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree, Status: model.EvidencePartial,
		Algorithm: "sha256", Digest: strings.Repeat("b", 64), Size: 10, Files: 2, Directories: 1, Symlinks: 1,
		Metadata: map[string]string{"completeness": "observed-subset", "cache": "miss"},
		Errors:   []model.EvidenceError{{Code: "read_unavailable", Message: "evidence tree entry is unavailable"}},
	})
	unsupported := finalizeTestEvidence(t, model.ContentEvidence{
		AssetID: "asset-two", ObservationID: obsPackage.ID,
		Kind: model.EvidencePackageContent, Subject: model.EvidenceSubjectPackageContent, Status: model.EvidenceUnsupported,
	})
	skipped := finalizeTestEvidence(t, model.ContentEvidence{
		AssetID: "asset-two", ObservationID: obsContainer.ID,
		Kind: model.EvidenceContainerIdentity, Subject: model.EvidenceSubjectContainerImage, Status: model.EvidenceSkipped,
		Metadata: map[string]string{}, Errors: []model.EvidenceError{},
	})

	scan := testScan(scanID, time.Unix(40, 0).UTC())
	scan.SchemaVersion = "ssc-init.scan.v4"
	scan.EvidenceCoverage = model.EvidenceCoverage{
		Status: model.CoveragePartial,
		Targets: []model.EvidenceTargetResult{
			{TargetID: "plugins.manifest", AssetID: "asset-one", ObservationID: obsManifest.ID, EvidenceID: complete.ID, Status: model.EvidenceComplete},
			{TargetID: "plugins.payload", AssetID: "asset-one", ObservationID: obsTree.ID, EvidenceID: partial.ID, Status: model.EvidencePartial,
				Errors: []model.EvidenceError{{Code: "read_unavailable", Message: "evidence tree entry is unavailable"}}},
			{TargetID: "packages.npm.content", AssetID: "asset-two", ObservationID: obsPackage.ID, EvidenceID: unsupported.ID, Status: model.EvidenceUnsupported},
			{TargetID: "packages.docker.container-identity", AssetID: "asset-two", ObservationID: obsContainer.ID, EvidenceID: skipped.ID, Status: model.EvidenceSkipped,
				Errors: []model.EvidenceError{}},
		},
		Errors: []model.CoverageError{{Code: "target_rejected", Message: "evidence target was rejected"}},
	}
	scan.Coverage = []model.CollectorResult{{Collector: "plugins", Status: model.CoveragePartial}}
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "asset-one", Type: model.AssetAgentPlugin, Name: "plugin-one"},
			{ID: "asset-two", Type: model.AssetPackage, Name: "package-two"},
		},
		Observations:  []model.Observation{obsManifest, obsTree, obsPackage, obsContainer},
		Evidence:      []model.ContentEvidence{complete, partial, unsupported, skipped},
		Relationships: []model.Relationship{{From: "asset-one", Kind: "uses", To: "asset-two"}},
		Errors:        []model.CoverageError{{Code: "collector_failed", Message: "collector failed"}},
	}
	return scan, inventory
}

func saveValidV3Snapshot(t *testing.T, s *Store, scanID string) (model.ScanResult, model.Inventory) {
	t.Helper()
	scan, inventory := validV3Snapshot(t, scanID)
	if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	return scan, inventory
}

func TestSnapshotV3EvidenceRoundTrip(t *testing.T) {
	s := openTestStore(t)
	scan, inventory := saveValidV3Snapshot(t, s, "v3-round-trip")
	got, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	want := model.Snapshot{Scan: scan, Inventory: inventory}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot mismatch\n got=%#v\nwant=%#v", got, want)
	}
	// Exact order and nil shapes must survive the reopen.
	for index, evidence := range got.Inventory.Evidence {
		if evidence.ID != inventory.Evidence[index].ID {
			t.Fatalf("evidence order changed at %d: got %q want %q", index, evidence.ID, inventory.Evidence[index].ID)
		}
	}
	if got.Inventory.Evidence[0].Errors != nil || got.Inventory.Evidence[2].Metadata != nil || got.Inventory.Evidence[2].Errors != nil {
		t.Fatal("nil evidence shapes were not preserved")
	}
	if got.Inventory.Evidence[3].Metadata == nil || len(got.Inventory.Evidence[3].Metadata) != 0 {
		t.Fatal("empty evidence metadata shape was not preserved")
	}
	if got.Inventory.Evidence[3].Errors == nil || len(got.Inventory.Evidence[3].Errors) != 0 {
		t.Fatal("empty evidence errors shape was not preserved")
	}
}

func TestSnapshotV3EvidenceInventoryShapeRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name     string
		evidence []model.ContentEvidence
	}{
		{name: "nil"},
		{name: "empty", evidence: []model.ContentEvidence{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			inventory := model.Inventory{Evidence: tt.evidence}
			if err := s.SaveScan(context.Background(), testScan("evidence-shape-"+tt.name, time.Unix(2, 0).UTC()), inventory); err != nil {
				t.Fatal(err)
			}
			got, ok, err := s.LatestSnapshot(context.Background())
			if err != nil || !ok || !reflect.DeepEqual(got.Inventory, inventory) {
				t.Fatalf("ok=%v got=%#v want=%#v err=%v", ok, got.Inventory, inventory, err)
			}
		})
	}
}

func TestSnapshotV3EvidenceCoverageShapeRoundTrip(t *testing.T) {
	t.Run("zero coverage stores no row", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.SaveScan(context.Background(), testScan("no-coverage", time.Unix(2, 0).UTC()), model.Inventory{}); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM evidence_coverage`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("evidence_coverage rows=%d want=0", count)
		}
		got, ok, err := s.LatestSnapshot(context.Background())
		if err != nil || !ok || !reflect.DeepEqual(got.Scan.EvidenceCoverage, model.EvidenceCoverage{}) {
			t.Fatalf("ok=%v coverage=%#v err=%v", ok, got.Scan.EvidenceCoverage, err)
		}
	})
	t.Run("empty target and nil error shapes survive", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("empty-coverage", time.Unix(2, 0).UTC())
		scan.EvidenceCoverage = model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{}}
		if err := s.SaveScan(context.Background(), scan, model.Inventory{}); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.LatestSnapshot(context.Background())
		if err != nil || !ok || !reflect.DeepEqual(got.Scan.EvidenceCoverage, scan.EvidenceCoverage) {
			t.Fatalf("ok=%v coverage=%#v want=%#v err=%v", ok, got.Scan.EvidenceCoverage, scan.EvidenceCoverage, err)
		}
	})
}

func TestSnapshotV3RequiresEvidenceCoverageAndEvidenceInventory(t *testing.T) {
	t.Run("missing evidence coverage is rejected without rows", func(t *testing.T) {
		s := openTestStore(t)
		scan, inventory := validV3Snapshot(t, "v3-no-coverage")
		scan.EvidenceCoverage = model.EvidenceCoverage{}
		if err := s.SaveScan(context.Background(), scan, inventory); err == nil {
			t.Fatal("SaveScan error=nil")
		}
		assertNoSnapshotRows(t, s)
	})
	t.Run("nil evidence inventory is rejected without rows", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("v3-nil-evidence", time.Unix(2, 0).UTC())
		scan.SchemaVersion = "ssc-init.scan.v4"
		scan.EvidenceCoverage = model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{}}
		if err := s.SaveScan(context.Background(), scan, model.Inventory{}); err == nil {
			t.Fatal("SaveScan error=nil")
		}
		assertNoSnapshotRows(t, s)
	})
	t.Run("v3 with empty evidence and complete empty coverage saves", func(t *testing.T) {
		s := openTestStore(t)
		scan := testScan("v3-empty-evidence", time.Unix(2, 0).UTC())
		scan.SchemaVersion = "ssc-init.scan.v4"
		scan.EvidenceCoverage = model.EvidenceCoverage{Status: model.CoverageComplete, Targets: []model.EvidenceTargetResult{}}
		if err := s.SaveScan(context.Background(), scan, model.Inventory{Evidence: []model.ContentEvidence{}}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy versions keep saving without coverage", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.SaveScan(context.Background(), testScan("legacy-no-coverage", time.Unix(2, 0).UTC()), model.Inventory{}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("deleted v3 coverage row fails the load", func(t *testing.T) {
		s := openTestStore(t)
		saveValidV3Snapshot(t, s, "v3-coverage-deleted")
		if _, err := s.db.Exec(`DELETE FROM evidence_coverage`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LatestSnapshot(context.Background()); err == nil {
			t.Fatal("LatestSnapshot error=nil")
		}
	})
}

func TestSnapshotV3EvidenceValidationHappensBeforeTransaction(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*model.ScanResult, *model.Inventory)
		wantError string
	}{
		{name: "duplicate id", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence = append(inventory.Evidence, inventory.Evidence[0])
		}, wantError: "duplicate inventory evidence id"},
		{name: "malformed id", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].ID = "evidence:sha256:not-hex"
		}, wantError: "invalid evidence id"},
		{name: "absent asset", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].AssetID = "missing-asset"
		}, wantError: "evidence references missing asset"},
		{name: "absent observation", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].ObservationID = "observation:sha256:" + strings.Repeat("d", 64)
		}, wantError: "evidence references missing observation"},
		{name: "asset mismatch", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].AssetID = "asset-two"
		}, wantError: "evidence observation asset mismatch"},
		{name: "unknown kind", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Kind = "unknown-kind"
		}, wantError: "invalid evidence kind or subject"},
		{name: "unknown subject", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Subject = "unknown-subject"
		}, wantError: "invalid evidence kind or subject"},
		{name: "mismatched kind subject pair", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Subject = model.EvidenceSubjectPayloadTree
		}, wantError: "invalid evidence kind or subject"},
		{name: "unknown status", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Status = "unknown-status"
		}, wantError: "invalid evidence status"},
		{name: "terminal-only kind with complete status", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[2].Status = model.EvidenceComplete
		}, wantError: "invalid evidence status"},
		{name: "uppercase digest", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Digest = strings.ToUpper(inventory.Evidence[0].Digest)
		}, wantError: "invalid evidence digest"},
		{name: "wrong digest length", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Digest = "abc123"
		}, wantError: "invalid evidence digest"},
		{name: "complete without digest", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Digest = ""
		}, wantError: "invalid evidence digest"},
		{name: "complete without algorithm", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Algorithm = ""
		}, wantError: "invalid evidence digest"},
		{name: "preset with digest", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[2].Algorithm = "sha256"
			inventory.Evidence[2].Digest = strings.Repeat("c", 64)
		}, wantError: "invalid evidence payload"},
		{name: "negative count", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Files = -1
		}, wantError: "invalid evidence counts"},
		{name: "file evidence with tree counts", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Files = 3
		}, wantError: "invalid evidence counts"},
		{name: "unknown metadata", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Metadata["target_path"] = "$HOME/private"
		}, wantError: "invalid evidence metadata"},
		{name: "cache metadata outside tree kind", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Metadata["cache"] = "hit"
		}, wantError: "invalid evidence metadata"},
		{name: "complete with error", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[0].Errors = []model.EvidenceError{{Code: "read_unavailable", Message: "evidence file is unavailable"}}
		}, wantError: "invalid evidence errors"},
		{name: "partial without error", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Errors = nil
		}, wantError: "invalid evidence errors"},
		{name: "bad error", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Errors = []model.EvidenceError{{Code: "read_unavailable", Message: ""}}
		}, wantError: "evidence error message must not be empty"},
		{name: "secret shape", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Errors = []model.EvidenceError{{Code: "read_unavailable", Message: "SERVICE_TOKEN=raw-value"}}
		}, wantError: ErrSensitiveSnapshot.Error()},
		{name: "absolute path", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Errors = []model.EvidenceError{{Code: "read_unavailable", Message: persistedRawPathSentinel}}
		}, wantError: errUnsafeSnapshotPath.Error()},
		{name: "encoded path masking", mutate: func(_ *model.ScanResult, inventory *model.Inventory) {
			inventory.Evidence[1].Errors = []model.EvidenceError{{Code: "read_unavailable", Message: strings.ReplaceAll(persistedRawPathSentinel, "/", "%2F")}}
		}, wantError: errUnsafeSnapshotPath.Error()},
		{name: "bad coverage reference", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Targets[0].EvidenceID = "evidence:sha256:" + strings.Repeat("f", 64)
		}, wantError: "evidence coverage references missing evidence"},
		{name: "coverage asset mismatch", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Targets[0].AssetID = "asset-two"
		}, wantError: "evidence coverage reference mismatch"},
		{name: "coverage status mismatch", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Targets[0].Status = model.EvidenceSkipped
		}, wantError: "evidence coverage status mismatch"},
		{name: "duplicate coverage target", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Targets[1] = scan.EvidenceCoverage.Targets[0]
		}, wantError: "duplicate evidence coverage target"},
		{name: "invalid coverage status", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Status = "unknown-status"
		}, wantError: "invalid evidence coverage status"},
		{name: "coverage targets without status", mutate: func(scan *model.ScanResult, _ *model.Inventory) {
			scan.EvidenceCoverage.Status = ""
		}, wantError: "invalid evidence coverage status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTestStore(t)
			scan, inventory := validV3Snapshot(t, "invalid-evidence")
			tt.mutate(&scan, &inventory)
			if err := s.SaveScan(context.Background(), scan, inventory); err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error=%v want substring %q", err, tt.wantError)
			}
			if err := s.SaveScan(context.Background(), scan, inventory); err != nil && strings.Contains(err.Error(), persistedRawPathSentinel) {
				t.Fatalf("error exposed raw path: %v", err)
			}
			assertNoSnapshotRows(t, s)
		})
	}
}

func TestSnapshotV3CorruptEvidenceRowsReturnError(t *testing.T) {
	uppercaseDigest := strings.ToUpper(strings.Repeat("a", 64))
	mutations := []struct {
		name       string
		statements [][]any
		want       string
	}{
		{name: "missing state", statements: [][]any{{`DELETE FROM evidence_state WHERE scan_id = 'corrupt-evidence'`}}, want: "missing evidence state"},
		{name: "invalid index", statements: [][]any{{`UPDATE evidence_state SET evidence_index = 7 WHERE evidence_index = 0`}}, want: "got index"},
		{name: "row count mismatch", statements: [][]any{{`UPDATE inventory_state SET evidence_count = 9 WHERE scan_id = 'corrupt-evidence'`}}, want: "evidence row count mismatch"},
		{name: "nil shape with rows", statements: [][]any{{`UPDATE inventory_state SET evidence_nil = 1 WHERE scan_id = 'corrupt-evidence'`}}, want: "evidence marked nil but rows exist"},
		{name: "mismatched JSON id", statements: [][]any{{`UPDATE evidence SET evidence_json = replace(evidence_json, 'evidence:sha256:', 'wrong:sha256:') WHERE scan_id = 'corrupt-evidence'`}}, want: "does not match row"},
		{name: "orphan asset id", statements: [][]any{
			{`PRAGMA foreign_keys=OFF`},
			{`UPDATE evidence SET asset_id = 'missing' WHERE scan_id = 'corrupt-evidence'`},
			{`PRAGMA foreign_keys=ON`},
		}, want: "missing asset"},
		{name: "orphan observation id", statements: [][]any{
			{`PRAGMA foreign_keys=OFF`},
			{`UPDATE evidence SET observation_id = 'missing' WHERE scan_id = 'corrupt-evidence'`},
			{`PRAGMA foreign_keys=ON`},
		}, want: "missing observation"},
		{name: "metadata nil flag conflict", statements: [][]any{{`UPDATE evidence_state SET metadata_nil = 1 WHERE evidence_index = 0`}}, want: "metadata marked nil but JSON contains metadata"},
		{name: "errors nil flag conflict", statements: [][]any{{`UPDATE evidence_state SET errors_nil = 1 WHERE evidence_index = 1`}}, want: "errors marked nil but JSON contains errors"},
		{name: "corrupted digest", statements: [][]any{{`UPDATE evidence SET evidence_json = replace(evidence_json, ?, ?) WHERE scan_id = 'corrupt-evidence'`, strings.Repeat("a", 64), uppercaseDigest}}, want: "invalid evidence digest"},
		{name: "corrupted coverage JSON", statements: [][]any{{`UPDATE evidence_coverage SET result_json = 'null' WHERE scan_id = 'corrupt-evidence'`}}, want: "evidence coverage"},
		{name: "corrupted coverage reference", statements: [][]any{{`UPDATE evidence_coverage SET result_json = replace(result_json, 'plugins.manifest', '') WHERE scan_id = 'corrupt-evidence'`}}, want: "evidence target id must not be empty"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			s := openTestStore(t)
			saveValidV3Snapshot(t, s, "corrupt-evidence")
			for _, statement := range mutation.statements {
				query, ok := statement[0].(string)
				if !ok {
					t.Fatal("invalid statement fixture")
				}
				if _, err := s.db.Exec(query, statement[1:]...); err != nil {
					t.Fatal(err)
				}
			}
			_, ok, err := s.LatestSnapshot(context.Background())
			if err == nil || ok || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("ok=%v error=%v want substring %q", ok, err, mutation.want)
			}
		})
	}
}

func TestSnapshotV3EvidenceRowFailureRollsBackEveryTable(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_evidence_coverage BEFORE INSERT ON evidence_coverage BEGIN SELECT RAISE(ABORT, 'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	scan, inventory := validV3Snapshot(t, "evidence-rollback")
	if err := s.SaveScan(context.Background(), scan, inventory); err == nil {
		t.Fatal("forced evidence coverage failure unexpectedly succeeded")
	}
	assertNoSnapshotRows(t, s)
}

func TestSnapshotV3EvidenceRuntimeTargetsNeverPersist(t *testing.T) {
	s := openTestStore(t)
	scan, inventory := validV3Snapshot(t, "runtime-fields")
	scan.Coverage = []model.CollectorResult{{
		Collector: "plugins",
		Status:    model.CoverageComplete,
		LocalEvidenceTargets: []model.LocalEvidenceTarget{{
			TargetID: "plugins.manifest", RootPath: "/Volumes/private-runtime-root", RelativePath: "manifest.json",
		}},
	}}
	wantScan := scan
	wantScan.Coverage = append([]model.CollectorResult(nil), scan.Coverage...)
	wantScan.Coverage[0].LocalEvidenceTargets = nil
	if err := s.SaveScan(context.Background(), scan, inventory); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LatestSnapshot(context.Background())
	if err != nil || !ok || !reflect.DeepEqual(got.Scan, wantScan) {
		t.Fatalf("ok=%v\n got=%#v\nwant=%#v\nerr=%v", ok, got.Scan, wantScan, err)
	}
	assertSQLiteFilesExclude(t, s.Path(), "private-runtime-root")
}

func TestValidateSnapshotRejectsErrorsExceedingEvidenceCap(t *testing.T) {
	scan, inventory := validV3Snapshot(t, "error-cap")
	overflow := make([]model.EvidenceError, 65)
	for index := range overflow {
		overflow[index] = model.EvidenceError{Code: "read_unavailable", Message: "evidence tree entry is unavailable"}
	}
	inventory.Evidence[1].Errors = overflow
	if err := validateSnapshot(scan, inventory); err == nil || !strings.Contains(err.Error(), "invalid evidence errors") {
		t.Fatalf("error=%v", err)
	}
}
