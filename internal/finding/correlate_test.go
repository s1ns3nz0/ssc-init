package finding

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/bundle"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestCorrelateMatchesCoordinateAndHashAndKeepsBenignTwinClear(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	badHash := strings.Repeat("a", 64)
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "pkg:npm/bad@1.0.0", Type: model.AssetPackage, Name: "bad", Version: "1.0.0", SHA256: badHash},
		{ID: "pkg:npm/benign@1.0.0", Type: model.AssetPackage, Name: "benign", Version: "1.0.0", SHA256: strings.Repeat("b", 64)},
	}}
	active := activeTI([]bundle.TIRecord{{ID: "ti:bad", AssetID: "pkg:npm/bad", SHA256: badHash, Verdict: "known-malicious", Confidence: "high", CampaignIDs: []string{"campaign-1"}, AttackTechniques: []string{"T1059.007"}}})
	findings := Correlate(inventory, active, now)
	if len(findings) != 1 || findings[0].AssetID != inventory.Assets[0].ID || findings[0].Verdict != model.VerdictKnownMalicious || findings[0].Level != 1 || findings[0].Action != model.ActionAdvisory {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestCorrelateRejectsCoordinateHashMismatchWithdrawnMissingVersionUnsupportedAndFalseName(t *testing.T) {
	asset := model.Asset{ID: "pkg:npm/example@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	records := []bundle.TIRecord{
		{ID: "hash-mismatch", AssetID: "pkg:npm/example", SHA256: strings.Repeat("b", 64), Verdict: "known-malicious", Confidence: "high"},
		{ID: "withdrawn", AssetID: "pkg:npm/example", SHA256: asset.SHA256, Verdict: "known-malicious", Confidence: "high", Withdrawn: true},
		{ID: "range-only", AssetID: "pkg:npm/example", VersionRange: "not a range", Verdict: "suspicious", Confidence: "medium"},
		{ID: "false-name", AssetID: "pkg:npm/other", SHA256: asset.SHA256, Verdict: "known-malicious", Confidence: "high"},
	}
	if got := Correlate(model.Inventory{Assets: []model.Asset{asset}}, activeTI(records), time.Now().UTC()); len(got) != 0 {
		t.Fatalf("unsupported records matched: %+v", got)
	}
	missingVersion := asset
	missingVersion.ID, missingVersion.Version = "pkg:npm/example@", ""
	if got := Correlate(model.Inventory{Assets: []model.Asset{missingVersion}}, activeTI([]bundle.TIRecord{{ID: "range", AssetID: "pkg:npm/example", VersionRange: ">=1.0.0", Verdict: "suspicious", Confidence: "medium"}}), time.Now().UTC()); len(got) != 0 {
		t.Fatalf("missing-version asset matched: %+v", got)
	}
	unsupported := asset
	unsupported.ID = "pkg:maven/example@1.0.0"
	if got := Correlate(model.Inventory{Assets: []model.Asset{unsupported}}, activeTI([]bundle.TIRecord{{ID: "unsupported", AssetID: "pkg:maven/example", SHA256: asset.SHA256, Verdict: "known-malicious", Confidence: "high"}}), time.Now().UTC()); len(got) != 0 {
		t.Fatalf("unsupported asset matched: %+v", got)
	}
}

func TestCorrelateMatchesVersionIndependentCoordinate(t *testing.T) {
	asset := model.Asset{ID: "pkg:npm/example@1.5.0", Type: model.AssetPackage, Name: "example", Version: "1.5.0"}
	active := activeTI([]bundle.TIRecord{{ID: "range-advisory", AssetID: "pkg:npm/example", VersionRange: ">=1.0.0 <2.0.0", Verdict: "known-malicious", Confidence: "high"}})
	got := Correlate(model.Inventory{Assets: []model.Asset{asset}}, active, time.Unix(1, 0).UTC())
	if len(got) != 1 || got[0].IntelligenceIDs[0] != "range-advisory" {
		t.Fatalf("findings=%+v", got)
	}
	asset.Version = "2.1.0"
	if got := Correlate(model.Inventory{Assets: []model.Asset{asset}}, active, time.Unix(1, 0).UTC()); len(got) != 0 {
		t.Fatalf("out-of-range matched: %+v", got)
	}
}

func TestCorrelateMergesCoordinateRecordsDeterministicallyByStrongestVerdict(t *testing.T) {
	asset := model.Asset{ID: "pkg:npm/example@1.0.0", Type: model.AssetPackage, Name: "example", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}
	records := []bundle.TIRecord{
		{ID: "z-record", AssetID: "pkg:npm/example", SHA256: asset.SHA256, Verdict: "needs-review", Confidence: "low"},
		{ID: "a-record", AssetID: "pkg:npm/example", SHA256: asset.SHA256, Verdict: "suspicious", Confidence: "medium"},
	}
	got := Correlate(model.Inventory{Assets: []model.Asset{asset}}, activeTI(records), time.Unix(1, 0).UTC())
	if len(got) != 1 || got[0].Verdict != model.VerdictSuspicious || strings.Join(got[0].IntelligenceIDs, ",") != "a-record,z-record" || !got[0].Valid() {
		t.Fatalf("finding=%+v", got)
	}
}

func activeTI(records []bundle.TIRecord) bundle.ActiveBundle {
	digest := sha256.Sum256([]byte("fixture bundle"))
	return bundle.ActiveBundle{
		Verified: bundle.Verified{Envelope: bundle.Envelope{Family: bundle.FamilyTI, Sequence: 7, TI: &bundle.TIPayload{Records: records}}, Digest: digest},
		Status:   bundle.Status{Family: bundle.FamilyTI, Freshness: bundle.FreshnessFresh, Sequence: 7},
	}
}
