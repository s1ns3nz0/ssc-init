package audit

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestValidateRejectsEverySensitiveMarker(t *testing.T) {
	for _, marker := range []string{"/Users/alice/private", "file:///Users/alice", "vscode-remote://ssh-remote+secret", "worktree-secret"} {
		record := validRecord()
		record.Run.Label = marker
		if Validate(record) == nil {
			t.Fatalf("accepted marker %q", marker)
		}
	}
}

func TestRedactRemovesNamesVersionsAndRetokenizesIDs(t *testing.T) {
	first, err := Redact(namedRecord(), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Redact(namedRecord(), [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if first.Inventory.Assets[0].Name != "" || first.Inventory.Assets[0].Version != "" {
		t.Fatal("identity display survived")
	}
	if first.Inventory.Assets[0].ID == second.Inventory.Assets[0].ID {
		t.Fatal("tokens correlate across salts")
	}
}

func TestRedactPreservesCountsStatusesAndRelationships(t *testing.T) {
	source := namedRecord()
	redacted, err := Redact(source, [32]byte{3})
	if err != nil || len(redacted.Inventory.Assets) != len(source.Inventory.Assets) || len(redacted.Inventory.Relationships) != len(source.Inventory.Relationships) || redacted.State != source.State {
		t.Fatalf("redacted=%+v err=%v", redacted, err)
	}
	if redacted.Inventory.Relationships[0].From != redacted.Inventory.Assets[0].ID || redacted.Inventory.Relationships[0].To != redacted.Inventory.Assets[1].ID {
		t.Fatal("relationships were not retokenized consistently")
	}
}

func TestRedactRewritesAnalyzerReferences(t *testing.T) {
	source := namedRecord()
	source.Inventory.AnalyzerFacts = []model.AnalyzerFact{{
		ID:          "fact:sha256:" + strings.Repeat("d", 64),
		AssetID:     source.Inventory.Assets[0].ID,
		EvidenceID:  "evidence:sha256:" + strings.Repeat("e", 64),
		RuleID:      "rule-1",
		Category:    model.AnalyzerObfuscation,
		Confidence:  model.ConfidenceHigh,
		Occurrences: 1,
	}}
	redacted, err := Redact(source, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	fact := redacted.Inventory.AnalyzerFacts[0]
	if fact.ID == source.Inventory.AnalyzerFacts[0].ID || fact.AssetID != redacted.Inventory.Assets[0].ID || fact.EvidenceID == source.Inventory.AnalyzerFacts[0].EvidenceID {
		t.Fatalf("analyzer references were not consistently retokenized: %+v", fact)
	}
}

func validRecord() Record {
	record, err := Build(model.ScanResult{Status: model.ScanComplete}, model.Inventory{}, model.Delta{}, nil, validRun())
	if err != nil {
		panic(err)
	}
	return record
}

func namedRecord() Record {
	first := "asset:sha256:" + strings.Repeat("a", 64)
	second := "asset:sha256:" + strings.Repeat("b", 64)
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: first, Type: model.AssetPackage, Name: "private-package", Version: "1.2.3", SHA256: strings.Repeat("c", 64)},
			{ID: second, Type: model.AssetTool, Name: "private-tool", Version: "4.5.6"},
		},
		Relationships: []model.Relationship{{From: first, To: second, Kind: model.RelationshipUses}},
	}
	record, err := Build(model.ScanResult{Status: model.ScanComplete}, inventory, model.Delta{}, nil, validRun())
	if err != nil {
		panic(err)
	}
	return record
}
