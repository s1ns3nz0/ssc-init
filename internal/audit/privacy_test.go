package audit

import (
	"strings"
	"testing"
	"time"

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
	source := graphRecord()
	source.Inventory.AnalyzerFacts = []model.AnalyzerFact{{
		ID:          "fact:sha256:" + strings.Repeat("d", 64),
		AssetID:     source.Inventory.Assets[0].ID,
		EvidenceID:  source.Inventory.Evidence[0].ID,
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

func TestValidateRedactedRejectsCanonicalIDsAndReferences(t *testing.T) {
	redacted, err := Redact(graphRecord(), [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Record){
		"asset ID":              func(record *Record) { record.Inventory.Assets[0].ID = "pkg:npm/private-package@1.2.3" },
		"relationship endpoint": func(record *Record) { record.Inventory.Relationships[0].From = "pkg:npm/private-package@1.2.3" },
		"observation ID":        func(record *Record) { record.Inventory.Observations[0].ID = "observation:private" },
		"project reference":     func(record *Record) { record.Inventory.Observations[0].ProjectID = "asset:private-project" },
		"evidence reference":    func(record *Record) { record.Inventory.Evidence[0].AssetID = "asset:private" },
		"finding reference":     func(record *Record) { record.Findings[0].AssetID = "asset:private" },
		"analyzer reference":    func(record *Record) { record.Inventory.AnalyzerFacts[0].EvidenceID = "evidence:private" },
		"coverage reference":    func(record *Record) { record.EvidenceCoverage.Targets[0].TargetID = "target:private" },
		"change reference":      func(record *Record) { record.Changes.Changes[0].EntityID = "asset:private" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record, err := clone(redacted)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if err := Validate(record); err == nil {
				t.Fatal("Validate accepted canonical/private identifier")
			}
		})
	}
}

func TestValidateRejectsPrivateMarkersAcrossSerializedModel(t *testing.T) {
	for _, marker := range []string{"alice-macbook.local", "private-code-workspace-id", "connected at /home/alice/private", "internal.example.test:8443", "ENV_VALUE=private", "--private-argument", "product-private-id", "git-worktree-private"} {
		t.Run(marker, func(t *testing.T) {
			record := graphRecord()
			record.Inventory.Assets[0].Metadata = map[string]string{"marker": marker}
			if err := Validate(record); err == nil {
				t.Fatalf("Validate accepted private marker %q", marker)
			}
		})
	}
}

func TestValidateRejectsInvalidNestedVocabularyAndGraphReferences(t *testing.T) {
	mutations := map[string]func(*Record){
		"collector status":  func(record *Record) { record.Coverage[0].Status = model.CoverageStatus("arbitrary") },
		"relationship kind": func(record *Record) { record.Inventory.Relationships[0].Kind = "arbitrary" },
		"change kind":       func(record *Record) { record.Changes.Changes[0].Kind = model.ChangeKind("arbitrary") },
		"evidence status":   func(record *Record) { record.Inventory.Evidence[0].Status = model.EvidenceStatus("arbitrary") },
		"missing asset":     func(record *Record) { record.Inventory.Relationships[0].To = "asset:missing" },
		"duplicate asset": func(record *Record) {
			record.Inventory.Assets = append(record.Inventory.Assets, record.Inventory.Assets[0])
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record := graphRecord()
			mutate(&record)
			record.Summary = summarize(record)
			if err := Validate(record); err == nil {
				t.Fatal("Validate accepted invalid nested model")
			}
		})
	}
}

func TestRedactRetokenizesProjectIDsInAllObservationCollections(t *testing.T) {
	redacted, err := Redact(graphRecord(), [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	projectID := redacted.Inventory.Assets[1].ID
	if got := projectReference(redacted.Inventory.Observations); got != projectID {
		t.Fatalf("inventory ProjectID = %q, want %q", got, projectID)
	}
	if got := projectReference(redacted.Coverage[0].Observations); got != projectID {
		t.Fatalf("coverage ProjectID = %q, want %q", got, projectID)
	}
}

func projectReference(observations []model.Observation) string {
	for _, observation := range observations {
		if observation.ProjectID != "" {
			return observation.ProjectID
		}
	}
	return ""
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

func graphRecord() Record {
	input := richInputRecord(time.UTC)
	project := input.Inventory.Assets[0].ID
	input.Inventory.Observations[0].ProjectID = project
	input.Scan.Coverage[0].Observations[0].ProjectID = project
	input.Inventory.AnalyzerFacts = []model.AnalyzerFact{{ID: "fact:one", AssetID: project, EvidenceID: input.Inventory.Evidence[0].ID, RuleID: "rule-1", Category: model.AnalyzerObfuscation, Confidence: model.ConfidenceHigh, Occurrences: 1}}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		panic(err)
	}
	return record
}
