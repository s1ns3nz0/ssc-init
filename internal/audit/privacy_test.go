package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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

func TestValidateRejectsEmbeddedPrivateMarkersWithoutRejectingDottedDisplayNames(t *testing.T) {
	for _, marker := range []string{"alice-macbook.local", "private workspace id", "workspace-secret", "see[/home/alice/private]", "endpoint 10.0.0.1:8443"} {
		record := validRecord()
		record.Run.Label = marker
		if err := Validate(record); err == nil {
			t.Fatalf("Validate accepted %q", marker)
		}
	}
	record := namedRecord()
	record.Inventory.Assets[0].Name = "socket.io"
	if err := Validate(record); err != nil {
		t.Fatalf("Validate rejected dotted display name: %v", err)
	}
}

func TestValidateRejectsPunctuationBypassedPrivateMarkers(t *testing.T) {
	for _, marker := range []string{"note,/home/alice/private", "note,/private-project/secret", "file:/Users/alice/private", "host{10.0.0.1:8443}", "env[API_KEY]=private", "cmd(--private-argument)"} {
		record := namedRecord()
		record.Inventory.Assets[0].Name = marker
		if err := Validate(record); err == nil {
			t.Fatalf("Validate accepted punctuated marker %q", marker)
		}
	}
}

func TestRedactPreservesDistinctCollectorTargetInstances(t *testing.T) {
	input := richInputRecord(time.UTC)
	input.Scan.Coverage[0].Targets = []model.TargetCoverage{
		{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-a", Status: model.TargetPartial},
		{TargetID: "projects.discovery.git-worktrees", InstanceRef: "instance-b", Status: model.TargetPartial},
	}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := Redact(record, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	targets := redacted.Coverage[0].Targets
	if len(targets) != 2 || targets[0].InstanceRef == "" || targets[0].InstanceRef == targets[1].InstanceRef {
		t.Fatalf("redacted target instances lost distinction: %+v", targets)
	}
}

func TestBuildTokenizesPrivateCollectorTargetInstances(t *testing.T) {
	input := richInputRecord(time.UTC)
	input.Scan.Coverage[0].Targets = []model.TargetCoverage{{
		TargetID: "mcp:vscode:workspace", InstanceRef: "JetBrains-IntelliJIdea2025.2-private-worktree", Status: model.TargetPartial,
	}}
	record, err := Build(input.Scan, input.Inventory, input.Delta, input.Findings, validRun())
	if err != nil {
		t.Fatal(err)
	}
	instance := record.Coverage[0].Targets[0].InstanceRef
	if !instanceToken(instance) || strings.Contains(instance, "IntelliJ") || strings.Contains(instance, "worktree") {
		t.Fatalf("Build retained collector instance identity %q", instance)
	}
	redacted, err := Redact(record, [32]byte{10})
	if err != nil {
		t.Fatal(err)
	}
	if !exportToken(redacted.Coverage[0].Targets[0].InstanceRef) {
		t.Fatalf("Redact did not retokenize collector instance %q", redacted.Coverage[0].Targets[0].InstanceRef)
	}
}

func TestValidateRejectsUnsortedEvidenceCoverageErrors(t *testing.T) {
	record := graphRecord()
	record.EvidenceCoverage.Errors = []model.CoverageError{{Code: "target_rejected"}, {Code: "identity_changed"}}
	if err := Validate(record); err == nil {
		t.Fatal("Validate accepted unsorted evidence coverage errors")
	}
}

func TestCoverageErrorCatalogParsesEveryProductionConstructorCode(t *testing.T) {
	root := filepath.Join("..", "collector")
	for _, code := range producerCoverageErrorCodes {
		if !validAuditErrorCode(code) {
			t.Fatalf("producer coverage code %q is absent from audit catalog", code)
		}
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, index := range coverageCodeArgumentIndexes(callName(call.Fun)) {
				if index >= len(call.Args) {
					continue
				}
				literal, ok := call.Args[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				code := strings.Trim(literal.Value, `"`)
				if !validAuditErrorCode(code) {
					t.Fatalf("producer code %q from %s is absent from audit catalog", code, path)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// producerCoverageErrorCodes is the extracted, audited union of every code
// emitted by current collector contracts, including helper-returned codes that
// cannot be discovered from a call literal alone.
var producerCoverageErrorCodes = []string{
	"byte_limit", "collector_error", "collector_failed", "collector_panic", "collector_timeout", "config_invalid", "config_limit", "config_malformed", "config_oversized", "config_size_limit", "config_unavailable", "coverage_contract_violation", "depth_limit", "docker_unavailable", "entry_limit", "evidence_unavailable", "executable_evidence_invalid", "executable_replaced", "executable_unavailable", "file_limit", "filesystem_unavailable", "identity_changed", "identity_rejected", "inspector_unavailable", "invalid_local_target", "invalid_server", "launch_malformed", "launch_unavailable", "legacy_manifest_partial", "legacy_transport_unknown", "manifest_changed", "manifest_invalid", "manifest_limit", "manifest_oversized", "manifest_size_limit", "manifest_unavailable", "metadata-conflict", "metadata_malformed", "metadata_oversize", "metadata_unavailable", "observation-conflict", "orphan-observation", "outside_home", "output_malformed", "output_truncated", "path_invalid", "path_unavailable", "probe_failed", "probe_output_invalid", "probe_output_truncated", "provenance_identity_changed", "provenance_identity_rejected", "provenance_malformed", "provenance_unavailable", "read_failed", "read_unavailable", "rejected_identity", "rejected_metadata", "root_limit", "root_unavailable", "rooted_access_unavailable", "runner_unavailable", "signature_unavailable", "special_file_rejected", "stale", "symlink_rejected", "target_not_reported", "target_rejected", "time_limit", "unknown_server_field", "unsupported", "unsupported_target",
}

func callName(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	default:
		return ""
	}
}

func coverageCodeArgumentIndexes(name string) []int {
	switch name {
	case "coverageError", "targetError", "ideCoverageError", "agentCoverageError", "runtimeTargetError", "addError":
		return []int{0}
	case "unavailableTarget", "appendProjectProvenanceError", "appendAgentTargetIssue":
		return []int{1}
	case "addIssue":
		return []int{0, 3}
	case "surfaceTargetError":
		return []int{2}
	case "appendPackageIssue":
		return []int{3}
	}
	return nil
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
