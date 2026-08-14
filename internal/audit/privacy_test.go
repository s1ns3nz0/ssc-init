package audit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/model"
	"golang.org/x/tools/go/packages"
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

func TestValidateRejectsOpenIntelligenceUpdateValues(t *testing.T) {
	base := validRecord()
	base.Intelligence = &IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 1, Digest: strings.Repeat("a", 64), KeyID: "ti-prod-1", RecordedAt: base.Run.FinishedAt}
	if err := Validate(base); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	for name, mutate := range map[string]func(*IntelligenceUpdate){
		"status": func(v *IntelligenceUpdate) { v.Status = "https://private.example" },
		"error":  func(v *IntelligenceUpdate) { v.ErrorCode = "/Users/alice/private" },
		"digest": func(v *IntelligenceUpdate) { v.Digest = "manifest bytes" },
		"key":    func(v *IntelligenceUpdate) { v.KeyID = "PRIVATE KEY" },
	} {
		t.Run(name, func(t *testing.T) {
			record := base
			value := *base.Intelligence
			record.Intelligence = &value
			mutate(record.Intelligence)
			if Validate(record) == nil {
				t.Fatal("accepted open receipt")
			}
		})
	}
}

func TestValidateIntelligenceUpdateAcceptsOnlyEmittableStateMatrix(t *testing.T) {
	identified := IntelligenceUpdate{Family: "ti", Status: "updated", Freshness: "fresh", Sequence: 7, Digest: strings.Repeat("a", 64), KeyID: "ti-prod-1", Records: 4, Malicious: 1, Vulnerable: 3}
	valid := []IntelligenceUpdate{
		identified,
		func() IntelligenceUpdate { v := identified; v.Status = "current"; return v }(),
		func() IntelligenceUpdate {
			v := identified
			v.Status, v.ErrorCode = "degraded", "network-unavailable"
			return v
		}(),
		func() IntelligenceUpdate {
			v := identified
			v.Status, v.ErrorCode, v.Freshness = "degraded", "signature-invalid", "stale"
			return v
		}(),
		{Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "missing"},
		{Family: "ti", Status: "unavailable", ErrorCode: "bundle-invalid", Freshness: "unavailable"},
		func() IntelligenceUpdate {
			v := identified
			v.Status, v.ErrorCode, v.Freshness = "unavailable", "network-unavailable", "expired"
			return v
		}(),
	}
	for index, receipt := range valid {
		record := validRecord()
		receipt.RecordedAt = record.Run.FinishedAt
		record.Intelligence = &receipt
		if err := Validate(record); err != nil {
			t.Fatalf("valid[%d]=%+v rejected: %v", index, receipt, err)
		}
	}

	invalid := map[string]IntelligenceUpdate{
		"wrong-family":              identified,
		"updated-no-identity":       {Family: "ti", Status: "updated", Freshness: "fresh"},
		"updated-stale":             identified,
		"updated-error":             identified,
		"current-stale":             identified,
		"degraded-no-error":         identified,
		"degraded-no-identity":      {Family: "ti", Status: "degraded", ErrorCode: "network-unavailable", Freshness: "fresh"},
		"degraded-expired":          identified,
		"missing-with-identity":     identified,
		"unavailable-with-identity": identified,
		"expired-no-identity":       {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "expired"},
		"fresh-unavailable":         identified,
		"sequence-only":             {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "expired", Sequence: 1},
		"digest-only":               {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "expired", Digest: strings.Repeat("a", 64)},
		"key-only":                  {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "expired", KeyID: "ti-prod-1"},
		"cancellation":              {Family: "ti", Status: "unavailable", ErrorCode: "cancellation", Freshness: "missing"},
		"count-mismatch":            identified,
		"negative-count":            identified,
		"count-over-limit":          identified,
		"missing-with-counts":       {Family: "ti", Status: "unavailable", ErrorCode: "network-unavailable", Freshness: "missing", Records: 1, Malicious: 1},
	}
	invalid["wrong-family"] = func() IntelligenceUpdate { v := invalid["wrong-family"]; v.Family = "policy"; return v }()
	invalid["updated-stale"] = func() IntelligenceUpdate { v := invalid["updated-stale"]; v.Freshness = "stale"; return v }()
	invalid["updated-error"] = func() IntelligenceUpdate {
		v := invalid["updated-error"]
		v.ErrorCode = "network-unavailable"
		return v
	}()
	invalid["current-stale"] = func() IntelligenceUpdate {
		v := invalid["current-stale"]
		v.Status, v.Freshness = "current", "stale"
		return v
	}()
	invalid["degraded-no-error"] = func() IntelligenceUpdate { v := invalid["degraded-no-error"]; v.Status = "degraded"; return v }()
	invalid["degraded-expired"] = func() IntelligenceUpdate {
		v := invalid["degraded-expired"]
		v.Status, v.ErrorCode, v.Freshness = "degraded", "network-unavailable", "expired"
		return v
	}()
	invalid["missing-with-identity"] = func() IntelligenceUpdate {
		v := invalid["missing-with-identity"]
		v.Status, v.ErrorCode, v.Freshness = "unavailable", "network-unavailable", "missing"
		return v
	}()
	invalid["unavailable-with-identity"] = func() IntelligenceUpdate {
		v := invalid["unavailable-with-identity"]
		v.Status, v.ErrorCode, v.Freshness = "unavailable", "network-unavailable", "unavailable"
		return v
	}()
	invalid["fresh-unavailable"] = func() IntelligenceUpdate {
		v := invalid["fresh-unavailable"]
		v.Status, v.ErrorCode = "unavailable", "network-unavailable"
		return v
	}()
	invalid["count-mismatch"] = func() IntelligenceUpdate { v := invalid["count-mismatch"]; v.Records = 5; return v }()
	invalid["negative-count"] = func() IntelligenceUpdate { v := invalid["negative-count"]; v.Malicious = -1; return v }()
	invalid["count-over-limit"] = func() IntelligenceUpdate {
		v := invalid["count-over-limit"]
		v.Records, v.Vulnerable = 100001, 100000
		return v
	}()
	for name, receipt := range invalid {
		t.Run(name, func(t *testing.T) {
			record := validRecord()
			receipt.RecordedAt = record.Run.FinishedAt
			record.Intelligence = &receipt
			if Validate(record) == nil {
				t.Fatalf("accepted impossible receipt %+v", receipt)
			}
		})
	}
	for name, timestamp := range map[string]time.Time{"before": validRecord().Run.StartedAt.Add(-time.Second), "after": validRecord().Run.FinishedAt.Add(time.Second), "non-utc": validRecord().Run.FinishedAt.In(time.FixedZone("KST", 9*60*60))} {
		t.Run("timestamp-"+name, func(t *testing.T) {
			record := validRecord()
			receipt := identified
			receipt.RecordedAt = timestamp
			record.Intelligence = &receipt
			if Validate(record) == nil {
				t.Fatal("accepted impossible timestamp")
			}
		})
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

func TestValidateRejectsRawSensitiveCategoriesInSafeTextField(t *testing.T) {
	for _, marker := range []string{"note/home/alice/private", "mailto:alice@example.com", "localhost:8080", "foo=private", "cmd(-p secret)"} {
		t.Run(marker, func(t *testing.T) {
			record := namedRecord()
			record.Inventory.Assets[1].Name = marker
			if err := Validate(record); err == nil {
				t.Fatalf("Validate accepted raw sensitive value %q in free asset name", marker)
			}
		})
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

func TestCoverageErrorCatalogMatchesEveryProductionValueFlow(t *testing.T) {
	codes, unresolved, err := productionCoverageErrorCodes([]string{filepath.Join("..", "collector"), filepath.Join("..", "evidence"), filepath.Join("..", "inventory")})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("production error-code sinks have unresolved value flow: %s", strings.Join(unresolved, ", "))
	}
	if _, found := codes["remote_unsupported"]; !found {
		t.Fatal("producer value flow did not reach indirect remote_unsupported materialization")
	}
	ordered := make([]string, 0, len(codes))
	for code := range codes {
		ordered = append(ordered, code)
	}
	sort.Strings(ordered)
	for _, code := range ordered {
		if !validAuditErrorCode(code) {
			t.Errorf("production error code %q is absent from audit catalog", code)
		}
	}
}

func TestProductionCoverageErrorValueFlowFollowsConstantsVariablesAndMaterialization(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

const indirectCode = "constant_indirect"

type CoverageError struct { Code string }

func materialize(codes []string) []CoverageError {
	var errors []CoverageError
	for _, code := range codes {
		errors = append(errors, CoverageError{Code: code})
	}
	return errors
}

func produce() []CoverageError {
	variable := indirectCode
	return materialize([]string{variable})
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("unresolved synthetic value flow: %v", unresolved)
	}
	if _, found := codes["constant_indirect"]; !found {
		t.Fatalf("constant/variable/materialized code absent: %v", codes)
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedForKnownAndUnknownCode(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func unknownCode() string

func produce(condition bool) CoverageError {
	code := "known_error"
	if condition {
		code = unknownCode()
	}
	return CoverageError{Code: code}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) == 0 {
		t.Fatal("known error code masked unresolved flow into the same sink")
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedForKnownAndUnresolvedIdentifier(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func produce(condition bool, unresolved string) CoverageError {
	code := "known_error"
	if condition {
		code = unresolved
	}
	return CoverageError{Code: code}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) == 0 {
		t.Fatal("known error code masked an unresolved identifier flowing into the same sink")
	}
}

func TestProductionCoverageErrorValueFlowRegistersUnkeyedComposites(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type EvidenceError struct { Code, Message string }

func unknownCode() string

func produceKnown() (CoverageError, EvidenceError) {
	return CoverageError{"unkeyed_coverage", "message", ""}, EvidenceError{"unkeyed_evidence", "message"}
}

func produceUnknown() CoverageError {
	return CoverageError{unknownCode(), "message", ""}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"unkeyed_coverage", "unkeyed_evidence"} {
		if _, found := codes[code]; !found {
			t.Errorf("unkeyed composite code %q was not registered", code)
		}
	}
	if len(unresolved) == 0 {
		t.Fatal("unkeyed composite with unresolved code was not rejected")
	}
}

func TestProductionCoverageErrorValueFlowRegistersElidedComposites(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type EvidenceError struct { Code, Message string }

func produce() ([]CoverageError, map[string]EvidenceError) {
	return []CoverageError{{Code: "elided_coverage"}, {"elided_unkeyed", "message", ""}}, map[string]EvidenceError{"read": {Code: "elided_evidence"}}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("elided composites were unresolved: %v", unresolved)
	}
	for _, code := range []string{"elided_coverage", "elided_unkeyed", "elided_evidence"} {
		if _, found := codes[code]; !found {
			t.Errorf("elided composite code %q was not registered", code)
		}
	}
}

func TestProductionCoverageErrorValueFlowRegistersPackageInitializers(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type EvidenceError struct { Code, Message string }

var packageCoverage = CoverageError{Code: "package_keyed"}
var packageUnkeyed = CoverageError{"package_unkeyed", "message", ""}
var packageEvidence = map[string]EvidenceError{
	"keyed": {Code: "package_elided_keyed"},
	"unkeyed": {"package_elided_unkeyed", "message"},
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("package-scope composites were unresolved: %v", unresolved)
	}
	for _, code := range []string{"package_keyed", "package_unkeyed", "package_elided_keyed", "package_elided_unkeyed"} {
		if _, found := codes[code]; !found {
			t.Errorf("package-scope composite code %q was not registered", code)
		}
	}
}

func TestProductionCoverageErrorValueFlowDetectsRealFixedFileErrorsMutation(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "evidence", "file.go"))
	if err != nil {
		t.Fatal(err)
	}
	const original = `"oversize": {Code: "byte_limit"`
	const mutated = `"oversize": {Code: "review_fixed_file_code"`
	changed := strings.Replace(string(source), original, mutated, 1)
	if changed == string(source) {
		t.Fatalf("fixedFileErrors fixture no longer contains %s", original)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.go"), []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("mutated fixedFileErrors initializer was unresolved: %v", unresolved)
	}
	if _, found := codes["review_fixed_file_code"]; !found {
		t.Fatal("production analyzer missed mutation in real fixedFileErrors package initializer")
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedForMalformedAndZeroValueBranches(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func malformed(condition bool) CoverageError {
	code := "read_failed"
	if condition {
		code = "INVALID"
	}
	return CoverageError{Code: code}
}

func zeroValue(condition bool) CoverageError {
	var code string
	if condition {
		code = "read_failed"
	}
	return CoverageError{Code: code}
}

func explicitZero(condition bool) CoverageError {
	code := ""
	if condition {
		code = "read_failed"
	}
	return CoverageError{Code: code}
}

func reassignedAfterGuard(condition bool) CoverageError {
	code := "read_failed"
	if code == "" {
		return CoverageError{Code: "fallback_error"}
	}
	if condition {
		code = ""
	}
	return CoverageError{Code: code}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 4 {
		t.Fatalf("malformed and zero-value branches must each fail closed, unresolved=%v", unresolved)
	}
}

func TestProductionCoverageErrorValueFlowHonorsNonEmptyGuards(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func maybeCode(condition bool) string {
	if condition {
		return "guarded_error"
	}
	return ""
}

func produce(condition bool) []CoverageError {
	code := maybeCode(condition)
	if code != "" {
		return []CoverageError{{Code: code}}
	}
	return nil
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("non-empty guard did not exclude its empty sentinel: %v", unresolved)
	}
	if _, found := codes["guarded_error"]; !found {
		t.Fatalf("guarded error code absent: %v", codes)
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedForImplicitResultAndMapZeros(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func maybeCode(condition bool) (code string) {
	if condition {
		code = "named_result_error"
	}
	return
}

func namedResult(condition bool) CoverageError {
	return CoverageError{Code: maybeCode(condition)}
}

func mapLookup(key string) CoverageError {
	codes := map[string]string{"known": "map_lookup_error"}
	return CoverageError{Code: codes[key]}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 2 {
		t.Fatalf("named result and map lookup zero paths must fail closed, unresolved=%v", unresolved)
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedAcrossGuardMutationsAndFieldObjects(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type codeHolder struct { Code string }

func externalMutation(*string)

func closureMutation() CoverageError {
	code := "closure_error"
	if code == "" {
		return CoverageError{Code: "fallback_error"}
	}
	mutate := func() { code = "" }
	mutate()
	return CoverageError{Code: code}
}

func pointerMutation() CoverageError {
	code := "pointer_error"
	pointer := &code
	if code == "" {
		return CoverageError{Code: "fallback_error"}
	}
	*pointer = ""
	return CoverageError{Code: code}
}

func callMutation() CoverageError {
	code := "call_error"
	if code == "" {
		return CoverageError{Code: "fallback_error"}
	}
	externalMutation(&code)
	return CoverageError{Code: code}
}

func conflatedFields() CoverageError {
	known := codeHolder{Code: "field_error"}
	var zero codeHolder
	if known.Code != "" {
		return CoverageError{Code: zero.Code}
	}
	return CoverageError{Code: "fallback_error"}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) < 4 {
		t.Fatalf("guard mutation and object-confined field flows must fail closed, unresolved=%v", unresolved)
	}
}

func TestProductionCoverageErrorValueFlowFailsClosedForCompoundAndGuardConditionMutation(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func compound() CoverageError {
	code := "read_failed"
	code += "write_failed"
	return CoverageError{Code: code}
}

func guardMutation() CoverageError {
	code := "guard_error"
	mutate := func() bool { code = ""; return true }
	if code != "" && mutate() {
		return CoverageError{Code: code}
	}
	return CoverageError{Code: "fallback_error"}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 2 {
		t.Fatalf("compound assignment and guard-condition mutation must fail closed, unresolved=%v", unresolved)
	}
}

func TestProductionCoverageErrorValueFlowKeepsNestedCodeFieldsObjectSpecific(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type holder struct { Code string }
type pair struct { A, B holder }

func produce() CoverageError {
	p := pair{A: holder{Code: "nested_field_error"}}
	if p.A.Code != "" {
		return CoverageError{Code: p.B.Code}
	}
	return CoverageError{Code: "fallback_error"}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) == 0 {
		t.Fatal("nested Code fields on different objects were conflated")
	}
}

func TestProductionCoverageErrorValueFlowSeedsCrossPackageStringAliasResultZero(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod": `module example.test/fixture

go 1.26
`,
		"helper/helper.go": `package helper

type Code = string
`,
		"producer.go": `package fixture

import "example.test/fixture/helper"

type CoverageError struct { Code, Message, Path string }

func maybe(condition bool) (code helper.Code) {
	if condition { code = "alias_result_error" }
	return
}

func produce(condition bool) CoverageError {
	return CoverageError{Code: maybe(condition)}
}
`,
	}
	for relative, contents := range files {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) == 0 {
		t.Fatal("cross-package string alias named result zero was not modeled")
	}
}

func TestProductionCoverageErrorValueFlowResolvesCrossPackageAliases(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"go.mod": `module example.test/fixture

go 1.26
`,
		"model/model.go": `package model

type CoverageError struct { Code, Message, Path string }
`,
		"helper/helper.go": `package helper

import "example.test/fixture/model"

type Alias = model.CoverageError
`,
		"producer.go": `package fixture

import "example.test/fixture/helper"

var crossPackage = helper.Alias{"cross_package_alias", "message", ""}
`,
	}
	for relative, contents := range files {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("cross-package alias was unresolved: %v", unresolved)
	}
	if _, found := codes["cross_package_alias"]; !found {
		t.Fatalf("cross-package alias sink was not registered: %v", codes)
	}
}

func TestProductionCoverageErrorValueFlowResolvesAliasesAndRecursiveElision(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }
type EvidenceError struct { Code, Message string }
type CoverageAlias = CoverageError
type EvidenceAlias EvidenceError
type CoverageRows = [][]CoverageAlias
type EvidenceTable map[string][]EvidenceAlias

var coverageRows = CoverageRows{{{Code: "nested_alias_keyed"}, {"nested_alias_unkeyed", "message", ""}}}
var evidenceTable = EvidenceTable{"errors": {{Code: "nested_defined_keyed"}, {"nested_defined_unkeyed", "message"}}}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	codes, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("aliased recursively elided composites were unresolved: %v", unresolved)
	}
	for _, code := range []string{"nested_alias_keyed", "nested_alias_unkeyed", "nested_defined_keyed", "nested_defined_unkeyed"} {
		if _, found := codes[code]; !found {
			t.Errorf("aliased recursively elided code %q was not registered", code)
		}
	}
}

func TestProductionCoverageErrorValueFlowRejectsUnknownTransformWithKnownArgument(t *testing.T) {
	root := t.TempDir()
	source := `package fixture

type CoverageError struct { Code, Message, Path string }

func transform(string) string

func produce() CoverageError {
	return CoverageError{Code: transform("argument_error")}
}
`
	if err := os.WriteFile(filepath.Join(root, "producer.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	_, unresolved, err := productionCoverageErrorCodes([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved) == 0 {
		t.Fatal("unknown transform laundered its known-looking argument into an error code")
	}
}

var productionErrorCodePattern = regexp.MustCompile(`\A(?:[a-z][a-z0-9]*(?:[_-][a-z0-9]+)+|stale|unsupported)\z`)

type sourceValueFlow struct {
	prefix         string
	packageNames   map[string]struct{}
	topLevel       map[*ast.Object]string
	namedTypes     map[string]ast.Expr
	functions      map[string][]*sourceFunction
	functionBodies map[*ast.BlockStmt]struct{}
	direct         map[string]map[string]struct{}
	edges          map[string]map[string]bool
	unknown        map[string]struct{}
	addressTaken   map[string]struct{}
	empty          map[string]struct{}
	sinks          map[string]string
	parents        map[ast.Node]ast.Node
	fileSet        *token.FileSet
	nodeLabels     map[string]string
	typedErrors    map[string]string
	typedStrings   map[string]struct{}
	nextSink       int
}

type sourceFunction struct {
	body         *ast.BlockStmt
	parameters   []string
	results      []string
	namedResults []string
}

func productionCoverageErrorCodes(roots []string) (map[string]struct{}, []string, error) {
	packageFiles := map[string][]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			packageFiles[filepath.Dir(path)] = append(packageFiles[filepath.Dir(path)], path)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	allCodes := map[string]struct{}{}
	var unresolved []string
	for directory, paths := range packageFiles {
		flow, err := newSourceValueFlow(directory, paths)
		if err != nil {
			return nil, nil, err
		}
		codes, missing := flow.resolveSinks()
		for code := range codes {
			allCodes[code] = struct{}{}
		}
		unresolved = append(unresolved, missing...)
	}
	sort.Strings(unresolved)
	return allCodes, unresolved, nil
}

func loadTypedSourceInfo(directory string) (map[string]string, map[string]struct{}, error) {
	if !insideGoModule(directory) {
		return map[string]string{}, map[string]struct{}{}, nil
	}
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedImports | packages.NeedDeps,
		Dir: directory,
	}, ".")
	if err != nil {
		return nil, nil, err
	}
	if len(loaded) != 1 {
		return nil, nil, fmt.Errorf("type load for %s returned %d packages", directory, len(loaded))
	}
	if len(loaded[0].Errors) != 0 {
		messages := make([]string, 0, len(loaded[0].Errors))
		for _, packageErr := range loaded[0].Errors {
			messages = append(messages, packageErr.Error())
		}
		return nil, nil, fmt.Errorf("type load for %s: %s", directory, strings.Join(messages, "; "))
	}
	typed := map[string]string{}
	stringsTyped := map[string]struct{}{}
	for _, file := range loaded[0].Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			composite, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if typeName := typedErrorStructName(loaded[0].TypesInfo.TypeOf(composite)); typeName != "" {
				typed[positionKey(loaded[0].Fset, composite)] = typeName
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && types.Identical(types.Unalias(loaded[0].TypesInfo.TypeOf(identifier)), types.Typ[types.String]) {
				stringsTyped[positionKey(loaded[0].Fset, identifier)] = struct{}{}
			}
			return true
		})
	}
	return typed, stringsTyped, nil
}

func insideGoModule(directory string) bool {
	current, err := filepath.Abs(directory)
	if err != nil {
		return false
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

func typedErrorStructName(typeValue types.Type) string {
	if typeValue == nil {
		return ""
	}
	typeValue = types.Unalias(typeValue)
	if pointer, ok := typeValue.(*types.Pointer); ok {
		typeValue = types.Unalias(pointer.Elem())
	}
	if named, ok := typeValue.(*types.Named); ok && errorStructName(named.Obj().Name()) {
		return named.Obj().Name()
	}
	structure, ok := typeValue.Underlying().(*types.Struct)
	if !ok {
		return ""
	}
	fields := []string{"Code", "Message"}
	typeName := "EvidenceError"
	if structure.NumFields() == 3 {
		fields = append(fields, "Path")
		typeName = "CoverageError"
	} else if structure.NumFields() != 2 {
		return ""
	}
	for index, name := range fields {
		field := structure.Field(index)
		if field.Name() != name || !types.Identical(field.Type(), types.Typ[types.String]) {
			return ""
		}
	}
	return typeName
}

func positionKey(fileSet *token.FileSet, node ast.Node) string {
	position := fileSet.Position(node.Pos())
	filename, err := filepath.Abs(position.Filename)
	if err != nil {
		filename = position.Filename
	}
	return fmt.Sprintf("%s:%d:%d", filepath.Clean(filename), position.Line, position.Column)
}

func newSourceValueFlow(directory string, paths []string) (*sourceValueFlow, error) {
	files := make([]*ast.File, 0, len(paths))
	fileSet := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	typedErrors, typedStrings, err := loadTypedSourceInfo(directory)
	if err != nil {
		return nil, err
	}
	flow := &sourceValueFlow{
		prefix:         filepath.ToSlash(directory),
		packageNames:   map[string]struct{}{},
		topLevel:       map[*ast.Object]string{},
		namedTypes:     map[string]ast.Expr{},
		functions:      map[string][]*sourceFunction{},
		functionBodies: map[*ast.BlockStmt]struct{}{},
		direct:         map[string]map[string]struct{}{},
		edges:          map[string]map[string]bool{},
		unknown:        map[string]struct{}{},
		addressTaken:   map[string]struct{}{},
		empty:          map[string]struct{}{},
		sinks:          map[string]string{},
		parents:        map[ast.Node]ast.Node{},
		fileSet:        fileSet,
		nodeLabels:     map[string]string{},
		typedErrors:    typedErrors,
		typedStrings:   typedStrings,
	}
	for _, file := range files {
		flow.indexParents(file)
		for name, object := range file.Scope.Objects {
			flow.packageNames[name] = struct{}{}
			flow.topLevel[object] = flow.packageNode(name)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if declaration, ok := node.(*ast.TypeSpec); ok {
				flow.namedTypes[declaration.Name.Name] = declaration.Type
			}
			return true
		})
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				flow.registerFunction(flow.packageNode(function.Name.Name), function.Type, function.Body)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.AssignStmt:
				flow.registerAssignedFunctionLiterals(value.Lhs, value.Rhs)
			case *ast.ValueSpec:
				names := make([]ast.Expr, len(value.Names))
				for index := range value.Names {
					names[index] = value.Names[index]
				}
				flow.registerAssignedFunctionLiterals(names, value.Values)
			case *ast.FuncLit:
				flow.registerFunction(fmt.Sprintf("%s:anonymous:%d", flow.prefix, value.Pos()), value.Type, value.Body)
			}
			return true
		})
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if ok {
				flow.analyzeGeneralDeclaration(general)
			}
		}
	}
	functions := make([]*sourceFunction, 0, len(flow.functions))
	for _, candidates := range flow.functions {
		functions = append(functions, candidates...)
	}
	for _, function := range functions {
		flow.analyzeFunction(function)
	}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			if composite, ok := node.(*ast.CompositeLit); ok {
				flow.analyzeCodeComposite(composite)
			}
			return true
		})
	}
	return flow, nil
}

func (flow *sourceValueFlow) indexParents(root ast.Node) {
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) != 0 {
			flow.parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
}

func (flow *sourceValueFlow) packageNode(name string) string {
	return flow.prefix + ":package:" + name
}

func (flow *sourceValueFlow) identifierNode(identifier *ast.Ident) string {
	if identifier == nil || identifier.Name == "_" {
		return ""
	}
	if node, found := flow.topLevel[identifier.Obj]; found {
		flow.labelNode(node, identifier)
		return node
	}
	if identifier.Obj != nil {
		node := fmt.Sprintf("%s:object:%p", flow.prefix, identifier.Obj)
		flow.labelNode(node, identifier)
		return node
	}
	if _, found := flow.packageNames[identifier.Name]; found {
		node := flow.packageNode(identifier.Name)
		flow.labelNode(node, identifier)
		return node
	}
	node := flow.prefix + ":external:" + identifier.Name
	flow.labelNode(node, identifier)
	return node
}

func (flow *sourceValueFlow) labelNode(node string, identifier *ast.Ident) {
	if node != "" && flow.nodeLabels[node] == "" {
		flow.nodeLabels[node] = fmt.Sprintf("%s at %s", identifier.Name, flow.fileSet.Position(identifier.Pos()))
	}
}

func (flow *sourceValueFlow) registerAssignedFunctionLiterals(left, right []ast.Expr) {
	for index, expression := range right {
		literal, ok := expression.(*ast.FuncLit)
		if !ok || index >= len(left) {
			continue
		}
		identifier, ok := left[index].(*ast.Ident)
		if !ok {
			continue
		}
		flow.registerFunction(flow.identifierNode(identifier), literal.Type, literal.Body)
	}
}

func (flow *sourceValueFlow) registerFunction(node string, typeValue *ast.FuncType, body *ast.BlockStmt) {
	if node == "" || body == nil {
		return
	}
	if _, registered := flow.functionBodies[body]; registered {
		return
	}
	flow.functionBodies[body] = struct{}{}
	function := &sourceFunction{body: body}
	function.parameters = flow.fieldNodes(typeValue.Params)
	function.results, function.namedResults = flow.resultNodes(node, typeValue.Results)
	flow.functions[node] = append(flow.functions[node], function)
}

func (flow *sourceValueFlow) fieldNodes(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	var nodes []string
	for _, field := range fields.List {
		for _, name := range field.Names {
			nodes = append(nodes, flow.identifierNode(name))
		}
		if len(field.Names) == 0 {
			nodes = append(nodes, "")
		}
	}
	return nodes
}

func (flow *sourceValueFlow) resultNodes(functionNode string, fields *ast.FieldList) ([]string, []string) {
	if fields == nil {
		return nil, nil
	}
	var results, named []string
	for _, field := range fields.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		for index := 0; index < count; index++ {
			results = append(results, fmt.Sprintf("%s:return:%d", functionNode, len(results)))
			if len(field.Names) != 0 {
				node := flow.identifierNode(field.Names[index])
				named = append(named, node)
				if flow.stringType(field.Type, map[string]struct{}{}) || flow.typedString(field.Names[index]) {
					flow.addDirect(node, "")
				}
			} else {
				named = append(named, "")
			}
		}
	}
	return results, named
}

func (flow *sourceValueFlow) analyzeGeneralDeclaration(declaration *ast.GenDecl) {
	var previous []ast.Expr
	for _, specification := range declaration.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		expressions := value.Values
		if len(expressions) == 0 && declaration.Tok == token.CONST {
			expressions = previous
		} else if len(expressions) != 0 {
			previous = expressions
		}
		for index, name := range value.Names {
			if len(expressions) == 0 {
				if declaration.Tok == token.VAR {
					node := flow.identifierNode(name)
					switch {
					case emptyContainerType(value.Type):
						flow.markEmpty(node)
					case flow.stringType(value.Type, map[string]struct{}{}):
						flow.addDirect(node, "")
					}
				}
				continue
			}
			expression := expressions[min(index, len(expressions)-1)]
			flow.linkExpression(flow.identifierNode(name), expression)
		}
	}
}

func emptyContainerType(expression ast.Expr) bool {
	switch expression.(type) {
	case *ast.ArrayType, *ast.MapType:
		return true
	default:
		return false
	}
}

func (flow *sourceValueFlow) analyzeFunction(function *sourceFunction) {
	ast.Inspect(function.body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok && literal.Body != function.body {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			flow.analyzeAssignment(value)
		case *ast.DeclStmt:
			if declaration, ok := value.Decl.(*ast.GenDecl); ok {
				flow.analyzeGeneralDeclaration(declaration)
			}
		case *ast.RangeStmt:
			flow.linkRangeVariable(value.Key, value.X)
			flow.linkRangeVariable(value.Value, value.X)
		case *ast.ReturnStmt:
			flow.analyzeReturn(function, value)
		case *ast.CallExpr:
			flow.connectCall(value)
		case *ast.UnaryExpr:
			if value.Op == token.AND {
				node := flow.baseIdentifierNode(value.X)
				flow.addressTaken[node] = struct{}{}
				flow.markUnknown(node)
			}
		}
		return true
	})
}

func (flow *sourceValueFlow) analyzeAssignment(assignment *ast.AssignStmt) {
	if assignment.Tok != token.ASSIGN && assignment.Tok != token.DEFINE {
		for _, left := range assignment.Lhs {
			flow.markUnknown(flow.expressionNode(left))
		}
		return
	}
	if len(assignment.Rhs) == 1 && len(assignment.Lhs) > 1 {
		if call, ok := assignment.Rhs[0].(*ast.CallExpr); ok {
			if functions := flow.calledFunctions(call); len(functions) != 0 {
				for index, left := range assignment.Lhs {
					for _, function := range functions {
						if index < len(function.results) {
							flow.linkLeft(left, nil, function.results[index])
						}
					}
				}
				return
			}
		}
	}
	for index, left := range assignment.Lhs {
		if len(assignment.Rhs) == 0 {
			continue
		}
		right := assignment.Rhs[min(index, len(assignment.Rhs)-1)]
		flow.linkLeft(left, right, "")
	}
}

func (flow *sourceValueFlow) linkLeft(left ast.Expr, right ast.Expr, sourceNode string) {
	switch value := left.(type) {
	case *ast.Ident:
		destination := flow.identifierNode(value)
		if sourceNode != "" {
			flow.addEdge(destination, sourceNode)
		} else {
			flow.linkExpression(destination, right)
		}
	case *ast.IndexExpr:
		if destination := flow.baseIdentifierNode(value.X); destination != "" {
			if setInsertion(right) {
				flow.linkPossiblyGuardedExpression(destination, value.Index)
			}
			if sourceNode != "" {
				flow.addEdge(destination, sourceNode)
			} else {
				flow.linkExpression(destination, right)
			}
		}
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			destination := flow.codeFieldNode(value.X)
			if sourceNode != "" {
				flow.addEdge(destination, sourceNode)
			} else {
				flow.linkExpression(destination, right)
			}
			flow.addSink(right, "assigned Code field")
		}
	}
}

func setInsertion(expression ast.Expr) bool {
	composite, ok := expression.(*ast.CompositeLit)
	if !ok || len(composite.Elts) != 0 {
		return false
	}
	structure, ok := composite.Type.(*ast.StructType)
	return ok && (structure.Fields == nil || len(structure.Fields.List) == 0)
}

func (flow *sourceValueFlow) baseIdentifierNode(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return flow.identifierNode(value)
	case *ast.IndexExpr:
		return flow.baseIdentifierNode(value.X)
	case *ast.SelectorExpr:
		return flow.baseIdentifierNode(value.X)
	}
	return ""
}

func (flow *sourceValueFlow) codeFieldNode(expression ast.Expr) string {
	if path := flow.expressionPath(expression); path != "" {
		return flow.prefix + ":field:Code:" + path
	}
	if expression != nil {
		return fmt.Sprintf("%s:field:Code:%d", flow.prefix, expression.Pos())
	}
	return ""
}

func (flow *sourceValueFlow) expressionPath(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return flow.identifierNode(value)
	case *ast.ParenExpr:
		return flow.expressionPath(value.X)
	case *ast.SelectorExpr:
		base := flow.expressionPath(value.X)
		if base != "" {
			return base + "." + value.Sel.Name
		}
	case *ast.StarExpr:
		base := flow.expressionPath(value.X)
		if base != "" {
			return "*" + base
		}
	case *ast.IndexExpr:
		base := flow.expressionPath(value.X)
		if base != "" {
			return base + "[]"
		}
	}
	return ""
}

func (flow *sourceValueFlow) linkRangeVariable(expression ast.Expr, ranged ast.Expr) {
	identifier, ok := expression.(*ast.Ident)
	if ok {
		flow.linkPossiblyGuardedExpression(flow.identifierNode(identifier), ranged)
	}
}

func (flow *sourceValueFlow) analyzeReturn(function *sourceFunction, statement *ast.ReturnStmt) {
	if len(statement.Results) == 0 {
		for index, named := range function.namedResults {
			if named != "" {
				flow.addEdge(function.results[index], named)
			}
		}
		return
	}
	if len(statement.Results) == 1 && len(function.results) > 1 {
		if call, ok := statement.Results[0].(*ast.CallExpr); ok {
			if calledFunctions := flow.calledFunctions(call); len(calledFunctions) != 0 {
				for index := range function.results {
					for _, called := range calledFunctions {
						if index < len(called.results) {
							flow.addEdge(function.results[index], called.results[index])
						}
					}
				}
				return
			}
		}
	}
	for index, result := range statement.Results {
		if index < len(function.results) {
			flow.linkExpression(function.results[index], result)
		}
	}
}

func (flow *sourceValueFlow) connectCall(call *ast.CallExpr) {
	for _, function := range flow.calledFunctions(call) {
		for index, argument := range call.Args {
			if index < len(function.parameters) && function.parameters[index] != "" {
				flow.linkPossiblyGuardedExpression(function.parameters[index], argument)
			}
		}
	}
}

func (flow *sourceValueFlow) calledFunctions(call *ast.CallExpr) []*sourceFunction {
	switch value := call.Fun.(type) {
	case *ast.Ident:
		return flow.functions[flow.identifierNode(value)]
	case *ast.SelectorExpr:
		return flow.functions[flow.packageNode(value.Sel.Name)]
	}
	return nil
}

func (flow *sourceValueFlow) analyzeCodeComposite(composite *ast.CompositeLit) {
	typeName := flow.compositeErrorType(composite)
	codeFound := false
	for _, element := range composite.Elts {
		keyed, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyed.Key.(*ast.Ident)
		if !ok || key.Name != "Code" {
			continue
		}
		codeFound = true
		flow.addSink(keyed.Value, flow.codeSinkLabel(typeNameOrCodeComposite(typeName), composite))
	}
	if codeFound || !errorStructName(typeName) {
		return
	}
	if len(composite.Elts) == 0 {
		flow.addSink(nil, flow.codeSinkLabel(typeName, composite))
		return
	}
	flow.addSink(composite.Elts[0], flow.codeSinkLabel(typeName, composite))
}

func (flow *sourceValueFlow) codeSinkLabel(kind string, node ast.Node) string {
	return fmt.Sprintf("%s at %s", kind, flow.fileSet.Position(node.Pos()))
}

func (flow *sourceValueFlow) positionKey(node ast.Node) string {
	return positionKey(flow.fileSet, node)
}

func (flow *sourceValueFlow) typedString(node ast.Node) bool {
	_, found := flow.typedStrings[flow.positionKey(node)]
	return found
}

func (flow *sourceValueFlow) compositeErrorType(composite *ast.CompositeLit) string {
	if typeName := flow.typedErrors[flow.positionKey(composite)]; typeName != "" {
		return typeName
	}
	return flow.namedErrorStruct(flow.compositeType(composite), map[string]struct{}{})
}

func (flow *sourceValueFlow) compositeType(composite *ast.CompositeLit) ast.Expr {
	if composite.Type != nil {
		return composite.Type
	}
	parent := flow.parents[composite]
	switch value := parent.(type) {
	case *ast.CompositeLit:
		return flow.containerElement(flow.compositeType(value), false, map[string]struct{}{})
	case *ast.KeyValueExpr:
		if value.Value != composite {
			return nil
		}
		if container, ok := flow.parents[value].(*ast.CompositeLit); ok {
			return flow.containerElement(flow.compositeType(container), true, map[string]struct{}{})
		}
	}
	return nil
}

func (flow *sourceValueFlow) containerElement(expression ast.Expr, mapValue bool, seen map[string]struct{}) ast.Expr {
	switch value := expression.(type) {
	case *ast.Ident:
		if _, found := seen[value.Name]; found {
			return nil
		}
		definition := flow.namedTypes[value.Name]
		if definition == nil {
			return nil
		}
		seen[value.Name] = struct{}{}
		return flow.containerElement(definition, mapValue, seen)
	case *ast.ArrayType:
		if !mapValue {
			return value.Elt
		}
	case *ast.MapType:
		if mapValue {
			return value.Value
		}
	case *ast.ParenExpr:
		return flow.containerElement(value.X, mapValue, seen)
	}
	return nil
}

func (flow *sourceValueFlow) namedErrorStruct(expression ast.Expr, seen map[string]struct{}) string {
	switch value := expression.(type) {
	case *ast.Ident:
		if errorStructName(value.Name) {
			return value.Name
		}
		if _, found := seen[value.Name]; found {
			return ""
		}
		definition := flow.namedTypes[value.Name]
		if definition == nil {
			return ""
		}
		seen[value.Name] = struct{}{}
		return flow.namedErrorStruct(definition, seen)
	case *ast.SelectorExpr:
		if errorStructName(value.Sel.Name) {
			return value.Sel.Name
		}
	case *ast.StarExpr:
		return flow.namedErrorStruct(value.X, seen)
	case *ast.ParenExpr:
		return flow.namedErrorStruct(value.X, seen)
	}
	return ""
}

func (flow *sourceValueFlow) stringType(expression ast.Expr, seen map[string]struct{}) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		if value.Name == "string" {
			return true
		}
		if _, found := seen[value.Name]; found {
			return false
		}
		definition := flow.namedTypes[value.Name]
		if definition == nil {
			return false
		}
		seen[value.Name] = struct{}{}
		return flow.stringType(definition, seen)
	case *ast.ParenExpr:
		return flow.stringType(value.X, seen)
	}
	return false
}

func errorStructName(value string) bool {
	return value == "CoverageError" || value == "EvidenceError"
}

func typeNameOrCodeComposite(value string) string {
	if value != "" {
		return value
	}
	return "Code composite"
}

func (flow *sourceValueFlow) addSink(expression ast.Expr, label string) {
	flow.nextSink++
	node := fmt.Sprintf("%s:sink:%d", flow.prefix, flow.nextSink)
	flow.sinks[node] = label
	flow.linkPossiblyGuardedExpression(node, expression)
}

func (flow *sourceValueFlow) linkPossiblyGuardedExpression(destination string, expression ast.Expr) {
	if !flow.provenNonEmpty(expression) {
		flow.linkExpression(destination, expression)
		return
	}
	switch value := expression.(type) {
	case *ast.Ident:
		flow.addNonEmptyEdge(destination, flow.identifierNode(value))
	case *ast.ParenExpr:
		flow.linkPossiblyGuardedExpression(destination, value.X)
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			flow.addNonEmptyEdge(destination, flow.codeFieldNode(value.X))
		} else {
			flow.linkExpression(destination, expression)
		}
	default:
		flow.linkExpression(destination, expression)
	}
}

func (flow *sourceValueFlow) provenNonEmpty(expression ast.Expr) bool {
	target := flow.expressionNode(expression)
	if target == "" {
		return false
	}
	for current := ast.Node(expression); current != nil; current = flow.parents[current] {
		parent := flow.parents[current]
		switch value := parent.(type) {
		case *ast.IfStmt:
			if value.Body != nil && value.Body.Pos() <= expression.Pos() && expression.End() <= value.Body.End() && flow.conditionProvesNonEmpty(value.Cond, target) {
				if flow.assignedBetween(value.Body, target, value.Body.Pos(), expression.Pos()) {
					flow.markUnknown(target)
				} else {
					return true
				}
			}
		case *ast.BlockStmt:
			for _, statement := range value.List {
				if statement.End() > expression.Pos() {
					break
				}
				guard, ok := statement.(*ast.IfStmt)
				if ok && flow.conditionProvesEmpty(guard.Cond, target) && terminatingGuard(guard.Body) {
					if flow.assignedBetween(value, target, guard.End(), expression.Pos()) {
						flow.markUnknown(target)
					} else {
						return true
					}
				}
			}
		}
	}
	return false
}

func (flow *sourceValueFlow) assignedBetween(root ast.Node, target string, after, before token.Pos) bool {
	assigned := false
	ast.Inspect(root, func(node ast.Node) bool {
		if assigned || node == nil {
			return false
		}
		if literal, ok := node.(*ast.FuncLit); ok && literal.Pos() >= after {
			return false
		}
		if node.End() <= after || node.Pos() >= before {
			return false
		}
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if flow.expressionNode(left) == target {
					assigned = true
					return false
				}
				if _, indirect := left.(*ast.StarExpr); indirect {
					assigned = true
					return false
				}
			}
		case *ast.CallExpr:
			_, addressTaken := flow.addressTaken[target]
			if value.End() <= before && (addressTaken || strings.Contains(target, ":package:") || flow.callMutates(value, target)) {
				assigned = true
				return false
			}
		case *ast.ValueSpec:
			for _, name := range value.Names {
				if flow.identifierNode(name) == target {
					assigned = true
					return false
				}
			}
		case *ast.RangeStmt:
			if flow.expressionNode(value.Key) == target || flow.expressionNode(value.Value) == target {
				assigned = true
				return false
			}
		}
		return true
	})
	return assigned
}

func (flow *sourceValueFlow) callMutates(call *ast.CallExpr, target string) bool {
	for _, function := range flow.calledFunctions(call) {
		mutated := false
		ast.Inspect(function.body, func(node ast.Node) bool {
			if mutated || node == nil {
				return false
			}
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, left := range assignment.Lhs {
				if flow.expressionNode(left) == target {
					mutated = true
					return false
				}
			}
			return true
		})
		if mutated {
			return true
		}
	}
	return false
}

func (flow *sourceValueFlow) expressionNode(expression ast.Expr) string {
	if expression == nil {
		return ""
	}
	switch value := expression.(type) {
	case *ast.Ident:
		return flow.identifierNode(value)
	case *ast.ParenExpr:
		return flow.expressionNode(value.X)
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			return flow.codeFieldNode(value.X)
		}
	}
	return ""
}

func (flow *sourceValueFlow) conditionProvesNonEmpty(expression ast.Expr, target string) bool {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return flow.conditionProvesNonEmpty(value.X, target)
	case *ast.BinaryExpr:
		if value.Op == token.LAND {
			return flow.sideEffectFreeCondition(value.Y) && (flow.conditionProvesNonEmpty(value.X, target) || flow.conditionProvesNonEmpty(value.Y, target))
		}
		return value.Op == token.NEQ && (flow.emptyStringComparison(value.X, value.Y, target) || flow.zeroLengthComparison(value.X, value.Y, target)) ||
			value.Op == token.GTR && flow.zeroLengthComparison(value.X, value.Y, target)
	}
	return false
}

func (flow *sourceValueFlow) sideEffectFreeCondition(expression ast.Expr) bool {
	safe := true
	ast.Inspect(expression, func(node ast.Node) bool {
		if !safe || node == nil {
			return false
		}
		switch node.(type) {
		case *ast.CallExpr, *ast.AssignStmt, *ast.IncDecStmt:
			safe = false
			return false
		}
		return true
	})
	return safe
}

func (flow *sourceValueFlow) conditionProvesEmpty(expression ast.Expr, target string) bool {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return flow.conditionProvesEmpty(value.X, target)
	case *ast.BinaryExpr:
		return value.Op == token.EQL && (flow.emptyStringComparison(value.X, value.Y, target) || flow.zeroLengthComparison(value.X, value.Y, target))
	}
	return false
}

func (flow *sourceValueFlow) zeroLengthComparison(left, right ast.Expr, target string) bool {
	return flow.lengthTarget(left) == target && zeroIntegerLiteral(right) ||
		flow.lengthTarget(right) == target && zeroIntegerLiteral(left)
}

func (flow *sourceValueFlow) lengthTarget(expression ast.Expr) string {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return ""
	}
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "len" {
		return ""
	}
	return flow.expressionNode(call.Args[0])
}

func zeroIntegerLiteral(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == "0"
}

func (flow *sourceValueFlow) emptyStringComparison(left, right ast.Expr, target string) bool {
	return flow.expressionNode(left) == target && emptyStringLiteral(right) ||
		flow.expressionNode(right) == target && emptyStringLiteral(left)
}

func emptyStringLiteral(expression ast.Expr) bool {
	literal, ok := expression.(*ast.BasicLit)
	return ok && literal.Kind == token.STRING && literal.Value == `""`
}

func terminatingGuard(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	switch value := body.List[len(body.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.BranchStmt:
		return value.Tok == token.CONTINUE
	}
	return false
}

func (flow *sourceValueFlow) linkExpression(destination string, expression ast.Expr) {
	if destination == "" || expression == nil {
		return
	}
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			if decoded, err := strconv.Unquote(value.Value); err == nil {
				flow.addDirect(destination, decoded)
				return
			}
		}
		flow.markUnknown(destination)
	case *ast.Ident:
		if value.Name == "nil" {
			flow.markEmpty(destination)
			return
		}
		source := flow.identifierNode(value)
		flow.addEdge(destination, source)
		if strings.Contains(source, ":external:") {
			flow.markUnknown(source)
		}
	case *ast.ParenExpr:
		flow.linkExpression(destination, value.X)
	case *ast.UnaryExpr:
		flow.markUnknown(destination)
	case *ast.BinaryExpr:
		flow.markUnknown(destination)
	case *ast.CallExpr:
		if identifier, ok := value.Fun.(*ast.Ident); ok {
			switch identifier.Name {
			case "append":
				for _, argument := range value.Args {
					flow.linkExpression(destination, argument)
				}
				return
			case "make":
				flow.markEmpty(destination)
				return
			}
		}
		if functions := flow.calledFunctions(value); len(functions) != 0 {
			linked := false
			for _, function := range functions {
				if len(function.results) != 0 {
					flow.addEdge(destination, function.results[0])
					linked = true
				}
			}
			if !linked {
				flow.markUnknown(destination)
			}
			return
		}
		flow.markUnknown(destination)
	case *ast.IndexExpr:
		flow.linkExpression(destination, value.X)
		flow.addDirect(destination, "")
	case *ast.SelectorExpr:
		if value.Sel.Name == "Code" {
			flow.addEdge(destination, flow.codeFieldNode(value.X))
		} else {
			flow.markUnknown(destination)
		}
	case *ast.CompositeLit:
		if len(value.Elts) == 0 {
			flow.markEmpty(destination)
			return
		}
		if code := compositeCodeExpression(value, flow.compositeErrorType(value) != ""); code != nil {
			flow.linkExpression(destination, code)
			return
		}
		for _, element := range value.Elts {
			if keyed, ok := element.(*ast.KeyValueExpr); ok {
				flow.linkExpression(destination, keyed.Value)
			} else {
				flow.linkExpression(destination, element)
			}
		}
	case *ast.KeyValueExpr:
		flow.linkExpression(destination, value.Value)
	case *ast.TypeAssertExpr:
		flow.linkExpression(destination, value.X)
	case *ast.SliceExpr:
		flow.linkExpression(destination, value.X)
	default:
		flow.markUnknown(destination)
	}
}

func compositeCodeExpression(composite *ast.CompositeLit, errorStruct bool) ast.Expr {
	for _, element := range composite.Elts {
		keyed, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyed.Key.(*ast.Ident)
		if ok && key.Name == "Code" {
			return keyed.Value
		}
	}
	if errorStruct && len(composite.Elts) != 0 {
		return composite.Elts[0]
	}
	return nil
}

func (flow *sourceValueFlow) addDirect(node, value string) {
	if flow.direct[node] == nil {
		flow.direct[node] = map[string]struct{}{}
	}
	flow.direct[node][value] = struct{}{}
}

func (flow *sourceValueFlow) addEdge(destination, source string) {
	if destination == "" || source == "" || destination == source {
		return
	}
	if flow.edges[destination] == nil {
		flow.edges[destination] = map[string]bool{}
	}
	flow.edges[destination][source] = false
}

func (flow *sourceValueFlow) addNonEmptyEdge(destination, source string) {
	if destination == "" || source == "" || destination == source {
		return
	}
	if flow.edges[destination] == nil {
		flow.edges[destination] = map[string]bool{}
	}
	if _, found := flow.edges[destination][source]; !found {
		flow.edges[destination][source] = true
	}
}

func (flow *sourceValueFlow) markUnknown(node string) {
	if node != "" {
		flow.unknown[node] = struct{}{}
	}
}

func (flow *sourceValueFlow) markEmpty(node string) {
	if node != "" {
		flow.empty[node] = struct{}{}
	}
}

func (flow *sourceValueFlow) resolveSinks() (map[string]struct{}, []string) {
	values := map[string]map[string]struct{}{}
	for node, direct := range flow.direct {
		values[node] = map[string]struct{}{}
		for value := range direct {
			values[node][value] = struct{}{}
		}
	}
	changed := true
	for changed {
		changed = false
		for destination, sources := range flow.edges {
			if values[destination] == nil {
				values[destination] = map[string]struct{}{}
			}
			for source, nonEmpty := range sources {
				for value := range values[source] {
					if nonEmpty && value == "" {
						continue
					}
					if _, found := values[destination][value]; !found {
						values[destination][value] = struct{}{}
						changed = true
					}
				}
			}
		}
	}
	resolvedEmpty := map[string]struct{}{}
	for node := range flow.empty {
		resolvedEmpty[node] = struct{}{}
	}
	changed = true
	for changed {
		changed = false
		for destination, sources := range flow.edges {
			if len(values[destination]) != 0 || len(sources) == 0 {
				continue
			}
			allEmpty := true
			for source := range sources {
				if _, empty := resolvedEmpty[source]; !empty {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				if _, found := resolvedEmpty[destination]; !found {
					resolvedEmpty[destination] = struct{}{}
					changed = true
				}
			}
		}
	}
	unknown := map[string]struct{}{}
	for node := range flow.unknown {
		unknown[node] = struct{}{}
	}
	nodes := map[string]struct{}{}
	for destination, sources := range flow.edges {
		nodes[destination] = struct{}{}
		for source := range sources {
			nodes[source] = struct{}{}
		}
	}
	for node := range flow.sinks {
		nodes[node] = struct{}{}
	}
	for node := range nodes {
		_, empty := resolvedEmpty[node]
		if len(values[node]) == 0 && !empty {
			unknown[node] = struct{}{}
			flow.unknown[node] = struct{}{}
		}
	}
	changed = true
	for changed {
		changed = false
		for destination, sources := range flow.edges {
			for source := range sources {
				if _, tainted := unknown[source]; tainted {
					if _, alreadyTainted := unknown[destination]; !alreadyTainted {
						unknown[destination] = struct{}{}
						changed = true
					}
				}
			}
		}
	}
	codes := map[string]struct{}{}
	var unresolved []string
	for node, label := range flow.sinks {
		found := false
		invalid := false
		var invalidValues []string
		for value := range values[node] {
			if productionErrorCodePattern.MatchString(value) {
				codes[value] = struct{}{}
				found = true
			} else {
				invalid = true
				invalidValues = append(invalidValues, strconv.Quote(value))
			}
		}
		_, tainted := unknown[node]
		if !found || invalid || tainted {
			detail := ""
			if tainted {
				detail = " via " + strings.Join(flow.unknownOrigins(node, map[string]struct{}{}), ", ")
			}
			if invalid {
				sort.Strings(invalidValues)
				detail += " with invalid values " + strings.Join(invalidValues, ", ")
				var origins []string
				for value := range values[node] {
					if !productionErrorCodePattern.MatchString(value) {
						origins = append(origins, flow.valueOrigins(node, value, map[string]struct{}{})...)
					}
				}
				if len(origins) != 0 {
					sort.Strings(origins)
					detail += " from " + strings.Join(origins, ", ")
				}
			}
			unresolved = append(unresolved, flow.prefix+":"+label+detail)
		}
	}
	return codes, unresolved
}

func (flow *sourceValueFlow) valueOrigins(node, value string, seen map[string]struct{}) []string {
	if _, found := seen[node]; found {
		return nil
	}
	seen[node] = struct{}{}
	var origins []string
	if _, found := flow.direct[node][value]; found {
		label := flow.nodeLabels[node]
		if label == "" {
			label = node
		}
		origins = append(origins, label)
	}
	for source, nonEmpty := range flow.edges[node] {
		if nonEmpty && value == "" {
			continue
		}
		origins = append(origins, flow.valueOrigins(source, value, seen)...)
	}
	return origins
}

func (flow *sourceValueFlow) unknownOrigins(node string, seen map[string]struct{}) []string {
	if _, found := seen[node]; found {
		return nil
	}
	seen[node] = struct{}{}
	var origins []string
	if _, found := flow.unknown[node]; found {
		label := flow.nodeLabels[node]
		if label == "" {
			label = node
		}
		origins = append(origins, label)
	}
	for source := range flow.edges[node] {
		origins = append(origins, flow.unknownOrigins(source, seen)...)
	}
	sort.Strings(origins)
	return origins
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
