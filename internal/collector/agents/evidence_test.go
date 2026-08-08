package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestAgentEvidenceTargetMatrix(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "claude-plugin", ".claude-plugin", "plugin.json"), `{"name":"claude-plugin","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", "codex-plugin", ".codex-plugin", "plugin.json"), `{"name":"codex-plugin","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "skills", "claude-skill", "SKILL.md"), "---\nname: claude-skill\n---\nbody\n")
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "codex-skill", "SKILL.md"), "---\nname: codex-skill\n---\nbody\n")
	writeAgentFile(t, filepath.Join(home, ".cursor", "skills", "cursor-skill", "SKILL.md"), "---\nname: cursor-skill\n---\nbody\n")
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "claude-plugin", "skills", "bundled-skill", "SKILL.md"), "---\nname: bundled-skill\n---\nbody\n")
	// Cursor plugin roots remain unsupported even when a plausible manifest exists.
	writeAgentFile(t, filepath.Join(home, ".cursor", "plugins", "unsupported", ".claude-plugin", "plugin.json"), `{"name":"unsupported"}`)

	got := collectAgents(t, New(), context.Background(), home)
	assertEvidenceTargets(t, got, map[string][]string{
		"agents.claude.plugins": {"manifest", "payload-tree", "skill-document", "payload-tree"},
		"agents.codex.plugins":  {"manifest", "payload-tree"},
		"agents.claude.skills":  {"skill-document", "payload-tree"},
		"agents.codex.skills":   {"skill-document", "payload-tree"},
		"agents.cursor.skills":  {"skill-document", "payload-tree"},
	})
	for _, target := range got.LocalEvidenceTargets {
		if target.TargetID == "agents.cursor.plugins.manifest" || target.TargetID == "agents.cursor.plugins.payload-tree" {
			t.Fatalf("unsupported Cursor plugin target emitted: %+v", target)
		}
	}
	collection := collectAgentEvidence(t, home, got)
	assertCompleteAgentEvidence(t, got, collection, map[string][]string{
		"agent-plugin:claude:claude-plugin@1.0.0": {"file-sha256/manifest", "tree-sha256/payload-tree"},
		"agent-skill:claude:bundled-skill":        {"file-sha256/skill-document", "tree-sha256/payload-tree"},
		"agent-plugin:codex:codex-plugin@1.0.0":   {"file-sha256/manifest", "tree-sha256/payload-tree"},
		"agent-skill:claude:claude-skill":         {"file-sha256/skill-document", "tree-sha256/payload-tree"},
		"agent-skill:codex:codex-skill":           {"file-sha256/skill-document", "tree-sha256/payload-tree"},
		"agent-skill:cursor:cursor-skill":         {"file-sha256/skill-document", "tree-sha256/payload-tree"},
	})
	before := agentEvidenceDigest(t, collection, "agent-plugin:claude:claude-plugin@1.0.0", model.EvidenceSubjectPayloadTree)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "outside-sibling.txt"), "outside payload mutation")
	again := collectAgents(t, New(), context.Background(), home)
	after := collectAgentEvidence(t, home, again)
	if digest := agentEvidenceDigest(t, after, "agent-plugin:claude:claude-plugin@1.0.0", model.EvidenceSubjectPayloadTree); digest != before {
		t.Fatalf("outside sibling changed plugin payload digest: before=%q after=%q", before, digest)
	}
}

func TestAgentEvidenceCompletesForCatalogRootPluginsAndSkills(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", ".claude-plugin", "plugin.json"), `{"name":"claude-root","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "payload.txt"), "claude payload")
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", ".codex-plugin", "plugin.json"), `{"name":"codex-root","version":"2.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", "payload.txt"), "codex payload")
	writeAgentFile(t, filepath.Join(home, ".claude", "skills", "SKILL.md"), "---\nname: claude-root-skill\n---\nbody\n")
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "SKILL.md"), "---\nname: codex-root-skill\n---\nbody\n")

	got := collectAgents(t, New(), context.Background(), home)
	collection := collectAgentEvidence(t, home, got)
	assertCompleteAgentEvidence(t, got, collection, map[string][]string{
		"agent-plugin:claude:claude-root@1.0.0": {"file-sha256/manifest", "tree-sha256/payload-tree"},
		"agent-plugin:codex:codex-root@2.0.0":   {"file-sha256/manifest", "tree-sha256/payload-tree"},
		"agent-skill:claude:claude-root-skill":  {"file-sha256/skill-document", "tree-sha256/payload-tree"},
		"agent-skill:codex:codex-root-skill":    {"file-sha256/skill-document", "tree-sha256/payload-tree"},
	})
	assertTarget(t, got, "agents.claude.plugins", model.TargetComplete, 1, 1)
	assertTarget(t, got, "agents.codex.plugins", model.TargetComplete, 1, 1)
}

func TestAgentEvidenceMissingOptionalPluginManifestEmitsNoFakeManifest(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", "missing", "README.md"), "not a manifest")

	got := collectAgents(t, New(), context.Background(), home)
	for _, target := range got.LocalEvidenceTargets {
		if target.TargetID == "agents.codex.plugins.manifest" || target.TargetID == "agents.codex.plugins.payload-tree" {
			t.Fatalf("fake optional-manifest evidence emitted: %+v", target)
		}
	}
}

func TestAgentEvidenceTargetsAreRuntimeOnly(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "fixture", "SKILL.md"), "---\nname: fixture\n---\nbody\n")

	got := collectAgents(t, New(), context.Background(), home)
	if len(got.LocalEvidenceTargets) == 0 || got.LocalEvidenceIssuer == nil {
		t.Fatalf("missing runtime evidence state: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{home, "payload-tree", "skill-document"} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatalf("runtime target value serialized: %q in %s", value, encoded)
		}
	}
}

func TestAgentTargetAnchorMatchesBytesUsedForIdentity(t *testing.T) {
	home := t.TempDir()
	skillPath := filepath.Join(home, ".codex", "skills", "fixture", "SKILL.md")
	writeAgentFile(t, skillPath, "---\nname: fixture\n---\nbody\n")
	collector := New().(*agentCollector)
	collector.afterManifestRead = func(relative string) {
		if filepath.ToSlash(relative) != "fixture/SKILL.md" {
			return
		}
		if err := os.WriteFile(skillPath, []byte("---\nname: fixture\n---\nchanged\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := collector.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	inventory := inventory.Build([]model.CollectorResult{result})
	got := (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory, []model.CollectorResult{result})
	if !hasEvidenceError(got, "identity_changed") {
		t.Fatalf("collection=%+v", got)
	}
}

func TestAgentEvidenceEngineClearsRuntimeTargetCapacityAndIssuer(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "fixture", "SKILL.md"), "---\nname: fixture\n---\nbody\n")
	result := collectAgents(t, New(), context.Background(), home)
	results := []model.CollectorResult{result}
	backing := results[0].LocalEvidenceTargets[:cap(results[0].LocalEvidenceTargets)]
	inventory := inventory.Build(results)
	_ = (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory, results)
	if results[0].LocalEvidenceTargets != nil || results[0].LocalEvidenceIssuer != nil {
		t.Fatalf("runtime state survived cleanup: %+v", results[0])
	}
	for index, target := range backing {
		if target != (model.LocalEvidenceTarget{}) {
			t.Fatalf("runtime target slot %d survived cleanup: %+v", index, target)
		}
	}
}

func hasEvidenceError(collection evidence.Collection, code string) bool {
	for _, record := range collection.Evidence {
		for _, issue := range record.Errors {
			if issue.Code == code {
				return true
			}
		}
	}
	for _, target := range collection.Coverage.Targets {
		for _, issue := range target.Errors {
			if issue.Code == code {
				return true
			}
		}
	}
	return false
}

func collectAgentEvidence(t *testing.T, home string, result model.CollectorResult) evidence.Collection {
	t.Helper()
	graph := inventory.Build([]model.CollectorResult{result})
	return (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), graph, []model.CollectorResult{result})
}

func assertCompleteAgentEvidence(t *testing.T, result model.CollectorResult, collection evidence.Collection, want map[string][]string) {
	t.Helper()
	observationIDs := make(map[string]map[string]struct{})
	for _, observation := range result.Observations {
		if observationIDs[observation.AssetID] == nil {
			observationIDs[observation.AssetID] = make(map[string]struct{})
		}
		observationIDs[observation.AssetID][observation.ID] = struct{}{}
	}
	got := make(map[string][]string)
	for _, record := range collection.Evidence {
		if record.Status != model.EvidenceComplete || record.Algorithm != "sha256" || len(record.Digest) != 64 || record.ID == "" {
			t.Fatalf("incomplete evidence record: %+v", record)
		}
		if _, bound := observationIDs[record.AssetID][record.ObservationID]; !bound {
			t.Fatalf("evidence is not bound to its asset observation: %+v", record)
		}
		got[record.AssetID] = append(got[record.AssetID], string(record.Kind)+"/"+record.Subject)
	}
	for index, terminal := range collection.Coverage.Targets {
		if terminal.Status != model.EvidenceComplete || index >= len(collection.Evidence) || terminal.AssetID != collection.Evidence[index].AssetID || terminal.ObservationID != collection.Evidence[index].ObservationID || terminal.EvidenceID != collection.Evidence[index].ID {
			t.Fatalf("terminal coverage is not bound to evidence: target=%+v evidence=%+v", terminal, collection.Evidence)
		}
	}
	for assetID := range got {
		sort.Strings(got[assetID])
	}
	for assetID := range want {
		sort.Strings(want[assetID])
	}
	if collection.Coverage.Status != model.CoverageComplete || len(collection.Coverage.Errors) != 0 || len(collection.Coverage.Targets) != len(collection.Evidence) || !reflect.DeepEqual(got, want) {
		t.Fatalf("collection=%+v got=%+v want=%+v", collection, got, want)
	}
}

func agentEvidenceDigest(t *testing.T, collection evidence.Collection, assetID, subject string) string {
	t.Helper()
	for _, record := range collection.Evidence {
		if record.AssetID == assetID && record.Subject == subject && record.Status == model.EvidenceComplete {
			return record.Digest
		}
	}
	t.Fatalf("missing complete evidence asset=%q subject=%q: %+v", assetID, subject, collection)
	return ""
}

func assertEvidenceTargets(t *testing.T, result model.CollectorResult, want map[string][]string) {
	t.Helper()
	got := make(map[string][]string)
	for _, target := range result.LocalEvidenceTargets {
		parts := splitEvidenceTargetID(target.TargetID)
		if len(parts) != 2 {
			t.Fatalf("target ID=%q", target.TargetID)
		}
		got[parts[0]] = append(got[parts[0]], target.Subject)
	}
	for id := range got {
		sort.Strings(got[id])
	}
	for id := range want {
		sort.Strings(want[id])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects=%+v want=%+v", got, want)
	}
}

func splitEvidenceTargetID(value string) []string {
	for _, suffix := range []string{".skill-document", ".payload-tree", ".manifest"} {
		if len(value) > len(suffix) && value[len(value)-len(suffix):] == suffix {
			return []string{value[:len(value)-len(suffix)], value[len(value)-len(suffix)+1:]}
		}
	}
	return nil
}
