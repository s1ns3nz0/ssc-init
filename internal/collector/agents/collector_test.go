package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/store"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestAgentCatalogDeclaresFixedAndUnsupportedTargets(t *testing.T) {
	want := []targetDeclaration{
		{spec: literalAgentTarget("agents.claude.plugins", "claude", model.TargetDirectory), relativePath: ".claude/plugins", kind: model.AssetAgentPlugin, marker: markerClaudePlugin, supported: true},
		{spec: literalAgentTarget("agents.claude.skills", "claude", model.TargetDirectory), relativePath: ".claude/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
		{spec: literalAgentTarget("agents.codex.plugins", "codex", model.TargetDirectory), relativePath: ".codex/plugins", kind: model.AssetAgentPlugin, marker: markerCodexPlugin, supported: true},
		{spec: literalAgentTarget("agents.codex.skills", "codex", model.TargetDirectory), relativePath: ".codex/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
		{spec: literalAgentTarget("agents.cursor.plugins", "cursor", model.TargetDirectory), relativePath: ".cursor/plugins", kind: model.AssetAgentPlugin},
		{spec: literalAgentTarget("agents.cursor.skills", "cursor", model.TargetDirectory), relativePath: ".cursor/skills", kind: model.AssetSkill, marker: markerSkill, supported: true},
		{spec: literalAgentTarget("agents.custom-roots", "", model.TargetDirectory)},
		{spec: literalAgentTarget("agents.dynamic-api", "", model.TargetDynamicAPI)},
		{spec: literalAgentTarget("agents.environment-relocated", "", model.TargetDirectory)},
		{spec: literalAgentTarget("agents.remote-host", "", model.TargetDirectory)},
		{spec: literalAgentTarget("agents.windsurf.plugins", "windsurf", model.TargetDirectory), relativePath: ".windsurf", kind: model.AssetAgentPlugin},
	}
	if got := catalogDeclarations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog=\n%+v\nwant=\n%+v", got, want)
	}

	var targeted collector.TargetedCollector = New()
	first := targeted.Targets()
	if len(first) != len(want) {
		t.Fatalf("targets=%+v", first)
	}
	for index, declaration := range want {
		if first[index] != declaration.spec {
			t.Fatalf("target[%d]=%+v want=%+v", index, first[index], declaration.spec)
		}
	}
	first[0].ID = "mutated"
	if targeted.Targets()[0].ID != "agents.claude.plugins" {
		t.Fatal("Targets returned mutable catalog storage")
	}
}

func literalAgentTarget(id, host string, method model.TargetMethod) model.TargetSpec {
	return model.TargetSpec{
		ID: id, Collector: "agents", Host: host, Scope: model.ScopeUser,
		Platform: "darwin", Method: method,
	}
}

func TestCatalogContainersAreNotAssets(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "cache", "vendor", "demo", "1.2.3", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.2.3"}`)
	for _, relative := range []string{
		".claude/plugins/extensions/README.md",
		".claude/plugins/marketplaces/README.md",
		".claude/plugins/readme-only/README.md",
		".claude/plugins/arbitrary/nested/file.txt",
		".windsurf/direct-tool/README.md",
	} {
		writeAgentFile(t, filepath.Join(home, filepath.FromSlash(relative)), "not evidence")
	}

	got := collectAgents(t, New(), context.Background(), home)
	assertNoAssetNamed(t, got.Assets, "cache")
	assertNoAssetNamed(t, got.Assets, "extensions")
	assertNoAssetNamed(t, got.Assets, "marketplaces")
	assertNoAssetNamed(t, got.Assets, "readme-only")
	assertNoAssetNamed(t, got.Assets, "arbitrary")
	assertNoAssetNamed(t, got.Assets, "direct-tool")
	asset := testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:demo@1.2.3")
	if asset.Type != model.AssetAgentPlugin || asset.Name != "demo" || asset.Version != "1.2.3" || asset.Source != "claude" || asset.Path != "" || asset.Metadata != nil {
		t.Fatalf("asset=%+v", asset)
	}
	assertTarget(t, got, "agents.claude.plugins", model.TargetComplete, 1, 1)
	assertObservation(t, got.Observations, asset.ID, "agents.claude.plugins", "claude", "$HOME/.claude/plugins/cache/vendor/demo/1.2.3/.claude-plugin/plugin.json", "cache/vendor/demo/1.2.3/.claude-plugin/plugin.json", "claude-plugin", "1.2.3")
	assertCatalogCoverage(t, got, map[string]model.TargetStatus{
		"agents.claude.plugins":        model.TargetComplete,
		"agents.claude.skills":         model.TargetNotPresent,
		"agents.codex.plugins":         model.TargetNotPresent,
		"agents.codex.skills":          model.TargetNotPresent,
		"agents.cursor.plugins":        model.TargetUnsupported,
		"agents.cursor.skills":         model.TargetNotPresent,
		"agents.custom-roots":          model.TargetUnsupported,
		"agents.dynamic-api":           model.TargetUnsupported,
		"agents.environment-relocated": model.TargetUnsupported,
		"agents.remote-host":           model.TargetUnsupported,
		"agents.windsurf.plugins":      model.TargetUnsupported,
	})
	if got.Status != model.CoveragePartial {
		t.Fatalf("status=%q result=%+v", got.Status, got)
	}
}

func TestAgentManifestBackedRepositoryFixture(t *testing.T) {
	got := collectAgents(t, New(), context.Background(), "../../../testdata/home")
	asset := testutil.AssertAsset(t, got.Assets, "agent-plugin:codex:example@1.2.3")
	if asset.Type != model.AssetAgentPlugin || asset.Name != "example" || asset.Version != "1.2.3" || asset.Path != "" {
		t.Fatalf("asset=%+v", asset)
	}
	if len(got.Assets) != 1 || len(got.Observations) != 1 {
		t.Fatalf("assets=%+v observations=%+v", got.Assets, got.Observations)
	}
	assertTarget(t, got, "agents.codex.plugins", model.TargetComplete, 1, 1)
	assertObservation(t, got.Observations, asset.ID, "agents.codex.plugins", "codex", "$HOME/.codex/plugins/example/.codex-plugin/plugin.json", "example/.codex-plugin/plugin.json", "codex-plugin", "1.2.3")
}

func TestAgentManifestFindsExplicitAndBundledSkillsWithoutReadingBody(t *testing.T) {
	home := t.TempDir()
	bodySecret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
	writeAgentFile(t, filepath.Join(home, ".claude", "skills", "directory-name", "SKILL.md"), "---\nname: review-safe\ndescription: ignored\n---\n"+bodySecret)
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "fallback-safe", "SKILL.md"), "instructions only")
	writeAgentFile(t, filepath.Join(home, ".cursor", "skills", "cursor-safe", "SKILL.md"), "---\ndescription: no name\n---\nbody")
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "bundle", ".claude-plugin", "plugin.json"), `{"name":"bundle","version":"2.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "bundle", "skills", "helper", "SKILL.md"), "---\nname: bundled-helper\n---\nbody")
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "not-a-plugin", "skills", "orphan", "SKILL.md"), "---\nname: orphan\n---\nbody")

	got := collectAgents(t, New(), context.Background(), home)
	again := collectAgents(t, New(), context.Background(), home)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("non-deterministic results:\nfirst=%+v\nsecond=%+v", got, again)
	}
	for _, id := range []string{
		"agent-skill:claude:review-safe",
		"agent-skill:codex:fallback-safe",
		"agent-skill:cursor:cursor-safe",
		"agent-plugin:claude:bundle@2.0.0",
		"agent-skill:claude:bundled-helper",
	} {
		testutil.AssertAsset(t, got.Assets, id)
	}
	assertNoAssetNamed(t, got.Assets, "directory-name")
	assertNoAssetNamed(t, got.Assets, "orphan")
	assertTarget(t, got, "agents.claude.plugins", model.TargetComplete, 2, 2)
	assertTarget(t, got, "agents.claude.skills", model.TargetComplete, 1, 1)
	assertTarget(t, got, "agents.codex.skills", model.TargetComplete, 1, 1)
	assertTarget(t, got, "agents.cursor.skills", model.TargetComplete, 1, 1)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(bodySecret)) || bytes.Contains(encoded, []byte("instructions only")) {
		t.Fatalf("skill body leaked: %s", encoded)
	}
}

func TestAgentManifestPreservesEveryVersionAndLocation(t *testing.T) {
	home := t.TempDir()
	for _, relative := range []string{
		".claude/plugins/cache/a/demo/1.0.0/.claude-plugin/plugin.json",
		".claude/plugins/cache/b/demo/1.0.0/.claude-plugin/plugin.json",
	} {
		writeAgentFile(t, filepath.Join(home, filepath.FromSlash(relative)), `{"name":"demo","version":"1.0.0"}`)
	}
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "cache", "c", "demo", "2.0.0", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"2.0.0"}`)

	got := collectAgents(t, New(), context.Background(), home)
	if countAssets(got.Assets, "agent-plugin:claude:demo@1.0.0") != 2 || countAssets(got.Assets, "agent-plugin:claude:demo@2.0.0") != 1 {
		t.Fatalf("assets=%+v", got.Assets)
	}
	if countObservations(got.Observations, "agent-plugin:claude:demo@1.0.0") != 2 || countObservations(got.Observations, "agent-plugin:claude:demo@2.0.0") != 1 {
		t.Fatalf("observations=%+v", got.Observations)
	}
	assertTarget(t, got, "agents.claude.plugins", model.TargetComplete, 3, 3)
	normalized := inventory.Build([]model.CollectorResult{got})
	if len(normalized.Assets) != 2 || len(normalized.Observations) != 3 || len(normalized.Errors) != 0 {
		t.Fatalf("normalized=%+v", normalized)
	}
}

func TestAgentManifestParsersRejectMalformedAndDuplicateKeys(t *testing.T) {
	valid, err := os.ReadFile("testdata/plugin/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := parsePluginManifest(valid); err != nil || got.name != "demo" || got.version != "1.2.3" {
		t.Fatalf("manifest=%+v err=%v", got, err)
	}
	for _, fixture := range []string{"testdata/plugin/duplicate-name.json", "testdata/plugin/duplicate-unknown.json", "testdata/plugin/duplicate-nested.json", "testdata/plugin/malformed.json"} {
		contents, readErr := os.ReadFile(fixture)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, parseErr := parsePluginManifest(contents); parseErr == nil {
			t.Fatalf("accepted %s", fixture)
		}
	}

	for _, test := range []struct {
		fixture  string
		fallback string
		want     string
		wantErr  bool
	}{
		{fixture: "testdata/skill/named.md", fallback: "directory", want: "frontmatter-name"},
		{fixture: "testdata/skill/fallback.md", fallback: "directory", want: "directory"},
		{fixture: "testdata/skill/body-secret.md", fallback: "directory", want: "safe-name"},
		{fixture: "testdata/skill/duplicate-name.md", fallback: "directory", wantErr: true},
		{fixture: "testdata/skill/unclosed.md", fallback: "directory", wantErr: true},
	} {
		contents, readErr := os.ReadFile(test.fixture)
		if readErr != nil {
			t.Fatal(readErr)
		}
		got, parseErr := parseSkillManifest(contents, test.fallback)
		if (parseErr != nil) != test.wantErr || (!test.wantErr && got != test.want) {
			t.Fatalf("fixture=%s got=%q err=%v", test.fixture, got, parseErr)
		}
	}
}

func TestAgentWalkMalformedSiblingIsPartialAndSafeSiblingContinues(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "a-safe", ".claude-plugin", "plugin.json"), `{"name":"safe","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "b-duplicate", ".claude-plugin", "plugin.json"), `{"name":"bad","name":"worse"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "c-malformed", ".claude-plugin", "plugin.json"), `{`)
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "safe-skill", "SKILL.md"), "---\nname: safe-skill\n---\nbody")
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "bad-skill", "SKILL.md"), "---\nname: first\nname: second\n---\nbody")

	got := collectAgents(t, New(), context.Background(), home)
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe@1.0.0")
	testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe-skill")
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "manifest_invalid")
	assertTargetIssue(t, got, "agents.codex.skills", model.TargetPartial, "manifest_invalid")
	assertTargetCounts(t, got, "agents.claude.plugins", 1, 1)
	assertTargetCounts(t, got, "agents.codex.skills", 1, 1)
}

func TestAgentWalkQuarantinesCredentialShapedIdentityGenerically(t *testing.T) {
	home := t.TempDir()
	secretName := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "rejected-plugin", ".claude-plugin", "plugin.json"), `{"name":"`+secretName+`","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "safe-plugin", ".claude-plugin", "plugin.json"), `{"name":"safe","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "rejected-skill", "SKILL.md"), "---\nname: "+secretName+"\n---\nbody")
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "safe-skill", "SKILL.md"), "---\nname: safe-skill\n---\nbody")

	got := collectAgents(t, New(), context.Background(), home)
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe@1.0.0")
	testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe-skill")
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "identity_rejected")
	assertTargetIssue(t, got, "agents.codex.skills", model.TargetPartial, "identity_rejected")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secretName, "rejected-plugin", "rejected-skill"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("quarantined identity leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestAgentWalkQuarantinesInvalidUTF8IdentityAndPersistsSafeSiblings(t *testing.T) {
	home := t.TempDir()
	invalid := []byte{0xff}
	invalidComponent := "invalid-" + string(invalid)

	writeAgentBytes(t, filepath.Join(home, ".claude", "plugins", "bad-name", ".claude-plugin", "plugin.json"), append(append([]byte(`{"name":"`), invalid...), []byte(`","version":"1.0.0"}`)...))
	writeAgentBytes(t, filepath.Join(home, ".claude", "plugins", "bad-version", ".claude-plugin", "plugin.json"), append(append([]byte(`{"name":"bad-version","version":"`), invalid...), []byte(`"}`)...))
	writeAgentBytes(t, filepath.Join(home, ".codex", "skills", "bad-frontmatter", "SKILL.md"), append(append([]byte("---\nname: "), invalid...), []byte("\n---\nbody")...))
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "zz-safe", ".claude-plugin", "plugin.json"), `{"name":"safe-plugin","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "zz-safe", "SKILL.md"), "---\nname: safe-skill\n---\nbody")

	got := collectAgents(t, New(), context.Background(), home)
	fallback, err := parseSkillManifest([]byte("fallback body"), invalidComponent)
	if err != nil {
		t.Fatal(err)
	}
	manualTarget := model.TargetCoverage{TargetID: "agents.codex.skills", Status: model.TargetComplete}
	if appendAgentEvidence(home, immutableCatalog[3], markerCandidate{kind: markerSkill, relativePath: "fallback/SKILL.md"}, fallback, "", &got, &manualTarget) {
		t.Fatal("invalid UTF-8 directory fallback was accepted")
	}
	invalidPath := "invalid-" + string(invalid) + "/.claude-plugin/plugin.json"
	if appendAgentEvidence(home, immutableCatalog[0], markerCandidate{kind: markerClaudePlugin, relativePath: invalidPath}, "bad-path", "1.0.0", &got, &manualTarget) {
		t.Fatal("invalid UTF-8 observation path was accepted")
	}
	if manualTarget.Status != model.TargetPartial || len(manualTarget.Errors) != 2 {
		t.Fatalf("manual quarantine target=%+v", manualTarget)
	}
	for _, issue := range manualTarget.Errors {
		if issue.Code != "identity_rejected" || issue.Path != "" {
			t.Fatalf("non-generic quarantine issue=%+v", issue)
		}
	}
	if len(got.Assets) != 2 || len(got.Observations) != 2 {
		t.Fatalf("invalid UTF-8 evidence escaped quarantine: assets=%+v observations=%+v", got.Assets, got.Observations)
	}
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe-plugin@1.0.0")
	testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe-skill")
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "identity_rejected")
	assertTargetIssue(t, got, "agents.codex.skills", model.TargetPartial, "identity_rejected")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(encoded) || bytes.Contains(encoded, invalid) || bytes.Contains(encoded, []byte("\ufffd")) {
		t.Fatalf("invalid UTF-8 survived result: %q", encoded)
	}

	databaseDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := store.Open(filepath.Join(databaseDirectory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	scan := model.ScanResult{
		SchemaVersion: "ssc-init.scan.v2", ScanID: "agents-invalid-utf8", Status: "partial",
		StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC(),
		Coverage: []model.CollectorResult{got},
		Scope:    model.ScanScope{Platform: "darwin", CatalogVersion: collector.CatalogVersion},
	}
	if err := state.SaveScan(context.Background(), scan, inventory.Build(scan.Coverage)); err != nil {
		t.Fatalf("persist safe siblings: %v", err)
	}
}

func TestAgentWalkRejectsSymlinkedRootsEntriesAndMarkers(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	outsideMarker := "outside-agent-marker"
	writeAgentFile(t, filepath.Join(outside, "codex", "linked", ".codex-plugin", "plugin.json"), `{"name":"`+outsideMarker+`"}`)
	if err := os.Symlink(filepath.Join(outside, "codex"), filepath.Join(home, ".codex")); err != nil {
		t.Fatal(err)
	}
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "safe", ".claude-plugin", "plugin.json"), `{"name":"safe"}`)
	writeAgentFile(t, filepath.Join(outside, "linked", ".claude-plugin", "plugin.json"), `{"name":"`+outsideMarker+`"}`)
	if err := os.Symlink(filepath.Join(outside, "linked"), filepath.Join(home, ".claude", "plugins", "linked")); err != nil {
		t.Fatal(err)
	}
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "marker-link", ".claude-plugin", "real.json"), `{"name":"`+outsideMarker+`"}`)
	if err := os.Symlink("real.json", filepath.Join(home, ".claude", "plugins", "marker-link", ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}

	got := collectAgents(t, New(), context.Background(), home)
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe")
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "symlink_rejected")
	assertTargetIssue(t, got, "agents.codex.plugins", model.TargetPartial, "symlink_rejected")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(outsideMarker)) || bytes.Contains(encoded, []byte(outside)) {
		t.Fatalf("symlink target leaked: %s", encoded)
	}
}

func TestAgentWalkDetectsIdentitySwapAndKeepsSafeSibling(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".claude", "plugins")
	writeAgentFile(t, filepath.Join(root, "safe", ".claude-plugin", "plugin.json"), `{"name":"safe"}`)
	writeAgentFile(t, filepath.Join(root, "swapped", ".claude-plugin", "plugin.json"), `{"name":"original"}`)
	replacement := filepath.Join(home, "replacement")
	writeAgentFile(t, filepath.Join(replacement, ".claude-plugin", "plugin.json"), `{"name":"replacement"}`)
	c := &agentCollector{limits: defaultWalkLimits()}
	c.beforeOpen = func(targetID, relative string) {
		if targetID != "agents.claude.plugins" || relative != "swapped" {
			return
		}
		if err := os.Rename(filepath.Join(root, "swapped"), filepath.Join(root, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, filepath.Join(root, "swapped")); err != nil {
			t.Fatal(err)
		}
	}

	got := collectAgents(t, c, context.Background(), home)
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe")
	assertNoAssetNamed(t, got.Assets, "original")
	assertNoAssetNamed(t, got.Assets, "replacement")
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "identity_changed")
}

func TestAgentWalkDetectsTargetRootIdentitySwapAndKeepsSafeTarget(t *testing.T) {
	home := t.TempDir()
	claudeRoot := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(claudeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "safe", "SKILL.md"), "---\nname: safe\n---\n")
	replacement := filepath.Join(home, "replacement")
	if err := os.MkdirAll(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := os.Stat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)
	env.FS = agentSwapFS{FileSystem: platform.OSFileSystem{}, swapPath: claudeRoot, replacement: replacementInfo}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "identity_changed")
	testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe")
}

func TestAgentWalkEnforcesRootDepthEntryManifestAndByteLimits(t *testing.T) {
	t.Run("roots", func(t *testing.T) {
		home := t.TempDir()
		writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "safe", ".claude-plugin", "plugin.json"), `{"name":"safe"}`)
		writeAgentFile(t, filepath.Join(home, ".claude", "skills", "later", "SKILL.md"), "---\nname: later\n---\n")
		limits := defaultWalkLimits()
		limits.maxRoots = 1
		got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
		testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:safe")
		assertTargetIssue(t, got, "agents.claude.skills", model.TargetPartial, "root_limit")
		assertNoAssetNamed(t, got.Assets, "later")
	})

	t.Run("depth and safe target", func(t *testing.T) {
		home := t.TempDir()
		writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "too", "deep", ".claude-plugin", "plugin.json"), `{"name":"too-deep"}`)
		writeAgentFile(t, filepath.Join(home, ".codex", "skills", "safe", "SKILL.md"), "---\nname: safe\n---\n")
		limits := defaultWalkLimits()
		limits.maxDepth = 1
		got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
		assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "depth_limit")
		testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe")
	})

	t.Run("entries and safe target", func(t *testing.T) {
		home := t.TempDir()
		for _, name := range []string{"a", "b", "c"} {
			if err := os.MkdirAll(filepath.Join(home, ".claude", "plugins", name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		writeAgentFile(t, filepath.Join(home, ".codex", "skills", "safe", "SKILL.md"), "---\nname: safe\n---\n")
		limits := defaultWalkLimits()
		limits.maxEntries = 2
		got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
		assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "entry_limit")
		testutil.AssertAsset(t, got.Assets, "agent-skill:codex:safe")
	})

	t.Run("manifest count", func(t *testing.T) {
		home := t.TempDir()
		writeAgentFile(t, filepath.Join(home, ".claude", "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
		writeAgentFile(t, filepath.Join(home, ".claude", "skills", "b", "SKILL.md"), "---\nname: b\n---\n")
		limits := defaultWalkLimits()
		limits.maxManifests = 1
		got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
		assertTargetIssue(t, got, "agents.claude.skills", model.TargetPartial, "manifest_limit")
		assertTargetCounts(t, got, "agents.claude.skills", 1, 1)
	})

	t.Run("manifest bytes", func(t *testing.T) {
		home := t.TempDir()
		writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "large", ".claude-plugin", "plugin.json"), `{"name":"far-too-large"}`)
		writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "safe", ".claude-plugin", "plugin.json"), `{"name":"ok"}`)
		limits := defaultWalkLimits()
		limits.maxManifestBytes = 16
		got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
		assertTargetIssue(t, got, "agents.claude.plugins", model.TargetPartial, "manifest_size_limit")
		testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:ok")
		assertTargetCounts(t, got, "agents.claude.plugins", 1, 1)
	})
}

func TestAgentWalkNonPluginSkillsDoNotExhaustManifestBudget(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "a-not-plugin", "skills", "hostile", "SKILL.md"), "---\nname: hostile\n---\n")
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "z-valid", ".claude-plugin", "plugin.json"), `{"name":"valid-plugin","version":"1.0.0"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "z-valid", "skills", "helper", "SKILL.md"), "---\nname: valid-helper\n---\n")
	limits := defaultWalkLimits()
	limits.maxManifests = 2

	got := collectAgents(t, &agentCollector{limits: limits}, context.Background(), home)
	testutil.AssertAsset(t, got.Assets, "agent-plugin:claude:valid-plugin@1.0.0")
	testutil.AssertAsset(t, got.Assets, "agent-skill:claude:valid-helper")
	assertNoAssetNamed(t, got.Assets, "hostile")
	assertTarget(t, got, "agents.claude.plugins", model.TargetComplete, 2, 2)
}

func TestAgentWalkHonorsCancellationBeforeAndDuringTraversal(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "one", ".claude-plugin", "plugin.json"), `{"name":"one"}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Collect(ctx, testutil.Environment(t, home)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled error=%v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	c := &agentCollector{limits: defaultWalkLimits()}
	c.beforeOpen = func(_, _ string) { cancel() }
	if _, err := c.Collect(ctx, testutil.Environment(t, home)); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-walk error=%v", err)
	}
}

func TestAgentWalkFailsClosedWithoutRootedFilesystem(t *testing.T) {
	home := t.TempDir()
	marker := "agent-path-fallback-marker"
	writeAgentFile(t, filepath.Join(home, ".codex", "plugins", marker, ".codex-plugin", "plugin.json"), `{"name":"safe"}`)
	env := testutil.Environment(t, home)
	env.FS = pathOnlyAgentFileSystem{FileSystem: platform.OSFileSystem{}}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 0 || len(got.Observations) != 0 {
		t.Fatalf("result=%+v", got)
	}
	for _, id := range []string{"agents.claude.plugins", "agents.claude.skills", "agents.codex.plugins", "agents.codex.skills", "agents.cursor.skills"} {
		assertTarget(t, got, id, model.TargetUnavailable, 0, 0)
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatalf("path fallback leaked: %s", encoded)
	}
}

func TestAgentWalkSanitizesAccessFailureAndDoesNotTraverseUnsupportedRoots(t *testing.T) {
	home := t.TempDir()
	claudeRoot := filepath.Join(home, ".claude", "plugins")
	cursorRoot := filepath.Join(home, ".cursor", "plugins")
	if err := os.MkdirAll(claudeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cursorRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)
	env.FS = &agentFaultFS{FileSystem: platform.OSFileSystem{}, blocked: map[string]error{
		claudeRoot: fs.ErrPermission,
		cursorRoot: errors.New("unsupported root must not be opened"),
	}}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	assertTargetIssue(t, got, "agents.claude.plugins", model.TargetUnavailable, "root_unavailable")
	assertTarget(t, got, "agents.cursor.plugins", model.TargetUnsupported, 0, 0)
	if env.FS.(*agentFaultFS).opened[cursorRoot] {
		t.Fatal("unsupported Cursor plugin root was traversed")
	}
	encoded, marshalErr := json.Marshal(got)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(home)) || bytes.Contains(encoded, []byte("permission")) {
		t.Fatalf("access detail leaked: %s", encoded)
	}
}

func TestAgentWalkOutputOrderIsDeterministic(t *testing.T) {
	home := t.TempDir()
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "z", "SKILL.md"), "---\nname: z\n---\n")
	writeAgentFile(t, filepath.Join(home, ".codex", "skills", "a", "SKILL.md"), "---\nname: a\n---\n")
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "z", ".claude-plugin", "plugin.json"), `{"name":"z"}`)
	writeAgentFile(t, filepath.Join(home, ".claude", "plugins", "a", ".claude-plugin", "plugin.json"), `{"name":"a"}`)

	got := collectAgents(t, New(), context.Background(), home)
	if !sort.SliceIsSorted(got.Targets, func(i, j int) bool { return got.Targets[i].TargetID < got.Targets[j].TargetID }) {
		t.Fatalf("targets=%+v", got.Targets)
	}
	if !sort.SliceIsSorted(got.Assets, func(i, j int) bool { return got.Assets[i].ID < got.Assets[j].ID }) {
		t.Fatalf("assets=%+v", got.Assets)
	}
	if !sort.SliceIsSorted(got.Observations, func(i, j int) bool { return got.Observations[i].ID < got.Observations[j].ID }) {
		t.Fatalf("observations=%+v", got.Observations)
	}
}

func collectAgents(t *testing.T, c collector.Collector, ctx context.Context, home string) model.CollectorResult {
	t.Helper()
	got, err := c.Collect(ctx, testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertNoAssetNamed(t *testing.T, assets []model.Asset, name string) {
	t.Helper()
	for _, asset := range assets {
		if asset.Name == name {
			t.Fatalf("unexpected asset named %q: %+v", name, asset)
		}
	}
}

func assertObservation(t *testing.T, observations []model.Observation, assetID, targetID, host, locationRef, manifestPath, markerKind, version string) {
	t.Helper()
	for _, observation := range observations {
		if observation.AssetID != assetID || observation.Source != targetID || observation.LocationRef != locationRef {
			continue
		}
		if observation.ID == "" || observation.Collector != "agents" || observation.Host != host || !reflect.DeepEqual(observation.Consumers, []string{host}) || observation.Scope != model.ScopeUser || observation.Metadata["marker_kind"] != markerKind || observation.Metadata["manifest_path"] != manifestPath || observation.Metadata["version"] != version {
			t.Fatalf("observation=%+v", observation)
		}
		return
	}
	t.Fatalf("missing observation asset=%q target=%q location=%q: %+v", assetID, targetID, locationRef, observations)
}

func assertCatalogCoverage(t *testing.T, result model.CollectorResult, want map[string]model.TargetStatus) {
	t.Helper()
	if len(result.Targets) != len(want) {
		t.Fatalf("targets=%+v want=%+v", result.Targets, want)
	}
	for _, target := range result.Targets {
		status, ok := want[target.TargetID]
		if !ok || status != target.Status || target.InstanceRef != "" {
			t.Fatalf("target=%+v want=%+v", target, want)
		}
	}
}

func assertTarget(t *testing.T, result model.CollectorResult, id string, status model.TargetStatus, assets, observations int) {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID == id {
			if target.Status != status || target.Assets != assets || target.Observations != observations || target.InstanceRef != "" {
				t.Fatalf("target=%+v", target)
			}
			return
		}
	}
	t.Fatalf("missing target %q: %+v", id, result.Targets)
}

func assertTargetCounts(t *testing.T, result model.CollectorResult, id string, assets, observations int) {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID == id {
			if target.Assets != assets || target.Observations != observations {
				t.Fatalf("target=%+v", target)
			}
			return
		}
	}
	t.Fatalf("missing target %q: %+v", id, result.Targets)
}

func assertTargetIssue(t *testing.T, result model.CollectorResult, id string, status model.TargetStatus, code string) {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID != id {
			continue
		}
		if target.Status != status {
			t.Fatalf("target=%+v", target)
		}
		for _, issue := range target.Errors {
			if issue.Code == code {
				return
			}
		}
		t.Fatalf("target=%+v missing issue %q", target, code)
	}
	t.Fatalf("missing target %q: %+v", id, result.Targets)
}

func countAssets(assets []model.Asset, id string) int {
	count := 0
	for _, asset := range assets {
		if asset.ID == id {
			count++
		}
	}
	return count
}

func countObservations(observations []model.Observation, assetID string) int {
	count := 0
	for _, observation := range observations {
		if observation.AssetID == assetID {
			count++
		}
	}
	return count
}

func writeAgentFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAgentBytes(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

type agentFaultFS struct {
	platform.FileSystem
	blocked map[string]error
	opened  map[string]bool
}

func (f *agentFaultFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	if f.opened == nil {
		f.opened = make(map[string]bool)
	}
	f.opened[name] = true
	if err := f.blocked[name]; err != nil {
		return nil, err
	}
	rooted, ok := f.FileSystem.(platform.RootedFileSystem)
	if !ok {
		return nil, fs.ErrInvalid
	}
	root, err := rooted.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentFaultRoot{RootedDirectory: root, current: name, owner: f}, nil
}

type agentFaultRoot struct {
	platform.RootedDirectory
	current string
	owner   *agentFaultFS
}

func (r *agentFaultRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	path := filepath.Join(r.current, name)
	if r.owner.opened == nil {
		r.owner.opened = make(map[string]bool)
	}
	r.owner.opened[path] = true
	if err := r.owner.blocked[path]; err != nil {
		return nil, err
	}
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentFaultRoot{RootedDirectory: child, current: path, owner: r.owner}, nil
}

type pathOnlyAgentFileSystem struct {
	platform.FileSystem
}

type agentSwapFS struct {
	platform.FileSystem
	swapPath    string
	replacement os.FileInfo
}

func (f agentSwapFS) OpenRoot(name string) (platform.RootedDirectory, error) {
	rooted, ok := f.FileSystem.(platform.RootedFileSystem)
	if !ok {
		return nil, fs.ErrInvalid
	}
	root, err := rooted.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentSwapRoot{RootedDirectory: root, current: name, swapPath: f.swapPath, replacement: f.replacement}, nil
}

type agentSwapRoot struct {
	platform.RootedDirectory
	current     string
	swapPath    string
	replacement os.FileInfo
}

func (r *agentSwapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &agentSwapRoot{
		RootedDirectory: child, current: filepath.Join(r.current, name),
		swapPath: r.swapPath, replacement: r.replacement,
	}, nil
}

func (r *agentSwapRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if r.current == r.swapPath && name == "." {
		return agentSwapFile{RootedFile: file, replacement: r.replacement}, nil
	}
	return file, nil
}

type agentSwapFile struct {
	platform.RootedFile
	replacement os.FileInfo
}

func (f agentSwapFile) Stat() (os.FileInfo, error) { return f.replacement, nil }
