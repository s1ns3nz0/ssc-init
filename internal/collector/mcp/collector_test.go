package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector"
	"github.com/ssc-init/ssc-init/internal/collector/mcp"
	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/identity"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

const maxConfigBytes = 4 << 20

func TestMCPCollectorAdvertisesImmutableCatalog(t *testing.T) {
	mcpCollector := mcp.New()
	got := mcpCollector.Targets()
	if len(got) != 20 {
		t.Fatalf("targets=%d: %+v", len(got), got)
	}
	for index := 1; index < len(got); index++ {
		if got[index-1].ID >= got[index].ID {
			t.Fatalf("targets are not strictly sorted: %+v", got)
		}
	}
	got[0].ID = "mutated"
	if mcpCollector.Targets()[0].ID == "mutated" {
		t.Fatal("target catalog mutated through caller slice")
	}
	var _ collector.TargetedCollector = mcpCollector
	var _ func(...model.LocalTarget) collector.TargetedCollector = mcp.New
}

func TestMCPCollectorInventoriesEveryOfficialUserPath(t *testing.T) {
	home := t.TempDir()
	targets := []struct {
		id        string
		relative  string
		host      string
		container string
		consumers []string
	}{
		{id: "mcp.claude-code.user", relative: ".claude.json", host: "claude-code", container: "mcpServers", consumers: []string{"claude-code"}},
		{id: "mcp.claude-code.legacy-user", relative: ".claude/settings.json", host: "claude-code", container: "mcpServers", consumers: []string{"claude-code"}},
		{id: "mcp.claude-desktop.user", relative: "Library/Application Support/Claude/claude_desktop_config.json", host: "claude-desktop", container: "mcpServers", consumers: []string{"claude-desktop"}},
		{id: "mcp.codex.user", relative: ".codex/config.toml", host: "codex", consumers: []string{"codex"}},
		{id: "mcp.cursor.user", relative: ".cursor/mcp.json", host: "cursor", container: "mcpServers", consumers: []string{"cursor"}},
		{id: "mcp.windsurf.user", relative: ".codeium/windsurf/mcp_config.json", host: "windsurf", container: "mcpServers", consumers: []string{"windsurf"}},
		{id: "mcp.windsurf.legacy-user", relative: ".windsurf/mcp.json", host: "windsurf", container: "mcpServers", consumers: []string{"windsurf"}},
		{id: "mcp.vscode.user", relative: "Library/Application Support/Code/User/mcp.json", host: "vscode", container: "servers", consumers: []string{"vscode"}},
		{id: "mcp.vscode-insiders.user", relative: "Library/Application Support/Code - Insiders/User/mcp.json", host: "vscode-insiders", container: "servers", consumers: []string{"vscode-insiders"}},
		{id: "mcp.github-copilot.user", relative: ".copilot/mcp-config.json", host: "github-copilot", container: "mcpServers", consumers: []string{"github-copilot"}},
	}
	for _, target := range targets {
		contents := `{"` + target.container + `":{"fixture":{"command":"tool"}}}`
		if target.id == "mcp.codex.user" {
			contents = `model = "unrelated-setting"
[mcp_servers.fixture]
command = "tool"
env = { API_TOKEN = "toml-secret-marker" }
env_vars = ["HOME"]
`
		}
		writeMCPFile(t, filepath.Join(home, filepath.FromSlash(target.relative)), contents)
	}

	got := collectMCP(t, home)
	if got.Status != model.CoveragePartial {
		t.Fatalf("status=%q targets=%+v", got.Status, got.Targets)
	}
	if len(got.Assets) != len(targets) || len(got.Observations) != len(targets) {
		t.Fatalf("assets=%d observations=%d", len(got.Assets), len(got.Observations))
	}
	for _, expected := range targets {
		target := assertTarget(t, got.Targets, expected.id, "")
		if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
			t.Fatalf("target=%+v", target)
		}
		assetID := "mcp:" + expected.host + ":fixture"
		asset := assertAsset(t, got.Assets, assetID)
		if asset.Type != model.AssetMCP || asset.Name != "fixture" || asset.Source != expected.host || asset.Path != "" || asset.Metadata != nil {
			t.Fatalf("asset=%+v", asset)
		}
		location := "$HOME/" + expected.relative
		observation := assertObservation(t, got.Observations, assetID, location)
		if observation.Host != expected.host || !reflect.DeepEqual(observation.Consumers, expected.consumers) || observation.Source != expected.id || observation.Scope != model.ScopeUser {
			t.Fatalf("observation=%+v", observation)
		}
	}
	for _, projectID := range []string{"mcp.codex.project", "mcp.cursor.project", "mcp.shared.project", "mcp.vscode.project"} {
		target := assertTarget(t, got.Targets, projectID, "")
		if target.Status != model.TargetNotPresent {
			t.Fatalf("project base target=%+v", target)
		}
	}
	for _, unsupportedID := range []string{"mcp.dev-container", "mcp.dynamic-api", "mcp.environment-relocated", "mcp.profile-specific", "mcp.remote-user", "mcp.service-managed"} {
		if target := assertTarget(t, got.Targets, unsupportedID, ""); target.Status != model.TargetUnsupported {
			t.Fatalf("unsupported target=%+v", target)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("toml-secret-marker")) || bytes.Contains(encoded, []byte(home)) {
		t.Fatalf("private data persisted: %s", encoded)
	}
}

func TestMCPCollectorInventoriesCodexProjectTOMLWithIssuedProvenance(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "Projects", "app", ".codex", "config.toml")
	writeMCPFile(t, path, `
[mcp_servers.remote]
url = "https://example.invalid/mcp?mode=safe"
http_headers = { Authorization = "Bearer project-header-secret" }
env_http_headers = { X-Token = "PROJECT_HTTP_TOKEN" }
bearer_token_env_var = "PROJECT_BEARER_TOKEN"
`)
	localTarget := projectTarget(t, home, path, "mcp.codex.project", "toml", "codex", []string{"codex"})

	got := collectMCP(t, home, localTarget)
	target := assertTarget(t, got.Targets, localTarget.TargetID, localTarget.InstanceRef)
	if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
		t.Fatalf("target=%+v", target)
	}
	asset := assertAsset(t, got.Assets, "mcp:codex:remote")
	if asset.Type != model.AssetMCP || asset.Name != "remote" || asset.Source != "codex" {
		t.Fatalf("asset=%+v", asset)
	}
	observation := assertObservation(t, got.Observations, asset.ID, localTarget.InstanceRef)
	if observation.Scope != model.ScopeProject || observation.Source != "mcp.codex.project" || observation.Metadata["url_shape"] != "https://example.invalid/mcp?query_keys=mode" || observation.Metadata["header_keys"] != "Authorization,X-Token" || observation.Metadata["env_keys"] != "PROJECT_BEARER_TOKEN,PROJECT_HTTP_TOKEN" {
		t.Fatalf("observation=%+v", observation)
	}
	assertJSONExcludes(t, got, "project-header-secret", "Bearer", path, home)
}

func TestMCPCollectorMarksOnlyCodexServerUnknownFieldPartial(t *testing.T) {
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".codex", "config.toml"), `
model = "unrelated-value"
[unrelated]
future = "unrelated-secret"

[mcp_servers.safe]
command = "node"
future_option = "server-secret"
`)

	got := collectMCP(t, home)
	target := assertTarget(t, got.Targets, "mcp.codex.user", "")
	if target.Status != model.TargetPartial || target.Assets != 1 || target.Observations != 1 || !hasErrorCode(target.Errors, "unknown_server_field") {
		t.Fatalf("target=%+v", target)
	}
	observation := assertObservation(t, got.Observations, "mcp:codex:safe", "$HOME/.codex/config.toml")
	if observation.Metadata["unknown_fields"] != "future_option" {
		t.Fatalf("metadata=%+v", observation.Metadata)
	}
	assertJSONExcludes(t, got, "server-secret", "unrelated-secret", "unrelated-value")
}

func TestMCPCollectorMarksMalformedCodexTOMLPartial(t *testing.T) {
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.broken\ncommand = \"node\"\n")

	got := collectMCP(t, home)
	target := assertTarget(t, got.Targets, "mcp.codex.user", "")
	if target.Status != model.TargetPartial || !hasErrorCode(target.Errors, "config_invalid") || target.Assets != 0 || target.Observations != 0 {
		t.Fatalf("target=%+v", target)
	}
}

func TestMCPCollectorPreservesCollisionCandidatesUntilGraphNormalization(t *testing.T) {
	home := t.TempDir()
	paths := []string{
		filepath.Join(home, "Projects", "alpha", ".mcp.json"),
		filepath.Join(home, "Projects", "beta", ".mcp.json"),
	}
	localTargets := make([]model.LocalTarget, 0, len(paths))
	for _, path := range paths {
		writeMCPFile(t, path, `{"mcpServers":{"same":{"command":"node"}}}`)
		localTargets = append(localTargets, sharedProjectTarget(t, home, path))
	}

	got := collectMCP(t, home, localTargets...)
	if assetCount(got.Assets, "mcp:shared:same") != 2 {
		t.Fatalf("candidate assets=%+v", got.Assets)
	}
	if observationCount(got.Observations, "mcp:shared:same") != 2 {
		t.Fatalf("candidate observations=%+v", got.Observations)
	}
	for _, path := range paths {
		instance := identity.SafeLocationRef(home, path, "external-root")
		target := assertTarget(t, got.Targets, "mcp.shared.project", instance)
		if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
			t.Fatalf("target=%+v", target)
		}
	}

	normalized := inventory.Build([]model.CollectorResult{got})
	if assetCount(normalized.Assets, "mcp:shared:same") != 1 || observationCount(normalized.Observations, "mcp:shared:same") != 2 {
		t.Fatalf("normalized=%+v", normalized)
	}
}

func TestMCPCollectorKeepsSameNameOnDifferentHostsDistinct(t *testing.T) {
	home := t.TempDir()
	cursorPath := filepath.Join(home, "Projects", "app", ".cursor", "mcp.json")
	vscodePath := filepath.Join(home, "Projects", "app", ".vscode", "mcp.json")
	writeMCPFile(t, cursorPath, `{"mcpServers":{"same":{"command":"node"}}}`)
	writeMCPFile(t, vscodePath, `{"servers":{"same":{"command":"node"}}}`)

	got := collectMCP(t, home,
		projectTarget(t, home, cursorPath, "mcp.cursor.project", "json", "cursor", []string{"cursor"}),
		projectTarget(t, home, vscodePath, "mcp.vscode.project", "json", "vscode", []string{"vscode"}),
	)
	if assetCount(got.Assets, "mcp:cursor:same") != 1 || assetCount(got.Assets, "mcp:vscode:same") != 1 {
		t.Fatalf("assets=%+v", got.Assets)
	}
}

func TestMCPCollectorQuarantinesSecretShapedIdentityAndKeepsSibling(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "Projects", "app", ".mcp.json")
	secretName := "ghp_12345678901234567890"
	invalidName := "/private/client/identity"
	writeMCPFile(t, path, `{"mcpServers":{"`+secretName+`":{"command":"bad"},"`+invalidName+`":{"command":"bad"},"safe":{"command":"good"}}}`)
	localTarget := sharedProjectTarget(t, home, path)

	got := collectMCP(t, home, localTarget)
	target := assertTarget(t, got.Targets, localTarget.TargetID, localTarget.InstanceRef)
	if target.Status != model.TargetPartial || target.Assets != 1 || target.Observations != 1 || !hasErrorCode(target.Errors, "rejected_identity") {
		t.Fatalf("target=%+v", target)
	}
	if len(got.Assets) != 1 || got.Assets[0].ID != "mcp:shared:safe" || len(got.Observations) != 1 {
		t.Fatalf("result=%+v", got)
	}
	assertJSONExcludes(t, got, secretName, invalidName, path, home)
}

func TestMCPCollectorUsesSafeExternalLocationAndDeduplicatesInstances(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	path := filepath.Join(external, "client", ".mcp.json")
	writeMCPFile(t, path, `{"mcpServers":{"external":{"command":"node"}}}`)
	localTarget := sharedProjectTarget(t, home, path)
	instance := localTarget.InstanceRef

	got := collectMCP(t, home, localTarget, localTarget)
	target := assertTarget(t, got.Targets, localTarget.TargetID, instance)
	if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
		t.Fatalf("target=%+v", target)
	}
	if countTarget(got.Targets, localTarget.TargetID) != 1 {
		t.Fatalf("duplicate target results=%+v", got.Targets)
	}
	observation := assertObservation(t, got.Observations, "mcp:shared:external", instance)
	if !strings.HasPrefix(observation.LocationRef, "external-root-1/path-sha256:") || strings.Contains(observation.LocationRef, external) {
		t.Fatalf("location=%q", observation.LocationRef)
	}
	assertJSONExcludes(t, got, external, path)
}

func TestMCPCollectorRejectsForgedExternalTargetBeforeOpen(t *testing.T) {
	home := t.TempDir()
	external := t.TempDir()
	path := filepath.Join(external, "client", ".mcp.json")
	writeMCPFile(t, path, `{"mcpServers":{"forged-marker":{"command":"node"}}}`)
	forged := model.LocalTarget{
		TargetID: "mcp.shared.project", InstanceRef: identity.SafeLocationRef(home, path, "external-root-1"), Path: path,
		Format: "json", Host: "shared", Consumers: []string{"claude-code", "vscode"},
	}
	rooted := &recordingRootFileSystem{}
	env := testutil.Environment(t, home)
	env.FS = rooted

	got, err := mcp.New(forged).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if rooted.opened(filepath.Dir(path)) {
		t.Fatalf("forged external parent was opened: %q", rooted.paths())
	}
	if assetCount(got.Assets, "mcp:shared:forged-marker") != 0 {
		t.Fatalf("forged target was inventoried: %+v", got)
	}
	target := assertTarget(t, got.Targets, "mcp.shared.project", "")
	if target.Status != model.TargetPartial || !hasErrorCode(target.Errors, "invalid_local_target") {
		t.Fatalf("target=%+v", target)
	}
	assertJSONExcludes(t, got, external, path, "forged-marker")
}

func TestMCPCollectorClearsCallerTargetBackingOnCancellation(t *testing.T) {
	consumers := []string{"claude-code", "vscode"}
	backing := []model.LocalTarget{{
		TargetID: "mcp.shared.project", InstanceRef: "$HOME/Projects/client/.mcp.json", Path: "/private/client/.mcp.json",
		Format: "json", Host: "shared", Consumers: consumers,
	}}
	mcpCollector := mcp.New(backing...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := mcpCollector.Collect(ctx, testutil.Environment(t, t.TempDir()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if !reflect.DeepEqual(backing[0], model.LocalTarget{}) {
		t.Fatalf("caller target backing retained data: %+v", backing[0])
	}
	if !reflect.DeepEqual(consumers, []string{"", ""}) {
		t.Fatalf("consumer backing retained data: %q", consumers)
	}
}

func TestMCPCollectorClearsCallerTargetBackingAfterSuccessfulCollection(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "Projects", "client", ".mcp.json")
	writeMCPFile(t, path, `{"mcpServers":{"issued":{"command":"node"}}}`)
	target := sharedProjectTarget(t, home, path)
	consumers := target.Consumers
	backing := []model.LocalTarget{target}

	got, err := mcp.New(backing...).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if assetCount(got.Assets, "mcp:shared:issued") != 1 {
		t.Fatalf("issued target was not inventoried: %+v", got)
	}
	if !reflect.DeepEqual(backing[0], model.LocalTarget{}) {
		t.Fatalf("caller target backing retained data: %+v", backing[0])
	}
	if !reflect.DeepEqual(consumers, []string{"", ""}) {
		t.Fatalf("consumer backing retained data: %q", consumers)
	}
}

func TestMCPCollectorMarksOnlyMalformedTargetPartialAndKeepsValidSibling(t *testing.T) {
	home := t.TempDir()
	badPath := filepath.Join(home, "Projects", "bad", ".mcp.json")
	goodPath := filepath.Join(home, "Projects", "good", ".mcp.json")
	writeMCPFile(t, badPath, `{"mcpServers":{"both":{"command":"node","url":"https://example.invalid"},"safe":{"command":"node","futureOption":"unknown-secret-value"}}}`)
	writeMCPFile(t, goodPath, `{"mcpServers":{"other":{"command":"node"}}}`)
	badTarget := sharedProjectTarget(t, home, badPath)
	goodTarget := sharedProjectTarget(t, home, goodPath)

	got := collectMCP(t, home, badTarget, goodTarget)
	bad := assertTarget(t, got.Targets, badTarget.TargetID, badTarget.InstanceRef)
	if bad.Status != model.TargetPartial || bad.Assets != 1 || bad.Observations != 1 || !hasErrorCode(bad.Errors, "invalid_server") || !hasErrorCode(bad.Errors, "unknown_server_field") {
		t.Fatalf("bad target=%+v", bad)
	}
	good := assertTarget(t, got.Targets, goodTarget.TargetID, goodTarget.InstanceRef)
	if good.Status != model.TargetComplete || good.Assets != 1 || good.Observations != 1 {
		t.Fatalf("good target=%+v", good)
	}
	observation := assertObservation(t, got.Observations, "mcp:shared:safe", badTarget.InstanceRef)
	if observation.Metadata["unknown_fields"] != "futureOption" {
		t.Fatalf("metadata=%+v", observation.Metadata)
	}
	assertJSONExcludes(t, got, "unknown-secret-value", badPath, goodPath)
}

func TestMCPCollectorObservationContainsSanitizedSemanticsOnly(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cursor", "mcp.json")
	writeMCPFile(t, path, `{
  "mcpServers": {
    "stdio": {
      "command": "/private/tools/runner",
      "args": ["--token", "argument-secret", "--root=/private/client/data", "--mode=safe"],
      "cwd": "/private/client/work",
      "env": {"API_TOKEN": "environment-secret"},
      "enabledTools": ["write", "read"],
      "disabledTools": ["delete"],
      "enabled": false
    },
    "remote": {
      "url": "https://alice:password@example.invalid/mcp?access_token=query-secret&mode=safe#fragment-secret",
      "headers": {"Authorization": "Bearer header-secret"}
    },
    "embedded-command": {
      "command": "runner --token embedded-secret-marker"
    },
    "assignment-command": {
      "command": "--token=command-secret"
    },
    "unsafe-unknown": {
      "command": "node",
      "/private/client/unknown-field": "unknown-field-secret"
    }
  }
}`)

	got := collectMCP(t, home)
	stdio := assertObservation(t, got.Observations, "mcp:cursor:stdio", "$HOME/.cursor/mcp.json")
	for _, key := range []string{"transport", "command", "args", "cwd_ref", "enabled", "env_keys", "enabled_tools", "disabled_tools", "source_target"} {
		if stdio.Metadata[key] == "" {
			t.Fatalf("stdio metadata missing %q: %+v", key, stdio.Metadata)
		}
	}
	if strings.Contains(stdio.Metadata["command"], "/private/") || strings.Contains(stdio.Metadata["cwd_ref"], "/private/") || strings.Contains(stdio.Metadata["args"], "/private/") {
		t.Fatalf("raw path in metadata=%+v", stdio.Metadata)
	}
	remote := assertObservation(t, got.Observations, "mcp:cursor:remote", "$HOME/.cursor/mcp.json")
	if remote.Metadata["url_shape"] != "https://example.invalid/mcp?query_keys=access_token,mode" || remote.Metadata["header_keys"] != "Authorization" {
		t.Fatalf("remote metadata=%+v", remote.Metadata)
	}
	commandSecret := assertObservation(t, got.Observations, "mcp:cursor:embedded-command", "$HOME/.cursor/mcp.json")
	if commandSecret.Metadata["command"] != "[redacted]" {
		t.Fatalf("command metadata=%+v", commandSecret.Metadata)
	}
	singleTokenCommandSecret := assertObservation(t, got.Observations, "mcp:cursor:assignment-command", "$HOME/.cursor/mcp.json")
	if singleTokenCommandSecret.Metadata["command"] != "[redacted]" {
		t.Fatalf("single-token command metadata=%+v", singleTokenCommandSecret.Metadata)
	}
	assertJSONExcludes(t, got,
		"argument-secret", "environment-secret", "query-secret", "password", "header-secret", "fragment-secret",
		"embedded-secret-marker", "command-secret", "unknown-field-secret",
		"/private/tools/runner", "/private/client/data", "/private/client/work", "/private/client/unknown-field",
	)
}

func TestMCPCollectorRejectsSymlinkDuplicateOversizeAndHonorsCancellation(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		home := t.TempDir()
		outside := t.TempDir()
		outsideConfig := filepath.Join(outside, "mcp.json")
		writeMCPFile(t, outsideConfig, `{"mcpServers":{"outside":{"command":"node"}}}`)
		if err := os.Symlink(outsideConfig, filepath.Join(home, ".claude.json")); err != nil {
			t.Fatal(err)
		}
		got := collectMCP(t, home)
		target := assertTarget(t, got.Targets, "mcp.claude-code.user", "")
		if target.Status != model.TargetPartial || !hasErrorCode(target.Errors, "config_unavailable") {
			t.Fatalf("target=%+v", target)
		}
		assertJSONExcludes(t, got, outside)
	})

	t.Run("duplicate keys", func(t *testing.T) {
		home := t.TempDir()
		writeMCPFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"bad":{"env":{"TOKEN":"one","TOKEN":"two"}}}}`)
		got := collectMCP(t, home)
		target := assertTarget(t, got.Targets, "mcp.claude-code.user", "")
		if target.Status != model.TargetPartial || !hasErrorCode(target.Errors, "config_invalid") {
			t.Fatalf("target=%+v", target)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		home := t.TempDir()
		writeMCPBytes(t, filepath.Join(home, ".cursor", "mcp.json"), bytes.Repeat([]byte("x"), maxConfigBytes+1))
		got := collectMCP(t, home)
		target := assertTarget(t, got.Targets, "mcp.cursor.user", "")
		if target.Status != model.TargetPartial || !hasErrorCode(target.Errors, "config_oversized") {
			t.Fatalf("target=%+v", target)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := mcp.New().Collect(ctx, testutil.Environment(t, t.TempDir()))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestMCPCollectorFailsClosedWithoutRootedFilesystem(t *testing.T) {
	home := t.TempDir()
	writeMCPFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"unsafe":{"command":"node"}}}`)
	env := testutil.Environment(t, home)
	env.FS = pathOnlyFileSystem{FileSystem: platform.OSFileSystem{}}

	got, err := mcp.New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"mcp.claude-code.legacy-user", "mcp.claude-code.user", "mcp.claude-desktop.user", "mcp.cursor.user",
		"mcp.github-copilot.user", "mcp.vscode-insiders.user", "mcp.vscode.user", "mcp.windsurf.legacy-user", "mcp.windsurf.user",
	} {
		target := assertTarget(t, got.Targets, id, "")
		if target.Status != model.TargetUnavailable || !hasErrorCode(target.Errors, "rooted_access_unavailable") {
			t.Fatalf("target=%+v", target)
		}
	}
	if len(got.Assets) != 0 || len(got.Observations) != 0 {
		t.Fatalf("result=%+v", got)
	}
}

func collectMCP(t *testing.T, home string, localTargets ...model.LocalTarget) model.CollectorResult {
	t.Helper()
	got, err := mcp.New(localTargets...).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func sharedProjectTarget(t *testing.T, home, path string) model.LocalTarget {
	t.Helper()
	return projectTarget(t, home, path, "mcp.shared.project", "json", "shared", []string{"claude-code", "vscode"})
}

func projectTarget(t *testing.T, home, path, targetID, format, host string, consumers []string) model.LocalTarget {
	t.Helper()
	projectRoot := filepath.Dir(path)
	if targetID == "mcp.cursor.project" || targetID == "mcp.vscode.project" || targetID == "mcp.codex.project" {
		projectRoot = filepath.Dir(projectRoot)
	}
	roots, err := projects.ResolveRoots(home, []string{projectRoot})
	if err != nil {
		t.Fatal(err)
	}
	result, err := projects.New(roots).Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range result.LocalTargets {
		if target.Path != path || target.TargetID != targetID {
			continue
		}
		if target.Format != format || target.Host != host || !reflect.DeepEqual(target.Consumers, consumers) || target.Provenance == nil {
			t.Fatalf("issued target=%+v", target)
		}
		return target
	}
	t.Fatalf("project collector did not issue target %q for %q: %+v", targetID, path, result.LocalTargets)
	return model.LocalTarget{}
}

func assertTarget(t *testing.T, targets []model.TargetCoverage, id, instance string) model.TargetCoverage {
	t.Helper()
	for _, target := range targets {
		if target.TargetID == id && target.InstanceRef == instance {
			return target
		}
	}
	t.Fatalf("missing target %q instance %q: %+v", id, instance, targets)
	return model.TargetCoverage{}
}

func assertAsset(t *testing.T, assets []model.Asset, id string) model.Asset {
	t.Helper()
	for _, asset := range assets {
		if asset.ID == id {
			return asset
		}
	}
	t.Fatalf("missing asset %q: %+v", id, assets)
	return model.Asset{}
}

func assertObservation(t *testing.T, observations []model.Observation, assetID, location string) model.Observation {
	t.Helper()
	for _, observation := range observations {
		if observation.AssetID == assetID && observation.LocationRef == location {
			return observation
		}
	}
	t.Fatalf("missing observation asset=%q location=%q: %+v", assetID, location, observations)
	return model.Observation{}
}

func assetCount(assets []model.Asset, id string) int {
	count := 0
	for _, asset := range assets {
		if asset.ID == id {
			count++
		}
	}
	return count
}

func observationCount(observations []model.Observation, assetID string) int {
	count := 0
	for _, observation := range observations {
		if observation.AssetID == assetID {
			count++
		}
	}
	return count
}

func countTarget(targets []model.TargetCoverage, id string) int {
	count := 0
	for _, target := range targets {
		if target.TargetID == id {
			count++
		}
	}
	return count
}

func hasErrorCode(errors []model.CoverageError, code string) bool {
	for _, issue := range errors {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func assertJSONExcludes(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range forbidden {
		if marker != "" && bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("forbidden value %q persisted: %s", marker, encoded)
		}
	}
}

func writeMCPFile(t *testing.T, path, contents string) {
	t.Helper()
	writeMCPBytes(t, path, []byte(contents))
}

func writeMCPBytes(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

type pathOnlyFileSystem struct {
	platform.FileSystem
}

type recordingRootFileSystem struct {
	platform.OSFileSystem
	mu    sync.Mutex
	opens []string
}

func (f *recordingRootFileSystem) OpenRoot(path string) (platform.RootedDirectory, error) {
	f.mu.Lock()
	f.opens = append(f.opens, filepath.Clean(path))
	f.mu.Unlock()
	return f.OSFileSystem.OpenRoot(path)
}

func (f *recordingRootFileSystem) opened(path string) bool {
	clean := filepath.Clean(path)
	for _, opened := range f.paths() {
		if opened == clean {
			return true
		}
	}
	return false
}

func (f *recordingRootFileSystem) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.opens...)
}
