package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNativePackagesDeclareTruthfulCapabilitiesAndNoBundledCore(t *testing.T) {
	root := repositoryRoot(t)
	for _, host := range []Host{HostClaude, HostCodex, HostCursor} {
		directory := filepath.Join(root, "adapters", string(host))
		raw, err := os.ReadFile(filepath.Join(directory, "ssc-init-capabilities.json"))
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var manifest CapabilityManifest
		if err := decoder.Decode(&manifest); err != nil || !manifest.Valid() || manifest.Host != host {
			t.Fatalf("host=%q manifest=%+v err=%v", host, manifest, err)
		}
		if _, err := os.Stat(filepath.Join(directory, "bin")); !os.IsNotExist(err) {
			t.Fatalf("host %q package must not bundle an unsigned core", host)
		}
		skill, err := os.ReadFile(filepath.Join(directory, "skills", "ssc-init", "SKILL.md"))
		if err != nil || !bytes.Contains(skill, []byte("ssc-init findings --json")) || bytes.Contains(bytes.ToLower(skill), []byte(" safe")) || !bytes.Contains(skill, []byte("explicit user")) {
			t.Fatalf("host=%q skill contract is unsafe", host)
		}
	}
}

func TestClaudeHookIsPostExecutionAdvisoryAndIgnoresHostPayload(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "adapters", "claude", "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{`"PostToolUse"`, `"command": "ssc-init hook"`, `"timeout": 30`} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, prohibited := range []string{"PreToolUse", "adapter evaluate", "curl", "download", "install"} {
		if strings.Contains(text, prohibited) {
			t.Fatalf("hook contains prohibited capability %q", prohibited)
		}
	}
}

func TestNativePluginManifestsStayMinimalAndVersionAligned(t *testing.T) {
	root := repositoryRoot(t)
	paths := map[Host]string{HostClaude: ".claude-plugin", HostCodex: ".codex-plugin", HostCursor: ".cursor-plugin"}
	for host, manifestDir := range paths {
		raw, err := os.ReadFile(filepath.Join(root, "adapters", string(host), manifestDir, "plugin.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Name, Description, Version string
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil || manifest.Name != "ssc-init" || manifest.Description == "" || manifest.Version != "0.1.0" {
			t.Fatalf("host=%q manifest=%+v err=%v", host, manifest, err)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate adapter tests")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
