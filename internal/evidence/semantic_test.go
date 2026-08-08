package evidence

import (
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestHashMCPObservationIgnoresUnknownMetadataWithoutMutatingInput(t *testing.T) {
	base := safeMCPObservation()
	base.Metadata["unknown_fields"] = "future"
	base.Metadata["future_value"] = "secret-marker-that-must-not-hash"
	before := cloneSemanticObservation(base)

	first, err := HashMCPObservation(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Metadata["unknown_fields"] = "another_future"
	base.Metadata["future_value"] = "/private/raw-config"
	second, err := HashMCPObservation(base)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("unknown metadata changed semantic digest: %q %q", first, second)
	}
	if got := before.Metadata["unknown_fields"]; got != "future" || before.Metadata["future_value"] != "secret-marker-that-must-not-hash" {
		t.Fatalf("test setup changed: %+v", before.Metadata)
	}
}

func TestHashMCPObservationChangesForEverySupportedSemanticField(t *testing.T) {
	base := safeMCPObservation()
	first, err := HashMCPObservation(base)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*model.Observation)
	}{
		{"host", func(v *model.Observation) { v.Host, v.Source = "cursor", "mcp.cursor.user" }},
		{"source", func(v *model.Observation) { v.Source = "mcp.codex.project" }},
		{"command", func(v *model.Observation) { v.Metadata["command"] = "python" }},
		{"args", func(v *model.Observation) { v.Metadata["args"] = "--mode\x1fstrict" }},
		{"cwd ref", func(v *model.Observation) { v.Metadata["cwd_ref"] = "config-relative/other" }},
		{"enabled", func(v *model.Observation) { v.Metadata["enabled"] = "false" }},
		{"environment key names", func(v *model.Observation) { v.Metadata["env_keys"] = "OTHER_TOKEN" }},
		{"header key names", func(v *model.Observation) { v.Metadata["header_keys"] = "X-Other" }},
		{"enabled tools", func(v *model.Observation) { v.Metadata["enabled_tools"] = "write" }},
		{"disabled tools", func(v *model.Observation) { v.Metadata["disabled_tools"] = "remove" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneSemanticObservation(base)
			test.mutate(&candidate)
			got, err := HashMCPObservation(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got == first {
				t.Fatalf("semantic mutation did not change digest: %s", test.name)
			}
		})
	}
	remote := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
		"transport": "http", "url_shape": "https://example.invalid/mcp?query_keys=mode",
	}}
	remoteDigest, err := HashMCPObservation(remote)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, key, value string }{
		{"transport", "transport", "sse"},
		{"url shape", "url_shape", "https://example.invalid/other?query_keys=mode"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneSemanticObservation(remote)
			candidate.Metadata[test.key] = test.value
			got, err := HashMCPObservation(candidate)
			if err != nil || got == remoteDigest {
				t.Fatalf("digest=%q baseline=%q err=%v", got, remoteDigest, err)
			}
		})
	}
}

func TestHashMCPObservationHasStableDomainOrderAndSafeOptionalValues(t *testing.T) {
	observation := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
		"transport": "stdio",
		"command":   "external-command/path-sha256:" + strings.Repeat("a", 64),
		"args":      "--root=$HOME/Projects/demo\x1f[redacted]",
		"cwd_ref":   "config-relative/work",
	}}
	first, err := HashMCPObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	const want = "af34be9dd3edbb5b2222909d753b657438eb0da6ae41815b6f311ba0807278d8"
	if first != want {
		t.Fatalf("digest=%q want=%q", first, want)
	}
	second, err := HashMCPObservation(observation)
	if err != nil || first != second || len(first) != 64 {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
}

func TestHashMCPObservationRejectsUnsafeIncludedValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Observation)
	}{
		{"missing transport", func(v *model.Observation) { delete(v.Metadata, "transport") }},
		{"raw absolute path", func(v *model.Observation) { v.Metadata["command"] = "/private/bin/tool" }},
		{"credential", func(v *model.Observation) { v.Metadata["args"] = "--token=actual-secret" }},
		{"secret-bearing header value", func(v *model.Observation) { v.Metadata["header_keys"] = "Authorization=Bearer actual-secret" }},
		{"control character", func(v *model.Observation) { v.Metadata["command"] = "tool\nnext" }},
		{"invalid utf8", func(v *model.Observation) { v.Metadata["command"] = string([]byte{0xff}) }},
		{"oversize", func(v *model.Observation) { v.Metadata["command"] = strings.Repeat("x", 4097) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := safeMCPObservation()
			test.mutate(&candidate)
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatal("unsafe included value accepted")
			}
		})
	}
}

func TestHashMCPObservationRejectsMalformedV1Tuples(t *testing.T) {
	cases := []struct {
		name  string
		value model.Observation
	}{
		{"uppercase host", model.Observation{Host: "Codex", Source: "mcp.Codex.user", Metadata: map[string]string{"transport": "stdio", "command": "node"}}},
		{"source host mismatch", model.Observation{Host: "codex", Source: "mcp.cursor.user", Metadata: map[string]string{"transport": "stdio", "command": "node"}}},
		{"source missing suffix", model.Observation{Host: "codex", Source: "mcp.codex", Metadata: map[string]string{"transport": "stdio", "command": "node"}}},
		{"unknown transport", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "websocket", "url_shape": "https://example.invalid/mcp"}}},
		{"stdio missing command", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "stdio"}}},
		{"stdio with url", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "stdio", "command": "node", "url_shape": "https://example.invalid/mcp"}}},
		{"remote missing url", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http"}}},
		{"remote with command", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http", "command": "node", "url_shape": "https://example.invalid/mcp"}}},
		{"remote with args", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "sse", "url_shape": "https://example.invalid/mcp", "args": "--mode"}}},
		{"remote with cwd", model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "streamable-http", "url_shape": "https://example.invalid/mcp", "cwd_ref": "config-relative/work"}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := HashMCPObservation(test.value); err == nil {
				t.Fatalf("malformed tuple accepted: %+v", test.value)
			}
		})
	}
}

func TestHashMCPObservationDefensivelyRejectsCombinedCredentialsAndEmbeddedPaths(t *testing.T) {
	unsafe := []string{
		"--auth:actualvalue", "--header=actualvalue", "--env:actualvalue", "--token:actualvalue",
		"--client-secret=actualvalue", "-Hactualvalue", "-H:actualvalue", "-eactualvalue", "-e:actualvalue",
		"--auth/actualvalue", "--header;actualvalue", "--env|actualvalue", "--token'actualvalue",
		`--client-secret"actualvalue`, "-H/actualvalue", "-e|actualvalue",
		"--auth/actualvalue:[redacted]", "--header;actualvalue=[redacted]", "--auth.actualvalue:[redacted]",
		"--key=actualvalue", "--githubToken=actualvalue", "--githubTOKEN=actualvalue", "--GitHubToken=actualvalue",
		"--root:/private/key", "x;/private/key",
	}
	for _, value := range unsafe {
		t.Run(value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["args"] = value
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("unsafe argument accepted: %q", value)
			}
		})
	}
	for _, value := range []string{
		"--auth:[redacted]", "--header=[redacted]", "--env:[redacted]", "--token:[redacted]",
		"--client-secret=[redacted]", "-H[redacted]", "-H:[redacted]", "-e[redacted]", "-e:[redacted]", "--tokenizer",
		"[redacted]", "Authorization: [redacted]", "Proxy-Authorization: [redacted]",
		"Authorization:\x1f[redacted]", "Proxy-Authorization:\x1f[redacted]",
		"--key=[redacted]", "--githubToken=[redacted]", "--githubTOKEN=[redacted]",
		"--authorizationHelper=safe", "--AuthorizationHelper=safe",
	} {
		t.Run("safe "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["args"] = value
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("sanitized argument rejected: %q: %v", value, err)
			}
		})
	}
	for _, value := range []string{
		"Authorization:", "Authorization: actualvalue", "Authorization:\x1factualvalue",
		"Proxy-Authorization:", "Proxy-Authorization: actualvalue", "Proxy-Authorization:\x1factualvalue",
	} {
		t.Run("invalid canonical header "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["args"] = value
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("noncanonical header credential accepted: %q", value)
			}
		})
	}
}

func TestHashMCPObservationRequiresExactCanonicalRedaction(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*model.Observation, string)
	}{
		{"command", func(candidate *model.Observation, value string) { candidate.Metadata["command"] = value }},
		{"argument", func(candidate *model.Observation, value string) { candidate.Metadata["args"] = value }},
		{"combined argument", func(candidate *model.Observation, value string) { candidate.Metadata["args"] = "--auth:" + value }},
		{"cwd", func(candidate *model.Observation, value string) { candidate.Metadata["cwd_ref"] = value }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, forged := range []string{"[REDACTED]", "redacted", "[ReDaCtEd]"} {
				candidate := safeMCPObservation()
				test.mutate(&candidate, forged)
				if _, err := HashMCPObservation(candidate); err == nil {
					t.Fatalf("forged placeholder %q accepted", forged)
				}
			}
			candidate := safeMCPObservation()
			test.mutate(&candidate, "[redacted]")
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("canonical placeholder rejected: %v", err)
			}
		})
	}

	for _, forged := range []string{"[REDACTED]", "redacted", "[ReDaCtEd]"} {
		candidate := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http", "url_shape": forged}}
		if _, err := HashMCPObservation(candidate); err == nil {
			t.Fatalf("forged URL placeholder %q accepted", forged)
		}
	}
	candidate := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http", "url_shape": "[redacted]"}}
	if _, err := HashMCPObservation(candidate); err != nil {
		t.Fatalf("canonical URL placeholder rejected: %v", err)
	}
}

func TestHashMCPObservationAppliesFieldSpecificListGrammars(t *testing.T) {
	for _, test := range []struct{ key, value string }{
		{"env_keys", "A,B"},
		{"header_keys", "A,B"},
		{"enabled_tools", "A,B"},
		{"disabled_tools", "A,B"},
		{"env_keys", "API_TOKEN,_PRIVATE2"},
		{"header_keys", "Authorization,X-Client_2"},
		{"enabled_tools", "read_file,tool-name,tool.name"},
		{"disabled_tools", "delete_file,tool-name,tool.name"},
	} {
		t.Run("safe "+test.key, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata[test.key] = test.value
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("safe %s=%q rejected: %v", test.key, test.value, err)
			}
		})
	}

	for _, test := range []struct{ key, value string }{
		{"env_keys", "B,A"},
		{"env_keys", "A,A"},
		{"header_keys", "B,A"},
		{"header_keys", "A,A"},
		{"enabled_tools", "B,A"},
		{"enabled_tools", "A,A"},
		{"disabled_tools", "B,A"},
		{"disabled_tools", "A,A"},
		{"env_keys", "API_TOKEN,BAD=actualvalue"},
		{"env_keys", "API_TOKEN,BAD/value"},
		{"env_keys", "2INVALID"},
		{"header_keys", "Authorization,X-Auth:actualvalue"},
		{"header_keys", "Authorization,Bad Header"},
		{"enabled_tools", "read_file,bad/tool"},
		{"disabled_tools", "delete_file,write:actualvalue"},
	} {
		t.Run("unsafe "+test.key+" "+test.value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata[test.key] = test.value
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("unsafe %s=%q accepted", test.key, test.value)
			}
		})
	}
}

func TestHashMCPObservationDetectsSlashRootedPathsAfterPunctuation(t *testing.T) {
	for _, value := range []string{
		"/private/direct", `--root:'/private/quoted`, "x|/private/piped", "x:/private/colon",
		"x;/private/semicolon", "x=/private/equals", "[/private/bracketed", `"/private/double-quoted`,
	} {
		t.Run("unsafe "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["args"] = value
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("slash-rooted path accepted: %q", value)
			}
		})
	}

	for _, value := range []string{
		"https://example.invalid/api/v1", "--url=https://example.invalid/api/v1", "https://[::1]/api/v1", "--url=https://[::1]/api/v1", "$HOME/Projects/demo",
		"config-relative/work/file", "external-arg/path-sha256:" + strings.Repeat("a", 64), "relative/path",
	} {
		t.Run("safe "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["args"] = value
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("safe path shape rejected: %q: %v", value, err)
			}
		})
	}
}

func TestHashMCPObservationRejectsUnsafeDecodedURLPaths(t *testing.T) {
	unsafe := []string{
		"https://example.invalid/password=actualvalue",
		"https://example.invalid/password:actualvalue",
		"https://example.invalid/password%3Dactualvalue",
		"https://example.invalid/password%3Aactualvalue",
		"https://example.invalid/token%2Fvalue",
		"https://example.invalid/password%253Dactualvalue",
		"https://example.invalid/password%253dactualvalue",
		"https://example.invalid/password%252Factualvalue",
		"https://example.invalid/key=actualvalue",
		"https://example.invalid/githubToken=actualvalue",
		"https://example.invalid/githubTOKEN=actualvalue",
		"https://example.invalid/authorizationhelper=actualvalue",
		"https://example.invalid/api/%0av1",
		"https://user:actualvalue@example.invalid/api/v1/mcp",
		"https://example.invalid/api/v1/mcp?mode=safe",
		"https://example.invalid/api/v1/mcp?query_keys=mode%2Cother",
		"https://example.invalid/api/v1/mcp?query_keys=mode#fragment",
	}
	for _, value := range unsafe {
		t.Run(value, func(t *testing.T) {
			candidate := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http", "url_shape": value}}
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("unsafe URL shape accepted: %q", value)
			}
		})
	}
	for _, value := range []string{
		"https://example.invalid/api/v1/mcp",
		"https://example.invalid/auth/callback",
		"https://example.invalid/token/refresh",
		"https://example.invalid/api%2Dv1/mcp",
		"https://example.invalid/authorizationHelper=value",
		"https://example.invalid/AuthorizationHelper=value",
		"https://example.invalid/api/v1/mcp?query_keys=access_token,mode",
		"[redacted]",
	} {
		t.Run("safe "+value, func(t *testing.T) {
			candidate := model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{"transport": "http", "url_shape": value}}
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("safe URL shape rejected: %q: %v", value, err)
			}
		})
	}
}

func TestHashMCPObservationValidatesHomeCWDReferenceSuffix(t *testing.T) {
	for _, value := range []string{"$HOME", "$HOME/work", "config-relative/work", "external-cwd/path-sha256:" + strings.Repeat("a", 64)} {
		t.Run("safe "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["cwd_ref"] = value
			if _, err := HashMCPObservation(candidate); err != nil {
				t.Fatalf("safe CWD rejected: %q: %v", value, err)
			}
		})
	}
	for _, value := range []string{
		"$HOME/", "$HOME/../work", "$HOME/work//nested", "$HOME/./work", "$HOME//work", `$HOME/work\nested`,
		"external-other/path-sha256:" + strings.Repeat("a", 64),
	} {
		t.Run("unsafe "+value, func(t *testing.T) {
			candidate := safeMCPObservation()
			candidate.Metadata["cwd_ref"] = value
			if _, err := HashMCPObservation(candidate); err == nil {
				t.Fatalf("unsafe CWD accepted: %q", value)
			}
		})
	}
}

func safeMCPObservation() model.Observation {
	return model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
		"transport": "stdio", "command": "node", "args": "--mode\x1fsafe",
		"cwd_ref": "config-relative/work",
		"enabled": "true", "env_keys": "API_TOKEN", "header_keys": "Authorization",
		"enabled_tools": "read", "disabled_tools": "delete",
	}}
}

func cloneSemanticObservation(value model.Observation) model.Observation {
	result := value
	result.Consumers = append([]string(nil), value.Consumers...)
	result.Metadata = make(map[string]string, len(value.Metadata))
	for key, item := range value.Metadata {
		result.Metadata[key] = item
	}
	return result
}
