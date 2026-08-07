package evidence

import (
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/model"
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
		{"host", func(v *model.Observation) { v.Host = "cursor" }},
		{"source", func(v *model.Observation) { v.Source = "mcp.cursor.user" }},
		{"transport", func(v *model.Observation) { v.Metadata["transport"] = "http" }},
		{"command", func(v *model.Observation) { v.Metadata["command"] = "python" }},
		{"args", func(v *model.Observation) { v.Metadata["args"] = "--mode\x1fstrict" }},
		{"url shape", func(v *model.Observation) { v.Metadata["url_shape"] = "https://example.invalid/other?query_keys=mode" }},
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

func safeMCPObservation() model.Observation {
	return model.Observation{Host: "codex", Source: "mcp.codex.user", Metadata: map[string]string{
		"transport": "stdio", "command": "node", "args": "--mode\x1fsafe",
		"url_shape": "https://example.invalid/mcp?query_keys=mode", "cwd_ref": "config-relative/work",
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
