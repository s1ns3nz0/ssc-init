package policy_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/policy"
)

func TestLoadAcceptsTheDocumentedShape(t *testing.T) {
	document, err := policy.Load([]byte(`{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [
    {
      "id": "mcp-shell-command",
      "family": "shape",
      "enabled": true,
      "description": "An MCP server whose command is a shell.",
      "match": {"assetType": ["mcp-server"], "metadataEquals": {"command": ["sh", "bash", "zsh"]}}
    }
  ]
}`))
	if err != nil {
		t.Fatalf("documented document rejected: %v", err)
	}
	if document.SchemaVersion != policy.SchemaVersion {
		t.Fatalf("schema version did not round-trip: %q", document.SchemaVersion)
	}
	if len(document.Rules) != 1 || document.Rules[0].ID != "mcp-shell-command" || !document.Rules[0].Enabled {
		t.Fatalf("document did not round-trip: %+v", document.Rules)
	}
	rule := document.Rules[0]
	if rule.Family != policy.FamilyShape || rule.Description == "" || rule.Match == nil {
		t.Fatalf("rule did not round-trip: %+v", rule)
	}
	if len(rule.Match.AssetType) != 1 || rule.Match.AssetType[0] != "mcp-server" {
		t.Fatalf("match assetType did not round-trip: %+v", rule.Match)
	}
	if commands := rule.Match.MetadataEquals["command"]; len(commands) != 3 || commands[0] != "sh" || commands[2] != "zsh" {
		t.Fatalf("match metadataEquals did not round-trip: %+v", rule.Match.MetadataEquals)
	}
}

func TestLoadAcceptsTheOtherFamilies(t *testing.T) {
	document, err := policy.Load([]byte(`{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [
    {"id": "new-asset", "family": "change", "enabled": false, "description": "d", "match": {"rungs": ["NEW", "CHANGED"]}},
    {"id": "pin-mismatch", "family": "pin", "enabled": false, "description": "d"}
  ]
}`))
	if err != nil {
		t.Fatalf("documented document rejected: %v", err)
	}
	if len(document.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(document.Rules))
	}
	if document.Rules[0].Family != policy.FamilyChange || document.Rules[1].Family != policy.FamilyPin {
		t.Fatalf("families did not round-trip: %+v", document.Rules)
	}
	if document.Rules[1].Match != nil {
		t.Fatalf("pin rule gained a match: %+v", document.Rules[1].Match)
	}
}

func TestLoadRejectsUnknownFieldsAndDuplicateKeys(t *testing.T) {
	for name, source := range map[string]string{
		"unknown document field":        `{"schemaVersion":"ssc-init.policy.v1","ruls":[]}`,
		"unknown rule field":            `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","sevrity":"high"}]}`,
		"unknown match field":           `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetKind":["mcp-server"]}}]}`,
		"duplicate key":                 `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":true,"enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"duplicate top-level key":       `{"schemaVersion":"ssc-init.policy.v1","rules":[],"rules":[]}`,
		"duplicate nested key":          `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"],"assetType":["package"]}}]}`,
		"duplicate rule id":             `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}},{"id":"a","family":"change","enabled":false,"description":"d","match":{"rungs":["NEW"]}}]}`,
		"unknown family":                `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"behavioral","enabled":false,"description":"d"}]}`,
		"wrong schema version":          `{"schemaVersion":"ssc-init.policy.v2","rules":[]}`,
		"missing schema version":        `{"rules":[]}`,
		"missing description":           `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"match":{"assetType":["mcp-server"]}}]}`,
		"missing enabled":               `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"missing id":                    `{"schemaVersion":"ssc-init.policy.v1","rules":[{"family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"invalid rule id":               `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"A Rule","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"missing family":                `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"shape rule without match":      `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d"}]}`,
		"change rule without match":     `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"change","enabled":false,"description":"d"}]}`,
		"pin rule with match":           `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"pin","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"rungs on a shape rule":         `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"rungs":["NEW"]}}]}`,
		"shape fields on a change rule": `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"change","enabled":false,"description":"d","match":{"rungs":["NEW"],"assetType":["package"]}}]}`,
		"unknown rung":                  `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"change","enabled":false,"description":"d","match":{"rungs":["SIDEWAYS"]}}]}`,
		"unknown asset type":            `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["kernel-module"]}}]}`,
		"unknown evidence status":       `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"evidenceStatus":["excellent"]}}]}`,
		"empty match":                   `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{}}]}`,
		"empty metadata key":            `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"metadataEquals":{"":["sh"]}}}]}`,
		"empty metadata value set":      `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"metadataEquals":{"command":[]}}}]}`,
		"trailing content":              `{"schemaVersion":"ssc-init.policy.v1","rules":[]}{"schemaVersion":"ssc-init.policy.v1","rules":[]}`,
		"not an object":                 `[]`,
		"empty source":                  ``,
	} {
		if _, err := policy.Load([]byte(source)); err == nil {
			t.Fatalf("%s: Load accepted an invalid document", name)
		}
	}
}

func TestLoadErrorsNameALocationAndNeverAValue(t *testing.T) {
	_, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[
		{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}},
		{"id":"b","family":"nonsense","enabled":false,"description":"d"}]}`))
	if err == nil {
		t.Fatal("Load accepted an unknown family")
	}
	if !strings.Contains(err.Error(), "rules[1].family") {
		t.Fatalf("error does not locate the fault: %v", err)
	}
	if strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("error echoed the offending value: %v", err)
	}
}

// A policy document may carry hostile text: a rule ID, a description, or a
// metadata value can be anything the author typed, including a credential
// shape. No load error may echo any of it — the store's validation errors hold
// the same line.
func TestLoadErrorsNeverEchoHostileContent(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	for name, source := range map[string]string{
		"hostile rule id":         `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"` + secret + `","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"hostile family":          `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"` + secret + `","enabled":false,"description":"d"}]}`,
		"hostile asset type":      `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["` + secret + `"]}}]}`,
		"hostile rung":            `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"change","enabled":false,"description":"d","match":{"rungs":["` + secret + `"]}}]}`,
		"hostile evidence status": `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"evidenceStatus":["` + secret + `"]}}]}`,
		"hostile unknown field":   `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","` + secret + `":1}]}`,
		"hostile duplicate key":   `{"schemaVersion":"ssc-init.policy.v1","rules":[],"` + secret + `":1,"` + secret + `":2}`,
		"hostile schema version":  `{"schemaVersion":"` + secret + `","rules":[]}`,
		"hostile duplicate id":    `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"pin","enabled":false,"description":"d"},{"id":"a","family":"pin","enabled":false,"description":"d"}]}`,
	} {
		_, err := policy.Load([]byte(source))
		if err == nil {
			t.Fatalf("%s: Load accepted an invalid document", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: error echoed the offending value: %v", name, err)
		}
	}
}

// Two documents that differ only in a value must produce the same error text:
// an error that varies with content is an error that carries content.
func TestLoadErrorsAreValueIndependent(t *testing.T) {
	first, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"one","enabled":false,"description":"d"}]}`))
	if err == nil {
		t.Fatalf("Load accepted an unknown family: %+v", first)
	}
	second, secondErr := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"two","enabled":false,"description":"d"}]}`))
	if secondErr == nil {
		t.Fatalf("Load accepted an unknown family: %+v", second)
	}
	if err.Error() != secondErr.Error() {
		t.Fatalf("error text varies with the offending value: %q vs %q", err, secondErr)
	}
}

// Same bytes in, same structure and same error out, every time.
func TestLoadIsDeterministic(t *testing.T) {
	const valid = `{"schemaVersion":"ssc-init.policy.v1","rules":[
		{"id":"a","family":"shape","enabled":true,"description":"d","match":{"assetType":["mcp-server"],"metadataEquals":{"command":["sh"],"transport":["stdio"]}}},
		{"id":"b","family":"change","enabled":false,"description":"d","match":{"rungs":["NEW","CHANGED"]}}]}`
	// Many independent faults at once: whichever is reported must be reported
	// every time, so the reader can act on a stable message.
	const invalid = `{"schemaVersion":"ssc-init.policy.v1","rules":[
		{"id":"A","family":"nope","enabled":false,"description":"","match":{"rungs":["SIDEWAYS"],"assetType":["kernel-module"]}},
		{"id":"A","family":"nope","enabled":false,"description":""}]}`

	wanted, err := policy.Load([]byte(valid))
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	_, wantedErr := policy.Load([]byte(invalid))
	if wantedErr == nil {
		t.Fatal("Load accepted an invalid document")
	}
	for attempt := range 50 {
		got, err := policy.Load([]byte(valid))
		if err != nil {
			t.Fatalf("attempt %d: valid document rejected: %v", attempt, err)
		}
		if !reflect.DeepEqual(got, wanted) {
			t.Fatalf("attempt %d: parse is not deterministic:\n%+v\n%+v", attempt, got, wanted)
		}
		if _, err := policy.Load([]byte(invalid)); err == nil || err.Error() != wantedErr.Error() {
			t.Fatalf("attempt %d: error is not deterministic: %v vs %v", attempt, err, wantedErr)
		}
	}
}

// Load takes bytes. The package opens no file, so there is no path to
// traverse, no symlink to follow, and no directory to escape; the caller owns
// the read. This asserts the seam stays that way.
func TestLoadTouchesNoFilesystem(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(source) == 0 {
		t.Fatal("empty go.mod")
	}
	sources, err := filepath.Glob(filepath.Join(".", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{`"os"`, `"os/exec"`, `"net"`, `"net/http"`, `"path/filepath"`, `"io/ioutil"`} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("%s imports %s: the policy package performs no I/O", name, forbidden)
			}
		}
	}
}
