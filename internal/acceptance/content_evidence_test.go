package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

// contentMutationCase drives one isolated-home baseline, one content-only
// mutation, and one rescan for a single supported evidence subject.
type contentMutationCase struct {
	name, assetType, subject string
	fixture                  func(t *testing.T, home string)
	mutate                   func(t *testing.T, home string)
	wantStatus               model.EvidenceStatus
	// wantChangedSubjects lists every evidence subject whose stable-ID record
	// must appear as a "changed" delta entry after the mutation.
	wantChangedSubjects []string
	// wantReplacedSubjects lists evidence subjects whose observation identity
	// changes with the mutation, producing removed+added observation and
	// evidence delta entries instead of an in-place change.
	wantReplacedSubjects []string
	externalProbes       bool
	probes               func(t *testing.T, home string) (platform.Runner, platform.ExecutableInspector)
}

func contentMutationCases() []contentMutationCase {
	cases := []contentMutationCase{
		{
			name: "claude plugin manifest", assetType: "agent-plugin", subject: model.EvidenceSubjectManifest,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v1\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0","description":"changed"}`)
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree},
		},
		{
			name: "claude plugin payload", assetType: "agent-plugin", subject: model.EvidenceSubjectPayloadTree,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", ".claude-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v1\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude", "plugins", "demo", "payload.js"), "payload v2\n")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectPayloadTree},
		},
		{
			name: "codex plugin manifest", assetType: "agent-plugin", subject: model.EvidenceSubjectManifest,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", "payload.js"), "payload v1\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0","description":"changed"}`)
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree},
		},
		{
			name: "codex plugin payload", assetType: "agent-plugin", subject: model.EvidenceSubjectPayloadTree,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", ".codex-plugin", "plugin.json"), `{"name":"demo","version":"1.0.0"}`)
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", "payload.js"), "payload v1\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "demo", "payload.js"), "payload v2\n")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectPayloadTree},
		},
	}
	for _, agent := range []string{"claude", "codex", "cursor"} {
		skillPath := filepath.Join("."+agent, "skills", "sample", "SKILL.md")
		cases = append(cases, contentMutationCase{
			name: agent + " skill body", assetType: "agent-skill", subject: model.EvidenceSubjectSkillDocument,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, skillPath), "---\nname: sample\n---\nInstruction body v1.\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, skillPath), "---\nname: sample\n---\nInstruction body v2.\n")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectSkillDocument, model.EvidenceSubjectPayloadTree},
		})
	}
	ideRoots := map[string]string{
		"vscode":          ".vscode/extensions",
		"vscode-insiders": ".vscode-insiders/extensions",
		"vscode-oss":      ".vscode-oss/extensions",
		"cursor":          ".cursor/extensions",
		"windsurf":        ".windsurf/extensions",
	}
	for _, host := range []string{"vscode", "vscode-insiders", "vscode-oss", "cursor", "windsurf"} {
		extensionDir := filepath.Join(filepath.FromSlash(ideRoots[host]), "acme.demo-1.0.0")
		writeExtension := func(t *testing.T, home string) {
			writeMatrixFile(t, filepath.Join(home, extensionDir, "package.json"),
				`{"name":"demo","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/browser.js"}`)
			writeMatrixFile(t, filepath.Join(home, extensionDir, "dist", "main.js"), "main v1\n")
			writeMatrixFile(t, filepath.Join(home, extensionDir, "dist", "browser.js"), "browser v1\n")
			writeMatrixFile(t, filepath.Join(home, extensionDir, "assets", "data.txt"), "data v1\n")
		}
		for _, ideCase := range []struct {
			suffix, subject, mutatePath, mutateContent string
		}{
			{"manifest", model.EvidenceSubjectManifest, "package.json",
				`{"name":"demo","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/browser.js","description":"changed"}`},
			{"main entry point", model.EvidenceSubjectEntrypointMain, "dist/main.js", "main v2\n"},
			{"browser entry point", model.EvidenceSubjectEntrypointBrowser, "dist/browser.js", "browser v2\n"},
			{"payload", model.EvidenceSubjectPayloadTree, "assets/data.txt", "data v2\n"},
		} {
			mutatePath := filepath.Join(extensionDir, filepath.FromSlash(ideCase.mutatePath))
			changed := []string{ideCase.subject}
			if ideCase.subject != model.EvidenceSubjectPayloadTree {
				changed = append(changed, model.EvidenceSubjectPayloadTree)
			}
			mutateContent := ideCase.mutateContent
			cases = append(cases, contentMutationCase{
				name: host + " extension " + ideCase.suffix, assetType: "ide-extension", subject: ideCase.subject,
				fixture: writeExtension,
				mutate: func(t *testing.T, home string) {
					writeMatrixFile(t, filepath.Join(home, mutatePath), mutateContent)
				},
				wantStatus:          model.EvidenceComplete,
				wantChangedSubjects: changed,
			})
		}
	}
	jetBrainsPlugin := filepath.Join("Library", "Application Support", "JetBrains", "Idea", "plugins", "demo")
	writeJetBrains := func(t *testing.T, home string) {
		writeMatrixFile(t, filepath.Join(home, jetBrainsPlugin, "META-INF", "plugin.xml"),
			"<idea-plugin>\n  <id>org.example.demo</id>\n  <name>Demo Plugin</name>\n  <version>1.0.0</version>\n</idea-plugin>\n")
		writeMatrixFile(t, filepath.Join(home, jetBrainsPlugin, "lib", "demo.jar"), "jar bytes v1")
	}
	cases = append(cases,
		contentMutationCase{
			name: "jetbrains plugin xml", assetType: "ide-extension", subject: model.EvidenceSubjectManifest,
			fixture: writeJetBrains,
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, jetBrainsPlugin, "META-INF", "plugin.xml"),
					"<idea-plugin>\n  <id>org.example.demo</id>\n  <name>Demo Plugin</name>\n  <version>1.0.0</version>\n  <description>changed</description>\n</idea-plugin>\n")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree},
		},
		contentMutationCase{
			name: "jetbrains plugin jar bytes", assetType: "ide-extension", subject: model.EvidenceSubjectPayloadTree,
			fixture: writeJetBrains,
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, jetBrainsPlugin, "lib", "demo.jar"), "jar bytes v2")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{model.EvidenceSubjectPayloadTree},
		},
		contentMutationCase{
			name: "mcp user declaration semantic field", assetType: "mcp-server", subject: model.EvidenceSubjectMCPDeclaration,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"demo":{"url":"https://one.invalid/mcp"}}}`)
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"demo":{"url":"https://two.invalid/mcp"}}}`)
			},
			wantStatus:           model.EvidenceComplete,
			wantReplacedSubjects: []string{model.EvidenceSubjectMCPDeclaration},
		},
		contentMutationCase{
			name: "mcp project declaration semantic field", assetType: "mcp-server", subject: model.EvidenceSubjectMCPDeclaration,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, "Projects", "sample", ".mcp.json"), `{"mcpServers":{"demo":{"url":"https://one.invalid/mcp"}}}`)
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, "Projects", "sample", ".mcp.json"), `{"mcpServers":{"demo":{"url":"https://two.invalid/mcp"}}}`)
			},
			wantStatus:           model.EvidenceComplete,
			wantReplacedSubjects: []string{model.EvidenceSubjectMCPDeclaration},
		},
	)
	for _, catalog := range []struct {
		basename string
		subject  string
	}{
		{"package.json", "project-manifest:package.json"},
		{"package-lock.json", "project-lockfile:package-lock.json"},
		{"npm-shrinkwrap.json", "project-lockfile:npm-shrinkwrap.json"},
		{"pnpm-lock.yaml", "project-lockfile:pnpm-lock.yaml"},
		{"yarn.lock", "project-lockfile:yarn.lock"},
		{"bun.lock", "project-lockfile:bun.lock"},
		{"bun.lockb", "project-lockfile:bun.lockb"},
		{"pyproject.toml", "project-manifest:pyproject.toml"},
		{"Pipfile", "project-manifest:Pipfile"},
		{"requirements.txt", "project-manifest:requirements.txt"},
		{"poetry.lock", "project-lockfile:poetry.lock"},
		{"Pipfile.lock", "project-lockfile:Pipfile.lock"},
		{"uv.lock", "project-lockfile:uv.lock"},
		{"go.mod", "project-manifest:go.mod"},
		{"go.sum", "project-lockfile:go.sum"},
		{"Cargo.toml", "project-manifest:Cargo.toml"},
		{"Cargo.lock", "project-lockfile:Cargo.lock"},
		{"Brewfile", "project-manifest:Brewfile"},
	} {
		basename := catalog.basename
		cases = append(cases, contentMutationCase{
			name: "project catalog " + basename, assetType: "project", subject: catalog.subject,
			fixture: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, "Projects", "app", basename), "content v1 of "+basename+"\n")
			},
			mutate: func(t *testing.T, home string) {
				writeMatrixFile(t, filepath.Join(home, "Projects", "app", basename), "content v2 of "+basename+"\n")
			},
			wantStatus:          model.EvidenceComplete,
			wantChangedSubjects: []string{catalog.subject},
		})
	}
	cases = append(cases,
		contentMutationCase{
			name: "package content stays unsupported", assetType: "package", subject: model.EvidenceSubjectPackageContent,
			fixture:        func(*testing.T, string) {},
			wantStatus:     model.EvidenceUnsupported,
			externalProbes: true,
			probes:         pipProbeFixture,
		},
		contentMutationCase{
			name: "docker full identity is complete", assetType: "package", subject: model.EvidenceSubjectContainerImage,
			fixture:        func(*testing.T, string) {},
			wantStatus:     model.EvidenceComplete,
			externalProbes: true,
			probes:         dockerProbeFixture,
		},
	)
	return cases
}

func TestContentEvidenceMutationMatrix(t *testing.T) {
	for _, testCase := range contentMutationCases() {
		t.Run(testCase.name, func(t *testing.T) {
			home := t.TempDir()
			testCase.fixture(t, home)
			databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
			options := baselineOptions{
				home: home, databasePath: databasePath,
				externalProbes: testCase.externalProbes,
				scanID:         "00000000-0000-4000-8000-0000000000a1",
			}
			if testCase.probes != nil {
				options.runner, options.inspector = testCase.probes(t, home)
			}
			first := runIsolatedBaseline(t, options)
			assertEvidenceCoverageTerminal(t, first.Scan, first.Inventory)
			before := requireContentEvidence(t, first.Inventory, testCase.assetType, testCase.subject)
			if before.Status != testCase.wantStatus {
				t.Fatalf("initial %s evidence status=%q want=%q record=%+v", testCase.subject, before.Status, testCase.wantStatus, before)
			}

			if testCase.mutate == nil {
				if testCase.wantStatus == model.EvidenceUnsupported {
					if before.Digest != "" || before.Algorithm != "" || before.Size != 0 || before.Files != 0 {
						t.Fatalf("unsupported evidence carries content claims: %+v", before)
					}
				} else if before.Algorithm != "sha256" || len(before.Digest) != 64 || before.Digest != strings.ToLower(before.Digest) {
					t.Fatalf("complete terminal evidence lacks a trusted digest: %+v", before)
				}
				assertEvidenceTargetStatus(t, first.Scan.EvidenceCoverage, before.ID, testCase.wantStatus)
				assertPrivacyBoundary(t, first)
				return
			}
			if before.Digest == "" || before.Algorithm != "sha256" || len(before.Digest) != 64 || before.Digest != strings.ToLower(before.Digest) {
				t.Fatalf("initial complete evidence lacks a trusted digest: %+v", before)
			}

			testCase.mutate(t, home)
			options.scanID = "00000000-0000-4000-8000-0000000000a2"
			second := runIsolatedBaseline(t, options)
			assertEvidenceCoverageTerminal(t, second.Scan, second.Inventory)
			after := requireContentEvidence(t, second.Inventory, testCase.assetType, testCase.subject)
			if after.Status != testCase.wantStatus {
				t.Fatalf("post-mutation %s evidence status=%q want=%q", testCase.subject, after.Status, testCase.wantStatus)
			}
			if after.Digest == before.Digest {
				t.Fatalf("mutation did not change the %s digest %q", testCase.subject, before.Digest)
			}

			wantChanges := make([]model.Change, 0, 2*len(testCase.wantChangedSubjects)+4)
			for _, subject := range testCase.wantChangedSubjects {
				previous := requireContentEvidence(t, first.Inventory, testCase.assetType, subject)
				current := requireContentEvidence(t, second.Inventory, testCase.assetType, subject)
				if previous.ID != current.ID {
					t.Fatalf("evidence ID for %s is not stable across content change: %q != %q", subject, previous.ID, current.ID)
				}
				if previous.Digest == current.Digest {
					t.Fatalf("expected %s digest change, both %q", subject, previous.Digest)
				}
				wantChanges = append(wantChanges, model.Change{Kind: model.ChangeChanged, Entity: model.ChangeEntityEvidence, EntityID: previous.ID})
			}
			for _, subject := range testCase.wantReplacedSubjects {
				previous := requireContentEvidence(t, first.Inventory, testCase.assetType, subject)
				current := requireContentEvidence(t, second.Inventory, testCase.assetType, subject)
				if previous.ID == current.ID || previous.ObservationID == current.ObservationID {
					t.Fatalf("semantic mutation must replace the observation identity: %+v vs %+v", previous, current)
				}
				wantChanges = append(wantChanges,
					model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: previous.ID},
					model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: current.ID},
					model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityObservation, EntityID: previous.ObservationID},
					model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityObservation, EntityID: current.ObservationID},
				)
			}
			sortMatrixChanges(wantChanges)
			if !reflect.DeepEqual(second.Delta.Changes, wantChanges) {
				t.Fatalf("mutation delta=\n%+v\nwant exactly=\n%+v", second.Delta.Changes, wantChanges)
			}

			reopened := reopenLatestSnapshot(t, databasePath)
			if !reflect.DeepEqual(reopened.Inventory, second.Inventory) || reopened.Inventory.Evidence == nil {
				t.Fatalf("reopened SQLite inventory drifted from the second scan:\n%+v\nwant\n%+v", reopened.Inventory, second.Inventory)
			}
			if !reflect.DeepEqual(reopened.Scan.EvidenceCoverage, second.Scan.EvidenceCoverage) {
				t.Fatalf("reopened evidence coverage drifted: %+v", reopened.Scan.EvidenceCoverage)
			}
			assertPrivacyBoundary(t, second)
		})
	}
}

// TestContentEvidenceGoldenBaselineReport locks the exact v4 report bytes for
// the official fixture home. Fixture modes are normalized so tree manifests
// are independent of the checkout umask.
func TestContentEvidenceGoldenBaselineReport(t *testing.T) {
	home := copyOfficialFixtureHome(t)
	normalizeEvidenceFixtureModes(t, home)
	result := runIsolatedBaseline(t, baselineOptions{
		home: home, scanID: "00000000-0000-4000-8000-000000000001",
	})
	goldenPath, err := filepath.Abs("../../testdata/golden/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SSC_INIT_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, result.Report, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Report, golden) {
		t.Fatalf("baseline report drifted from golden:\n got: %s\nwant: %s", result.Report, golden)
	}
	// The golden must stay rich enough that dropping a public report field
	// fails: coverage, evidence coverage, and every inventory slice must be
	// present with non-empty evidence.
	var document map[string]any
	if err := json.Unmarshal(golden, &document); err != nil {
		t.Fatal(err)
	}
	if document["schemaVersion"] != "ssc-init.scan.v5" {
		t.Fatalf("golden schemaVersion=%v", document["schemaVersion"])
	}
	if _, ok := document["evidenceCoverage"].(map[string]any); !ok {
		t.Fatalf("golden is missing evidenceCoverage: %v", document["evidenceCoverage"])
	}
	inventoryDocument, ok := document["inventory"].(map[string]any)
	if !ok {
		t.Fatal("golden is missing the inventory object")
	}
	for _, field := range []string{"assets", "observations", "evidence", "relationships"} {
		values, ok := inventoryDocument[field].([]any)
		if !ok || len(values) == 0 {
			t.Fatalf("golden inventory field %q is missing or empty", field)
		}
	}
}

// TestContentEvidenceCLIBaselineAndStatusEndToEnd drives the real CLI command
// surface (scan --baseline --json, then status --json) against the real
// SQLite store and the full collector set, including the project-MCP
// follow-up and the evidence engine, inside an isolated home.
func TestContentEvidenceCLIBaselineAndStatusEndToEnd(t *testing.T) {
	home := copyOfficialFixtureHome(t)
	normalizeEvidenceFixtureModes(t, home)
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")

	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()
	roots, err := projects.ResolveRoots(home, []string{"$HOME/Projects"})
	if err != nil {
		t.Fatal(err)
	}
	environment := collector.Environment{
		Home: home, Platform: "darwin",
		Scope:  model.ScanScope{Platform: "darwin", ProjectRoots: projects.RootRefs(roots)},
		FS:     &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home},
		Runner: &matrixRunner{failOnCall: true}, Inspector: &matrixInspector{failOnCall: true},
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	service := scan.NewService(
		collector.Orchestrator{
			Timeout: time.Second, MaxConcurrent: 4,
			Collectors: []collector.Collector{agents.New(), ide.New(), projects.New(roots), packages.New()},
		},
		snapshots,
		environment.Now,
		func() string { return "00000000-0000-4000-8000-0000000000b1" },
		environment,
	)
	app := cli.App{BaselineScanner: service, StatusReader: snapshots}

	var scanStdout, scanStderr bytes.Buffer
	code := app.Run(context.Background(), []string{"scan", "--baseline", "--json"}, &scanStdout, &scanStderr)
	if code != 0 || scanStderr.Len() != 0 {
		t.Fatalf("scan exit=%d stderr=%q", code, scanStderr.String())
	}
	var baselineReport struct {
		SchemaVersion    string                  `json:"schemaVersion"`
		EvidenceCoverage *model.EvidenceCoverage `json:"evidenceCoverage"`
		Inventory        *model.Inventory        `json:"inventory"`
	}
	if err := json.Unmarshal(scanStdout.Bytes(), &baselineReport); err != nil {
		t.Fatalf("decode baseline report: %v\n%s", err, scanStdout.String())
	}
	if baselineReport.SchemaVersion != "ssc-init.scan.v5" || baselineReport.EvidenceCoverage == nil || baselineReport.Inventory == nil {
		t.Fatalf("CLI baseline contract=%+v", baselineReport)
	}
	if baselineReport.EvidenceCoverage.Status != model.CoverageComplete || len(baselineReport.Inventory.Evidence) == 0 {
		t.Fatalf("CLI baseline produced no complete evidence: %+v", baselineReport.EvidenceCoverage)
	}
	// The project-MCP follow-up must survive the full CLI path: the sample
	// project's semantic MCP evidence has to appear in the CLI report.
	foundProjectMCP := false
	for _, record := range baselineReport.Inventory.Evidence {
		if record.AssetID == "mcp:vscode:workspace" && record.Subject == model.EvidenceSubjectMCPDeclaration && record.Status == model.EvidenceComplete {
			foundProjectMCP = true
		}
	}
	if !foundProjectMCP {
		t.Fatal("CLI baseline lost project MCP semantic evidence")
	}

	var stdout, stderr bytes.Buffer
	code = app.Run(context.Background(), []string{"status", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("status exit=%d stderr=%q", code, stderr.String())
	}
	var status matrixStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, stdout.String())
	}
	if status.SchemaVersion != "ssc-init.status.v5" || !status.Initialized || status.InventorySchemaVersion != "ssc-init.scan.v5" || status.LegacyInventory {
		t.Fatalf("CLI status provenance=%+v", status)
	}
	if status.EvidenceCoverage == nil || !reflect.DeepEqual(*status.EvidenceCoverage, *baselineReport.EvidenceCoverage) {
		t.Fatalf("CLI status evidence coverage=%+v want=%+v", status.EvidenceCoverage, baselineReport.EvidenceCoverage)
	}
	if status.Inventory == nil || !reflect.DeepEqual(*status.Inventory, *baselineReport.Inventory) {
		t.Fatal("CLI status did not surface the persisted v3 inventory")
	}
	for _, output := range []string{scanStdout.String(), stdout.String()} {
		for _, forbidden := range []string{home, fixtureSecretSentinel} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("CLI output leaked %q", forbidden)
			}
		}
		if realHome := os.Getenv("HOME"); realHome != "" && realHome != home && strings.Contains(output, realHome) {
			t.Fatal("CLI output leaked the real home path")
		}
	}
}

func requireContentEvidence(t *testing.T, inventory model.Inventory, assetType, subject string) model.ContentEvidence {
	t.Helper()
	assetTypes := make(map[string]string, len(inventory.Assets))
	for _, asset := range inventory.Assets {
		assetTypes[asset.ID] = string(asset.Type)
	}
	var matches []model.ContentEvidence
	for _, record := range inventory.Evidence {
		if record.Subject == subject && assetTypes[record.AssetID] == assetType {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("evidence for %s/%s: matches=%d in %+v", assetType, subject, len(matches), inventory.Evidence)
	}
	return matches[0]
}

func assertEvidenceCoverageTerminal(t *testing.T, scanResult model.ScanResult, inventory model.Inventory) {
	t.Helper()
	evidenceByID := make(map[string]model.ContentEvidence, len(inventory.Evidence))
	for _, record := range inventory.Evidence {
		evidenceByID[record.ID] = record
	}
	if len(scanResult.EvidenceCoverage.Targets) != len(inventory.Evidence) {
		t.Fatalf("evidence target results=%d records=%d", len(scanResult.EvidenceCoverage.Targets), len(inventory.Evidence))
	}
	seen := map[string]struct{}{}
	for _, target := range scanResult.EvidenceCoverage.Targets {
		if _, duplicate := seen[target.EvidenceID]; duplicate {
			t.Fatalf("duplicate evidence target result for %q", target.EvidenceID)
		}
		seen[target.EvidenceID] = struct{}{}
		record, exists := evidenceByID[target.EvidenceID]
		if !exists || record.Status != target.Status || record.AssetID != target.AssetID || record.ObservationID != target.ObservationID {
			t.Fatalf("evidence target result %+v does not match record %+v", target, record)
		}
		switch target.Status {
		case model.EvidenceComplete, model.EvidencePartial, model.EvidenceOversize,
			model.EvidenceUnavailable, model.EvidenceUnsupported, model.EvidenceSkipped:
		default:
			t.Fatalf("non-terminal evidence target status %q", target.Status)
		}
	}
}

func assertEvidenceTargetStatus(t *testing.T, coverage model.EvidenceCoverage, evidenceID string, want model.EvidenceStatus) {
	t.Helper()
	for _, target := range coverage.Targets {
		if target.EvidenceID == evidenceID {
			if target.Status != want {
				t.Fatalf("evidence target %q status=%q want=%q", target.TargetID, target.Status, want)
			}
			return
		}
	}
	t.Fatalf("no terminal evidence target result references %q: %+v", evidenceID, coverage.Targets)
}

func sortMatrixChanges(changes []model.Change) {
	sort.Slice(changes, func(i, j int) bool {
		left, right := changes[i], changes[j]
		if left.Entity != right.Entity {
			return left.Entity < right.Entity
		}
		if left.EntityID != right.EntityID {
			return left.EntityID < right.EntityID
		}
		return left.Kind < right.Kind
	})
}

func reopenLatestSnapshot(t *testing.T, databasePath string) model.Snapshot {
	t.Helper()
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()
	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil || !initialized {
		t.Fatalf("reopen snapshot initialized=%v err=%v", initialized, err)
	}
	return snapshot
}

// normalizeEvidenceFixtureModes pins deterministic permission bits so tree
// manifest digests do not depend on the developer's checkout umask.
func normalizeEvidenceFixtureModes(t *testing.T, home string) {
	t.Helper()
	err := filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return os.Chmod(path, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func pipProbeFixture(t *testing.T, home string) (platform.Runner, platform.ExecutableInspector) {
	t.Helper()
	pythonPath := filepath.Join(home, "fake-bin", "python3")
	inspector := &matrixInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {
				Command: "python3", Path: pythonPath, LocationRef: "$HOME/fake-bin/python3",
				SHA256: strings.Repeat("a", 64), Mode: 0o755,
			},
		},
		errors: map[string]error{},
	}
	for _, capability := range packages.Capabilities() {
		if capability.Executable != "python3" {
			inspector.errors[capability.Executable] = exec.ErrNotFound
		}
	}
	runner := &matrixRunner{results: map[string]platform.CommandResult{
		matrixCommandKey(pythonPath, "-m", "pip", "list", "--format=json"): {
			Stdout: `[{"name":"demo-package","version":"1.0.0"}]`,
		},
	}, errors: map[string]error{}}
	return runner, inspector
}

func dockerProbeFixture(t *testing.T, home string) (platform.Runner, platform.ExecutableInspector) {
	t.Helper()
	dockerPath := filepath.Join(home, "fake-bin", "docker")
	inspector := &matrixInspector{
		evidence: map[string]platform.ExecutableEvidence{
			"docker": {
				Command: "docker", Path: dockerPath, LocationRef: "$HOME/fake-bin/docker",
				SHA256: strings.Repeat("b", 64), Mode: 0o755,
			},
		},
		errors: map[string]error{},
	}
	for _, capability := range packages.Capabilities() {
		if capability.Executable != "docker" {
			inspector.errors[capability.Executable] = exec.ErrNotFound
		}
	}
	runner := &matrixRunner{results: map[string]platform.CommandResult{
		matrixCommandKey(dockerPath, "image", "ls", "--no-trunc", "--format", "{{json .}}"): {
			Stdout: `{"Repository":"demo-image","Tag":"1.0.0","ID":"sha256:` + strings.Repeat("c", 64) + `"}` + "\n",
		},
	}, errors: map[string]error{}}
	return runner, inspector
}
