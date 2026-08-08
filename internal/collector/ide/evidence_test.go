package ide

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/evidence"
	"github.com/ssc-init/ssc-init/internal/inventory"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestVSCodeExtensionIssuesManifestEntrypointAndTreeTargets(t *testing.T) {
	home := fixtureVSCodeExtension(t, string(readIDEContentFixture(t, "vscode/package.json")))
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "fixture", "dist", "main.js"), string(readIDEContentFixture(t, "vscode/dist/main.js")))
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "fixture", "dist", "web.js"), string(readIDEContentFixture(t, "vscode/dist/web.js")))
	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"entrypoint-browser", "entrypoint-main", "manifest", "payload-tree"}
	if subjects := ideEvidenceSubjects(got.LocalEvidenceTargets); !reflect.DeepEqual(subjects, want) {
		t.Fatalf("subjects=%v want=%v", subjects, want)
	}
	assertIDERuntimeOnly(t, got, home)
	expected := append([]model.LocalEvidenceTarget(nil), got.LocalEvidenceTargets...)
	collection := collectIDEEvidence(t, home, got)
	assertCompleteIDEEvidence(t, got, expected, collection)
}

func TestJetBrainsPluginIssuesManifestAndExactPluginTree(t *testing.T) {
	home := t.TempDir()
	plugin := filepath.Join(home, "Library", "Application Support", "JetBrains", "IDEA", "plugins", "fixture")
	writeIDEFile(t, filepath.Join(plugin, "META-INF", "plugin.xml"), string(readIDEContentFixture(t, "jetbrains/META-INF/plugin.xml")))
	writeIDEFile(t, filepath.Join(plugin, "lib", "plugin.jar"), string(readIDEContentFixture(t, "jetbrains/lib/plugin.jar")))
	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if subjects := ideEvidenceSubjects(got.LocalEvidenceTargets); !reflect.DeepEqual(subjects, []string{"manifest", "payload-tree"}) {
		t.Fatalf("subjects=%v", subjects)
	}
	first := collectIDEEvidence(t, home, got)
	assertIDERecordSet(t, got, first, map[string]model.EvidenceStatus{
		model.EvidenceSubjectManifest:    model.EvidenceComplete,
		model.EvidenceSubjectPayloadTree: model.EvidenceComplete,
	})
	beforeManifest := ideDigest(t, first, model.EvidenceSubjectManifest)
	beforeTree := ideDigest(t, first, model.EvidenceSubjectPayloadTree)
	writeIDEFile(t, filepath.Join(plugin, "lib", "plugin.jar"), "jar-two")
	again, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	second := collectIDEEvidence(t, home, again)
	assertIDERecordSet(t, again, second, map[string]model.EvidenceStatus{
		model.EvidenceSubjectManifest:    model.EvidenceComplete,
		model.EvidenceSubjectPayloadTree: model.EvidenceComplete,
	})
	if digest := ideDigest(t, second, model.EvidenceSubjectManifest); digest != beforeManifest {
		t.Fatalf("manifest changed after jar mutation: before=%q after=%q", beforeManifest, digest)
	}
	if digest := ideDigest(t, second, model.EvidenceSubjectPayloadTree); digest == beforeTree {
		t.Fatal("plugin tree digest did not change after jar mutation")
	}
}

func TestVSCodeEntrypointMutationChangesOnlyMainAndTreeEvidence(t *testing.T) {
	home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/web.js"}`)
	base := filepath.Join(home, ".vscode", "extensions", "fixture")
	writeIDEFile(t, filepath.Join(base, "dist", "main.js"), "main-one")
	writeIDEFile(t, filepath.Join(base, "dist", "web.js"), "browser")
	firstResult, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	first := collectIDEEvidence(t, home, firstResult)
	assertIDERecordSet(t, firstResult, first, map[string]model.EvidenceStatus{
		model.EvidenceSubjectEntrypointBrowser: model.EvidenceComplete,
		model.EvidenceSubjectEntrypointMain:    model.EvidenceComplete,
		model.EvidenceSubjectManifest:          model.EvidenceComplete,
		model.EvidenceSubjectPayloadTree:       model.EvidenceComplete,
	})
	before := ideDigests(first)
	writeIDEFile(t, filepath.Join(base, "dist", "main.js"), "main-two")
	secondResult, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	second := collectIDEEvidence(t, home, secondResult)
	assertIDERecordSet(t, secondResult, second, map[string]model.EvidenceStatus{
		model.EvidenceSubjectEntrypointBrowser: model.EvidenceComplete,
		model.EvidenceSubjectEntrypointMain:    model.EvidenceComplete,
		model.EvidenceSubjectManifest:          model.EvidenceComplete,
		model.EvidenceSubjectPayloadTree:       model.EvidenceComplete,
	})
	after := ideDigests(second)
	if after[model.EvidenceSubjectManifest] != before[model.EvidenceSubjectManifest] || after[model.EvidenceSubjectEntrypointBrowser] != before[model.EvidenceSubjectEntrypointBrowser] {
		t.Fatalf("stable evidence changed: before=%v after=%v", before, after)
	}
	if after[model.EvidenceSubjectEntrypointMain] == before[model.EvidenceSubjectEntrypointMain] || after[model.EvidenceSubjectPayloadTree] == before[model.EvidenceSubjectPayloadTree] {
		t.Fatalf("main/tree evidence did not change: before=%v after=%v", before, after)
	}
}

func TestIDESecondaryBrowserInvalidPathsAreTerminalWithoutOutsideOpen(t *testing.T) {
	for _, entry := range []string{"../outside.js", "/private/outside.js", "dist/../../outside.js", "dist/\x00bad.js"} {
		t.Run(entry, func(t *testing.T) {
			home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":`+jsonQuote(entry)+`}`)
			writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "fixture", "dist", "main.js"), "main")
			outside := filepath.Join(home, ".vscode", "extensions", "outside.js")
			writeIDEFile(t, outside, "outside")
			recorder := &recordingIDEFileSystem{forbidden: outside}
			env := testutil.Environment(t, home)
			env.FS = recorder
			result, err := New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			quoted := jsonQuote(entry)
			if bytes.Contains(encoded, []byte(quoted[1:len(quoted)-1])) {
				t.Fatalf("secondary runtime entry leaked into JSON: entry=%q json=%s", entry, encoded)
			}
			collection := (evidence.Engine{}).Collect(context.Background(), env, inventory.Build([]model.CollectorResult{result}), []model.CollectorResult{result})
			if !ideCollectionHasError(collection, model.EvidenceSubjectEntrypointBrowser, "path_invalid") {
				t.Fatalf("entry=%q collection=%+v", entry, collection)
			}
			if recorder.forbiddenOpens != 0 {
				t.Fatalf("entry=%q outside opens=%d", entry, recorder.forbiddenOpens)
			}
		})
	}
}

func TestIDEWhitespaceEntrypointsUsePathInvalidSentinelWithoutOpeningSpacedFile(t *testing.T) {
	for _, test := range []struct {
		name, manifest, raw, subject, publicEntry string
		wantSubjects                              []string
	}{
		{
			name: "legacy-selected-main", raw: " main.js ", subject: model.EvidenceSubjectEntrypointMain, publicEntry: "main.js",
			manifest:     `{"name":"fixture","publisher":"acme","version":"1.0.0","main":" main.js "}`,
			wantSubjects: []string{"entrypoint-main", "manifest", "payload-tree"},
		},
		{
			name: "secondary-browser", raw: " web.js ", subject: model.EvidenceSubjectEntrypointBrowser, publicEntry: "main.js",
			manifest:     `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"main.js","browser":" web.js "}`,
			wantSubjects: []string{"entrypoint-browser", "entrypoint-main", "manifest", "payload-tree"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := fixtureVSCodeExtension(t, test.manifest)
			base := filepath.Join(home, ".vscode", "extensions", "fixture")
			if test.name == "secondary-browser" {
				writeIDEFile(t, filepath.Join(base, "main.js"), "main")
			}
			spaced := filepath.Join(base, test.raw)
			writeIDEFile(t, spaced, "must not be read")
			recorder := &recordingIDEFileSystem{forbidden: spaced}
			env := testutil.Environment(t, home)
			env.FS = recorder
			result, err := New().Collect(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Assets) != 1 || len(result.Observations) != 1 {
				t.Fatalf("assets=%+v observations=%+v", result.Assets, result.Observations)
			}
			if result.Observations[0].Metadata["entry_point"] != test.publicEntry {
				t.Fatalf("entry_point=%q want=%q", result.Observations[0].Metadata["entry_point"], test.publicEntry)
			}
			if subjects := ideEvidenceSubjects(result.LocalEvidenceTargets); !reflect.DeepEqual(subjects, test.wantSubjects) {
				t.Fatalf("subjects=%v want=%v", subjects, test.wantSubjects)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(test.raw)) {
				t.Fatalf("raw declaration leaked: raw=%q json=%s", test.raw, encoded)
			}
			entryOnly := result
			entryOnly.LocalEvidenceTargets = nil
			for _, target := range result.LocalEvidenceTargets {
				if target.Subject == test.subject {
					entryOnly.LocalEvidenceTargets = append(entryOnly.LocalEvidenceTargets, target)
				}
			}
			collection := (evidence.Engine{}).Collect(context.Background(), env, inventory.Build([]model.CollectorResult{result}), []model.CollectorResult{entryOnly})
			assertIDERecordSet(t, result, collection, map[string]model.EvidenceStatus{test.subject: model.EvidenceUnavailable})
			assertIDEOnlyError(t, collection, test.subject, "path_invalid")
			if recorder.forbiddenOpens != 0 {
				t.Fatalf("spaced file opens=%d collection=%+v", recorder.forbiddenOpens, collection)
			}
		})
	}
}

func TestIDELegacyRejectedSelectedEntrypointEmitsNoPublicRecords(t *testing.T) {
	for _, entry := range []string{"dist/\x00bad.js", "dist/\x01bad.js", strings.Repeat("x", maxMetadataLength+1)} {
		t.Run(entry[:min(len(entry), 16)], func(t *testing.T) {
			home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":`+jsonQuote(entry)+`}`)
			result, err := New().Collect(context.Background(), testutil.Environment(t, home))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Assets) != 0 || len(result.Observations) != 0 || len(result.LocalEvidenceTargets) != 0 {
				t.Fatalf("entry=%q assets=%+v observations=%+v evidence=%+v", entry, result.Assets, result.Observations, result.LocalEvidenceTargets)
			}
			target := assertIDETarget(t, result, "ide.vscode.extensions", "", model.TargetPartial, 0, 0)
			if len(target.Errors) != 1 || target.Errors[0].Code != "manifest_invalid" {
				t.Fatalf("entry=%q target=%+v", entry, target)
			}
		})
	}
}

func TestIDEEntrypointIntermediateSymlinkAndNonregularAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name, want string
		setup      func(t *testing.T, base string)
	}{
		{name: "intermediate-symlink", want: "symlink_rejected", setup: func(t *testing.T, base string) {
			writeIDEFile(t, filepath.Join(base, "real", "main.js"), "main")
			if err := os.Symlink("real", filepath.Join(base, "dist")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonregular", want: "symlink_rejected", setup: func(t *testing.T, base string) {
			if err := os.MkdirAll(filepath.Join(base, "dist", "main.js"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
			test.setup(t, filepath.Join(home, ".vscode", "extensions", "fixture"))
			result, err := New().Collect(context.Background(), testutil.Environment(t, home))
			if err != nil {
				t.Fatal(err)
			}
			if !ideCollectionHasError(collectIDEEvidence(t, home, result), model.EvidenceSubjectEntrypointMain, test.want) {
				t.Fatalf("expected %s", test.want)
			}
		})
	}
}

func TestIDEEveryVSCodeTargetRejectsPostCollectionManifestMutation(t *testing.T) {
	home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js","browser":"dist/web.js"}`)
	base := filepath.Join(home, ".vscode", "extensions", "fixture")
	writeIDEFile(t, filepath.Join(base, "dist", "main.js"), "main")
	writeIDEFile(t, filepath.Join(base, "dist", "web.js"), "browser")
	result, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	writeIDEFile(t, filepath.Join(base, "package.json"), `{"name":"fixture","publisher":"acme","version":"2.0.0","main":"dist/main.js","browser":"dist/web.js"}`)
	collection := collectIDEEvidence(t, home, result)
	assertIDERecordSet(t, result, collection, map[string]model.EvidenceStatus{
		model.EvidenceSubjectEntrypointBrowser: model.EvidenceUnavailable,
		model.EvidenceSubjectEntrypointMain:    model.EvidenceUnavailable,
		model.EvidenceSubjectManifest:          model.EvidenceUnavailable,
		model.EvidenceSubjectPayloadTree:       model.EvidenceUnavailable,
	})
	for _, subject := range []string{model.EvidenceSubjectEntrypointBrowser, model.EvidenceSubjectEntrypointMain, model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree} {
		assertIDEOnlyError(t, collection, subject, "identity_changed")
	}
}

func TestIDEEveryJetBrainsTargetRejectsPostCollectionManifestMutation(t *testing.T) {
	home := t.TempDir()
	plugin := filepath.Join(home, "Library", "Application Support", "JetBrains", "IDEA", "plugins", "fixture")
	manifest := filepath.Join(plugin, "META-INF", "plugin.xml")
	writeIDEFile(t, manifest, `<idea-plugin><id>org.example.fixture</id><name>Fixture</name><version>1.0.0</version></idea-plugin>`)
	writeIDEFile(t, filepath.Join(plugin, "lib", "plugin.jar"), "jar")
	result, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	writeIDEFile(t, manifest, `<idea-plugin><id>org.example.fixture</id><name>Fixture</name><version>2.0.0</version></idea-plugin>`)
	collection := collectIDEEvidence(t, home, result)
	assertIDERecordSet(t, result, collection, map[string]model.EvidenceStatus{
		model.EvidenceSubjectManifest:    model.EvidenceUnavailable,
		model.EvidenceSubjectPayloadTree: model.EvidenceUnavailable,
	})
	for _, subject := range []string{model.EvidenceSubjectManifest, model.EvidenceSubjectPayloadTree} {
		assertIDEOnlyError(t, collection, subject, "identity_changed")
	}
}

func TestIDEPayloadTreeExcludesExtensionSiblings(t *testing.T) {
	home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
	base := filepath.Join(home, ".vscode", "extensions", "fixture")
	writeIDEFile(t, filepath.Join(base, "dist", "main.js"), "main")
	firstResult, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	before := ideDigest(t, collectIDEEvidence(t, home, firstResult), model.EvidenceSubjectPayloadTree)
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "other-extension.txt"), "sibling")
	secondResult, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if after := ideDigest(t, collectIDEEvidence(t, home, secondResult), model.EvidenceSubjectPayloadTree); after != before {
		t.Fatalf("sibling changed payload tree: before=%q after=%q", before, after)
	}
}

func TestIDEEvidenceSupportsDistinctObservationsWithSharedCatalogTarget(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"fixture-a", "fixture-b"} {
		base := filepath.Join(home, ".vscode", "extensions", name)
		writeIDEFile(t, filepath.Join(base, "package.json"), `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
		writeIDEFile(t, filepath.Join(base, "dist", "main.js"), name)
	}
	result, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.LocalEvidenceTargets) != 6 {
		t.Fatalf("targets=%+v", result.LocalEvidenceTargets)
	}
	collection := collectIDEEvidence(t, home, result)
	if len(collection.Evidence) != 6 || collection.Coverage.Status != model.CoverageComplete {
		t.Fatalf("collection=%+v", collection)
	}
	observations := make(map[string]struct{})
	for _, terminal := range collection.Coverage.Targets {
		if terminal.TargetID == "ide.vscode.extensions.manifest" {
			observations[terminal.ObservationID] = struct{}{}
		}
	}
	if len(observations) != 2 {
		t.Fatalf("manifest bindings=%+v", collection.Coverage.Targets)
	}
}

func TestIDEEvidenceEngineClearsRuntimeTargetsAndIssuer(t *testing.T) {
	home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "fixture", "dist", "main.js"), "main")
	result, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	results := []model.CollectorResult{result}
	backing := results[0].LocalEvidenceTargets[:cap(results[0].LocalEvidenceTargets)]
	_ = (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory.Build(results), results)
	if results[0].LocalEvidenceTargets != nil || results[0].LocalEvidenceIssuer != nil {
		t.Fatalf("runtime state survived cleanup: %+v", results[0])
	}
	for index, target := range backing {
		if target != (model.LocalEvidenceTarget{}) {
			t.Fatalf("runtime target slot %d survived cleanup: %+v", index, target)
		}
	}
}

func TestIDEEntrypointSymlinkAndMissingAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name, setup, want string
	}{
		{name: "final-symlink", setup: "symlink", want: "symlink_rejected"},
		{name: "missing", want: "read_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := fixtureVSCodeExtension(t, `{"name":"fixture","publisher":"acme","version":"1.0.0","main":"dist/main.js"}`)
			base := filepath.Join(home, ".vscode", "extensions", "fixture")
			if test.setup == "symlink" {
				writeIDEFile(t, filepath.Join(base, "outside.js"), "outside")
				if err := os.MkdirAll(filepath.Join(base, "dist"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../outside.js", filepath.Join(base, "dist", "main.js")); err != nil {
					t.Fatal(err)
				}
			}
			result, err := New().Collect(context.Background(), testutil.Environment(t, home))
			if err != nil {
				t.Fatal(err)
			}
			if !ideCollectionHasError(collectIDEEvidence(t, home, result), model.EvidenceSubjectEntrypointMain, test.want) {
				t.Fatalf("expected %s", test.want)
			}
		})
	}
}

func fixtureVSCodeExtension(t *testing.T, manifest string) string {
	t.Helper()
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "fixture", "package.json"), manifest)
	return home
}

func readIDEContentFixture(t *testing.T, relative string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "content", filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func jsonQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func ideEvidenceSubjects(targets []model.LocalEvidenceTarget) []string {
	got := make([]string, 0, len(targets))
	for _, target := range targets {
		got = append(got, target.Subject)
	}
	sort.Strings(got)
	return got
}

func collectIDEEvidence(t *testing.T, home string, result model.CollectorResult) evidence.Collection {
	t.Helper()
	return (evidence.Engine{}).Collect(context.Background(), testutil.Environment(t, home), inventory.Build([]model.CollectorResult{result}), []model.CollectorResult{result})
}

func assertCompleteIDEEvidence(t *testing.T, result model.CollectorResult, expected []model.LocalEvidenceTarget, collection evidence.Collection) {
	t.Helper()
	if collection.Coverage.Status != model.CoverageComplete || len(collection.Evidence) != len(result.LocalEvidenceTargets) || len(collection.Coverage.Targets) != len(collection.Evidence) {
		t.Fatalf("collection=%+v targets=%+v", collection, result.LocalEvidenceTargets)
	}
	observations := make(map[string]string, len(result.Observations))
	for _, observation := range result.Observations {
		observations[observation.ID] = observation.AssetID
	}
	targets := make(map[string]model.LocalEvidenceTarget, len(expected))
	for _, target := range expected {
		targets[target.TargetID] = target
	}
	for index, record := range collection.Evidence {
		if record.Status != model.EvidenceComplete || record.Algorithm != "sha256" || len(record.Digest) != 64 || record.AssetID == "" || record.ObservationID == "" || record.ID == "" {
			t.Fatalf("record=%+v", record)
		}
		if observations[record.ObservationID] != record.AssetID {
			t.Fatalf("record is not exactly bound to collector observation: %+v observations=%+v", record, observations)
		}
		terminal := collection.Coverage.Targets[index]
		target, ok := targets[terminal.TargetID]
		if !ok || target.AssetID != record.AssetID || target.ObservationID != record.ObservationID || target.Kind != record.Kind || target.Subject != record.Subject {
			t.Fatalf("terminal=%+v record=%+v target=%+v", terminal, record, target)
		}
		if terminal.AssetID != record.AssetID || terminal.ObservationID != record.ObservationID || terminal.EvidenceID != record.ID || terminal.Status != record.Status {
			t.Fatalf("terminal=%+v record=%+v", terminal, record)
		}
	}
}

func assertIDERecordSet(t *testing.T, result model.CollectorResult, collection evidence.Collection, want map[string]model.EvidenceStatus) {
	t.Helper()
	if len(collection.Evidence) != len(want) || len(collection.Coverage.Targets) != len(want) {
		t.Fatalf("evidence=%+v terminals=%+v want=%+v", collection.Evidence, collection.Coverage.Targets, want)
	}
	observations := make(map[string]string, len(result.Observations))
	for _, observation := range result.Observations {
		observations[observation.ID] = observation.AssetID
	}
	seen := make(map[string]struct{}, len(want))
	wantCoverage := model.CoverageComplete
	for index, record := range collection.Evidence {
		status, ok := want[record.Subject]
		if !ok || record.Status != status || observations[record.ObservationID] != record.AssetID {
			t.Fatalf("record=%+v observations=%+v want=%+v", record, observations, want)
		}
		if _, duplicate := seen[record.Subject]; duplicate {
			t.Fatalf("duplicate subject %q", record.Subject)
		}
		seen[record.Subject] = struct{}{}
		terminal := collection.Coverage.Targets[index]
		if terminal.AssetID != record.AssetID || terminal.ObservationID != record.ObservationID || terminal.EvidenceID != record.ID || terminal.Status != record.Status {
			t.Fatalf("terminal=%+v record=%+v", terminal, record)
		}
		if status == model.EvidenceComplete && (record.Algorithm != "sha256" || len(record.Digest) != 64) {
			t.Fatalf("complete record=%+v", record)
		}
		if status != model.EvidenceComplete {
			wantCoverage = model.CoveragePartial
		}
	}
	if collection.Coverage.Status != wantCoverage || len(collection.Coverage.Errors) != 0 {
		t.Fatalf("coverage=%+v wantStatus=%q", collection.Coverage, wantCoverage)
	}
}

func assertIDEOnlyError(t *testing.T, collection evidence.Collection, subject, code string) {
	t.Helper()
	for index, record := range collection.Evidence {
		if record.Subject != subject {
			continue
		}
		if len(record.Errors) != 1 || record.Errors[0].Code != code {
			t.Fatalf("subject=%q record=%+v", subject, record)
		}
		terminal := collection.Coverage.Targets[index]
		if len(terminal.Errors) != 1 || terminal.Errors[0].Code != code {
			t.Fatalf("subject=%q terminal=%+v", subject, terminal)
		}
		return
	}
	t.Fatalf("missing subject=%q collection=%+v", subject, collection)
}

func ideCollectionHasError(collection evidence.Collection, subject, code string) bool {
	for _, record := range collection.Evidence {
		if record.Subject != subject {
			continue
		}
		for _, issue := range record.Errors {
			if issue.Code == code {
				return true
			}
		}
	}
	return false
}

func ideDigests(collection evidence.Collection) map[string]string {
	result := make(map[string]string, len(collection.Evidence))
	for _, record := range collection.Evidence {
		result[record.Subject] = record.Digest
	}
	return result
}

func ideDigest(t *testing.T, collection evidence.Collection, subject string) string {
	t.Helper()
	if digest := ideDigests(collection)[subject]; digest != "" {
		return digest
	}
	t.Fatalf("missing %s in %+v", subject, collection)
	return ""
}

func assertIDERuntimeOnly(t *testing.T, result model.CollectorResult, home string) {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{home, "payload-tree", "entrypoint-main", "entrypoint-browser"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("runtime evidence leaked %q in %s", forbidden, encoded)
		}
	}
}

type recordingIDEFileSystem struct {
	platform.OSFileSystem
	forbidden      string
	forbiddenOpens int
}

func (f *recordingIDEFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &recordingIDERoot{RootedDirectory: root, path: name, recorder: f}, nil
}

type recordingIDERoot struct {
	platform.RootedDirectory
	path     string
	recorder *recordingIDEFileSystem
}

func (r *recordingIDERoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &recordingIDERoot{RootedDirectory: child, path: filepath.Join(r.path, name), recorder: r.recorder}, nil
}

func (r *recordingIDERoot) Open(name string) (platform.RootedFile, error) {
	if filepath.Clean(filepath.Join(r.path, name)) == filepath.Clean(r.recorder.forbidden) {
		r.recorder.forbiddenOpens++
	}
	return r.RootedDirectory.Open(name)
}
