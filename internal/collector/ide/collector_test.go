package ide

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/inventory"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/store"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestIDECatalogReportsMissingEmptyAndUnsupportedTargets(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".vscode", "extensions"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.TargetStatus{
		"ide.cursor.extensions":          model.TargetNotPresent,
		"ide.custom-roots":               model.TargetUnsupported,
		"ide.dev-container":              model.TargetUnsupported,
		"ide.environment-relocated":      model.TargetUnsupported,
		"ide.jetbrains.plugins":          model.TargetNotPresent,
		"ide.remote-ssh":                 model.TargetUnsupported,
		"ide.remote-wsl":                 model.TargetUnsupported,
		"ide.service-api":                model.TargetUnsupported,
		"ide.vscode-insiders.extensions": model.TargetNotPresent,
		"ide.vscode-oss.extensions":      model.TargetNotPresent,
		"ide.vscode.extensions":          model.TargetComplete,
		"ide.windsurf.extensions":        model.TargetNotPresent,
	}
	assertIDECoverage(t, got, want)
	if got.Status != model.CoveragePartial {
		t.Fatalf("status=%q targets=%+v", got.Status, got.Targets)
	}
}

func TestIDECatalogJetBrainsRootWithOnlyNonProductEntriesIsComplete(t *testing.T) {
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", ".DS_Store"), "ignored")

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	assertIDETarget(t, got, "ide.jetbrains.plugins", "", model.TargetComplete, 0, 0)
}

func TestSameVSCodeExtensionAtTwoLocationsPreservesBothObservations(t *testing.T) {
	home := t.TempDir()
	writeVSCodeManifest(t, home, ".vscode/extensions/demo-a/package.json", "pub", "demo", "1.0.0")
	writeVSCodeManifest(t, home, ".vscode/extensions/demo-b/package.json", "pub", "demo", "1.0.0")

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	assetID := "ide-extension:vscode:pub.demo@1.0.0"
	if countIDEAssets(got.Assets, assetID) != 2 {
		t.Fatalf("assets=%+v", got.Assets)
	}
	if countIDEObservations(got.Observations, assetID) != 2 {
		t.Fatalf("observations=%+v", got.Observations)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetComplete, 2, 2)
	for _, asset := range got.Assets {
		if asset.ID == assetID && (asset.Path != "" || asset.Source != "vscode" || !reflect.DeepEqual(asset.Metadata, map[string]string{"publisher": "pub"})) {
			t.Fatalf("canonical asset retained observed fields: %+v", asset)
		}
	}

	normalized := inventory.Build([]model.CollectorResult{got})
	if countIDEAssets(normalized.Assets, assetID) != 1 || countIDEObservations(normalized.Observations, assetID) != 2 {
		t.Fatalf("inventory=%+v", normalized)
	}
	assertIDECountsMatchEmitted(t, got)
}

func TestSameVSCodeExtensionAcrossRootsAndVersionsPreservesEveryOccurrence(t *testing.T) {
	home := t.TempDir()
	writeVSCodeManifest(t, home, ".vscode/extensions/stable/package.json", "pub", "demo", "1.0.0")
	writeVSCodeManifest(t, home, ".vscode/extensions/next/package.json", "pub", "demo", "2.0.0")
	writeVSCodeManifest(t, home, ".cursor/extensions/stable/package.json", "pub", "demo", "1.0.0")

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]int{
		"ide-extension:vscode:pub.demo@1.0.0": 1,
		"ide-extension:vscode:pub.demo@2.0.0": 1,
		"ide-extension:cursor:pub.demo@1.0.0": 1,
	} {
		if countIDEAssets(got.Assets, id) != want || countIDEObservations(got.Observations, id) != want {
			t.Fatalf("id=%q assets=%+v observations=%+v", id, got.Assets, got.Observations)
		}
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetComplete, 2, 2)
	assertIDETarget(t, got, "ide.cursor.extensions", "", model.TargetComplete, 1, 1)
	assertIDECountsMatchEmitted(t, got)
}

func TestIDEJetBrainsProductInstancesPreserveSamePluginObservations(t *testing.T) {
	home := t.TempDir()
	for _, product := range []string{"IdeaIC2025.1", "PyCharm2025.1"} {
		writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", product, "plugins", "demo", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.demo</id><name>Demo</name><version>1.0.0</version></idea-plugin>`)
	}

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	assetID := "ide-extension:jetbrains:org.example.demo@1.0.0"
	if countIDEAssets(got.Assets, assetID) != 2 || countIDEObservations(got.Observations, assetID) != 2 {
		t.Fatalf("assets=%+v observations=%+v", got.Assets, got.Observations)
	}
	for _, product := range []string{"IdeaIC2025.1", "PyCharm2025.1"} {
		assertIDETarget(t, got, "ide.jetbrains.plugins", product, model.TargetComplete, 1, 1)
		observation := observationForIDEProduct(t, got.Observations, assetID, product)
		wantLocation := "$HOME/Library/Application Support/JetBrains/" + product + "/plugins/demo"
		if observation.LocationRef != wantLocation || observation.Source != "ide.jetbrains.plugins" || observation.Metadata["manifest_path"] != "demo/META-INF/plugin.xml" || observation.Metadata["source_target"] != "ide.jetbrains.plugins" {
			t.Fatalf("observation=%+v", observation)
		}
	}
	normalized := inventory.Build([]model.CollectorResult{got})
	if countIDEAssets(normalized.Assets, assetID) != 1 || countIDEObservations(normalized.Observations, assetID) != 2 {
		t.Fatalf("inventory=%+v", normalized)
	}
	assertIDECountsMatchEmitted(t, got)
}

func TestIDEJetBrainsMalformedSiblingIsLocalizedToProductInstance(t *testing.T) {
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "Alpha", "plugins", "bad", "META-INF", "plugin.xml"), `<idea-plugin><id>broken`)
	writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "Zulu", "plugins", "good", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.good</id><name>Good</name><version>1.0.0</version></idea-plugin>`)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Alpha", model.TargetPartial, 0, 0)
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Zulu", model.TargetComplete, 1, 1)
	testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.good@1.0.0")
	assertIDECountsMatchEmitted(t, got)
}

func TestIDEIdentityQuarantinesCredentialShapedPublisherAndName(t *testing.T) {
	home := t.TempDir()
	publisherSecret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nameSecret := "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
	writeVSCodeManifest(t, home, ".vscode/extensions/good/package.json", "acme", "good", "1.0.0")
	writeVSCodeManifest(t, home, ".vscode/extensions/bad-publisher/package.json", publisherSecret, "bad", "1.0.0")
	writeVSCodeManifest(t, home, ".vscode/extensions/bad-name/package.json", "acme", nameSecret, "1.0.0")

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.good@1.0.0")
	target := assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
	if len(target.Errors) != 2 {
		t.Fatalf("target=%+v", target)
	}
	for _, issue := range target.Errors {
		if issue.Code != "identity_rejected" || issue.Path != "" {
			t.Fatalf("issue=%+v", issue)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{publisherSecret, nameSecret, home} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("rejected identity leaked: %s", encoded)
		}
	}
}

func TestCollectorFindsVSCodeAndJetBrainsExtensions(t *testing.T) {
	got, err := New().Collect(context.Background(), testutil.Environment(t, "../../../testdata/home"))
	if err != nil {
		t.Fatal(err)
	}

	vscode := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.safe@1.2.3")
	if vscode.Path != "" || vscode.Source != "vscode" || !reflect.DeepEqual(vscode.Metadata, map[string]string{"publisher": "acme"}) {
		t.Fatalf("vscode asset=%+v", vscode)
	}
	vscodeObservation := observationForIDEAsset(t, got.Observations, vscode.ID)
	if vscodeObservation.Metadata["entry_point"] != "dist/extension.js" || vscodeObservation.Metadata["activation_events"] != "onCommand:acme.safe.run" || vscodeObservation.Metadata["capabilities"] != "commands" {
		t.Fatalf("vscode observation=%+v", vscodeObservation)
	}
	jetbrains := testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.sample@1.0.0")
	if jetbrains.Name != "Sample Plugin" || jetbrains.Path != "" || jetbrains.Source != "jetbrains" || !reflect.DeepEqual(jetbrains.Metadata, map[string]string{"plugin_id": "org.example.sample", "publisher": "org.example"}) {
		t.Fatalf("jetbrains asset=%+v", jetbrains)
	}
}

func TestCollectorRejectsDuplicateManifestIdentityKeysAndKeepsValidSibling(t *testing.T) {
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "good", "package.json"), `{
		"name":"good","publisher":"acme","version":"1.0.0"
	}`)
	marker := "duplicate-publisher-secret-marker"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "bad", "package.json"), `{
		"name":"bad","publisher":"acme","publisher":"`+marker+`","version":"1.0.0"
	}`)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 1 || strings.Contains(string(encoded), marker) {
		t.Fatalf("result=%s", encoded)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
}

func TestCollectorKeepsValidSiblingWhenManifestsAreMalformedOrOversized(t *testing.T) {
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "good", "package.json"), `{"name":"good","publisher":"acme","version":"1.0.0"}`)
	marker := "malformed-manifest-secret-marker"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "malformed", "package.json"), `{"name":"`+marker+`"`)
	writeIDEBytes(t, filepath.Join(home, ".vscode", "extensions", "oversized", "package.json"), bytes.Repeat([]byte("x"), maxManifestBytes+1))

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 1 || len(got.Errors) != 2 {
		t.Fatalf("result=%s", encoded)
	}
	wantCodes := []string{"manifest_invalid", "manifest_oversized"}
	gotCodes := []string{got.Errors[0].Code, got.Errors[1].Code}
	if !reflect.DeepEqual(gotCodes, wantCodes) {
		t.Fatalf("codes=%v want=%v", gotCodes, wantCodes)
	}
	for _, sensitive := range []string{home, marker, "invalid character"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("sensitive detail persisted: %s", encoded)
		}
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
}

func TestCollectorScansOnlyDirectChildrenOfFixedVSCodeRoots(t *testing.T) {
	home := t.TempDir()
	for _, target := range []struct {
		relative string
		host     string
	}{
		{relative: filepath.Join(".vscode", "extensions"), host: "vscode"},
		{relative: filepath.Join(".vscode-insiders", "extensions"), host: "vscode-insiders"},
		{relative: filepath.Join(".cursor", "extensions"), host: "cursor"},
		{relative: filepath.Join(".windsurf", "extensions"), host: "windsurf"},
		{relative: filepath.Join(".vscode-oss", "extensions"), host: "vscode-oss"},
	} {
		writeIDEFile(t, filepath.Join(home, target.relative, target.host, "package.json"), `{"name":"safe","publisher":"acme","version":"1.0.0"}`)
	}
	marker := "nested-extension-marker"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "wrapper", "nested", "package.json"), `{"name":"`+marker+`","publisher":"acme","version":"9.9.9"}`)
	writeIDEFile(t, filepath.Join(home, "unrelated", "extensions", "outside", "package.json"), `{"name":"outside","publisher":"acme","version":"9.9.9"}`)
	env := testutil.Environment(t, home)
	runner := &testutil.FakeRunner{}
	env.Runner = runner

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"vscode", "vscode-insiders", "cursor", "windsurf", "vscode-oss"} {
		testutil.AssertAsset(t, got.Assets, "ide-extension:"+host+":acme.safe@1.0.0")
	}
	for _, targetID := range []string{"ide.vscode-insiders.extensions", "ide.cursor.extensions", "ide.windsurf.extensions", "ide.vscode-oss.extensions"} {
		assertIDETarget(t, got, targetID, "", model.TargetComplete, 1, 1)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 5 || strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "outside") || len(runner.Calls) != 0 {
		t.Fatalf("result=%s runner_calls=%v", encoded, runner.Calls)
	}
	for index := 1; index < len(got.Assets); index++ {
		if got.Assets[index-1].ID > got.Assets[index].ID {
			t.Fatalf("assets not sorted: %+v", got.Assets)
		}
	}
}

func TestCollectorFailsClosedWithoutRootedFilesystem(t *testing.T) {
	home := t.TempDir()
	marker := "path-fallback-extension-marker"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", marker, "package.json"), `{"name":"safe","publisher":"acme","version":"1.0.0"}`)
	env := testutil.Environment(t, home)
	env.FS = pathOnlyIDEFileSystem{FileSystem: platform.OSFileSystem{}}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 0 || len(got.Errors) != 1 || strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), home) {
		t.Fatalf("result=%s", encoded)
	}
	for _, targetID := range []string{"ide.vscode.extensions", "ide.vscode-insiders.extensions", "ide.cursor.extensions", "ide.windsurf.extensions", "ide.vscode-oss.extensions", "ide.jetbrains.plugins"} {
		assertIDETarget(t, got, targetID, "", model.TargetUnavailable, 0, 0)
	}
}

func TestCollectorRejectsSymlinkedRootsAndEntries(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	marker := "symlinked-extension-secret-marker"
	writeIDEFile(t, filepath.Join(outside, "root", marker, "package.json"), `{"name":"outside","publisher":"acme","version":"9.9.9"}`)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "root"), filepath.Join(home, ".cursor", "extensions")); err != nil {
		t.Fatal(err)
	}
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "good", "package.json"), `{"name":"good","publisher":"acme","version":"1.0.0"}`)
	if err := os.Symlink(filepath.Join(outside, "root", marker), filepath.Join(home, ".vscode", "extensions", "linked")); err != nil {
		t.Fatal(err)
	}

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 1 || len(got.Errors) != 2 || strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), outside) {
		t.Fatalf("result=%s", encoded)
	}
	assertIDETarget(t, got, "ide.cursor.extensions", "", model.TargetPartial, 0, 0)
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
}

func TestCollectorRejectsManifestIdentitySwap(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".vscode", "extensions", "swapped", "package.json")
	writeIDEFile(t, target, `{"name":"expected","publisher":"acme","version":"1.0.0"}`)
	marker := "identity-swap-secret-marker"
	replacement := filepath.Join(home, "replacement.json")
	writeIDEFile(t, replacement, `{"name":"`+marker+`","publisher":"acme","version":"9.9.9"}`)
	env := testutil.Environment(t, home)
	env.FS = ideSwapFileSystem{OSFileSystem: platform.OSFileSystem{}, targetDirectory: filepath.Dir(target), replacement: replacement}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 0 || len(got.Errors) != 1 || strings.Contains(string(encoded), marker) {
		t.Fatalf("result=%s", encoded)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 0, 0)
}

func TestIDEIdentityRejectsExtensionDirectorySwapAfterEnumeration(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".vscode", "extensions", "swapped")
	writeIDEFile(t, filepath.Join(target, "package.json"), `{"name":"expected","publisher":"acme","version":"1.0.0"}`)
	marker := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	replacement := filepath.Join(home, "replacement-extension")
	writeIDEFile(t, filepath.Join(replacement, "package.json"), `{"name":"replacement","publisher":"`+marker+`","version":"9.9.9"}`)

	ideCollector := New().(*ideCollector)
	swapped := false
	ideCollector.beforeOpen = func(targetID, relative string) {
		if swapped || targetID != "ide.vscode.extensions" || relative != "swapped" {
			return
		}
		swapped = true
		if err := os.Rename(target, target+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, target); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ideCollector.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 0, 0)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatalf("replacement leaked: %s", encoded)
	}
}

func TestIDEManifestRejectsSameSizeMutationAfterReadAndKeepsSafeSibling(t *testing.T) {
	original := `{"name":"bad1","publisher":"acme","version":"1.0.0"}`
	replacement := `{"name":"evil","publisher":"acme","version":"1.0.0"}`
	if len(original) != len(replacement) {
		t.Fatal("same-size mutation fixture is not the same size")
	}
	assertIDEPostReadManifestMutation(t, original, "manifest_changed", func(t *testing.T, path string) {
		if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
			t.Fatal(err)
		}
		changed := time.Unix(200, 0)
		if err := os.Chtimes(path, changed, changed); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIDEManifestRejectsBoundedGrowthAfterReadAndKeepsSafeSibling(t *testing.T) {
	original := `{"name":"bad","publisher":"acme","version":"1.0.0"}`
	assertIDEPostReadManifestMutation(t, original, "manifest_changed", func(t *testing.T, path string) {
		if err := os.WriteFile(path, append([]byte(original), ' '), 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIDEManifestRejectsOversizeGrowthAfterReadAndKeepsSafeSibling(t *testing.T) {
	original := `{"name":"bad","publisher":"acme","version":"1.0.0"}`
	assertIDEPostReadManifestMutation(t, original, "manifest_oversized", func(t *testing.T, path string) {
		if err := os.Truncate(path, maxManifestBytes+1); err != nil {
			t.Fatal(err)
		}
	})
}

func assertIDEPostReadManifestMutation(t *testing.T, original, wantCode string, mutate func(*testing.T, string)) {
	t.Helper()
	home := t.TempDir()
	badPath := filepath.Join(home, ".vscode", "extensions", "bad", "package.json")
	writeIDEFile(t, badPath, original)
	stable := time.Unix(100, 0)
	if err := os.Chtimes(badPath, stable, stable); err != nil {
		t.Fatal(err)
	}
	writeVSCodeManifest(t, home, ".vscode/extensions/zz-safe/package.json", "acme", "safe", "1.0.0")

	ideCollector := New().(*ideCollector)
	mutated := false
	ideCollector.afterManifestRead = func(targetID, relative string) {
		if mutated || targetID != "ide.vscode.extensions" || relative != "bad/package.json" {
			return
		}
		mutated = true
		mutate(t, badPath)
	}
	got, err := ideCollector.Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	if !mutated {
		t.Fatal("post-read mutation seam was not reached")
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.safe@1.0.0")
	if len(got.Assets) != 1 || len(got.Observations) != 1 {
		t.Fatalf("mutated manifest escaped quarantine: assets=%+v observations=%+v", got.Assets, got.Observations)
	}
	target := assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
	for _, issue := range target.Errors {
		if issue.Code == wantCode {
			return
		}
	}
	t.Fatalf("missing issue %q: %+v", wantCode, target.Errors)
}

func TestCollectorRedactsHomeAndDoesNotPersistUnselectedManifestData(t *testing.T) {
	home := t.TempDir()
	marker := "credential-value-marker"
	manifest := fmt.Sprintf(`{
		"name":"safe","publisher":"acme","version":"1.0.0",
		"main":%q,"activationEvents":["onStartupFinished"],
		"capabilities":{"virtualWorkspaces":{}},
		"contributes":{"commands":[{"command":"safe.run","title":%q}]},
		"token":%q
	}`, filepath.Join(home, "extension.js"), marker, marker)
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "safe", "package.json"), manifest)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.safe@1.0.0")
	observation := observationForIDEAsset(t, got.Observations, asset.ID)
	if observation.Metadata["entry_point"] != "$HOME/extension.js" || observation.Metadata["capabilities"] != "commands\x1fvirtualWorkspaces" {
		t.Fatalf("observation=%+v", observation)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), home) {
		t.Fatalf("sensitive detail persisted: %s", encoded)
	}
}

func TestCollectorSanitizesSelectedVSCodeManifestMetadata(t *testing.T) {
	home := t.TempDir()
	markers := []string{
		"main-user-marker", "main-password-marker", "main-token-marker", "main-fragment-marker",
		"browser-user-marker", "browser-password-marker", "browser-secret-marker", "browser-fragment-marker",
		"authorization-marker", "env-assignment-marker", "capability-api-key-marker", "capability-header-marker",
	}
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "main", "package.json"), `{
		"name":"main","publisher":"acme","version":"1.0.0",
		"main":"https://main-user-marker:main-password-marker@example.test/extension.js?mode=safe&token=main-token-marker#main-fragment-marker",
		"activationEvents":["onCommand:acme.safe","Authorization: Bearer authorization-marker","NODE_ENV=env-assignment-marker"],
		"contributes":{"commands":{},"api-key=capability-api-key-marker":{},"X-Header: capability-header-marker":{}}
	}`)
	writeIDEFile(t, filepath.Join(home, ".cursor", "extensions", "browser", "package.json"), `{
		"name":"browser","publisher":"acme","version":"1.0.0",
		"browser":"https://browser-user-marker:browser-password-marker@example.test/browser.js?secret=browser-secret-marker&mode=safe#browser-fragment-marker",
		"activationEvents":["onStartupFinished"],"capabilities":{"virtualWorkspaces":{}}
	}`)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	mainAsset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.main@1.0.0")
	main := observationForIDEAsset(t, got.Observations, mainAsset.ID)
	if !strings.Contains(main.Metadata["entry_point"], "https://example.test/extension.js") || !strings.Contains(main.Metadata["entry_point"], "mode=safe") || !strings.Contains(main.Metadata["entry_point"], "redacted") ||
		!strings.Contains(main.Metadata["activation_events"], "onCommand:acme.safe") || !strings.Contains(main.Metadata["activation_events"], "redacted") ||
		!strings.Contains(main.Metadata["capabilities"], "commands") || !strings.Contains(main.Metadata["capabilities"], "redacted") {
		t.Fatalf("main metadata=%v", main.Metadata)
	}
	browserAsset := testutil.AssertAsset(t, got.Assets, "ide-extension:cursor:acme.browser@1.0.0")
	browser := observationForIDEAsset(t, got.Observations, browserAsset.ID)
	if !strings.Contains(browser.Metadata["entry_point"], "https://example.test/browser.js") || !strings.Contains(browser.Metadata["entry_point"], "mode=safe") || !strings.Contains(browser.Metadata["entry_point"], "redacted") ||
		browser.Metadata["activation_events"] != "onStartupFinished" || browser.Metadata["capabilities"] != "virtualWorkspaces" {
		t.Fatalf("browser metadata=%v", browser.Metadata)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("marker %q persisted: %s", marker, encoded)
		}
	}
}

func TestCollectorRedactsStandaloneHighConfidenceCredentialFormats(t *testing.T) {
	home := t.TempDir()
	tokens := []string{
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567",
		"xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
		"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
		"sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
		"AKIAABCDEFGHIJKLMNOP",
		"ASIAQRSTUVWXYZ012345",
		"npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQtdXNlciJ9.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
		"-----BEGIN PRIVATE KEY-----",
	}
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "tokens", "package.json"), fmt.Sprintf(`{
		"name":"tokens","publisher":"acme","version":"1.0.0",
		"main":"https://example.test/%s/extension.js",
		"activationEvents":["onCommand:acme.safe","event:ghp_short","hash:0123456789abcdef0123456789abcdef","event:%s","event:%s","event:%s","event:%s","event:%s"],
		"contributes":{"commands":{},%q:{},%q:{}}
	}`, tokens[0], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6], tokens[7], tokens[8]))
	writeIDEFile(t, filepath.Join(home, ".cursor", "extensions", "browser-token", "package.json"), fmt.Sprintf(`{
		"name":"browser-token","publisher":"acme","version":"1.0.0",
		"browser":"https://example.test/browser.js?artifact=%s",
		"activationEvents":[%q],"capabilities":{"virtualWorkspaces":{}}
	}`, tokens[1], tokens[9]))

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	mainAsset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.tokens@1.0.0")
	main := observationForIDEAsset(t, got.Observations, mainAsset.ID)
	if main.Metadata["entry_point"] != redactedMetadata || !strings.Contains(main.Metadata["activation_events"], "onCommand:acme.safe") || !strings.Contains(main.Metadata["activation_events"], "event:ghp_short") || !strings.Contains(main.Metadata["activation_events"], "hash:0123456789abcdef0123456789abcdef") || !strings.Contains(main.Metadata["activation_events"], redactedMetadata) || !strings.Contains(main.Metadata["capabilities"], "commands") {
		t.Fatalf("main metadata=%v", main.Metadata)
	}
	browserAsset := testutil.AssertAsset(t, got.Assets, "ide-extension:cursor:acme.browser-token@1.0.0")
	browser := observationForIDEAsset(t, got.Observations, browserAsset.ID)
	if !strings.Contains(browser.Metadata["entry_point"], "artifact=%5Bredacted%5D") || browser.Metadata["activation_events"] != redactedMetadata || browser.Metadata["capabilities"] != "virtualWorkspaces" {
		t.Fatalf("browser metadata=%v", browser.Metadata)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if strings.Contains(string(encoded), token) {
			t.Fatalf("credential signature persisted: %s", encoded)
		}
	}
}

func TestCollectorRedactsPercentEncodedCredentialInBenignQueryValue(t *testing.T) {
	home := t.TempDir()
	token := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "encoded", "package.json"), `{
		"name":"encoded","publisher":"acme","version":"1.0.0",
		"main":"https://example.test/extension.js?artifact=ghp%5FABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&mode=safe"
	}`)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.encoded@1.0.0")
	observation := observationForIDEAsset(t, got.Observations, asset.ID)
	if !strings.Contains(observation.Metadata["entry_point"], "artifact=%5Bredacted%5D") || !strings.Contains(observation.Metadata["entry_point"], "mode=safe") {
		t.Fatalf("metadata=%v", observation.Metadata)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{token, "ghp%5FABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"} {
		if strings.Contains(string(encoded), marker) {
			t.Fatalf("credential marker persisted: %s", encoded)
		}
	}
}

func TestCollectorRedactsSharedPrivacySKDashedPathAndExplicitSecretFamilies(t *testing.T) {
	home := t.TempDir()
	legacy := "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl"
	project := "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl"
	anthropic := "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "sk-shapes", "package.json"), fmt.Sprintf(`{
		"name":"sk-shapes","publisher":"acme","version":"1.0.0",
		"main":"dist/sk-language-server-extension.js",
		"activationEvents":["onCommand:acme.safe","event:%s","event:%s","event:%s"]
	}`, legacy, project, anthropic))

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.sk-shapes@1.0.0")
	observation := observationForIDEAsset(t, got.Observations, asset.ID)
	if observation.Metadata["entry_point"] != redactedMetadata || !strings.Contains(observation.Metadata["activation_events"], "onCommand:acme.safe") || !strings.Contains(observation.Metadata["activation_events"], redactedMetadata) {
		t.Fatalf("metadata=%v", observation.Metadata)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{legacy, project, anthropic} {
		if strings.Contains(string(encoded), token) {
			t.Fatalf("secret family persisted: %s", encoded)
		}
	}
}

func TestIDEPrivacySharedClassificationAlwaysWinsForSKTokenPath(t *testing.T) {
	home := t.TempDir()
	token := "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "direct", "package.json"), fmt.Sprintf(`{
		"name":"direct","publisher":"acme","version":"1.0.0","main":%q
	}`, token))
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "segment", "package.json"), fmt.Sprintf(`{
		"name":"segment","publisher":"acme","version":"1.0.0","main":%q
	}`, "dist/"+token+"/extension.js"))

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	for _, assetID := range []string{
		"ide-extension:vscode:acme.direct@1.0.0",
		"ide-extension:vscode:acme.segment@1.0.0",
	} {
		observation := observationForIDEAsset(t, got.Observations, assetID)
		if observation.Metadata["entry_point"] != redactedMetadata || strings.HasPrefix(observation.Metadata["entry_point"], "extension-relative/path-sha256:") {
			t.Fatalf("shared privacy classification was downgraded: %+v", observation)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(token)) {
		t.Fatalf("shared privacy token leaked: %s", encoded)
	}
}

func TestIDEObservationMetadataPassesPersistencePrivacyBackstop(t *testing.T) {
	home := t.TempDir()
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "safe", "package.json"), `{
		"name":"safe","publisher":"acme","version":"1.0.0",
		"main":"dist/sk-language-server-extension.js",
		"activationEvents":["onCommand:acme.safe"]
	}`)
	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.safe@1.0.0")
	if observation := observationForIDEAsset(t, got.Observations, asset.ID); observation.Metadata["entry_point"] != redactedMetadata {
		t.Fatalf("entry point was not privacy-safe: %+v", observation)
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
		SchemaVersion: "ssc-init.scan.v2", ScanID: "ide-privacy-backstop", Status: "partial",
		StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC(),
		Coverage: []model.CollectorResult{got},
		Scope:    model.ScanScope{Platform: "darwin", CatalogVersion: collector.CatalogVersion},
	}
	if err := state.SaveScan(context.Background(), scan, inventory.Build(scan.Coverage)); err != nil {
		t.Fatalf("persist IDE observation metadata: %v", err)
	}
}

func TestCollectorRedactsAllGitHubClassicTokenPrefixes(t *testing.T) {
	home := t.TempDir()
	tokens := []string{
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	}
	writeIDEFile(t, filepath.Join(home, ".vscode", "extensions", "github-prefixes", "package.json"), fmt.Sprintf(`{
		"name":"github-prefixes","publisher":"acme","version":"1.0.0",
		"main":"dist/extension.js",
		"activationEvents":["event:ghp_short","event:gho_short","event:ghu_short","event:ghs_short","event:ghr_short","event:%s","event:%s","event:%s","event:%s","event:%s"]
	}`, tokens[0], tokens[1], tokens[2], tokens[3], tokens[4]))

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	asset := testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.github-prefixes@1.0.0")
	observation := observationForIDEAsset(t, got.Observations, asset.ID)
	for _, safe := range []string{"event:ghp_short", "event:gho_short", "event:ghu_short", "event:ghs_short", "event:ghr_short"} {
		if !strings.Contains(observation.Metadata["activation_events"], safe) {
			t.Fatalf("safe lookalike %q missing: %v", safe, observation.Metadata)
		}
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if strings.Contains(string(encoded), token) {
			t.Fatalf("GitHub token persisted: %s", encoded)
		}
	}
}

func TestCollectorHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().Collect(ctx, testutil.Environment(t, t.TempDir()))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestCollectorUsesOnlyTheBoundedJetBrainsManifestPattern(t *testing.T) {
	home := t.TempDir()
	exact := filepath.Join(home, "Library", "Application Support", "JetBrains", "Idea", "plugins")
	writeIDEFile(t, filepath.Join(exact, "good", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.good</id><name>Good</name><version>1.0.0</version></idea-plugin>`)
	marker := "nested-jetbrains-secret-marker"
	writeIDEFile(t, filepath.Join(exact, "wrapper", "nested", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.`+marker+`</id><name>Nested</name><version>9.9.9</version></idea-plugin>`)
	writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "Idea", "other", "outside", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.outside</id><name>Outside</name><version>9.9.9</version></idea-plugin>`)
	writeIDEFile(t, filepath.Join(exact, "malformed", "META-INF", "plugin.xml"), `<idea-plugin><id>`+marker)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 1 || strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "org.example.outside") {
		t.Fatalf("result=%s", encoded)
	}
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Idea", model.TargetPartial, 1, 1)
}

func TestCollectorContinuesAfterOneJetBrainsProductCannotBeRead(t *testing.T) {
	home := t.TempDir()
	blocked := filepath.Join(home, "Library", "Application Support", "JetBrains", "Alpha", "plugins")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	writeIDEFile(t, filepath.Join(home, "Library", "Application Support", "JetBrains", "Zulu", "plugins", "good", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.good</id><name>Good</name><version>1.0.0</version></idea-plugin>`)
	env := testutil.Environment(t, home)
	env.FS = ideReadDirFaultFileSystem{OSFileSystem: platform.OSFileSystem{}, blocked: blocked}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Path != "$HOME/Library/Application Support/JetBrains/Alpha/plugins" || strings.Contains(string(encoded), home) || strings.Contains(string(encoded), "permission denied") {
		t.Fatalf("result=%s", encoded)
	}
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Alpha", model.TargetUnavailable, 0, 0)
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Zulu", model.TargetComplete, 1, 1)
}

func TestCollectorRejectsRepeatedDirectJetBrainsIdentityElements(t *testing.T) {
	home := t.TempDir()
	plugins := filepath.Join(home, "Library", "Application Support", "JetBrains", "Idea", "plugins")
	writeIDEFile(t, filepath.Join(plugins, "good", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.good</id><name>Good</name><version>1.0.0</version><vendor><id>nested-id-ignored</id></vendor></idea-plugin>`)
	marker := "duplicate-jetbrains-secret-marker"
	writeIDEFile(t, filepath.Join(plugins, "duplicate-id", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.ambiguous</id><id>org.example.`+marker+`</id><name>Ambiguous</name><version>1.0.0</version></idea-plugin>`)
	writeIDEFile(t, filepath.Join(plugins, "duplicate-name", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.name</id><name>Ambiguous</name><name>`+marker+`</name><version>1.0.0</version></idea-plugin>`)
	writeIDEFile(t, filepath.Join(plugins, "duplicate-version", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.version</id><name>Ambiguous</name><version>1.0.0</version><version>`+marker+`</version></idea-plugin>`)

	got, err := New().Collect(context.Background(), testutil.Environment(t, home))
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.good@1.0.0")
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Assets) != 1 || len(got.Errors) != 3 || strings.Contains(string(encoded), marker) || strings.Contains(string(encoded), "nested-id-ignored") {
		t.Fatalf("result=%s", encoded)
	}
	for _, coverageErr := range got.Errors {
		if coverageErr.Code != "manifest_invalid" {
			t.Fatalf("error=%+v", coverageErr)
		}
	}
	assertIDETarget(t, got, "ide.jetbrains.plugins", "Idea", model.TargetPartial, 1, 1)
}

func TestJetBrainsDirectoryReadStopsAtEntryLimit(t *testing.T) {
	home := t.TempDir()
	rooted, err := platform.OSFileSystem{}.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer rooted.Close()
	generated := &generatedRoot{RootedDirectory: rooted, entries: maxJetBrainsEntries + 1}

	_, err = readDirectory(context.Background(), generated, maxJetBrainsEntries)
	if !errors.Is(err, errDirectoryEntryLimit) {
		t.Fatalf("error=%v", err)
	}
}

func TestJetBrainsDirectoryReadRejectsEntriesWhenBudgetIsExhausted(t *testing.T) {
	home := t.TempDir()
	rooted, err := platform.OSFileSystem{}.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer rooted.Close()
	generated := &generatedRoot{RootedDirectory: rooted, entries: 1}

	_, err = readDirectory(context.Background(), generated, 0)
	if !errors.Is(err, errDirectoryEntryLimit) {
		t.Fatalf("error=%v", err)
	}
}

func TestDirectoryReadReturnsDeterministicBoundedPrefixAtLimit(t *testing.T) {
	home := t.TempDir()
	rooted, err := platform.OSFileSystem{}.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer rooted.Close()
	generated := &generatedRoot{RootedDirectory: rooted, entries: 3}

	entries, err := readDirectory(context.Background(), generated, 2)
	if !errors.Is(err, errDirectoryEntryLimit) {
		t.Fatalf("error=%v", err)
	}
	got := make([]string, len(entries))
	for index, entry := range entries {
		got[index] = entry.Name()
	}
	if want := []string{"entry-00000", "entry-00001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%v want=%v", got, want)
	}
}

func TestCollectorMarksVSCodeRootPartialAndProcessesPrefixAtEntryLimit(t *testing.T) {
	home := t.TempDir()
	extensions := filepath.Join(home, ".vscode", "extensions")
	writeIDEFile(t, filepath.Join(extensions, "aaa-good", "package.json"), `{"name":"good","publisher":"acme","version":"1.0.0"}`)
	actual, err := os.ReadDir(extensions)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]os.DirEntry, 0, maxVSCodeEntries+1)
	entries = append(entries, actual[0])
	for index := 0; index < maxVSCodeEntries; index++ {
		entries = append(entries, generatedEntry{name: fmt.Sprintf("zzzz-synthetic-%05d", index)})
	}
	env := testutil.Environment(t, home)
	env.FS = boundedVSFileSystem{OSFileSystem: platform.OSFileSystem{}, target: extensions, entries: entries}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:vscode:acme.good@1.0.0")
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Code != "entry_limit" || got.Errors[0].Path != "$HOME/.vscode/extensions" {
		t.Fatalf("result=%+v", got)
	}
	assertIDETarget(t, got, "ide.vscode.extensions", "", model.TargetPartial, 1, 1)
}

func TestJetBrainsEntryBudgetChargesEachEnumeratedEntryOnce(t *testing.T) {
	budget := newEntryBudget(maxJetBrainsEntries)
	if !budget.charge(1) || !budget.charge(5_000) {
		t.Fatal("product plus 5,000 plugins must fit")
	}
	if budget.remaining != 4_999 {
		t.Fatalf("remaining=%d want=4999", budget.remaining)
	}
	if !budget.charge(4_999) {
		t.Fatal("exact 10,000-entry boundary must fit")
	}
	if budget.charge(1) {
		t.Fatal("entry 10,001 must be rejected")
	}
}

func TestCollectorStopsJetBrainsEnumerationGloballyAtExactEntryLimit(t *testing.T) {
	home := t.TempDir()
	jetBrains := filepath.Join(home, "Library", "Application Support", "JetBrains")
	alphaPlugins := filepath.Join(jetBrains, "Alpha", "plugins")
	zuluPlugins := filepath.Join(jetBrains, "Zulu", "plugins")
	writeIDEFile(t, filepath.Join(alphaPlugins, "zzzz-valid", "META-INF", "plugin.xml"), `<idea-plugin><id>org.example.boundary</id><name>Boundary</name><version>1.0.0</version></idea-plugin>`)
	if err := os.MkdirAll(zuluPlugins, 0o755); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadDir(alphaPlugins)
	if err != nil {
		t.Fatal(err)
	}
	alphaEntries := make([]os.DirEntry, 0, maxJetBrainsEntries-2)
	for index := 0; index < maxJetBrainsEntries-3; index++ {
		alphaEntries = append(alphaEntries, generatedEntry{name: fmt.Sprintf("aaaa-synthetic-%05d", index)})
	}
	alphaEntries = append(alphaEntries, actual[0])
	zuluReads := 0
	env := testutil.Environment(t, home)
	env.FS = jetBrainsCapFileSystem{
		OSFileSystem: platform.OSFileSystem{},
		alphaPlugins: alphaPlugins,
		alphaEntries: alphaEntries,
		zuluPlugins:  zuluPlugins,
		zuluReads:    &zuluReads,
	}

	got, err := New().Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "ide-extension:jetbrains:org.example.boundary@1.0.0")
	if zuluReads != 0 {
		t.Fatalf("later plugins directory read %d times", zuluReads)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Code != "entry_limit" || got.Errors[0].Path != "$HOME/Library/Application Support/JetBrains" {
		t.Fatalf("result=%+v", got)
	}
}

func writeIDEFile(t *testing.T, path, contents string) {
	t.Helper()
	writeIDEBytes(t, path, []byte(contents))
}

func writeIDEBytes(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeVSCodeManifest(t *testing.T, home, relative, publisher, name, version string) {
	t.Helper()
	contents, err := json.Marshal(map[string]string{
		"name": name, "publisher": publisher, "version": version,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeIDEBytes(t, filepath.Join(home, filepath.FromSlash(relative)), contents)
}

func countIDEAssets(assets []model.Asset, id string) int {
	count := 0
	for _, asset := range assets {
		if asset.ID == id {
			count++
		}
	}
	return count
}

func countIDEObservations(observations []model.Observation, assetID string) int {
	count := 0
	for _, observation := range observations {
		if observation.AssetID == assetID {
			count++
		}
	}
	return count
}

func observationForIDEAsset(t *testing.T, observations []model.Observation, assetID string) model.Observation {
	t.Helper()
	for _, observation := range observations {
		if observation.AssetID == assetID {
			return observation
		}
	}
	t.Fatalf("missing observation for %q: %+v", assetID, observations)
	return model.Observation{}
}

func observationForIDEProduct(t *testing.T, observations []model.Observation, assetID, product string) model.Observation {
	t.Helper()
	for _, observation := range observations {
		if observation.AssetID == assetID && observation.Metadata["product_instance"] == product {
			return observation
		}
	}
	t.Fatalf("missing observation for %q product %q: %+v", assetID, product, observations)
	return model.Observation{}
}

func assertIDECountsMatchEmitted(t *testing.T, result model.CollectorResult) {
	t.Helper()
	for _, target := range result.Targets {
		if target.Status == model.TargetUnsupported {
			continue
		}
		observations := 0
		for _, observation := range result.Observations {
			if observation.Source != target.TargetID {
				continue
			}
			if target.InstanceRef != "" && observation.Metadata["product_instance"] != target.InstanceRef {
				continue
			}
			if target.InstanceRef == "" && observation.Metadata["product_instance"] != "" {
				continue
			}
			if observation.ID == "" {
				t.Fatalf("unfinalized observation=%+v", observation)
			}
			observations++
		}
		if target.Assets != observations || target.Observations != observations {
			t.Fatalf("target counts do not match emitted evidence: target=%+v observations=%+v", target, result.Observations)
		}
	}
}

func assertIDETarget(t *testing.T, result model.CollectorResult, id, instance string, status model.TargetStatus, assets, observations int) model.TargetCoverage {
	t.Helper()
	for _, target := range result.Targets {
		if target.TargetID != id || target.InstanceRef != instance {
			continue
		}
		if target.Status != status || target.Assets != assets || target.Observations != observations {
			t.Fatalf("target=%+v", target)
		}
		return target
	}
	t.Fatalf("missing target %q instance %q: %+v", id, instance, result.Targets)
	return model.TargetCoverage{}
}

func assertIDECoverage(t *testing.T, result model.CollectorResult, want map[string]model.TargetStatus) {
	t.Helper()
	if len(result.Targets) != len(want) {
		t.Fatalf("targets=%+v want=%+v", result.Targets, want)
	}
	for _, target := range result.Targets {
		status, ok := want[target.TargetID]
		if !ok || target.InstanceRef != "" || target.Status != status {
			t.Fatalf("target=%+v want=%+v", target, want)
		}
	}
}

type pathOnlyIDEFileSystem struct {
	platform.FileSystem
}

type ideSwapFileSystem struct {
	platform.OSFileSystem
	targetDirectory string
	replacement     string
}

type ideReadDirFaultFileSystem struct {
	platform.OSFileSystem
	blocked string
}

type boundedVSFileSystem struct {
	platform.OSFileSystem
	target  string
	entries []os.DirEntry
}

type jetBrainsCapFileSystem struct {
	platform.OSFileSystem
	alphaPlugins string
	alphaEntries []os.DirEntry
	zuluPlugins  string
	zuluReads    *int
}

func (f jetBrainsCapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &jetBrainsCapRoot{
		RootedDirectory: root,
		current:         name,
		alphaPlugins:    f.alphaPlugins,
		alphaEntries:    f.alphaEntries,
		zuluPlugins:     f.zuluPlugins,
		zuluReads:       f.zuluReads,
	}, nil
}

type jetBrainsCapRoot struct {
	platform.RootedDirectory
	current      string
	alphaPlugins string
	alphaEntries []os.DirEntry
	zuluPlugins  string
	zuluReads    *int
}

func (r *jetBrainsCapRoot) Lstat(name string) (os.FileInfo, error) {
	if r.current == r.alphaPlugins && strings.HasPrefix(name, "aaaa-synthetic-") {
		return generatedInfo{}, nil
	}
	return r.RootedDirectory.Lstat(name)
}

func (r *jetBrainsCapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &jetBrainsCapRoot{
		RootedDirectory: child,
		current:         filepath.Join(r.current, name),
		alphaPlugins:    r.alphaPlugins,
		alphaEntries:    r.alphaEntries,
		zuluPlugins:     r.zuluPlugins,
		zuluReads:       r.zuluReads,
	}, nil
}

func (r *jetBrainsCapRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if name != "." {
		return file, nil
	}
	switch r.current {
	case r.alphaPlugins:
		return &sliceDirectory{RootedFile: file, entries: r.alphaEntries}, nil
	case r.zuluPlugins:
		return &countingDirectory{RootedFile: file, reads: r.zuluReads}, nil
	default:
		return file, nil
	}
}

type countingDirectory struct {
	platform.RootedFile
	reads *int
}

func (d *countingDirectory) ReadDir(int) ([]os.DirEntry, error) {
	*d.reads++
	return nil, io.EOF
}

func (f boundedVSFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &boundedVSRoot{RootedDirectory: root, current: name, target: f.target, entries: f.entries}, nil
}

type boundedVSRoot struct {
	platform.RootedDirectory
	current string
	target  string
	entries []os.DirEntry
}

func (r *boundedVSRoot) Lstat(name string) (os.FileInfo, error) {
	if r.current == r.target && strings.HasPrefix(name, "zzzz-synthetic-") {
		return generatedInfo{}, nil
	}
	return r.RootedDirectory.Lstat(name)
}

func (r *boundedVSRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &boundedVSRoot{RootedDirectory: child, current: filepath.Join(r.current, name), target: r.target, entries: r.entries}, nil
}

func (r *boundedVSRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if r.current == r.target && name == "." {
		return &sliceDirectory{RootedFile: file, entries: r.entries}, nil
	}
	return file, nil
}

type sliceDirectory struct {
	platform.RootedFile
	entries []os.DirEntry
	offset  int
}

func (d *sliceDirectory) ReadDir(count int) ([]os.DirEntry, error) {
	if d.offset == len(d.entries) {
		return nil, io.EOF
	}
	end := len(d.entries)
	if count > 0 && d.offset+count < end {
		end = d.offset + count
	}
	batch := d.entries[d.offset:end]
	d.offset = end
	return batch, nil
}

func (f ideReadDirFaultFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &ideReadDirFaultRoot{RootedDirectory: root, current: name, blocked: f.blocked}, nil
}

type ideReadDirFaultRoot struct {
	platform.RootedDirectory
	current string
	blocked string
}

func (r *ideReadDirFaultRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &ideReadDirFaultRoot{RootedDirectory: child, current: filepath.Join(r.current, name), blocked: r.blocked}, nil
}

func (r *ideReadDirFaultRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if r.current == r.blocked && name == "." {
		return &ideReadDirFaultFile{RootedFile: file}, nil
	}
	return file, nil
}

type ideReadDirFaultFile struct {
	platform.RootedFile
}

func (*ideReadDirFaultFile) ReadDir(int) ([]os.DirEntry, error) {
	return nil, fs.ErrPermission
}

func (f ideSwapFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	root, err := f.OSFileSystem.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &ideSwapRoot{RootedDirectory: root, current: name, targetDirectory: f.targetDirectory, replacement: f.replacement}, nil
}

type ideSwapRoot struct {
	platform.RootedDirectory
	current         string
	targetDirectory string
	replacement     string
}

func (r *ideSwapRoot) OpenRoot(name string) (platform.RootedDirectory, error) {
	child, err := r.RootedDirectory.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return &ideSwapRoot{RootedDirectory: child, current: filepath.Join(r.current, name), targetDirectory: r.targetDirectory, replacement: r.replacement}, nil
}

func (r *ideSwapRoot) Open(name string) (platform.RootedFile, error) {
	if r.current == r.targetDirectory && name == "package.json" {
		return os.Open(r.replacement)
	}
	return r.RootedDirectory.Open(name)
}

type generatedRoot struct {
	platform.RootedDirectory
	entries int
}

func (r *generatedRoot) Open(name string) (platform.RootedFile, error) {
	file, err := r.RootedDirectory.Open(name)
	if err != nil {
		return nil, err
	}
	if name != "." {
		return file, nil
	}
	return &generatedDirectory{RootedFile: file, remaining: r.entries}, nil
}

type generatedDirectory struct {
	platform.RootedFile
	remaining int
	index     int
}

func (d *generatedDirectory) ReadDir(count int) ([]os.DirEntry, error) {
	if d.remaining == 0 {
		return nil, io.EOF
	}
	if count <= 0 || count > d.remaining {
		count = d.remaining
	}
	entries := make([]os.DirEntry, count)
	for index := range entries {
		entries[index] = generatedEntry{name: fmt.Sprintf("entry-%05d", d.index)}
		d.index++
	}
	d.remaining -= count
	return entries, nil
}

type generatedEntry struct {
	name string
}

func (e generatedEntry) Name() string             { return e.name }
func (generatedEntry) IsDir() bool                { return false }
func (generatedEntry) Type() fs.FileMode          { return 0 }
func (generatedEntry) Info() (os.FileInfo, error) { return generatedInfo{}, nil }

type generatedInfo struct{}

func (generatedInfo) Name() string       { return "generated" }
func (generatedInfo) Size() int64        { return 0 }
func (generatedInfo) Mode() fs.FileMode  { return 0 }
func (generatedInfo) ModTime() time.Time { return time.Time{} }
func (generatedInfo) IsDir() bool        { return false }
func (generatedInfo) Sys() any           { return nil }
