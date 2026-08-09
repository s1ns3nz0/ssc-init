package packages

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/evidence"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestPackageObservationsIssueVisibleUnsupportedEvidence(t *testing.T) {
	got := collectWithFakeProbes(t)
	assets := make(map[string]model.Asset, len(got.Assets))
	for _, asset := range got.Assets {
		assets[asset.ID] = asset
	}
	byObservation := make(map[string]model.LocalEvidenceTarget)
	for _, target := range got.LocalEvidenceTargets {
		byObservation[target.ObservationID] = target
	}
	packages := 0
	for _, observation := range got.Observations {
		if assets[observation.AssetID].Type != model.AssetPackage {
			continue
		}
		packages++
		target, ok := byObservation[observation.ID]
		wantStatus := model.EvidenceUnsupported
		if observation.Source == dockerProbeTargetID {
			wantStatus = model.EvidenceComplete
		}
		if !ok || target.PresetStatus != wantStatus || target.RootPath != "" || target.RelativePath != "" {
			t.Fatalf("observation=%+v target=%+v present=%v", observation, target, ok)
		}
		if wantStatus == model.EvidenceComplete && (target.PresetAlgorithm != "sha256" || target.PresetDigest != assets[observation.AssetID].SHA256) {
			t.Fatalf("docker asset=%+v target=%+v", assets[observation.AssetID], target)
		}
	}
	if packages == 0 {
		t.Fatalf("fixture produced no package observations: %+v", got.Observations)
	}
	if len(byObservation) != len(got.LocalEvidenceTargets) || len(got.LocalEvidenceTargets) != packages {
		t.Fatalf("targets=%d observations=%d packages=%d", len(got.LocalEvidenceTargets), len(byObservation), packages)
	}
}

func TestDockerEvidenceWithoutAFullSHA256RemainsUnsupported(t *testing.T) {
	result := model.CollectorResult{Collector: "packages"}
	probe := commandProbe{targetID: dockerProbeTargetID, ecosystem: "docker"}
	observation := model.Observation{ID: "observation:test", AssetID: "pkg:docker/alpine@3.20"}

	if err := issuePackageArtifactEvidence(context.Background(), &result, probe, observation, model.Asset{ID: observation.AssetID}); err != nil {
		t.Fatal(err)
	}
	if len(result.LocalEvidenceTargets) != 1 {
		t.Fatalf("targets=%+v", result.LocalEvidenceTargets)
	}
	target := result.LocalEvidenceTargets[0]
	if target.PresetStatus != model.EvidenceUnsupported || target.PresetAlgorithm != "" || target.PresetDigest != "" {
		t.Fatalf("target=%+v", target)
	}
}

func TestPackageEvidenceTargetsUseDockerAndPackageIdentitiesOnly(t *testing.T) {
	got := collectWithFakeProbes(t)
	assets := make(map[string]model.Asset, len(got.Assets))
	for _, asset := range got.Assets {
		assets[asset.ID] = asset
	}
	observations := make(map[string]model.Observation, len(got.Observations))
	for _, observation := range got.Observations {
		observations[observation.ID] = observation
	}
	containers := 0
	contents := 0
	for _, target := range got.LocalEvidenceTargets {
		observation, ok := observations[target.ObservationID]
		if !ok || assets[target.AssetID].Type != model.AssetPackage || observation.AssetID != target.AssetID {
			t.Fatalf("target=%+v observation=%+v", target, observation)
		}
		if observation.Source == "packages.docker" {
			containers++
			if target.TargetID != "packages.docker.container-identity" || target.Kind != model.EvidenceContainerIdentity || target.Subject != model.EvidenceSubjectContainerImage {
				t.Fatalf("docker target=%+v", target)
			}
			continue
		}
		contents++
		// The appended package asset carries no Source, so the plan's
		// "packages.<ecosystem>.content" identity is derived from the probe that
		// finalized the observation.
		want := "packages." + observation.Metadata["manager"] + ".content"
		if target.TargetID != observation.Source+".content" || target.TargetID != want || assets[target.AssetID].Source != "" {
			t.Fatalf("target=%+v asset=%+v observation=%+v", target, assets[target.AssetID], observation)
		}
		if target.Kind != model.EvidencePackageContent || target.Subject != model.EvidenceSubjectPackageContent {
			t.Fatalf("target=%+v", target)
		}
	}
	if containers != 1 || contents == 0 {
		t.Fatalf("containers=%d contents=%d targets=%+v", containers, contents, got.LocalEvidenceTargets)
	}
}

func TestPackageToolObservationsReceiveNoEvidenceTarget(t *testing.T) {
	got := collectWithFakeProbes(t)
	assets := make(map[string]model.Asset, len(got.Assets))
	for _, asset := range got.Assets {
		assets[asset.ID] = asset
	}
	targeted := make(map[string]struct{}, len(got.LocalEvidenceTargets))
	for _, target := range got.LocalEvidenceTargets {
		targeted[target.ObservationID] = struct{}{}
	}
	tools := 0
	for _, observation := range got.Observations {
		if assets[observation.AssetID].Type != model.AssetTool {
			continue
		}
		tools++
		if _, ok := targeted[observation.ID]; ok {
			t.Fatalf("tool observation received a target: %+v", observation)
		}
	}
	if tools == 0 {
		t.Fatalf("fixture produced no tool observations: %+v", got.Observations)
	}
}

func TestPackageEvidenceCollectsAsTerminalUnsupportedWithoutHostAccess(t *testing.T) {
	got := collectWithFakeProbes(t)
	wantTargets := len(got.LocalEvidenceTargets)
	if wantTargets == 0 {
		t.Fatal("fixture issued no evidence targets")
	}
	recorder := &countingFileSystem{}
	runner := &countingRunner{}
	inventory := model.Inventory{Assets: got.Assets, Observations: got.Observations}

	collection := (evidence.Engine{}).Collect(context.Background(), collector.Environment{FS: recorder, Runner: runner}, inventory, []model.CollectorResult{got})

	if len(collection.Coverage.Errors) != 0 {
		t.Fatalf("coverage errors=%+v", collection.Coverage.Errors)
	}
	if len(collection.Evidence) != wantTargets || len(collection.Coverage.Targets) != wantTargets {
		t.Fatalf("records=%d coverage=%d want=%d", len(collection.Evidence), len(collection.Coverage.Targets), wantTargets)
	}
	complete := 0
	for _, record := range collection.Evidence {
		if record.Kind == model.EvidenceContainerIdentity {
			complete++
			if record.Status != model.EvidenceComplete || record.Algorithm != "sha256" || record.Digest != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
				t.Fatalf("container record=%+v", record)
			}
			continue
		}
		if record.Status != model.EvidenceUnsupported || record.ID == "" || record.Algorithm != "" || record.Digest != "" ||
			record.Size != 0 || record.Files != 0 || record.Directories != 0 || record.Symlinks != 0 ||
			len(record.Metadata) != 0 || len(record.Errors) != 0 {
			t.Fatalf("record=%+v", record)
		}
		if record.Kind != model.EvidencePackageContent && record.Kind != model.EvidenceContainerIdentity {
			t.Fatalf("record=%+v", record)
		}
	}
	if complete != 1 {
		t.Fatalf("complete container identities=%d evidence=%+v", complete, collection.Evidence)
	}
	for _, result := range collection.Coverage.Targets {
		if result.Status != model.EvidenceUnsupported && result.Status != model.EvidenceComplete || len(result.Errors) != 0 {
			t.Fatalf("coverage target=%+v", result)
		}
	}
	if collection.Coverage.Status != model.CoveragePartial {
		t.Fatalf("coverage status=%s", collection.Coverage.Status)
	}
	if len(collection.CacheWrites) != 0 {
		t.Fatalf("cache writes=%+v", collection.CacheWrites)
	}
	if calls := recorder.calls.Load(); calls != 0 {
		t.Fatalf("filesystem calls=%d", calls)
	}
	if calls := runner.calls.Load(); calls != 0 {
		t.Fatalf("runner calls=%d", calls)
	}
}

func collectWithFakeProbes(t *testing.T) model.CollectorResult {
	t.Helper()
	home := t.TempDir()
	npmRoot := filepath.Join(home, ".npm-global", "lib", "node_modules")
	goPath := filepath.Join(home, "go")
	writeFile(t, filepath.Join(npmRoot, "eslint", "package.json"), `{"name":"eslint","version":"9.1.0"}`)
	writeFile(t, filepath.Join(goPath, "bin", "gopls"), "binary")

	runner := &testutil.FakeRunner{Results: map[string]platform.CommandResult{
		commandKey("npm", "root", "-g"):                                             {Stdout: npmRoot + "\n"},
		commandKey("python3", "-m", "pip", "list", "--format=json"):                 {Stdout: `[{"name":"requests","version":"2.32.3"}]`},
		commandKey("pipx", "list", "--json"):                                        {Stdout: `{"venvs":{"black":{"metadata":{"main_package":{"package":"black","package_version":"24.4.2"}}}}}`},
		commandKey("uv", "tool", "list"):                                            {Stdout: "ruff v0.5.0\n"},
		commandKey("cargo", "install", "--list"):                                    {Stdout: "ripgrep v14.1.0:\n    rg\n"},
		commandKey("go", "env", "GOPATH"):                                           {Stdout: goPath + "\n"},
		commandKey("brew", "list", "--versions"):                                    {Stdout: "jq 1.7.1\n"},
		commandKey("docker", "image", "ls", "--no-trunc", "--format", "{{json .}}"): {Stdout: `{"Repository":"alpine","Tag":"3.20","ID":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` + "\n"},
	}}
	got, err := New().Collect(context.Background(), optInEnvironment(t, home, runner))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("status=%s errors=%+v", got.Status, got.Errors)
	}
	return got
}

type countingFileSystem struct{ calls atomic.Int64 }

func (c *countingFileSystem) ReadFile(string) ([]byte, error) {
	c.calls.Add(1)
	return nil, fs.ErrPermission
}

func (c *countingFileSystem) ReadDir(string) ([]os.DirEntry, error) {
	c.calls.Add(1)
	return nil, fs.ErrPermission
}

func (c *countingFileSystem) Stat(string) (os.FileInfo, error) {
	c.calls.Add(1)
	return nil, fs.ErrPermission
}

func (c *countingFileSystem) Lstat(string) (os.FileInfo, error) {
	c.calls.Add(1)
	return nil, fs.ErrPermission
}

func (c *countingFileSystem) WalkDir(string, fs.WalkDirFunc) error {
	c.calls.Add(1)
	return fs.ErrPermission
}

func (c *countingFileSystem) OpenRoot(string) (platform.RootedDirectory, error) {
	c.calls.Add(1)
	return nil, fs.ErrPermission
}

type countingRunner struct{ calls atomic.Int64 }

func (c *countingRunner) Run(context.Context, string, ...string) (platform.CommandResult, error) {
	c.calls.Add(1)
	return platform.CommandResult{}, fs.ErrPermission
}
