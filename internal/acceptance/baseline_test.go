package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/report"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/testutil"
)

func TestBaselineFixtureNeverReadsRealHome(t *testing.T) {
	env := testutil.Environment(t, "../../testdata/home")
	env.Platform = "darwin"
	env.Scope = model.ScanScope{ProjectRoots: []string{"$HOME/Projects"}}
	env.FS = &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: env.Home}
	roots, err := projects.ResolveRoots(env.Home, env.Scope.ProjectRoots)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := env.Runner.(*testutil.FakeRunner); !ok {
		t.Fatal("acceptance environment must use the fake runner")
	}
	orchestrator := collector.Orchestrator{
		Timeout:       time.Second,
		MaxConcurrent: 4,
		Collectors: []collector.Collector{
			agents.New(),
			ide.New(),
			projects.New(roots),
			packages.New(),
		},
	}
	snapshots := newMemorySnapshots()
	service := scan.NewService(
		orchestrator,
		snapshots,
		env.Now,
		func() string { return "00000000-0000-4000-8000-000000000001" },
		env,
	)

	result, inventory, delta, _, err := service.Baseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshots.saveCount() != 1 {
		t.Fatalf("saved snapshots=%d, want 1", snapshots.saveCount())
	}
	if result.Status != "complete" && result.Status != "partial" {
		t.Fatalf("status=%q", result.Status)
	}

	var output bytes.Buffer
	if err := report.WriteJSON(&output, result, inventory, delta); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, output.String())
	}
	if document["schemaVersion"] != "ssc-init.scan.v5" {
		t.Fatalf("schemaVersion=%v", document["schemaVersion"])
	}
	if _, ok := document["evidenceCoverage"].(map[string]any); !ok {
		t.Fatalf("baseline report is missing evidence coverage: %v", document["evidenceCoverage"])
	}
	if scope, ok := document["scope"].(map[string]any); !ok || scope["platform"] != "darwin" || scope["catalogVersion"] != collector.CatalogVersion {
		t.Fatalf("scope=%v", document["scope"])
	}
	if realHome := os.Getenv("HOME"); realHome != "" && realHome != env.Home && strings.Contains(output.String(), realHome) {
		t.Fatalf("real home leaked into fixture report: %q", realHome)
	}
}
