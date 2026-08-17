package scanconfig

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

func TestConfigureProjectOnlyUsesOnlyProjectsAndNeverDiscovers(t *testing.T) {
	root := projects.Root{Path: t.TempDir(), Ref: "$HOME/work"}
	environment, configured, err := Configure(context.Background(), collector.Environment{Home: t.TempDir(), Platform: "darwin"}, cli.Options{
		Command: "scan", Baseline: true, JSON: true, ProjectOnly: true, ProjectRoots: []string{"$HOME/work"},
	}, func(string, []string) ([]projects.Root, error) {
		return []projects.Root{root}, nil
	}, func(context.Context, collector.Environment) (projects.Discovery, error) {
		t.Fatal("project-only invoked discovery")
		return projects.Discovery{}, errors.New("must not discover")
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(configured) != 1 || configured[0].Name() != "projects" {
		t.Fatalf("configured=%v", collectorNames(configured))
	}
	if environment.Scope.Mode != model.ScanScopeProjectOnly {
		t.Fatalf("scope=%+v", environment.Scope)
	}
}

func TestConfigureOrdinaryExplicitRootRetainsHostCollectors(t *testing.T) {
	root := projects.Root{Path: t.TempDir(), Ref: "$HOME/work"}
	environment, configured, err := Configure(context.Background(), collector.Environment{Home: t.TempDir(), Platform: "darwin"}, cli.Options{
		Command: "scan", Baseline: true, JSON: true, ProjectRoots: []string{"$HOME/work"},
	}, func(string, []string) ([]projects.Root, error) {
		return []projects.Root{root}, nil
	}, func(context.Context, collector.Environment) (projects.Discovery, error) {
		t.Fatal("explicit root invoked discovery")
		return projects.Discovery{}, errors.New("must not discover")
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"agents", "ide", "projects", "surfaces", "packages", "runtime"}
	if got := collectorNames(configured); !reflect.DeepEqual(got, want) {
		t.Fatalf("configured=%v want=%v", got, want)
	}
	if environment.Scope.Mode != model.ScanScopeHost {
		t.Fatalf("scope=%+v", environment.Scope)
	}
}

func collectorNames(configured []collector.Collector) []string {
	names := make([]string, len(configured))
	for index, item := range configured {
		names[index] = item.Name()
	}
	return names
}
