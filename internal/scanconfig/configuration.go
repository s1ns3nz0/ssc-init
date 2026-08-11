// Package scanconfig constructs the final immutable scan scope and production
// collector set from explicit or automatically discovered project roots.
package scanconfig

import (
	"context"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	runtimecollector "github.com/s1ns3nz0/ssc-init/internal/collector/runtime"
	"github.com/s1ns3nz0/ssc-init/internal/collector/surfaces"
	"github.com/s1ns3nz0/ssc-init/internal/model"
)

type ResolveRoots func(string, []string) ([]projects.Root, error)
type DiscoverRoots func(context.Context, collector.Environment) (projects.Discovery, error)

// Configure finalizes project roots before constructing the production
// collectors. Explicit roots are an exact override of automatic discovery.
func Configure(ctx context.Context, environment collector.Environment, options cli.Options, resolve ResolveRoots, discover DiscoverRoots) (collector.Environment, []collector.Collector, error) {
	var (
		roots             []projects.Root
		discoveryCoverage []model.TargetCoverage
		err               error
	)
	if len(options.ProjectRoots) > 0 {
		roots, err = resolve(environment.Home, options.ProjectRoots)
	} else {
		var discovery projects.Discovery
		discovery, err = discover(ctx, environment)
		roots = discovery.Roots
		discoveryCoverage = discovery.Coverage
	}
	if err != nil {
		return collector.Environment{}, nil, err
	}
	environment.Scope = model.ScanScope{
		Platform: environment.Platform, CatalogVersion: collector.CatalogVersion,
		ProjectRoots: projects.RootRefs(roots), ExternalProbes: options.ExternalProbes,
	}
	projectCollector := projects.New(roots)
	if len(options.ProjectRoots) == 0 {
		projectCollector = projects.NewWithDiscovery(roots, discoveryCoverage)
	}
	configured := []collector.Collector{
		agents.New(), ide.New(), projectCollector, surfaces.New(), packages.New(), runtimecollector.New(),
	}
	return environment, configured, nil
}
