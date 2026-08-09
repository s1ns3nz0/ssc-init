package acceptance

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s1ns3nz0/ssc-init/internal/cli"
	"github.com/s1ns3nz0/ssc-init/internal/collector"
	"github.com/s1ns3nz0/ssc-init/internal/collector/agents"
	"github.com/s1ns3nz0/ssc-init/internal/collector/ide"
	"github.com/s1ns3nz0/ssc-init/internal/collector/mcp"
	"github.com/s1ns3nz0/ssc-init/internal/collector/packages"
	"github.com/s1ns3nz0/ssc-init/internal/collector/projects"
	"github.com/s1ns3nz0/ssc-init/internal/identity"
	"github.com/s1ns3nz0/ssc-init/internal/model"
	"github.com/s1ns3nz0/ssc-init/internal/platform"
	"github.com/s1ns3nz0/ssc-init/internal/report"
	"github.com/s1ns3nz0/ssc-init/internal/scan"
	"github.com/s1ns3nz0/ssc-init/internal/store"
)

const fixtureSecretSentinel = "fixture-secret"
const unconfiguredHomeSentinel = "unconfigured-home-sentinel"

type baselineOptions struct {
	home           string
	projectRoots   []string
	externalProbes bool
	runner         platform.Runner
	inspector      platform.ExecutableInspector
	databasePath   string
	scanID         string
}

type isolatedBaseline struct {
	Scan         model.ScanResult
	Inventory    model.Inventory
	Delta        model.Delta
	Snapshot     model.Snapshot
	Report       []byte
	Home         string
	DatabasePath string
	Catalog      map[string][]model.TargetSpec
	FileSystem   *matrixFileSystem
	Runner       *matrixRunner
	Inspector    *matrixInspector
}

type approvedCatalogTarget struct {
	Spec        model.TargetSpec
	Implemented bool
	InstanceRef string
	Status      model.TargetStatus
}

type approvedTargetCoverage struct {
	Collector string
	Target    model.TargetCoverage
}

var unsupportedTargetErrors = []model.CoverageError{{Code: "unsupported_target", Message: "target is not supported"}}

var approvedHostileCoverage = [...]approvedTargetCoverage{
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.claude.plugins", Status: model.TargetNotPresent}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.claude.skills", Status: model.TargetNotPresent}},
	{Collector: "agents", Target: model.TargetCoverage{
		TargetID: "agents.codex.plugins", Status: model.TargetPartial, Assets: 1, Observations: 1,
		Errors: []model.CoverageError{
			{Code: "symlink_rejected", Message: "symbolic link was not followed"},
			{Code: "manifest_invalid", Message: "agent manifest is invalid"},
			{Code: "identity_rejected", Message: "agent identity was rejected"},
		},
	}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.codex.skills", Status: model.TargetNotPresent}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.cursor.plugins", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.cursor.skills", Status: model.TargetNotPresent}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.custom-roots", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.dynamic-api", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.environment-relocated", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.remote-host", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "agents", Target: model.TargetCoverage{TargetID: "agents.windsurf.plugins", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},

	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.cursor.extensions", Status: model.TargetNotPresent}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.custom-roots", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.dev-container", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.environment-relocated", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.jetbrains.plugins", Status: model.TargetNotPresent}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.remote-ssh", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.remote-wsl", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.service-api", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.vscode-insiders.extensions", Status: model.TargetNotPresent}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.vscode-oss.extensions", Status: model.TargetNotPresent}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.vscode.extensions", Status: model.TargetNotPresent}},
	{Collector: "ide", Target: model.TargetCoverage{TargetID: "ide.windsurf.extensions", Status: model.TargetNotPresent}},

	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.claude-code.legacy-user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.claude-code.user", Status: model.TargetComplete, Assets: 1, Observations: 1}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.claude-desktop.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.codex.project", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.codex.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.cursor.project", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.cursor.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.dev-container", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.dynamic-api", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.environment-relocated", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.github-copilot.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.profile-specific", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.remote-user", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.service-managed", Status: model.TargetUnsupported, Errors: unsupportedTargetErrors}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.shared.project", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.vscode-insiders.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.vscode.project", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.vscode.user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.windsurf.legacy-user", Status: model.TargetNotPresent}},
	{Collector: "mcp", Target: model.TargetCoverage{TargetID: "mcp.windsurf.user", Status: model.TargetNotPresent}},

	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.cargo", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.docker", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.go", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.homebrew", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.npm", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.pip", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.pipx", Status: model.TargetSkipped}},
	{Collector: "packages", Target: model.TargetCoverage{TargetID: "packages.uv", Status: model.TargetSkipped}},

	{Collector: "projects", Target: model.TargetCoverage{TargetID: "projects.root", InstanceRef: "$HOME/Projects", Status: model.TargetNotPresent}},
}

var approvedHappyCatalog = [...]approvedCatalogTarget{
	{Spec: model.TargetSpec{ID: "agents.claude.plugins", Collector: "agents", Host: "claude", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "agents.claude.skills", Collector: "agents", Host: "claude", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "agents.codex.plugins", Collector: "agents", Host: "codex", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "agents.codex.skills", Collector: "agents", Host: "codex", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "agents.cursor.plugins", Collector: "agents", Host: "cursor", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "agents.cursor.skills", Collector: "agents", Host: "cursor", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "agents.custom-roots", Collector: "agents", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "agents.dynamic-api", Collector: "agents", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDynamicAPI}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "agents.environment-relocated", Collector: "agents", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "agents.remote-host", Collector: "agents", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "agents.windsurf.plugins", Collector: "agents", Host: "windsurf", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},

	{Spec: model.TargetSpec{ID: "ide.cursor.extensions", Collector: "ide", Host: "cursor", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "json", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "ide.custom-roots", Collector: "ide", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.dev-container", Collector: "ide", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.environment-relocated", Collector: "ide", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.jetbrains.plugins", Collector: "ide", Host: "jetbrains", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "xml", Method: model.TargetDirectory}, Implemented: true, InstanceRef: "Idea", Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "ide.remote-ssh", Collector: "ide", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.remote-wsl", Collector: "ide", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetDirectory}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.service-api", Collector: "ide", Scope: model.ScopeSystem, Platform: "darwin", Method: model.TargetServiceAPI}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "ide.vscode-insiders.extensions", Collector: "ide", Host: "vscode-insiders", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "json", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "ide.vscode-oss.extensions", Collector: "ide", Host: "vscode-oss", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "json", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},
	{Spec: model.TargetSpec{ID: "ide.vscode.extensions", Collector: "ide", Host: "vscode", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "json", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "ide.windsurf.extensions", Collector: "ide", Host: "windsurf", Scope: model.ScopeIDEProfile, Platform: "darwin", Format: "json", Method: model.TargetDirectory}, Implemented: true, Status: model.TargetNotPresent},

	{Spec: model.TargetSpec{ID: "mcp.claude-code.legacy-user", Collector: "mcp", Host: "claude-code", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.claude-code.user", Collector: "mcp", Host: "claude-code", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.claude-desktop.user", Collector: "mcp", Host: "claude-desktop", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.codex.project", Collector: "mcp", Host: "codex", Scope: model.ScopeProject, Platform: "darwin", Format: "toml", Method: model.TargetFile}, Implemented: true, InstanceRef: "$HOME/Projects/sample/.codex/config.toml", Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.codex.user", Collector: "mcp", Host: "codex", Scope: model.ScopeUser, Platform: "darwin", Format: "toml", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.cursor.project", Collector: "mcp", Host: "cursor", Scope: model.ScopeProject, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, InstanceRef: "$HOME/Projects/sample/.cursor/mcp.json", Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.cursor.user", Collector: "mcp", Host: "cursor", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.dev-container", Collector: "mcp", Scope: model.ScopeProject, Platform: "darwin", Method: model.TargetFile}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.dynamic-api", Collector: "mcp", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetDynamicAPI}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.environment-relocated", Collector: "mcp", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetFile}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.github-copilot.user", Collector: "mcp", Host: "github-copilot", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.profile-specific", Collector: "mcp", Scope: model.ScopeIDEProfile, Platform: "darwin", Method: model.TargetFile}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.remote-user", Collector: "mcp", Scope: model.ScopeUser, Platform: "darwin", Method: model.TargetFile}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.service-managed", Collector: "mcp", Scope: model.ScopeSystem, Platform: "darwin", Method: model.TargetServiceAPI}, Status: model.TargetUnsupported},
	{Spec: model.TargetSpec{ID: "mcp.shared.project", Collector: "mcp", Host: "shared", Scope: model.ScopeProject, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, InstanceRef: "$HOME/Projects/sample/.mcp.json", Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.vscode-insiders.user", Collector: "mcp", Host: "vscode-insiders", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.vscode.project", Collector: "mcp", Host: "vscode", Scope: model.ScopeProject, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, InstanceRef: "$HOME/Projects/sample/.vscode/mcp.json", Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.vscode.user", Collector: "mcp", Host: "vscode", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.windsurf.legacy-user", Collector: "mcp", Host: "windsurf", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},
	{Spec: model.TargetSpec{ID: "mcp.windsurf.user", Collector: "mcp", Host: "windsurf", Scope: model.ScopeUser, Platform: "darwin", Format: "json", Method: model.TargetFile}, Implemented: true, Status: model.TargetComplete},

	{Spec: model.TargetSpec{ID: "packages.cargo", Collector: "packages", Host: "cargo", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "text", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.docker", Collector: "packages", Host: "docker", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "ndjson", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.go", Collector: "packages", Host: "go", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "text", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.homebrew", Collector: "packages", Host: "homebrew", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "text", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.npm", Collector: "packages", Host: "npm", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "text", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.pip", Collector: "packages", Host: "pip", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "json", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.pipx", Collector: "packages", Host: "pipx", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "json", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},
	{Spec: model.TargetSpec{ID: "packages.uv", Collector: "packages", Host: "uv", Scope: model.ScopeToolEnvironment, Platform: "darwin", Format: "text", Method: model.TargetCommand}, Implemented: true, Status: model.TargetSkipped},

	{Spec: model.TargetSpec{ID: "projects.root", Collector: "projects", Scope: model.ScopeProject, Platform: "darwin", Method: model.TargetDirectory}, Implemented: true, InstanceRef: "$HOME/Projects", Status: model.TargetComplete},
}

func TestApprovedCatalogOracleIsExact(t *testing.T) {
	if len(approvedHappyCatalog) != 52 {
		t.Fatalf("approved happy catalog instances=%d want=52", len(approvedHappyCatalog))
	}
	statusCounts := map[model.TargetStatus]int{}
	seenSpecs := map[string]struct{}{}
	seenInstances := map[string]struct{}{}
	for _, target := range approvedHappyCatalog {
		statusCounts[target.Status]++
		if target.Implemented == (target.Status == model.TargetUnsupported) {
			t.Fatalf("target %q implemented=%v status=%q", target.Spec.ID, target.Implemented, target.Status)
		}
		specKey := target.Spec.Collector + "\x00" + target.Spec.ID
		if _, duplicate := seenSpecs[specKey]; duplicate {
			t.Fatalf("approved catalog contains duplicate spec %q", specKey)
		}
		seenSpecs[specKey] = struct{}{}
		instanceKey := specKey + "\x00" + target.InstanceRef
		if _, duplicate := seenInstances[instanceKey]; duplicate {
			t.Fatalf("approved catalog contains duplicate instance %q", instanceKey)
		}
		seenInstances[instanceKey] = struct{}{}
	}
	wantCounts := map[model.TargetStatus]int{
		model.TargetComplete: 18, model.TargetNotPresent: 8,
		model.TargetUnsupported: 18, model.TargetSkipped: 8,
	}
	if !reflect.DeepEqual(statusCounts, wantCounts) {
		t.Fatalf("approved status counts=%v want=%v", statusCounts, wantCounts)
	}
}

func TestApprovedHostileCoverageOracleIsExact(t *testing.T) {
	if len(approvedHostileCoverage) != 52 {
		t.Fatalf("approved hostile coverage instances=%d want=52", len(approvedHostileCoverage))
	}
	seen := map[string]struct{}{}
	partial := 0
	for _, approved := range approvedHostileCoverage {
		key := approved.Collector + "\x00" + approved.Target.TargetID + "\x00" + approved.Target.InstanceRef
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("approved hostile coverage contains duplicate %q", key)
		}
		seen[key] = struct{}{}
		if approved.Target.Status == model.TargetPartial {
			partial++
		}
	}
	if partial != 1 {
		t.Fatalf("approved hostile partial targets=%d want=1", partial)
	}
}

func TestOfficialCatalogMatrixIsTruthful(t *testing.T) {
	unconfiguredHome := t.TempDir()
	writeMatrixFile(t, filepath.Join(unconfiguredHome, ".claude.json"), `{"mcpServers":{"`+unconfiguredHomeSentinel+`":{"url":"https://unconfigured.invalid/mcp"}}}`)
	t.Setenv("HOME", unconfiguredHome)
	result := runIsolatedBaseline(t, baselineOptions{externalProbes: false})
	assertEveryApplicableTargetInstanceReportedOnce(t, result)
	assertImplementedFixtureTargetsComplete(t, result)
	assertUnsupportedDynamicTargetsVisible(t, result)
	assertNoContainerAsset(t, result.Inventory, "cache")
	assertPrivacyBoundary(t, result, unconfiguredHomeSentinel, unconfiguredHome)
	assertRunnerAndInspectorUnused(t, result)
}

func TestScopedCollectorsUseOnlyTheInjectedFilesystemForHostReads(t *testing.T) {
	repositoryRoot := matrixRepositoryRoot(t)
	for _, relativeDirectory := range []string{
		"internal/collector/agents",
		"internal/collector/ide",
		"internal/collector/mcp",
		"internal/collector/packages",
		"internal/collector/projects",
		"internal/policy",
	} {
		directory := filepath.Join(repositoryRoot, relativeDirectory)
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			assertSourceHasNoDirectHostFilesystemCalls(t, filepath.Join(directory, entry.Name()))
		}
	}
}

func TestDirectHostFilesystemReferenceAudit(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		source string
		want   []string
	}{
		{name: "deny os Open", source: "package fixture\nimport \"os\"\nvar denied = os.Open", want: []string{"os.Open"}},
		{name: "deny os OpenFile", source: "package fixture\nimport \"os\"\nvar denied = os.OpenFile", want: []string{"os.OpenFile"}},
		{name: "deny os OpenRoot", source: "package fixture\nimport \"os\"\nvar denied = os.OpenRoot", want: []string{"os.OpenRoot"}},
		{name: "deny os DirFS", source: "package fixture\nimport \"os\"\nvar denied = os.DirFS", want: []string{"os.DirFS"}},
		{name: "deny os ReadDir", source: "package fixture\nimport \"os\"\nvar denied = os.ReadDir", want: []string{"os.ReadDir"}},
		{name: "deny os ReadFile", source: "package fixture\nimport \"os\"\nvar denied = os.ReadFile", want: []string{"os.ReadFile"}},
		{name: "deny os Readlink", source: "package fixture\nimport \"os\"\nvar denied = os.Readlink", want: []string{"os.Readlink"}},
		{name: "deny os Lstat", source: "package fixture\nimport \"os\"\nvar denied = os.Lstat", want: []string{"os.Lstat"}},
		{name: "deny os Stat", source: "package fixture\nimport \"os\"\nvar denied = os.Stat", want: []string{"os.Stat"}},
		{name: "deny filepath Glob", source: "package fixture\nimport \"path/filepath\"\nvar denied = filepath.Glob", want: []string{"path/filepath.Glob"}},
		{name: "deny filepath EvalSymlinks", source: "package fixture\nimport \"path/filepath\"\nvar denied = filepath.EvalSymlinks", want: []string{"path/filepath.EvalSymlinks"}},
		{name: "deny filepath Walk", source: "package fixture\nimport \"path/filepath\"\nvar denied = filepath.Walk", want: []string{"path/filepath.Walk"}},
		{name: "deny filepath WalkDir", source: "package fixture\nimport \"path/filepath\"\nvar denied = filepath.WalkDir", want: []string{"path/filepath.WalkDir"}},
		{
			name: "direct call", source: `package fixture
import "path/filepath"
func scan() { _ = filepath.WalkDir(".", nil) }`,
			want: []string{"path/filepath.WalkDir"},
		},
		{
			name: "function value alias", source: `package fixture
import "os"
var open = os.OpenRoot`,
			want: []string{"os.OpenRoot"},
		},
		{
			name: "aliased import", source: `package fixture
import host "os"
var filesystem = host.DirFS(".")`,
			want: []string{"os.DirFS"},
		},
		{
			name: "exact removed primitive", source: `package fixture
import "os"
func scan() { _, _ = os.OpenRoot(".") }`,
			want: []string{"os.OpenRoot"},
		},
		{
			name: "dot import", source: `package fixture
import . "os"
var open = OpenRoot`,
			want: []string{"dot-import:os"},
		},
		{
			name: "harmless references", source: `package fixture
import (
  "os"
  "path/filepath"
)
var _ os.FileInfo
var _ = os.SameFile
var _ = filepath.Join`,
		},
		{
			name: "local os Open field", source: `package fixture
import "os"
func harmless() {
  os := struct{ Open func() }{}
  _ = os.Open
}`,
		},
		{
			name: "local os OpenRoot field", source: `package fixture
import "os"
func harmless() {
  os := struct{ OpenRoot func() }{}
  _ = os.OpenRoot
}`,
		},
		{
			name: "local filepath WalkDir field", source: `package fixture
import "path/filepath"
func harmless() {
  filepath := struct{ WalkDir func() }{}
  _ = filepath.WalkDir
}`,
		},
		{
			name: "local filepath EvalSymlinks field", source: `package fixture
import "path/filepath"
func harmless() {
  filepath := struct{ EvalSymlinks func() }{}
  _ = filepath.EvalSymlinks
}`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := directHostFilesystemReferences("fixture.go", []byte(testCase.source))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("references=%q want=%q", got, testCase.want)
			}
		})
	}
}

func TestOfficialMCPFixturesCoverBothContainersAndCodexTransports(t *testing.T) {
	result := runIsolatedBaseline(t, baselineOptions{externalProbes: false})
	want := map[string]struct {
		location   string
		transports []string
	}{
		"mcp.claude-code.legacy-user": {"$HOME/.claude/settings.json", []string{"http"}},
		"mcp.claude-code.user":        {"$HOME/.claude.json", []string{"stdio"}},
		"mcp.claude-desktop.user":     {"$HOME/Library/Application Support/Claude/claude_desktop_config.json", []string{"http"}},
		"mcp.codex.project":           {"$HOME/Projects/sample/.codex/config.toml", []string{"http", "stdio"}},
		"mcp.codex.user":              {"$HOME/.codex/config.toml", []string{"http", "stdio"}},
		"mcp.cursor.project":          {"$HOME/Projects/sample/.cursor/mcp.json", []string{"stdio"}},
		"mcp.cursor.user":             {"$HOME/.cursor/mcp.json", []string{"stdio"}},
		"mcp.github-copilot.user":     {"$HOME/.copilot/mcp-config.json", []string{"http"}},
		"mcp.shared.project":          {"$HOME/Projects/sample/.mcp.json", []string{"http"}},
		"mcp.vscode-insiders.user":    {"$HOME/Library/Application Support/Code - Insiders/User/mcp.json", []string{"stdio"}},
		"mcp.vscode.project":          {"$HOME/Projects/sample/.vscode/mcp.json", []string{"http"}},
		"mcp.vscode.user":             {"$HOME/Library/Application Support/Code/User/mcp.json", []string{"http"}},
		"mcp.windsurf.legacy-user":    {"$HOME/.windsurf/mcp.json", []string{"http"}},
		"mcp.windsurf.user":           {"$HOME/.codeium/windsurf/mcp_config.json", []string{"stdio"}},
	}
	for source, expected := range want {
		observations := matrixObservationsForSource(result.Inventory, source)
		if len(observations) != len(expected.transports) {
			t.Fatalf("source %q observations=%+v want transports=%v", source, observations, expected.transports)
		}
		gotTransports := make([]string, len(observations))
		for index, observation := range observations {
			if observation.LocationRef != expected.location {
				t.Fatalf("source %q location=%q want=%q", source, observation.LocationRef, expected.location)
			}
			gotTransports[index] = observation.Metadata["transport"]
		}
		sort.Strings(gotTransports)
		if strings.Join(gotTransports, "\x00") != strings.Join(expected.transports, "\x00") {
			t.Fatalf("source %q transports=%v want=%v", source, gotTransports, expected.transports)
		}
	}
	assertPrivacyBoundary(t, result)
}

func TestMissingExpansionRootsRemainExplicit(t *testing.T) {
	home := t.TempDir()
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	projectRoot := requireMatrixTarget(t, result.Scan.Coverage, "projects", "projects.root", "$HOME/Projects")
	if projectRoot.Status != model.TargetNotPresent {
		t.Fatalf("missing configured project root=%+v", projectRoot)
	}
	jetBrains := requireMatrixTarget(t, result.Scan.Coverage, "ide", "ide.jetbrains.plugins", "")
	if jetBrains.Status != model.TargetNotPresent {
		t.Fatalf("missing JetBrains expansion base=%+v", jetBrains)
	}
	for _, targetID := range []string{
		"mcp.codex.project", "mcp.cursor.project", "mcp.shared.project", "mcp.vscode.project",
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, "mcp", targetID, "")
		if target.Status != model.TargetNotPresent {
			t.Fatalf("missing project expansion base %q=%+v", targetID, target)
		}
	}
	assertRunnerAndInspectorUnused(t, result)
}

func TestSameNamedMCPServerInTwoProjectsRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	for _, project := range []string{"alpha", "beta"} {
		writeMatrixFile(t, filepath.Join(home, "Projects", project, ".mcp.json"), `{
  "mcpServers": {
    "same": {"url": "https://same-project.invalid/mcp"}
  }
}`)
	}
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	assetCount := 0
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "mcp:shared:same" {
			assetCount++
		}
	}
	observations := make([]model.Observation, 0, 2)
	for _, observation := range result.Inventory.Observations {
		if observation.AssetID == "mcp:shared:same" {
			observations = append(observations, observation)
		}
	}
	if assetCount != 1 || len(observations) != 2 {
		t.Fatalf("same-name asset count=%d observations=%+v", assetCount, observations)
	}
	locations := []string{observations[0].LocationRef, observations[1].LocationRef}
	sort.Strings(locations)
	if strings.Join(locations, "\n") != "$HOME/Projects/alpha/.mcp.json\n$HOME/Projects/beta/.mcp.json" {
		t.Fatalf("same-name locations=%v", locations)
	}
	for _, location := range locations {
		target := requireMatrixTarget(t, result.Scan.Coverage, "mcp", "mcp.shared.project", location)
		if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
			t.Fatalf("same-name project target=%+v", target)
		}
	}
}

func TestNestedPluginCacheRetainsManifestBackedPluginWithoutCacheAsset(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(
		t,
		filepath.Join(home, ".codex", "plugins", "cache", "example.invalid", "fixture-plugin", "1.2.3", ".codex-plugin", "plugin.json"),
		`{"name":"fixture-plugin","version":"1.2.3"}`,
	)
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	assertNoContainerAsset(t, result.Inventory, "cache")
	found := 0
	for _, asset := range result.Inventory.Assets {
		if asset.ID == "agent-plugin:codex:fixture-plugin@1.2.3" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("manifest-backed nested plugin count=%d inventory=%+v", found, result.Inventory)
	}
	target := requireMatrixTarget(t, result.Scan.Coverage, "agents", "agents.codex.plugins", "")
	if target.Status != model.TargetComplete || target.Assets != 1 || target.Observations != 1 {
		t.Fatalf("nested cache target=%+v", target)
	}
}

func TestSameIDEExtensionInTwoLocationsRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	manifest := `{"name":"same","publisher":"acme","version":"1.0.0","main":"dist/extension.js"}`
	for _, installation := range []string{"acme.same-1.0.0", "acme.same-copy-1.0.0"} {
		writeMatrixFile(t, filepath.Join(home, ".vscode", "extensions", installation, "package.json"), manifest)
	}
	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})

	const assetID = "ide-extension:vscode:acme.same@1.0.0"
	wantAsset := model.Asset{
		ID: assetID, Type: model.AssetIDEExtension, Name: "same", Version: "1.0.0", Source: "vscode",
		Metadata: map[string]string{"publisher": "acme"},
	}
	assetCount := 0
	var observations []model.Observation
	for _, asset := range result.Inventory.Assets {
		if asset.ID == assetID {
			assetCount++
			if !reflect.DeepEqual(asset, wantAsset) {
				t.Fatalf("same-extension asset=%+v want=%+v", asset, wantAsset)
			}
		}
	}
	for _, observation := range result.Inventory.Observations {
		if observation.AssetID == assetID {
			observations = append(observations, observation)
		}
	}
	if assetCount != 1 || len(observations) != 2 {
		t.Fatalf("same-extension assets=%d observations=%+v", assetCount, observations)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].LocationRef < observations[j].LocationRef })
	wantObservations := make([]model.Observation, 0, 2)
	for _, installation := range []string{"acme.same-1.0.0", "acme.same-copy-1.0.0"} {
		wantObservations = append(wantObservations, finalizeMatrixObservation(t, model.Observation{
			AssetID: assetID, Collector: "ide", Host: "vscode", Consumers: []string{"vscode"},
			Scope: model.ScopeIDEProfile, LocationRef: "$HOME/.vscode/extensions/" + installation,
			Source: "ide.vscode.extensions", Metadata: map[string]string{
				"entry_point": "dist/extension.js", "manifest_path": installation + "/package.json",
				"source_target": "ide.vscode.extensions",
			},
		}))
	}
	if !reflect.DeepEqual(observations, wantObservations) {
		t.Fatalf("same-extension observations=\n%+v\nwant=\n%+v", observations, wantObservations)
	}
	target := requireMatrixTarget(t, result.Scan.Coverage, "ide", "ide.vscode.extensions", "")
	if target.Status != model.TargetComplete || target.Assets != 2 || target.Observations != 2 {
		t.Fatalf("same-extension target=%+v", target)
	}
}

func TestSamePackageThroughTwoEnabledManagersRetainsBothObservations(t *testing.T) {
	home := t.TempDir()
	pythonPath := filepath.Join(home, "fake-bin", "python3")
	uvPath := filepath.Join(home, "fake-bin", "uv")
	events := &matrixEventLog{}
	inspector := &matrixInspector{
		events: events,
		evidence: map[string]platform.ExecutableEvidence{
			"python3": {
				Command: "python3", Path: pythonPath, LocationRef: "$HOME/fake-bin/python3",
				SHA256: strings.Repeat("a", 64), Mode: 0o755,
			},
			"uv": {
				Command: "uv", Path: uvPath, LocationRef: "$HOME/fake-bin/uv",
				SHA256: strings.Repeat("b", 64), Mode: 0o755,
			},
		},
		errors: map[string]error{},
	}
	for _, capability := range packages.Capabilities() {
		if capability.Executable != "python3" && capability.Executable != "uv" {
			inspector.errors[capability.Executable] = exec.ErrNotFound
		}
	}
	runner := &matrixRunner{events: events, results: map[string]platform.CommandResult{
		matrixCommandKey(pythonPath, "-m", "pip", "list", "--format=json"): {
			Stdout: `[{"name":"shared-fixture","version":"1.0.0"}]`,
		},
		matrixCommandKey(uvPath, "tool", "list"): {Stdout: "shared-fixture v1.0.0\n"},
	}, errors: map[string]error{}}
	result := runIsolatedBaseline(t, baselineOptions{
		home: home, externalProbes: true, runner: runner, inspector: inspector,
	})

	const assetID = "pkg:pypi/shared-fixture@1.0.0"
	wantPackageAsset := model.Asset{ID: assetID, Type: model.AssetPackage, Name: "shared-fixture", Version: "1.0.0"}
	wantTools := map[string]model.Asset{
		"pip": {ID: "tool-executable:sha256:" + strings.Repeat("a", 64), Type: model.AssetTool, Name: "executable", SHA256: strings.Repeat("a", 64)},
		"uv":  {ID: "tool-executable:sha256:" + strings.Repeat("b", 64), Type: model.AssetTool, Name: "executable", SHA256: strings.Repeat("b", 64)},
	}
	wantExecutableObservations := map[string]model.Observation{
		"pip": finalizeMatrixObservation(t, model.Observation{
			AssetID: wantTools["pip"].ID, Collector: "packages", Host: "pip", Consumers: []string{"pip"}, Scope: model.ScopeToolEnvironment,
			LocationRef: "$HOME/fake-bin/python3", Source: "packages.pip",
			Metadata: map[string]string{"command_basename": "python3", "mode": "755", "probe_target_id": "packages.pip"},
		}),
		"uv": finalizeMatrixObservation(t, model.Observation{
			AssetID: wantTools["uv"].ID, Collector: "packages", Host: "uv", Consumers: []string{"uv"}, Scope: model.ScopeToolEnvironment,
			LocationRef: "$HOME/fake-bin/uv", Source: "packages.uv",
			Metadata: map[string]string{"command_basename": "uv", "mode": "755", "probe_target_id": "packages.uv"},
		}),
	}
	wantPackageObservations := map[string]model.Observation{}
	for _, manager := range []string{"pip", "uv"} {
		probeSource := manager
		if manager == "pip" {
			probeSource = "python3"
		}
		wantPackageObservations[manager] = finalizeMatrixObservation(t, model.Observation{
			AssetID: assetID, Collector: "packages", Host: manager, Consumers: []string{manager}, Scope: model.ScopeToolEnvironment,
			LocationRef: "probe-target:packages." + manager, Source: "packages." + manager,
			Metadata: map[string]string{
				"manager": manager, "probe_source": probeSource, "probe_target_id": "packages." + manager,
				"executable_observation_id": wantExecutableObservations[manager].ID,
			},
		})
	}
	assertExactPackageCollisionEvidence(t, result.Inventory, wantPackageAsset, wantTools, wantExecutableObservations, wantPackageObservations)
	for _, targetID := range []string{"packages.pip", "packages.uv"} {
		target := requireMatrixTarget(t, result.Scan.Coverage, "packages", targetID, "")
		if target.Status != model.TargetComplete || target.Assets != 2 || target.Observations != 2 {
			t.Fatalf("enabled package target %q=%+v", targetID, target)
		}
	}
	if calls := runner.callCount(); calls != 2 {
		t.Fatalf("enabled package runner calls=%d want=2", calls)
	}
	if inspect, verify := inspector.callCounts(); inspect != len(packages.Capabilities()) || verify != 2 {
		t.Fatalf("enabled package inspector calls inspect=%d verify=%d", inspect, verify)
	}
	wantEvents := []string{
		"inspect:npm",
		"inspect:python3", "run:" + matrixCommandKey(pythonPath, "-m", "pip", "list", "--format=json"), "verify:python3",
		"inspect:pipx",
		"inspect:uv", "run:" + matrixCommandKey(uvPath, "tool", "list"), "verify:uv",
		"inspect:cargo", "inspect:go", "inspect:brew", "inspect:docker",
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("package probe event order=\n%q\nwant=\n%q", got, wantEvents)
	}
	assertPrivacyBoundary(t, result)
}

func TestHostileMalformedAndSymlinkSiblingsRemainPartialWithoutLosingSafeInventory(t *testing.T) {
	home := t.TempDir()
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "safe", ".codex-plugin", "plugin.json"), `{"name":"safe-fixture","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "broken", ".codex-plugin", "plugin.json"), `{`)
	const hostileIdentity = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
	writeMatrixFile(t, filepath.Join(home, ".codex", "plugins", "hostile", ".codex-plugin", "plugin.json"), `{"name":"`+hostileIdentity+`","version":"1.0.0"}`)
	writeMatrixFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"safe-sibling":{"url":"https://safe-sibling.invalid/mcp"}}}`)
	outside := t.TempDir()
	writeMatrixFile(t, filepath.Join(outside, ".codex-plugin", "plugin.json"), `{"name":"outside-fixture","version":"1.0.0"}`)
	if err := os.Symlink(outside, filepath.Join(home, ".codex", "plugins", "outside-link")); err != nil {
		t.Fatal(err)
	}

	result := runIsolatedBaseline(t, baselineOptions{home: home, externalProbes: false})
	assertApprovedHostileCoverage(t, result.Scan.Coverage)
	wantAssets := map[string]bool{
		"agent-plugin:codex:safe-fixture@1.0.0": false,
		"mcp:claude-code:safe-sibling":          false,
	}
	for _, asset := range result.Snapshot.Inventory.Assets {
		if _, wanted := wantAssets[asset.ID]; wanted {
			wantAssets[asset.ID] = true
		}
		if asset.Name == "outside-fixture" || strings.Contains(asset.ID, hostileIdentity) {
			t.Fatalf("hostile or symlinked asset survived: %+v", asset)
		}
	}
	for assetID, found := range wantAssets {
		if !found {
			t.Fatalf("safe sibling %q did not persist", assetID)
		}
	}
	assertPrivacyBoundary(t, result, hostileIdentity, outside, "outside-fixture")
}

func TestMigrationThreeLegacySnapshotSurfacesThroughStatusV3AsLegacyInventory(t *testing.T) {
	databasePath := createMigrationThreeLegacyDatabase(t)
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshots.Close()

	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil || !initialized {
		t.Fatalf("load migrated legacy snapshot initialized=%v err=%v", initialized, err)
	}
	wantInventory := migrationThreeLegacyInventory()
	wantCoverage := migrationThreeLegacyCoverage()
	if !reflect.DeepEqual(snapshot.Inventory, wantInventory) {
		t.Fatalf("migrated legacy inventory=\n%#v\nwant=\n%#v", snapshot.Inventory, wantInventory)
	}
	if !reflect.DeepEqual(snapshot.Scan.Coverage, wantCoverage) {
		t.Fatalf("migrated legacy coverage=\n%#v\nwant=\n%#v", snapshot.Scan.Coverage, wantCoverage)
	}
	if !reflect.DeepEqual(snapshot.Scan.Scope, model.ScanScope{}) || snapshot.Inventory.Observations != nil {
		t.Fatalf("legacy snapshot gained v2-only state: scope=%+v observations=%+v", snapshot.Scan.Scope, snapshot.Inventory.Observations)
	}
	if snapshot.Inventory.Evidence != nil || !reflect.DeepEqual(snapshot.Scan.EvidenceCoverage, model.EvidenceCoverage{}) {
		t.Fatalf("legacy snapshot invented evidence state: %+v %+v", snapshot.Inventory.Evidence, snapshot.Scan.EvidenceCoverage)
	}

	// A v1 snapshot cannot substantiate v3 evidence claims: the status contract
	// is v3, but the payload is explicitly legacy with nil evidence and no
	// scope, coverage, or evidence-coverage echo.
	raw := readMatrixStatusRaw(t, snapshots)
	var status matrixStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, raw)
	}
	if status.SchemaVersion != "ssc-init.status.v5" || !status.Initialized || status.InventorySchemaVersion != "ssc-init.scan.v1" || !status.LegacyInventory {
		t.Fatalf("legacy status=%+v", status)
	}
	if status.Scope != nil || status.Coverage != nil || status.EvidenceCoverage != nil || status.Inventory == nil {
		t.Fatalf("legacy status exposed v3 provenance it cannot substantiate: %+v", status)
	}
	if !reflect.DeepEqual(*status.Inventory, wantInventory) || status.Inventory.Observations != nil || status.Inventory.Evidence != nil {
		t.Fatalf("legacy status inventory=\n%#v\nwant=\n%#v", *status.Inventory, wantInventory)
	}
	if !bytes.Contains(raw, []byte(`"evidence":null`)) {
		t.Fatalf("legacy status must encode \"evidence\":null: %s", raw)
	}
	for _, forbidden := range []string{`"scope"`, `"coverage"`, `"evidenceCoverage"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("legacy status leaked %s: %s", forbidden, raw)
		}
	}
}

func TestV3BaselineReopenStatusQuiescentRescanAndObservedLocationDelta(t *testing.T) {
	home := copyOfficialFixtureHome(t)
	databasePath := filepath.Join(privateMatrixTempDir(t), "state.db")
	const extensionAssetID = "ide-extension:vscode:acme.safe@1.2.3"
	preObservation := finalizeMatrixObservation(t, model.Observation{
		AssetID: extensionAssetID, Collector: "ide", Host: "vscode", Consumers: []string{"vscode"}, Scope: model.ScopeIDEProfile,
		LocationRef: "$HOME/.vscode/extensions/acme.safe-1.2.3", Source: "ide.vscode.extensions",
		Metadata: map[string]string{
			"entry_point": "dist/extension.js", "activation_events": "onCommand:acme.safe.run", "capabilities": "commands",
			"manifest_path": "acme.safe-1.2.3/package.json", "source_target": "ide.vscode.extensions",
		},
	})
	postObservation := finalizeMatrixObservation(t, model.Observation{
		AssetID: extensionAssetID, Collector: "ide", Host: "vscode", Consumers: []string{"vscode"}, Scope: model.ScopeIDEProfile,
		LocationRef: "$HOME/.vscode/extensions/acme.safe-relocated-1.2.3", Source: "ide.vscode.extensions",
		Metadata: map[string]string{
			"entry_point": "dist/extension.js", "activation_events": "onCommand:acme.safe.run", "capabilities": "commands",
			"manifest_path": "acme.safe-relocated-1.2.3/package.json", "source_target": "ide.vscode.extensions",
		},
	})
	first := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000013",
	})
	status := readMatrixStatusFromPath(t, databasePath)
	if status.SchemaVersion != "ssc-init.status.v5" || status.InventorySchemaVersion != "ssc-init.scan.v5" || status.LegacyInventory || !status.Initialized {
		t.Fatalf("v3 status provenance=%+v", status)
	}
	if status.Scope == nil || !reflect.DeepEqual(*status.Scope, first.Scan.Scope) || !reflect.DeepEqual(status.Coverage, first.Scan.Coverage) || status.Inventory == nil || !reflect.DeepEqual(*status.Inventory, first.Inventory) {
		t.Fatalf("reopened v3 status did not preserve the full snapshot: %+v", status)
	}
	if status.EvidenceCoverage == nil || !reflect.DeepEqual(*status.EvidenceCoverage, first.Scan.EvidenceCoverage) {
		t.Fatalf("reopened v3 status evidence coverage=%+v want=%+v", status.EvidenceCoverage, first.Scan.EvidenceCoverage)
	}
	if got := matrixObservationsForAsset(first.Inventory, extensionAssetID); !reflect.DeepEqual(got, []model.Observation{preObservation}) {
		t.Fatalf("pre-move extension observation=\n%+v\nwant=\n%+v", got, preObservation)
	}

	// A cache-warm rescan of an unchanged home reuses complete leaf digests.
	// Evidence diffing excludes observation timestamps and cache provenance, so
	// an unchanged home is completely quiescent: the recorded tree cache
	// provenance flipping miss->hit is not a change signal, and every digest
	// stays identical.
	second := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000014",
	})
	if len(second.Delta.Changes) != 0 {
		t.Fatalf("quiescent rescan delta=\n%+v\nwant no changes", second.Delta.Changes)
	}
	storeCachedTrees := 0
	firstEvidenceByID := map[string]model.ContentEvidence{}
	for _, record := range first.Inventory.Evidence {
		firstEvidenceByID[record.ID] = record
		if record.Kind == model.EvidenceTreeSHA256 && record.Metadata[model.MetadataCache] == "miss" {
			storeCachedTrees++
		}
	}
	if storeCachedTrees == 0 {
		t.Fatal("fixture home produced no store-cached payload trees")
	}
	for _, record := range second.Inventory.Evidence {
		previous, exists := firstEvidenceByID[record.ID]
		if !exists {
			t.Fatalf("cache-warm rescan invented evidence %+v", record)
		}
		if record.Digest != previous.Digest || record.Status != previous.Status {
			t.Fatalf("cache-warm rescan altered content evidence:\n%+v\nwas\n%+v", record, previous)
		}
		if previous.Metadata[model.MetadataCache] == "miss" && record.Metadata[model.MetadataCache] != "hit" {
			t.Fatalf("cache-warm rescan did not hit the content cache: %+v", record)
		}
	}
	if len(second.Inventory.Evidence) != len(first.Inventory.Evidence) || !reflect.DeepEqual(second.Inventory.Assets, first.Inventory.Assets) || !reflect.DeepEqual(second.Inventory.Observations, first.Inventory.Observations) || !reflect.DeepEqual(second.Scan.Scope, first.Scan.Scope) || !reflect.DeepEqual(second.Scan.Coverage, first.Scan.Coverage) {
		t.Fatalf("unchanged second scan drifted beyond cache provenance: %+v", second.Delta)
	}

	oldLocation := filepath.Join(home, ".vscode", "extensions", "acme.safe-1.2.3")
	newLocation := filepath.Join(home, ".vscode", "extensions", "acme.safe-relocated-1.2.3")
	if err := os.Rename(oldLocation, newLocation); err != nil {
		t.Fatal(err)
	}
	third := runIsolatedBaseline(t, baselineOptions{
		home: home, databasePath: databasePath,
		scanID: "00000000-0000-4000-8000-000000000015",
	})
	if got := matrixObservationsForAsset(third.Inventory, extensionAssetID); !reflect.DeepEqual(got, []model.Observation{postObservation}) {
		t.Fatalf("post-move extension observation=\n%+v\nwant=\n%+v", got, postObservation)
	}
	wantChanges := []model.Change{
		{Kind: model.ChangeRemoved, Entity: model.ChangeEntityObservation, EntityID: preObservation.ID},
		{Kind: model.ChangeAdded, Entity: model.ChangeEntityObservation, EntityID: postObservation.ID},
	}
	// The moved observation carries its evidence identities with it: every
	// evidence record bound to the old observation is removed and re-added
	// under the new observation with an identical digest.
	movedDigests := map[string]string{}
	for _, record := range second.Inventory.Evidence {
		if record.ObservationID == preObservation.ID {
			wantChanges = append(wantChanges, model.Change{Kind: model.ChangeRemoved, Entity: model.ChangeEntityEvidence, EntityID: record.ID})
			movedDigests[record.Subject] = record.Digest
		}
	}
	if len(movedDigests) != 3 {
		t.Fatalf("moved extension evidence subjects=%v want manifest, entrypoint-main, payload-tree", movedDigests)
	}
	for _, record := range third.Inventory.Evidence {
		if record.ObservationID != postObservation.ID {
			continue
		}
		wantChanges = append(wantChanges, model.Change{Kind: model.ChangeAdded, Entity: model.ChangeEntityEvidence, EntityID: record.ID})
		if record.Digest != movedDigests[record.Subject] {
			t.Fatalf("relocated %s evidence digest drifted: %+v", record.Subject, record)
		}
	}
	sort.Slice(wantChanges, func(i, j int) bool {
		left, right := wantChanges[i], wantChanges[j]
		if left.Entity != right.Entity {
			return left.Entity < right.Entity
		}
		return left.EntityID < right.EntityID
	})
	if len(wantChanges) != 8 || !reflect.DeepEqual(third.Delta.Changes, wantChanges) {
		t.Fatalf("observed-location delta=\n%+v\nwant exactly=\n%+v", third.Delta.Changes, wantChanges)
	}
	latestStatus := readMatrixStatusFromPath(t, databasePath)
	if latestStatus.Inventory == nil || !reflect.DeepEqual(*latestStatus.Inventory, third.Inventory) || latestStatus.Scope == nil || !reflect.DeepEqual(*latestStatus.Scope, third.Scan.Scope) || !reflect.DeepEqual(latestStatus.Coverage, third.Scan.Coverage) {
		t.Fatalf("latest status did not use the third full snapshot: %+v", latestStatus)
	}
	if latestStatus.EvidenceCoverage == nil || !reflect.DeepEqual(*latestStatus.EvidenceCoverage, third.Scan.EvidenceCoverage) {
		t.Fatalf("latest status evidence coverage=%+v", latestStatus.EvidenceCoverage)
	}
}

func runIsolatedBaseline(t *testing.T, options baselineOptions) isolatedBaseline {
	t.Helper()
	home := options.home
	if home == "" {
		home = copyOfficialFixtureHome(t)
	}
	home, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Clean(home)

	rootValues := options.projectRoots
	if len(rootValues) == 0 {
		rootValues = []string{"$HOME/Projects"}
	}
	roots, err := projects.ResolveRoots(home, rootValues)
	if err != nil {
		t.Fatal(err)
	}

	fileSystem := &matrixFileSystem{OSFileSystem: platform.OSFileSystem{}, root: home}
	runner, runnerOK := options.runner.(*matrixRunner)
	if options.runner == nil {
		runner = &matrixRunner{failOnCall: true}
		options.runner = runner
	} else if !runnerOK {
		runner = nil
	}
	inspector, inspectorOK := options.inspector.(*matrixInspector)
	if options.inspector == nil {
		inspector = &matrixInspector{failOnCall: true}
		options.inspector = inspector
	} else if !inspectorOK {
		inspector = nil
	}

	environment := collector.Environment{
		Home: home, Platform: "darwin",
		Scope: model.ScanScope{
			Platform: "darwin", ProjectRoots: projects.RootRefs(roots),
			ExternalProbes: options.externalProbes,
		},
		FS: fileSystem, Runner: options.runner, Inspector: options.inspector,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	configured := []collector.Collector{
		agents.New(),
		ide.New(),
		projects.New(roots),
		packages.New(),
	}
	catalog := make(map[string][]model.TargetSpec, len(configured)+1)
	for _, configuredCollector := range configured {
		targeted, ok := configuredCollector.(collector.TargetedCollector)
		if !ok {
			t.Fatalf("production collector %q does not expose its target catalog", configuredCollector.Name())
		}
		catalog[configuredCollector.Name()] = targeted.Targets()
	}
	catalog["mcp"] = mcp.New().Targets()

	databasePath := options.databasePath
	if databasePath == "" {
		databasePath = filepath.Join(privateMatrixTempDir(t), "state.db")
	}
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	orchestrator := collector.Orchestrator{
		Timeout: time.Second, MaxConcurrent: 4, Collectors: configured,
	}
	scanID := options.scanID
	if scanID == "" {
		scanID = "00000000-0000-4000-8000-000000000013"
	}
	service := scan.NewService(
		orchestrator,
		snapshots,
		environment.Now,
		func() string { return scanID },
		environment,
	)
	scanResult, inventory, delta, _, err := service.Baseline(context.Background())
	if err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	snapshot, initialized, err := snapshots.LatestSnapshot(context.Background())
	if err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	if !initialized {
		_ = snapshots.Close()
		t.Fatal("baseline did not persist a snapshot")
	}
	var output bytes.Buffer
	if err := report.WriteJSON(&output, scanResult, inventory, delta); err != nil {
		_ = snapshots.Close()
		t.Fatal(err)
	}
	if err := snapshots.Close(); err != nil {
		t.Fatal(err)
	}
	return isolatedBaseline{
		Scan: scanResult, Inventory: inventory, Delta: delta, Snapshot: snapshot,
		Report: output.Bytes(), Home: home, DatabasePath: databasePath,
		Catalog: catalog, FileSystem: fileSystem, Runner: runner, Inspector: inspector,
	}
}

func assertEveryApplicableTargetInstanceReportedOnce(t *testing.T, result isolatedBaseline) {
	t.Helper()
	wantCatalog := map[string][]model.TargetSpec{}
	type coverageIdentity struct {
		collector   string
		targetID    string
		instanceRef string
	}
	wantCoverage := make(map[coverageIdentity]model.TargetStatus, len(approvedHappyCatalog))
	for _, approved := range approvedHappyCatalog {
		wantCatalog[approved.Spec.Collector] = append(wantCatalog[approved.Spec.Collector], approved.Spec)
		wantCoverage[coverageIdentity{approved.Spec.Collector, approved.Spec.ID, approved.InstanceRef}] = approved.Status
	}
	if !reflect.DeepEqual(result.Catalog, wantCatalog) {
		t.Fatalf("production catalog drifted from the approved literal oracle:\n got: %#v\nwant: %#v", result.Catalog, wantCatalog)
	}

	gotCoverage := make(map[coverageIdentity]model.TargetStatus, len(approvedHappyCatalog))
	seenCollectors := make(map[string]struct{}, len(result.Scan.Coverage))
	for _, collectorResult := range result.Scan.Coverage {
		if _, duplicate := seenCollectors[collectorResult.Collector]; duplicate {
			t.Fatalf("collector %q reported more than once", collectorResult.Collector)
		}
		seenCollectors[collectorResult.Collector] = struct{}{}
		if collectorResult.LocalTargets != nil {
			t.Fatalf("collector %q retained raw local targets", collectorResult.Collector)
		}
		for _, target := range collectorResult.Targets {
			identity := coverageIdentity{collectorResult.Collector, target.TargetID, target.InstanceRef}
			if _, duplicate := gotCoverage[identity]; duplicate {
				t.Fatalf("duplicate target instance %+v", identity)
			}
			gotCoverage[identity] = target.Status
		}
	}
	if !reflect.DeepEqual(gotCoverage, wantCoverage) {
		t.Fatalf("happy-path target coverage drifted from the approved literal oracle:\n got: %#v\nwant: %#v", gotCoverage, wantCoverage)
	}
}

func assertApprovedHostileCoverage(t *testing.T, coverage []model.CollectorResult) {
	t.Helper()
	got := make([]approvedTargetCoverage, 0, len(approvedHostileCoverage))
	for _, collectorResult := range coverage {
		if collectorResult.LocalTargets != nil {
			t.Fatalf("collector %q retained raw local targets", collectorResult.Collector)
		}
		for _, target := range collectorResult.Targets {
			got = append(got, approvedTargetCoverage{Collector: collectorResult.Collector, Target: target})
		}
	}
	want := approvedHostileCoverage[:]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hostile target coverage drifted from the literal oracle:\n got: %#v\nwant: %#v", got, want)
	}
}

func assertImplementedFixtureTargetsComplete(t *testing.T, result isolatedBaseline) {
	t.Helper()
	for _, pair := range []struct{ collector, target, instance string }{
		{"agents", "agents.codex.plugins", ""},
		{"ide", "ide.jetbrains.plugins", "Idea"},
		{"ide", "ide.vscode.extensions", ""},
		{"mcp", "mcp.claude-code.legacy-user", ""},
		{"mcp", "mcp.claude-code.user", ""},
		{"mcp", "mcp.claude-desktop.user", ""},
		{"mcp", "mcp.codex.project", "$HOME/Projects/sample/.codex/config.toml"},
		{"mcp", "mcp.codex.user", ""},
		{"mcp", "mcp.cursor.project", "$HOME/Projects/sample/.cursor/mcp.json"},
		{"mcp", "mcp.cursor.user", ""},
		{"mcp", "mcp.github-copilot.user", ""},
		{"mcp", "mcp.shared.project", "$HOME/Projects/sample/.mcp.json"},
		{"mcp", "mcp.vscode-insiders.user", ""},
		{"mcp", "mcp.vscode.project", "$HOME/Projects/sample/.vscode/mcp.json"},
		{"mcp", "mcp.vscode.user", ""},
		{"mcp", "mcp.windsurf.legacy-user", ""},
		{"mcp", "mcp.windsurf.user", ""},
		{"projects", "projects.root", "$HOME/Projects"},
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, pair.collector, pair.target, pair.instance)
		if target.Status != model.TargetComplete || target.Assets == 0 || target.Observations == 0 {
			t.Fatalf("implemented fixture target %q/%q=%+v", pair.target, pair.instance, target)
		}
	}
}

func assertUnsupportedDynamicTargetsVisible(t *testing.T, result isolatedBaseline) {
	t.Helper()
	for _, pair := range []struct{ collector, target string }{
		{"agents", "agents.cursor.plugins"},
		{"agents", "agents.custom-roots"},
		{"agents", "agents.dynamic-api"},
		{"agents", "agents.environment-relocated"},
		{"agents", "agents.remote-host"},
		{"agents", "agents.windsurf.plugins"},
		{"ide", "ide.custom-roots"},
		{"ide", "ide.dev-container"},
		{"ide", "ide.environment-relocated"},
		{"ide", "ide.remote-ssh"},
		{"ide", "ide.remote-wsl"},
		{"ide", "ide.service-api"},
		{"mcp", "mcp.dev-container"},
		{"mcp", "mcp.dynamic-api"},
		{"mcp", "mcp.environment-relocated"},
		{"mcp", "mcp.profile-specific"},
		{"mcp", "mcp.remote-user"},
		{"mcp", "mcp.service-managed"},
	} {
		target := requireMatrixTarget(t, result.Scan.Coverage, pair.collector, pair.target, "")
		if target.Status != model.TargetUnsupported || len(target.Errors) != 1 || target.Errors[0].Code != "unsupported_target" {
			t.Fatalf("unsupported target %q=%+v", pair.target, target)
		}
	}
}

func assertNoContainerAsset(t *testing.T, inventory model.Inventory, name string) {
	t.Helper()
	for _, asset := range inventory.Assets {
		if asset.Type == model.AssetAgentPlugin && asset.Name == name {
			t.Fatalf("container %q was reported as a plugin: %+v", name, asset)
		}
	}
}

func assertPrivacyBoundary(t *testing.T, result isolatedBaseline, additionalForbidden ...string) {
	t.Helper()
	forbidden := append([]string{
		fixtureSecretSentinel,
		"placeholder-value",
		result.Home,
	}, additionalForbidden...)
	serialized := encodeMatrixResult(t, result)
	for _, value := range forbidden {
		if value != "" && bytes.Contains(serialized, []byte(value)) {
			t.Fatalf("forbidden raw value leaked into serialized report or snapshot: %q", value)
		}
	}
	for _, databasePath := range []string{result.DatabasePath, result.DatabasePath + "-wal", result.DatabasePath + "-shm"} {
		database, err := os.ReadFile(databasePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range forbidden {
			if value != "" && bytes.Contains(database, []byte(value)) {
				t.Fatalf("forbidden raw value %q persisted in %s", value, filepath.Base(databasePath))
			}
		}
	}
	if denied := result.FileSystem.deniedPaths(); len(denied) != 0 {
		t.Fatalf("collector attempted unconfigured filesystem paths: %v", denied)
	}
}

func matrixRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve acceptance source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", ".."))
}

func assertSourceHasNoDirectHostFilesystemCalls(t *testing.T, sourcePath string) {
	t.Helper()
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	references, err := directHostFilesystemReferences(sourcePath, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range references {
		t.Errorf("%s directly references %s; scoped collection must use Environment.FS", sourcePath, reference)
	}
}

func directHostFilesystemReferences(filename string, source []byte) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		return nil, err
	}
	importPaths := map[string]string{}
	references := map[string]struct{}{}
	for _, imported := range parsed.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		if path != "os" && path != "path/filepath" {
			continue
		}
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name == "." {
			references["dot-import:"+path] = struct{}{}
			continue
		}
		if name == "_" {
			continue
		}
		importPaths[name] = path
	}
	directHostReferences := map[string]map[string]bool{
		"os": {
			"DirFS": true, "Open": true, "OpenFile": true, "OpenRoot": true,
			"ReadDir": true, "ReadFile": true, "Readlink": true, "Lstat": true, "Stat": true,
		},
		"path/filepath": {"EvalSymlinks": true, "Glob": true, "Walk": true, "WalkDir": true},
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if packageName.Obj != nil {
			return true
		}
		importPath := importPaths[packageName.Name]
		if directHostReferences[importPath][selector.Sel.Name] {
			references[importPath+"."+selector.Sel.Name] = struct{}{}
		}
		return true
	})
	if len(references) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(references))
	for reference := range references {
		result = append(result, reference)
	}
	sort.Strings(result)
	return result, nil
}

func assertRunnerAndInspectorUnused(t *testing.T, result isolatedBaseline) {
	t.Helper()
	if result.Runner == nil || result.Inspector == nil {
		t.Fatal("default matrix did not install fail-on-call execution fakes")
	}
	if calls := result.Runner.callCount(); calls != 0 {
		t.Fatalf("default runner calls=%d want=0", calls)
	}
	if inspect, verify := result.Inspector.callCounts(); inspect != 0 || verify != 0 {
		t.Fatalf("default inspector calls inspect=%d verify=%d want=0", inspect, verify)
	}
}

func requireMatrixTarget(t *testing.T, coverage []model.CollectorResult, collectorName, targetID, instanceRef string) model.TargetCoverage {
	t.Helper()
	for _, result := range coverage {
		if result.Collector != collectorName {
			continue
		}
		for _, target := range result.Targets {
			if target.TargetID == targetID && target.InstanceRef == instanceRef {
				return target
			}
		}
	}
	t.Fatalf("missing target %q/%q from collector %q", targetID, instanceRef, collectorName)
	return model.TargetCoverage{}
}

func finalizeMatrixObservation(t *testing.T, observation model.Observation) model.Observation {
	t.Helper()
	finalized, err := identity.FinalizeObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	return finalized
}

func assertExactPackageCollisionEvidence(
	t *testing.T,
	inventory model.Inventory,
	wantPackageAsset model.Asset,
	wantTools map[string]model.Asset,
	wantExecutableObservations map[string]model.Observation,
	wantPackageObservations map[string]model.Observation,
) {
	t.Helper()
	packageAssets := 0
	toolAssetCount := 0
	executableObservationCount := 0
	packageObservationCount := 0
	toolAssets := map[string]model.Asset{}
	executableObservations := map[string]model.Observation{}
	packageObservations := map[string]model.Observation{}
	for _, asset := range inventory.Assets {
		if asset.Type == model.AssetTool {
			toolAssetCount++
		}
		if asset.ID == wantPackageAsset.ID {
			packageAssets++
			if !reflect.DeepEqual(asset, wantPackageAsset) {
				t.Fatalf("same-package asset=%+v want=%+v", asset, wantPackageAsset)
			}
		}
		for manager, want := range wantTools {
			if asset.ID == want.ID {
				toolAssets[manager] = asset
			}
		}
	}
	for _, observation := range inventory.Observations {
		if observation.AssetID == wantTools["pip"].ID || observation.AssetID == wantTools["uv"].ID {
			executableObservationCount++
		}
		for manager, want := range wantExecutableObservations {
			if observation.ID == want.ID {
				executableObservations[manager] = observation
			}
		}
		if observation.AssetID == wantPackageAsset.ID {
			packageObservationCount++
			packageObservations[observation.Host] = observation
		}
	}
	if packageAssets != 1 || toolAssetCount != 2 || !reflect.DeepEqual(toolAssets, wantTools) {
		t.Fatalf("same-package asset count=%d tool count=%d tools=%+v want tools=%+v", packageAssets, toolAssetCount, toolAssets, wantTools)
	}
	if executableObservationCount != 2 || !reflect.DeepEqual(executableObservations, wantExecutableObservations) {
		t.Fatalf("executable observations=\n%+v\nwant=\n%+v", executableObservations, wantExecutableObservations)
	}
	if packageObservationCount != 2 || !reflect.DeepEqual(packageObservations, wantPackageObservations) {
		t.Fatalf("package observations=\n%+v\nwant=\n%+v", packageObservations, wantPackageObservations)
	}
	if packageObservations["pip"].Metadata["executable_observation_id"] == packageObservations["uv"].Metadata["executable_observation_id"] {
		t.Fatal("pip and uv package observations cross-linked to the same executable observation")
	}
}

func matrixObservationsForSource(inventory model.Inventory, source string) []model.Observation {
	var observations []model.Observation
	for _, observation := range inventory.Observations {
		if observation.Collector == "mcp" && observation.Source == source {
			observations = append(observations, observation)
		}
	}
	return observations
}

func matrixObservationsForAsset(inventory model.Inventory, assetID string) []model.Observation {
	var observations []model.Observation
	for _, observation := range inventory.Observations {
		if observation.AssetID == assetID {
			observations = append(observations, observation)
		}
	}
	return observations
}

func encodeMatrixResult(t *testing.T, result isolatedBaseline) []byte {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Scan      model.ScanResult `json:"scan"`
		Inventory model.Inventory  `json:"inventory"`
		Delta     model.Delta      `json:"delta"`
		Snapshot  model.Snapshot   `json:"snapshot"`
		Report    json.RawMessage  `json:"report"`
	}{result.Scan, result.Inventory, result.Delta, result.Snapshot, result.Report})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func copyOfficialFixtureHome(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs("../../testdata/home")
	if err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := os.CopyFS(destination, os.DirFS(source)); err != nil {
		t.Fatal(err)
	}
	return destination
}

func privateMatrixTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeMatrixFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func matrixCommandKey(command string, args ...string) string {
	return strings.Join(append([]string{command}, args...), "\x1f")
}

type matrixStatus struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Initialized            bool                    `json:"initialized"`
	InventorySchemaVersion string                  `json:"inventorySchemaVersion"`
	LegacyInventory        bool                    `json:"legacyInventory"`
	Scope                  *model.ScanScope        `json:"scope"`
	Coverage               []model.CollectorResult `json:"coverage"`
	EvidenceCoverage       *model.EvidenceCoverage `json:"evidenceCoverage"`
	Inventory              *model.Inventory        `json:"inventory"`
}

func readMatrixStatusFromReader(t *testing.T, reader cli.StatusReader) matrixStatus {
	t.Helper()
	raw := readMatrixStatusRaw(t, reader)
	var status matrixStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, raw)
	}
	return status
}

func readMatrixStatusRaw(t *testing.T, reader cli.StatusReader) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := (cli.App{StatusReader: reader}).Run(context.Background(), []string{"status", "--json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("status exit=%d stderr=%q", code, stderr.String())
	}
	return stdout.Bytes()
}

func readMatrixStatusFromPath(t *testing.T, databasePath string) matrixStatus {
	t.Helper()
	snapshots, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	status := readMatrixStatusFromReader(t, snapshots)
	if err := snapshots.Close(); err != nil {
		t.Fatal(err)
	}
	return status
}

func createMigrationThreeLegacyDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(privateMatrixTempDir(t), "legacy.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(legacyMigrationThreeSchema); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 3; version++ {
		if _, err := database.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, "2026-08-06T00:00:00.000000000Z"); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	if _, err := database.Exec(`INSERT INTO scans(id, schema_version, status, started_at, finished_at) VALUES (?, ?, ?, ?, ?)`,
		"legacy-migration-three", "ssc-init.scan.v1", "complete", "2026-08-06T00:00:00.000000000Z", "2026-08-06T00:00:01.000000000Z"); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	wantInventory := migrationThreeLegacyInventory()
	if _, err := database.Exec(`INSERT INTO inventory_state(scan_id, assets_nil, relationships_nil, errors_nil, asset_count, relationship_count, error_count) VALUES (?, 0, 0, 0, ?, ?, ?)`,
		"legacy-migration-three", len(wantInventory.Assets), len(wantInventory.Relationships), len(wantInventory.Errors)); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	for index := len(wantInventory.Assets) - 1; index >= 0; index-- {
		asset := wantInventory.Assets[index]
		encoded, err := json.Marshal(asset)
		if err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
		if _, err := database.Exec(`INSERT INTO assets(scan_id, asset_id, asset_json) VALUES (?, ?, ?)`, "legacy-migration-three", asset.ID, encoded); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
		metadataNil := 0
		if asset.Metadata == nil {
			metadataNil = 1
		}
		if _, err := database.Exec(`INSERT INTO asset_state(scan_id, asset_id, asset_index, metadata_nil) VALUES (?, ?, ?, ?)`, "legacy-migration-three", asset.ID, index, metadataNil); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	for index, relationship := range wantInventory.Relationships {
		if _, err := database.Exec(`INSERT INTO relationships(scan_id, from_id, kind, to_id) VALUES (?, ?, ?, ?)`, "legacy-migration-three", relationship.From, relationship.Kind, relationship.To); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
		if _, err := database.Exec(`INSERT INTO relationship_state(scan_id, from_id, kind, to_id, relationship_index) VALUES (?, ?, ?, ?, ?)`, "legacy-migration-three", relationship.From, relationship.Kind, relationship.To, index); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	for index, inventoryError := range wantInventory.Errors {
		encoded, err := json.Marshal(inventoryError)
		if err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
		if _, err := database.Exec(`INSERT INTO inventory_errors(scan_id, error_index, error_json) VALUES (?, ?, ?)`, "legacy-migration-three", index, encoded); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	wantCoverage := migrationThreeLegacyCoverage()
	for index := len(wantCoverage) - 1; index >= 0; index-- {
		collectorResult := wantCoverage[index]
		encoded, err := json.Marshal(collectorResult)
		if err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
		if _, err := database.Exec(`INSERT INTO coverage(scan_id, collector, result_json) VALUES (?, ?, ?)`, "legacy-migration-three", collectorResult.Collector, encoded); err != nil {
			_ = database.Close()
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func migrationThreeLegacyInventory() model.Inventory {
	return model.Inventory{
		Assets: []model.Asset{
			{ID: "agent-plugin:codex:legacy-plugin@1.0.0", Type: model.AssetAgentPlugin, Name: "legacy-plugin", Version: "1.0.0", Source: "codex", Metadata: map[string]string{"channel": "stable"}},
			{ID: "mcp:shared:legacy-server", Type: model.AssetMCP, Name: "legacy-server", Source: "shared"},
		},
		Relationships: []model.Relationship{{From: "agent-plugin:codex:legacy-plugin@1.0.0", To: "mcp:shared:legacy-server", Kind: "configures"}},
		Errors: []model.CoverageError{
			{Code: "legacy_manifest_partial", Message: "legacy plugin evidence was incomplete", Path: "$HOME/.codex/plugins/legacy-plugin"},
			{Code: "legacy_transport_unknown", Message: "legacy MCP transport was unknown"},
		},
	}
}

func migrationThreeLegacyCoverage() []model.CollectorResult {
	inventory := migrationThreeLegacyInventory()
	return []model.CollectorResult{
		{
			Collector: "agents", Status: model.CoveragePartial,
			Assets: []model.Asset{inventory.Assets[0]}, Errors: []model.CoverageError{inventory.Errors[0]},
			Targets: []model.TargetCoverage{{TargetID: "agents.codex.plugins", Status: model.TargetPartial, Assets: 1, Errors: []model.CoverageError{inventory.Errors[0]}}},
		},
		{
			Collector: "mcp", Status: model.CoveragePartial,
			Assets: []model.Asset{inventory.Assets[1]}, Errors: []model.CoverageError{inventory.Errors[1]},
			Targets: []model.TargetCoverage{{TargetID: "mcp.shared.project", InstanceRef: "$HOME/Projects/legacy/.mcp.json", Status: model.TargetPartial, Assets: 1, Errors: []model.CoverageError{inventory.Errors[1]}}},
		},
	}
}

const legacyMigrationThreeSchema = `
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE assets (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, asset_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE relationships (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, from_id, kind, to_id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE coverage (
    scan_id TEXT NOT NULL,
    collector TEXT NOT NULL,
    result_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, collector),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE inventory_state (
    scan_id TEXT PRIMARY KEY,
    assets_nil INTEGER NOT NULL CHECK (assets_nil IN (0, 1)),
    relationships_nil INTEGER NOT NULL CHECK (relationships_nil IN (0, 1)),
    errors_nil INTEGER NOT NULL CHECK (errors_nil IN (0, 1)),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE asset_state (
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_index INTEGER NOT NULL CHECK (asset_index >= 0),
    metadata_nil INTEGER NOT NULL CHECK (metadata_nil IN (0, 1)),
    PRIMARY KEY (scan_id, asset_id),
    UNIQUE (scan_id, asset_index),
    FOREIGN KEY (scan_id, asset_id) REFERENCES assets(scan_id, asset_id)
);
CREATE TABLE relationship_state (
    scan_id TEXT NOT NULL,
    from_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    to_id TEXT NOT NULL,
    relationship_index INTEGER NOT NULL CHECK (relationship_index >= 0),
    PRIMARY KEY (scan_id, from_id, kind, to_id),
    UNIQUE (scan_id, relationship_index),
    FOREIGN KEY (scan_id, from_id, kind, to_id) REFERENCES relationships(scan_id, from_id, kind, to_id)
);
CREATE TABLE inventory_errors (
    scan_id TEXT NOT NULL,
    error_index INTEGER NOT NULL CHECK (error_index >= 0),
    error_json BLOB NOT NULL,
    PRIMARY KEY (scan_id, error_index),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
ALTER TABLE inventory_state ADD COLUMN asset_count INTEGER NOT NULL DEFAULT 0 CHECK (asset_count >= 0);
ALTER TABLE inventory_state ADD COLUMN relationship_count INTEGER NOT NULL DEFAULT 0 CHECK (relationship_count >= 0);
ALTER TABLE inventory_state ADD COLUMN error_count INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0);
UPDATE inventory_state SET
    asset_count = (SELECT count(*) FROM assets WHERE assets.scan_id = inventory_state.scan_id),
    relationship_count = (SELECT count(*) FROM relationships WHERE relationships.scan_id = inventory_state.scan_id),
    error_count = (SELECT count(*) FROM inventory_errors WHERE inventory_errors.scan_id = inventory_state.scan_id);
CREATE INDEX scans_latest_idx ON scans(finished_at DESC, id DESC);
`

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type matrixFileSystem struct {
	platform.OSFileSystem
	root string

	mu     sync.Mutex
	denied []string
}

func (f *matrixFileSystem) ReadFile(name string) ([]byte, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadFile(name)
}

func (f *matrixFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.ReadDir(name)
}

func (f *matrixFileSystem) Stat(name string) (os.FileInfo, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.Stat(name)
}

func (f *matrixFileSystem) Lstat(name string) (os.FileInfo, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.Lstat(name)
}

func (f *matrixFileSystem) WalkDir(root string, walk fs.WalkDirFunc) error {
	if !f.allows(root) {
		return fs.ErrPermission
	}
	return f.OSFileSystem.WalkDir(root, walk)
}

func (f *matrixFileSystem) OpenRoot(name string) (platform.RootedDirectory, error) {
	if !f.allows(name) {
		return nil, fs.ErrPermission
	}
	return f.OSFileSystem.OpenRoot(name)
}

func (f *matrixFileSystem) allows(name string) bool {
	relative, err := filepath.Rel(filepath.Clean(f.root), filepath.Clean(name))
	allowed := err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	if !allowed {
		f.mu.Lock()
		f.denied = append(f.denied, filepath.Clean(name))
		f.mu.Unlock()
	}
	return allowed
}

func (f *matrixFileSystem) deniedPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.denied...)
}

type matrixRunner struct {
	mu         sync.Mutex
	failOnCall bool
	calls      int
	events     *matrixEventLog
	results    map[string]platform.CommandResult
	errors     map[string]error
}

func (r *matrixRunner) Run(_ context.Context, command string, args ...string) (platform.CommandResult, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.failOnCall {
		return platform.CommandResult{}, errors.New("matrix runner must not be called")
	}
	key := strings.Join(append([]string{command}, args...), "\x1f")
	if r.events != nil {
		r.events.add("run:" + key)
	}
	return r.results[key], r.errors[key]
}

func (r *matrixRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type matrixInspector struct {
	mu          sync.Mutex
	failOnCall  bool
	inspectCall int
	verifyCall  int
	events      *matrixEventLog
	evidence    map[string]platform.ExecutableEvidence
	errors      map[string]error
}

func (i *matrixInspector) Inspect(_ context.Context, _ string, command string) (platform.ExecutableEvidence, error) {
	i.mu.Lock()
	i.inspectCall++
	i.mu.Unlock()
	if i.failOnCall {
		return platform.ExecutableEvidence{}, errors.New("matrix inspector must not be called")
	}
	if i.events != nil {
		i.events.add("inspect:" + command)
	}
	return i.evidence[command], i.errors[command]
}

func (i *matrixInspector) Verify(evidence platform.ExecutableEvidence) error {
	i.mu.Lock()
	i.verifyCall++
	i.mu.Unlock()
	if i.failOnCall {
		return errors.New("matrix inspector must not be called")
	}
	if i.events != nil {
		i.events.add("verify:" + evidence.Command)
	}
	return nil
}

func (i *matrixInspector) callCounts() (int, int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.inspectCall, i.verifyCall
}

type matrixEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *matrixEventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *matrixEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}
