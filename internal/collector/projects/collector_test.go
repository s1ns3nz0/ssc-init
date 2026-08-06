package projects_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ssc-init/ssc-init/internal/collector/projects"
	"github.com/ssc-init/ssc-init/internal/model"
	"github.com/ssc-init/ssc-init/internal/platform"
	"github.com/ssc-init/ssc-init/internal/testutil"
)

func TestProjectsCollectorFindsLockfileAndSkipsNodeModules(t *testing.T) {
	env := testutil.Environment(t, "../../../testdata/home")
	got, err := projects.New([]string{"$HOME/Projects", "$HOME/Projects/."}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}

	manifest := testutil.AssertAsset(t, got.Assets, "project-file:manifest:$HOME/Projects/sample/package.json")
	lockfile := testutil.AssertAsset(t, got.Assets, "project-file:lockfile:$HOME/Projects/sample/package-lock.json")
	projectMCP := testutil.AssertAsset(t, got.Assets, "project-file:mcp:$HOME/Projects/sample/.vscode/mcp.json")
	if manifest.Path != "$HOME/Projects/sample/package.json" || lockfile.Path != "$HOME/Projects/sample/package-lock.json" || projectMCP.Path != "$HOME/Projects/sample/.vscode/mcp.json" {
		t.Fatalf("manifest=%+v lockfile=%+v projectMCP=%+v", manifest, lockfile, projectMCP)
	}
	projectPath := "$HOME/Projects/sample"
	projectID := fmt.Sprintf("project:sha256:%x", sha256.Sum256([]byte(projectPath)))
	project := testutil.AssertAsset(t, got.Assets, projectID)
	if project.Type != model.AssetProject || project.Path != projectPath {
		t.Fatalf("project=%+v", project)
	}
	wantRelationships := []model.Relationship{
		{From: projectID, To: lockfile.ID, Kind: "contains"},
		{From: projectID, To: manifest.ID, Kind: "contains"},
		{From: projectID, To: projectMCP.ID, Kind: "contains"},
	}
	if !reflect.DeepEqual(got.Relationships, wantRelationships) {
		t.Fatalf("relationships=%+v want=%+v", got.Relationships, wantRelationships)
	}
	for _, asset := range got.Assets {
		if strings.Contains(asset.Path, "node_modules") {
			t.Fatalf("unexpected=%s", asset.Path)
		}
	}
	if got.Status != model.CoverageComplete {
		t.Fatalf("status=%s errors=%+v", got.Status, got.Errors)
	}
}

func TestProjectsCollectorSkipsEffectivelyEmptyRootSet(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := testutil.Environment(t, home)

	for _, roots := range [][]string{nil, {}, {""}, {" ", "\t", "\n"}} {
		got, err := projects.New(roots).Collect(context.Background(), env)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != model.CoverageSkipped || len(got.Assets) != 0 {
			t.Fatalf("roots=%q result=%+v", roots, got)
		}
	}
}

func TestProjectsCollectorPreservesSpacesInSuppliedRoot(t *testing.T) {
	home := t.TempDir()
	for _, directory := range []string{"Projects", "Projects "} {
		path := filepath.Join(home, directory, "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := testutil.Environment(t, home)

	got, err := projects.New([]string{"$HOME/Projects "}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "project-file:manifest:$HOME/Projects /package.json")
	for _, asset := range got.Assets {
		if asset.Path == "$HOME/Projects/package.json" || asset.Path == "$HOME/Projects" {
			t.Fatalf("traversed unsupplied root: %+v", asset)
		}
	}
}

func TestProjectsCollectorRecognizesSupportedFilesAndProjectMCP(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "Projects", "polyglot")
	files := []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
		"pyproject.toml", "requirements.txt", "requirements-dev.txt", "uv.lock",
		"Cargo.toml", "Cargo.lock", "go.mod", "go.sum", filepath.Join(".vscode", "mcp.json"),
	}
	for _, name := range files {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	env := testutil.Environment(t, home)
	got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		kind := "manifest"
		switch name {
		case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "uv.lock", "Cargo.lock", "go.sum":
			kind = "lockfile"
		case filepath.Join(".vscode", "mcp.json"):
			kind = "mcp"
		}
		redacted := filepath.ToSlash(filepath.Join("$HOME/Projects/polyglot", name))
		testutil.AssertAsset(t, got.Assets, "project-file:"+kind+":"+redacted)
	}
}

func TestProjectsCollectorStaysWithinRootsAndExcludesHeavyDirectories(t *testing.T) {
	home := t.TempDir()
	inside := filepath.Join(home, "allowed", "app", "package.json")
	outside := filepath.Join(home, "outside", "package.json")
	excluded := []string{
		"node_modules", ".venv", "venv", "vendor", "dist", "build", "Library", ".cache",
		".npm", ".pnpm-store", ".yarn", ".bun", ".cargo", ".rustup", ".gradle", ".m2",
		".ivy2", ".nuget", ".pub-cache", filepath.Join(".git", "objects"),
	}
	for _, path := range append([]string{inside, outside}, pathsUnder(home, "allowed", excluded)...) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	env := testutil.Environment(t, home)
	got, err := projects.New([]string{"$HOME/allowed"}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertAsset(t, got.Assets, "project-file:manifest:$HOME/allowed/app/package.json")
	for _, asset := range got.Assets {
		if strings.Contains(asset.Path, "$HOME/outside") {
			t.Fatalf("scanned outside root: %+v", asset)
		}
		for _, dir := range excluded {
			if strings.Contains(asset.Path, filepath.ToSlash(dir)) {
				t.Fatalf("scanned excluded directory %q: %+v", dir, asset)
			}
		}
	}
}

func TestProjectsCollectorEnforcesDepthTwelve(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "Projects")
	atDepthTwelve := filepath.Join(append([]string{root}, append(repeat("d", 11), "package.json")...)...)
	beyondDepthTwelve := filepath.Join(append([]string{root}, append(repeat("x", 12), "package.json")...)...)
	for _, path := range []string{atDepthTwelve, beyondDepthTwelve} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	env := testutil.Environment(t, home)
	got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Assets) != 2 {
		t.Fatalf("assets=%+v", got.Assets)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Code != "depth_limit" {
		t.Fatalf("status=%s errors=%+v", got.Status, got.Errors)
	}
}

func TestProjectsCollectorEnforcesEntryLimitPerRoot(t *testing.T) {
	home := "/synthetic/home"
	env := testutil.Environment(t, t.TempDir())
	env.Home = home
	env.FS = countingFS{entries: 100_001}
	got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.CoveragePartial || len(got.Errors) != 1 || got.Errors[0].Code != "entry_limit" {
		t.Fatalf("status=%s errors=%+v", got.Status, got.Errors)
	}
}

func TestProjectsCollectorDoesNotPersistGitRemoteSecrets(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, "Projects", "secret", ".git", "config")
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_do_not_persist"
	if err := os.WriteFile(config, []byte("[remote \"origin\"]\nurl = https://user:"+secret+"@example.test/acme/repo.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := testutil.Environment(t, home)
	got, err := projects.New([]string{"$HOME/Projects"}).Collect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), secret) {
		t.Fatalf("secret persisted: %+v", got)
	}
	if len(got.Assets) != 1 || got.Assets[0].Type != model.AssetProject {
		t.Fatalf("assets=%+v", got.Assets)
	}
}

func pathsUnder(home, root string, directories []string) []string {
	paths := make([]string, 0, len(directories))
	for _, directory := range directories {
		paths = append(paths, filepath.Join(home, root, directory, "package.json"))
	}
	return paths
}

func repeat(value string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value
	}
	return values
}

type countingFS struct {
	entries int
}

func (f countingFS) ReadFile(string) ([]byte, error)       { return nil, fs.ErrNotExist }
func (f countingFS) ReadDir(string) ([]os.DirEntry, error) { return nil, fs.ErrNotExist }
func (f countingFS) Stat(string) (os.FileInfo, error)      { return nil, fs.ErrNotExist }
func (f countingFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	if err := fn(root, syntheticDirEntry{name: filepath.Base(root), dir: true}, nil); err != nil {
		return err
	}
	for i := 0; i < f.entries; i++ {
		path := filepath.Join(root, fmt.Sprintf("file-%06d.txt", i))
		if err := fn(path, syntheticDirEntry{name: filepath.Base(path)}, nil); err != nil {
			return err
		}
	}
	return nil
}

type syntheticDirEntry struct {
	name string
	dir  bool
}

func (e syntheticDirEntry) Name() string               { return e.name }
func (e syntheticDirEntry) IsDir() bool                { return e.dir }
func (e syntheticDirEntry) Type() fs.FileMode          { return 0 }
func (e syntheticDirEntry) Info() (fs.FileInfo, error) { return nil, fs.ErrInvalid }

var _ platform.FileSystem = countingFS{}
