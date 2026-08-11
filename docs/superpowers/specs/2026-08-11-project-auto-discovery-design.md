# Project Auto-Discovery Design

Date: 2026-08-11

Authority: foundation design §4.3–§4.4, §5.2.1–§5.2.2, §6.1, §10–§12,
and the existing project collector's descriptor-rooted filesystem boundary.

## 1. Goal

Discover local projects from bounded IDE workspace metadata and Git linked
worktree metadata when the user does not supply `--project-root`. Feed the
validated `$HOME`-local directories into the existing project collector
without persisting raw IDE history, absolute paths, remote workspace
locations, repository names, or metadata content.

This feature reduces dependence on the conventional `$HOME/Projects`
directory. It does not broaden scanning to the complete home directory,
external volumes, network mounts, remote IDE targets, or arbitrary recent-file
history.

## 2. User-visible contract

- One or more explicit `--project-root` values disable automatic discovery.
  Only the explicit roots are resolved and scanned.
- With no explicit root, `$HOME/Projects` remains the conventional seed and is
  combined with auto-discovered roots.
- Only existing regular directories strictly inside `$HOME` are eligible as
  discovered projects. `$HOME` itself is never an auto-discovered project
  root. The conventional `$HOME/Projects` scope placeholder is the sole
  exception: it remains present when missing so existing `not_present`
  behavior stays compatible, but it yields no discovered project.
- Auto-discovery performs no process execution and opens no socket.
- The final deterministic root references are recorded in the existing scan
  scope before collection begins; no scan schema change is required.
- Missing metadata is `not_present`. Malformed, oversize, identity-changing,
  or partially unreadable metadata produces privacy-safe component detail and
  does not invalidate safe siblings.

## 3. Architecture

Add a bounded discovery prepass under `internal/collector/projects`. It runs
before `scan.Service.Baseline` receives its final scope and returns:

```go
type Discovery struct {
    Roots    []Root
    Coverage []model.TargetCoverage
}

func DiscoverRoots(ctx context.Context, env collector.Environment) (Discovery, error)
```

`DiscoverRoots` owns source catalogs and parsing. `ResolveRoots` remains the
only path for explicit CLI values. Both paths produce the existing sealed
`Root` values, and `projects.New` remains the only project collector.

The automatic flow is:

1. Seed `$HOME/Projects` if it exists as a safe directory.
2. Read the closed IDE metadata catalog and collect candidate local project
   directories.
3. Perform a metadata-only bounded walk below the conventional seed and the
   verified IDE candidates to locate repository administration entries.
4. Read linked-worktree backlinks and collect additional candidates.
5. Validate, canonicalize, deduplicate, minimize nesting, sort, cap, and seal
   all candidates.
6. Construct `model.ScanScope.ProjectRoots` from the final root references.
7. Run the unchanged project collector over those roots.

The prepass may revisit directory entries that the project collector later
walks. That deliberate duplication keeps scan scope immutable and truthful
before collection. The prepass reads directory names and Git administration
metadata only; it never hashes manifests or parses project content.

## 4. Closed discovery sources

### 4.1 VS Code family

The source catalog contains these macOS roots:

- `$HOME/Library/Application Support/Code/User/workspaceStorage`;
- `$HOME/Library/Application Support/Cursor/User/workspaceStorage`;
- `$HOME/Library/Application Support/Windsurf/User/workspaceStorage`.

Below each root, at most 256 direct child directories are considered, sorted
by basename. Only a direct `workspace.json` regular file is opened. The file
limit is 64 KiB. The accepted JSON is one object with unique keys and no
trailing value. It may identify one `folder` URI or one local workspace
configuration URI. Only canonical `file:` URIs with no authority, user-info,
query, or fragment are accepted.

A `.code-workspace` file is not opened in this slice. Its containing directory
is the candidate. Remote SSH, Dev Container, WSL, tunnel, virtual-workspace,
and unknown schemes produce no candidate.

### 4.2 JetBrains

The source root is `$HOME/Library/Application Support/JetBrains`. At most 32
direct product directories are considered, sorted by basename. Only
`options/recentProjects.xml` is opened, with a 256 KiB limit.

The parser accepts only an `application` document containing a `component`
whose `name` is `RecentProjectsManager` or
`RecentDirectoryProjectsManager`, then an `option name="recentPaths"`, a
`list`, and direct `option value="..."` entries. `$USER_HOME$` and `~`
prefixes may resolve to the configured home. Other components, option names,
variables, URLs, relative paths, and unknown nesting produce no candidate. XML
DTDs, entities, processing instructions, and more than 4,096 tokens are
rejected.

The parser does not retain project names, groups, timestamps, display names,
or window state.

### 4.3 Git linked worktrees

Git discovery never invokes `git`. The prepass considers repositories found
under the conventional seed or exact IDE candidates. Its metadata-only walk
reuses the project walk limits: depth 12, 100,000 entries total, sorted batches
of 256, and the existing excluded-directory catalog. It stops descending when
it finds a repository root. A repository root has either a `.git` directory or
a regular `.git` file. Symlinks are never followed.

For a main-worktree `.git` directory, at most 64 sorted
`.git/worktrees/<id>/gitdir` regular files are read, each limited to 4 KiB.
The backlink must be one absolute canonical path ending in `/.git`. Its parent
directory becomes a candidate only after reciprocal validation: that
candidate's `.git` regular file must point back to the exact administration
directory that supplied the backlink.

For a linked-worktree `.git` file, the administration path is used only to
locate the common repository and validate reciprocity. It is never emitted or
persisted. Stale, prunable, moved, malformed, nonreciprocal, or outside-home
entries produce fixed coverage detail and no candidate.

## 5. Candidate validation

Every IDE or Git candidate passes the same sequence:

1. decode without NUL, control characters, or invalid UTF-8;
2. require an absolute lexically canonical path;
3. require strict containment below the configured home;
4. reject known excluded home subtrees including unrelated `Library`, media,
   caches, backups, Trash, and hidden application state;
5. `Lstat` without following a symlink;
6. open a rooted directory and compare the opened identity to the discovery
   identity;
7. canonicalize to a `$HOME/...` reference;
8. recheck identity immediately before returning the sealed root.

IDE metadata under `Library/Application Support` is a permitted *source* but
can never itself become a project candidate. A candidate under any `Library`
subtree is rejected.

The conventional `$HOME/Projects` placeholder is constructed through the
existing explicit-root resolver and kept separately from discovered
candidates. If it exists, it also undergoes the existing project collector's
no-follow identity validation. If it is missing, it remains only a
`not_present` scope entry and is never treated as a verified discovery result.

Candidate roots are deduplicated by verified filesystem identity and canonical
path. If one candidate contains another, only the parent is retained, except
that `$HOME/Projects` is retained as the conventional parent and subsumed
children are removed. This prevents duplicate project observations.

The final root count remains the existing `maxConfiguredRoots` value of 32.
Selection is deterministic: the conventional seed first, then source priority
`Code`, `Cursor`, `Windsurf`, `JetBrains`, `Git`, then canonical `$HOME` ref.
When the cap is reached, remaining candidates are not accessed by the project
collector and coverage reports `root_limit` without their names or paths.

## 6. Coverage and privacy

Discovery coverage uses a closed source catalog:

- `projects.discovery.vscode`;
- `projects.discovery.cursor`;
- `projects.discovery.windsurf`;
- `projects.discovery.jetbrains`;
- `projects.discovery.git-worktrees`.

Statuses use the existing target vocabulary. Error codes are closed and
messages are fixed: `metadata_malformed`, `metadata_oversize`,
`metadata_unavailable`, `identity_changed`, `symlink_rejected`,
`outside_home`, `remote_unsupported`, and `root_limit`.

Coverage may contain counts but never candidate names, raw paths, URIs,
workspace hashes, Git worktree IDs, JetBrains product directory names, or XML
values. No discovery source becomes an inventory asset. Only projects that the
existing collector subsequently recognizes produce project assets.

Cancellation clears candidate paths and returns the caller error. A failure in
one IDE family or one repository does not erase candidates from safe siblings.
Deterministic input produces byte-identical root ordering, scope, coverage,
inventory, report JSON, and stored snapshot state.

## 7. Integration

Command construction distinguishes explicit and automatic roots before calling
the scan service:

```go
if len(options.ProjectRoots) > 0 {
    roots, err = projects.ResolveRoots(home, options.ProjectRoots)
} else {
    discovery, err = projects.DiscoverRoots(ctx, environment)
    roots = discovery.Roots
}
```

Discovery coverage is supplied to the projects collector constructor and
prepended to its ordinary configured-root coverage. It is not a separate scan
collector and does not add a second project inventory owner.

If no automatic candidate exists, the returned sealed root set contains the
conventional `$HOME/Projects` root even when absent, preserving the current
`not_present` scope and first-run behavior. Explicit root behavior remains
byte-for-byte compatible.

## 8. Testing

Parser tests cover each supported host shape, duplicate JSON keys, trailing
JSON, XML entity/DTD refusal, URI escaping, remote schemes, path variables,
oversize files, cancellation, and deterministic ordering.

Filesystem tests cover metadata and directory replacement, symlinked sources
and candidates, outside-home paths, excluded home subtrees, nested roots,
identity deduplication, root limits, Git backlink reciprocity, stale worktrees,
and hostile sibling isolation.

Integration and acceptance tests prove:

- absent explicit roots enables discovery;
- one explicit root disables every metadata read;
- the final scope is fixed before collection;
- IDE and linked-worktree projects are inventoried;
- default scans execute zero processes and open zero sockets;
- reports and snapshots exclude raw paths, URIs, workspace IDs, repository
  names, worktree IDs, and metadata contents;
- cancellation persists no partial discovery or scan;
- repeated runs are byte-identical.

The final gate is:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
```

No runtime dependency, schema migration, external process, network permission,
or new CLI flag is introduced.
