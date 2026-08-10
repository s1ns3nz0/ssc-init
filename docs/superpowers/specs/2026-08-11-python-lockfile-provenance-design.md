# Python Lockfile Provenance Design

Date: 2026-08-11

Authority: foundation design §4.4, §5.2, §6.1–§6.3 and Program D's bounded
local provenance model.

## 1. Goal

Turn the Python project files that the project collector already discovers
into bounded package provenance and graph facts. The supported formats are
`requirements.txt`, `Pipfile.lock`, `poetry.lock`, and `uv.lock`.

This program reads only local files. It performs no registry lookup, package
manager execution, environment resolution, installation, or source download.
It does not claim that a package is safe.

## 2. Architecture

`internal/provenance` owns four format-specific parsers behind the existing
`Parse` entry point. Each parser emits the existing normalized `Record` type.
`internal/collector/projects` maps the four basenames to their formats and
reuses its existing descriptor-rooted open, size bound, cancellation,
discovery-fingerprint comparison, post-read identity check, asset creation,
and `declared-by` relationship path.

The parsers remain separate because the formats have different grammars and
integrity semantics. Shared helpers own only PyPI name normalization, version
classification, SHA-256 decoding, record conflict detection, and deterministic
sorting.

No model or database schema change is required. The output remains within the
current `ssc-init.scan.v7` contract.

## 3. Common output rules

Every accepted dependency produces:

- ecosystem `pypi`;
- a normalized PEP 503-style package name: ASCII letters are lowercased and
  each run of `.`, `_`, or `-` becomes one `-`;
- the exact version text when the source format provides one;
- provenance source `lockfile`;
- a package asset connected to its source lockfile by `declared-by`.

Names and versions must also pass the existing bounded, printable,
path-excluding coordinate validation. Empty names, duplicate normalized
coordinates with conflicting facts, unsupported containers, trailing data,
invalid encodings, and invalid integrity fields make the complete lockfile
provenance parse fail with the fixed `ErrMalformed` error. Errors never include
the offending name, version, URL, path, or digest.

The collector persists no raw requirement line, source URL, index URL,
credential, marker expression, local path, filename, or complete hash list.

## 4. Provenance classification

Classification is deliberately conservative:

- `immutable`: an exact version is present and the dependency resolves to
  exactly one distinct valid SHA-256 artifact digest in the lockfile;
- `unknown`: an exact version is present but no digest is present, or the
  format lists multiple valid artifact digests for the same coordinate because
  the installed platform artifact is not known;
- `mutable`: the dependency is editable, path-based, URL-based, VCS-based,
  workspace-based, unversioned, or uses a range/wildcard rather than one exact
  version.

Only an `immutable` record carries `sha256:<lowercase-hex>` in
`Provenance.Integrity`. A multi-hash record does not select an arbitrary hash
and does not retain the hash set. Invalid declared SHA-256 values fail closed;
valid non-SHA-256 hashes are ignored as unsupported integrity evidence.

Environment markers and optional/development groups do not change identity.
If the same normalized name and version appears in multiple groups, identical
facts deduplicate. Conflicting facts fail closed instead of choosing a group.

## 5. Format contracts

### 5.1 `requirements.txt`

The supported logical requirement form is a single physical line containing
an optional leading whitespace prefix, a package name, `==`, one exact
version, optional environment marker, and zero or more `--hash` options.
Continuation lines ending in `\` are joined before parsing. Blank lines and
full-line comments are ignored; an unescaped trailing `#` begins a comment.

Options that configure indexes, find-links, trusted hosts, constraints, or
requirements includes are ignored as non-package configuration and are never
persisted. Editable requirements, direct references, VCS/URL/path entries,
and non-`==` specifiers produce a `mutable` record only when a safe package
name is explicitly available; ambiguous unnamed entries are skipped. The
parser never opens an included file.

Hashes accept only the exact `sha256:<64 lowercase hex>` form after
`--hash=` or `--hash <value>`. A declared malformed SHA-256 fails the parse.

### 5.2 `Pipfile.lock`

The document must be one JSON value with unique object keys and no trailing
data. Dependencies are read from the `default` and `develop` objects. Each
dependency must be an object. `version: "==X"` is exact; other version forms,
`path`, `file`, `git`, or `editable: true` are mutable. `hashes` is an optional
array of integrity strings governed by the common classification rules.

The `_meta` object and source/index declarations are ignored and never
persisted.

### 5.3 `poetry.lock`

The document is parsed as TOML with the existing pinned pure-Go TOML module.
Each `[[package]]` entry supplies `name`, `version`, optional `develop`,
optional `source`, and optional `files`. Registry packages with one exact
version follow the common hash rules over `files[].hash`. Directory, file,
URL, Git, and editable/develop source types are mutable.

Lock metadata such as `content-hash`, groups, Python constraints, markers,
extras, and filenames is not persisted.

### 5.4 `uv.lock`

The document is parsed as TOML with the same pinned parser. Each `[[package]]`
entry supplies `name`, optional `version`, source information, and optional
`sdist`/`wheels` artifact hashes. A registry source with one exact version
follows the common hash rules over every declared artifact. Git, URL, path,
editable, virtual, workspace, or missing-version entries are mutable.

Resolution metadata, Python constraints, markers, dependency edges, source
URLs, filenames, and indexes are not persisted in this slice. Dependency-edge
extraction remains a separate graph expansion because the current model cannot
truthfully bind marker-conditional edges to a selected Python environment.

## 6. Failure and coverage behavior

An unsupported Python project file remains ordinary bounded content evidence;
it is not silently treated as parsed provenance. For a supported file:

- oversize, cancellation, and identity-change behavior remains owned by the
  existing project collector boundary;
- malformed provenance adds the existing fixed
  `provenance_malformed` coverage error and emits no package records from that
  file;
- one hostile lockfile does not erase safe sibling project evidence;
- cancellation propagates and does not persist a partial parse;
- deterministic input produces byte-identical assets, observations,
  relationships, reports, and snapshot state.

## 7. Testing

Each format receives parser tests for exact, hashless, single-hash,
multi-hash, mutable, duplicate, malformed, oversize, cancellation, and stable
sorting behavior. JSON tests include duplicate keys and trailing values. TOML
tests include wrong container types and invalid artifact hashes.

Project collector tests prove basename routing, package assets, PyPI identity,
`declared-by` relationships, identity drift refusal, sibling isolation, and
privacy-safe errors. Acceptance tests scan an isolated project containing all
four formats and verify that no raw path, URL, credential, marker, filename,
or unselected digest enters serialized output.

The final gate is:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
go mod verify
git diff --check
```

No runtime dependency, network permission, CLI flag, schema migration, or
external process is added.
