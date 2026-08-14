# Task 7 Report: Publication Workflow and End-to-End Acceptance

Status: implementation complete; production provisioning remains externally blocked.

## Implementation

- Added a manually approved, serialized TI publication workflow with pinned
  action SHAs, read-only default permissions, publication-job-only contents
  write, bounded HTTPS source downloads, exact source digest checks, monotonic
  immutable tags, protected key handling, post-sign verification through the
  compiled production registry, four-asset upload, and always cleanup.
- Added an explicit key-generation script. It prints only the public key and
  operator guidance unless an absolute private output is requested; that file
  is exclusive and mode 0600. The publication script rejects tracked dirty
  state, absent provenance/digests, test/placeholder IDs, nonpositive or
  nonmonotonic sequences, and existing release tags.
- Added a closed `publisher verify` subcommand because workflow post-sign
  verification cannot safely accept a public key at runtime. It reads the exact
  four artifact names through bounded regular-file snapshots, uses only
  `bundle.ProductionKeys()`, checks manifest/bundle binding, and emits closed
  path-free failures. Its function seam exists only for package tests.
- Added operator documentation for licensing, dual-key rotation, compromise,
  higher-sequence emergency withdrawal, rollback semantics, immutable release
  operation, and real Mac smoke evidence. The public repo ID, key, protected
  environment, initial release, and real evidence are explicitly blocked.

## End-to-end acceptance

The real CLI test builds `ssc-init` with the exclusive `ti_acceptance` build
tag, uses an isolated real HOME and bounded local TLS feed, runs actual `bundle
update --family ti --json` for sequence 1, then actual `scan --baseline
--update-ti --json` for sequence 2 over npm/PyPI fixture manifests. Reloading
the generated audit ZIP proves one known-malicious finding, one ordinary OSV
needs-review finding, signed counts, and sequence-2 bundle references.

The tag-only file supplies local TLS roots/base/repository identity/test trust
to this separately built acceptance binary. `go list` proves the file is absent
from default builds. A normal built CLI is separately run with hostile lookalike
environment values and a default scan makes zero feed requests.

Supplemental component lifecycle coverage proves missing -> seq1, invalid
manifest signature preserving seq1 LKG, same-length bundle digest mismatch
rejection, seq2 activation, lower-sequence rejection, deterministic signed
fixture bytes, correlation, audit reload, and absence of URL/path/secret bytes.
These assertions cover the six required mutation boundaries: default-network
guard, manifest signature, bundle digest, rollback, classification separation,
and update-before-finding evaluation.

All six source mutations were executed individually and restored. The exact RED
signals were: default scan made four feed requests; bad manifest signature
advanced visible LKG state to sequence 2; digest bypass returned `updated`;
rollback guard bypass fetched four files instead of manifest/signature only;
classifier merge produced 4 malicious/0 vulnerable instead of 2/2; and deferred
update archived a TI finding bound to sequence 1 instead of sequence 2. The
rollback and ordering exercises found two initially insensitive assertions;
both tests were strengthened before the mutations were rerun RED.

## Verification before commit

Focused acceptance, workflow, production-build exclusion, publisher verify,
module verification, formatting, build, vet, and race gates passed. The legacy
release-script tests intentionally require a clean commit and are rerun after
this commit.

## External stop

No GitHub repository, environment, secret, release, tag, or production key was
created or changed. Production remains fail closed because
`productionTIRepositoryID` and `ProductionKeys()` are intentionally empty.
