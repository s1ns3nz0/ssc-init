#!/bin/sh
set -eu

: "${TI_OSV_SOURCE:?absolute pinned OSV snapshot required}"
: "${TI_OPENSSF_SOURCE:?absolute pinned OpenSSF snapshot required}"
: "${TI_OSV_SHA256:?OSV digest required}"
: "${TI_OPENSSF_SHA256:?OpenSSF digest required}"
: "${TI_OSV_REVISION:?OSV source revision required}"
: "${TI_OPENSSF_REVISION:?OpenSSF source revision required}"
: "${TI_OSV_LICENSE:?reviewed OSV license required}"
: "${TI_OPENSSF_LICENSE:?reviewed OpenSSF license required}"
: "${TI_SOURCE_RETRIEVED_AT:?source retrieval timestamp required}"
: "${TI_OSV_PUBLIC_URL:?public OSV snapshot URL required}"
: "${TI_OPENSSF_PUBLIC_URL:?public OpenSSF snapshot URL required}"
: "${TI_VERSION:?version required}"
: "${TI_SEQUENCE:?sequence required}"
: "${TI_KEY_ID:?reviewed key ID required}"
: "${TI_GENERATED_AT:?generated time required}"
: "${TI_VALID_FROM:?valid-from time required}"
: "${TI_VALID_UNTIL:?valid-until time required}"
: "${TI_PRIVATE_KEY_FILE:?absolute private key file required}"
: "${TI_OUTPUT_DIR:?absolute existing output directory required}"

case "$TI_OSV_SOURCE:$TI_OPENSSF_SOURCE:$TI_PRIVATE_KEY_FILE:$TI_OUTPUT_DIR" in /*:/*:/*:/*) ;; *) echo "publication paths must be absolute" >&2; exit 2;; esac
case "$TI_KEY_ID" in test*|TEST*|placeholder*|PLACEHOLDER*) echo "test or placeholder key ID refused" >&2; exit 1;; esac
case "$TI_SEQUENCE" in ''|*[!0-9]*|0) echo "sequence must be a positive integer" >&2; exit 2;; esac

git diff --quiet HEAD -- && git diff --cached --quiet || { echo "publication requires a clean tracked worktree" >&2; exit 1; }
printf '%s  %s\n' "$TI_OSV_SHA256" "$TI_OSV_SOURCE" | shasum -a 256 -c - >/dev/null
printf '%s  %s\n' "$TI_OPENSSF_SHA256" "$TI_OPENSSF_SOURCE" | shasum -a 256 -c - >/dev/null

tag=$(printf 'ti-%08d' "$TI_SEQUENCE")
if [ -n "${TI_LAST_SEQUENCE:-}" ] && [ "$TI_SEQUENCE" -le "$TI_LAST_SEQUENCE" ]; then
  echo "sequence must be greater than the last published sequence" >&2
  exit 1
fi
if [ "${TI_RELEASE_TAG_EXISTS:-0}" = 1 ]; then
  echo "immutable release tag already exists" >&2
  exit 1
fi

go run ./cmd/ssc-init-ti-publisher \
  --osv-source "$TI_OSV_SOURCE" --osv-license "$TI_OSV_LICENSE" --osv-base-url https://osv.dev/vulnerability/ \
  --openssf-source "$TI_OPENSSF_SOURCE" --openssf-license "$TI_OPENSSF_LICENSE" --openssf-base-url https://github.com/ossf/malicious-packages/blob/main/osv/malicious/ \
  --version "$TI_VERSION" --sequence "$TI_SEQUENCE" --key-id "$TI_KEY_ID" \
  --generated-at "$TI_GENERATED_AT" --valid-from "$TI_VALID_FROM" --valid-until "$TI_VALID_UNTIL" --output-dir "$TI_OUTPUT_DIR"

go run ./cmd/ssc-init-ti-publisher sign \
  --manifest-file "$TI_OUTPUT_DIR/ti-manifest.json" --bundle-file "$TI_OUTPUT_DIR/ti-bundle.json" \
  --private-key-file "$TI_PRIVATE_KEY_FILE" --key-id "$TI_KEY_ID" --output-dir "$TI_OUTPUT_DIR"

for file in ti-manifest.json ti-manifest.sig ti-bundle.json ti-bundle.sig attribution-report.json; do
  [ -s "$TI_OUTPUT_DIR/$file" ] || { echo "publication artifact missing" >&2; exit 1; }
done
go run ./scripts/write-ti-provenance.go "$TI_OUTPUT_DIR/source-provenance.json" \
  "$TI_SOURCE_RETRIEVED_AT" "$TI_OSV_REVISION" "$TI_OSV_SHA256" "$TI_OSV_LICENSE" "$TI_OSV_PUBLIC_URL" \
  "$TI_OPENSSF_REVISION" "$TI_OPENSSF_SHA256" "$TI_OPENSSF_LICENSE" "$TI_OPENSSF_PUBLIC_URL"
(cd "$TI_OUTPUT_DIR" && shasum -a 256 ti-manifest.json ti-manifest.sig ti-bundle.json ti-bundle.sig attribution-report.json source-provenance.json > checksums.txt)
printf 'prepared immutable TI release %s\n' "$tag"
