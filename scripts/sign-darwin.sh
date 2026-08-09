#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${SSC_INIT_DIST_DIR:-$REPOSITORY_ROOT/dist}
UNIVERSAL="$DIST_DIR/ssc-init-darwin-universal"
BUNDLE_IDENTIFIER=${SSC_INIT_BUNDLE_IDENTIFIER:-dev.sscinit.core}

if [ -z "${SSC_INIT_SIGNING_IDENTITY:-}" ]; then
	echo "SSC_INIT_SIGNING_IDENTITY is not set; a Developer ID Application identity is required to sign" >&2
	exit 1
fi

if [ ! -f "$UNIVERSAL" ]; then
	echo "universal binary not found; run scripts/build-darwin.sh first" >&2
	exit 1
fi

codesign \
	--sign "$SSC_INIT_SIGNING_IDENTITY" \
	--identifier "$BUNDLE_IDENTIFIER" \
	--options runtime \
	--timestamp \
	--force \
	"$UNIVERSAL"

codesign --verify --strict --verbose=2 "$UNIVERSAL"

shasum -a 256 "$UNIVERSAL" | sed "s|$DIST_DIR/|dist/|" > "$DIST_DIR/checksums-signed.txt"
