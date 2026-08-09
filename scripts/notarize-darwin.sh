#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${SSC_INIT_DIST_DIR:-$REPOSITORY_ROOT/dist}
UNIVERSAL="$DIST_DIR/ssc-init-darwin-universal"
DISK_IMAGE="$DIST_DIR/ssc-init-darwin.dmg"

if [ -z "${SSC_INIT_NOTARY_PROFILE:-}" ]; then
	echo "SSC_INIT_NOTARY_PROFILE is not set; run xcrun notarytool store-credentials first" >&2
	exit 1
fi

if [ ! -f "$UNIVERSAL" ]; then
	echo "universal binary not found; run scripts/build-darwin.sh first" >&2
	exit 1
fi

if ! codesign --verify --strict "$UNIVERSAL" >/dev/null 2>&1; then
	echo "universal binary is not signed; run scripts/sign-darwin.sh first" >&2
	exit 1
fi

if [ -z "${SSC_INIT_SIGNING_IDENTITY:-}" ]; then
	echo "SSC_INIT_SIGNING_IDENTITY is not set; the disk image must use the same Developer ID Application identity" >&2
	exit 1
fi

STAGING=$(mktemp -d "$DIST_DIR/.ssc-init-dmg.XXXXXX")
cleanup() {
	rm -rf "$STAGING"
}
trap cleanup EXIT HUP INT TERM

cp "$UNIVERSAL" "$STAGING/ssc-init"
hdiutil create -quiet -ov -format UDZO -volname "SSC Init" -srcfolder "$STAGING" "$DISK_IMAGE"
codesign --sign "$SSC_INIT_SIGNING_IDENTITY" --timestamp --force "$DISK_IMAGE"
codesign --verify --strict --verbose=2 "$DISK_IMAGE"

xcrun notarytool submit "$DISK_IMAGE" \
	--keychain-profile "$SSC_INIT_NOTARY_PROFILE" \
	--wait
xcrun stapler staple "$DISK_IMAGE"
xcrun stapler validate "$DISK_IMAGE"
spctl --assess -vvv --type open --context context:primary-signature "$DISK_IMAGE"

shasum -a 256 "$DISK_IMAGE" | sed "s|$DIST_DIR/|dist/|" > "$DIST_DIR/checksums-notarized.txt"
