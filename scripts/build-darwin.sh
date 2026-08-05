#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd)
DIST_DIR="$REPOSITORY_ROOT/dist"

export CGO_ENABLED=0
export GOOS=darwin
export GOTOOLCHAIN=local
export GOPROXY=off
export GOSUMDB=off
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH
export LC_ALL=C

mkdir -p "$DIST_DIR"
cd "$REPOSITORY_ROOT"

REVISION=$(git -C "$REPOSITORY_ROOT" rev-parse --verify "HEAD^{commit}") || {
	echo "failed to resolve source worktree revision" >&2
	exit 1
}
case "$REVISION" in
	"" | *[!0-9a-f]*)
		echo "source worktree revision is not a 40-character lowercase hexadecimal commit" >&2
		exit 1
		;;
esac
if [ "${#REVISION}" -ne 40 ]; then
	echo "source worktree revision is not a 40-character lowercase hexadecimal commit" >&2
	exit 1
fi

VERSION="dev+git.$REVISION"
LINKER_FLAGS="-s -w -buildid= -X main.version=$VERSION"

GOARCH=arm64 go build -mod=readonly -trimpath -buildvcs=false -ldflags="$LINKER_FLAGS" -o "$DIST_DIR/ssc-init-darwin-arm64" ./cmd/ssc-init
GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -ldflags="$LINKER_FLAGS" -o "$DIST_DIR/ssc-init-darwin-amd64" ./cmd/ssc-init

shasum -a 256 dist/ssc-init-darwin-amd64 dist/ssc-init-darwin-arm64 | sort -k 2 > "$DIST_DIR/checksums.txt"
