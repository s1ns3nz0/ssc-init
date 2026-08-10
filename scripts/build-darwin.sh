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

cd "$REPOSITORY_ROOT"

require_clean_worktree() {
	echo "release build requires a clean worktree" >&2
	exit 1
}

require_annotated_version_tag() {
	echo "release build requires an exact annotated v* tag" >&2
	exit 1
}

RELEASE_MODE=${SSC_INIT_RELEASE:-0}
case "$RELEASE_MODE" in
	0 | 1) ;;
	*)
		echo "SSC_INIT_RELEASE must be 0 or 1" >&2
		exit 1
		;;
esac

git -C "$REPOSITORY_ROOT" diff --quiet -- 2>/dev/null || require_clean_worktree
git -C "$REPOSITORY_ROOT" diff --cached --quiet -- 2>/dev/null || require_clean_worktree
UNTRACKED_ENTRIES=$(git -C "$REPOSITORY_ROOT" ls-files --others --exclude-standard 2>/dev/null) || require_clean_worktree
if [ -n "$UNTRACKED_ENTRIES" ]; then
	require_clean_worktree
fi

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
EXACT_TAG=$(git -C "$REPOSITORY_ROOT" describe --tags --exact-match 2>/dev/null) || EXACT_TAG=
if [ "$RELEASE_MODE" = 1 ]; then
	EXACT_TAG=$(git -C "$REPOSITORY_ROOT" describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null) || require_annotated_version_tag
	case "$EXACT_TAG" in
		v[0-9]*[!0-9A-Za-z.+-]* | "") require_annotated_version_tag ;;
		v[0-9]*) ;;
		*) require_annotated_version_tag ;;
	esac
	TAG_OBJECT_TYPE=$(git -C "$REPOSITORY_ROOT" cat-file -t "refs/tags/$EXACT_TAG" 2>/dev/null) || require_annotated_version_tag
	if [ "$TAG_OBJECT_TYPE" != tag ]; then
		require_annotated_version_tag
	fi
	VERSION="$EXACT_TAG"
else
	case "$EXACT_TAG" in
		v[0-9]*)
			case "$EXACT_TAG" in
				*[!0-9A-Za-z.+-]*) ;;
				*) VERSION="$EXACT_TAG" ;;
			esac
			;;
	esac
fi
LINKER_FLAGS="-s -w -buildid= -X main.version=$VERSION"

mkdir -p "$DIST_DIR"

go run ./scripts/package-adapters.go "$REPOSITORY_ROOT/adapters" "$DIST_DIR"

GOARCH=arm64 go build -mod=readonly -trimpath -buildvcs=false -ldflags="$LINKER_FLAGS" -o "$DIST_DIR/ssc-init-darwin-arm64" ./cmd/ssc-init
GOARCH=amd64 go build -mod=readonly -trimpath -buildvcs=false -ldflags="$LINKER_FLAGS" -o "$DIST_DIR/ssc-init-darwin-amd64" ./cmd/ssc-init

lipo -create -output "$DIST_DIR/ssc-init-darwin-universal" \
	"$DIST_DIR/ssc-init-darwin-arm64" \
	"$DIST_DIR/ssc-init-darwin-amd64"

# The dependency set that actually shipped is embedded in the artifact, so the
# CycloneDX document is derived from the universal binary rather than go.mod.
# The go.sum h1: value is a base64 module dirhash, not a hex SHA-256; it is
# recorded as a property because a CycloneDX hash would misstate its algorithm.
# A pipeline would hide a go failure from set -e, leaving a dependency-free
# SBOM that claims the build had no dependencies.
EMBEDDED_MODULES=$(go version -m dist/ssc-init-darwin-universal)

printf '%s\n' "$EMBEDDED_MODULES" |
	awk -v version="$VERSION" -v revision="$REVISION" '
		BEGIN {
			printf "{\n"
			printf "  \"bomFormat\": \"CycloneDX\",\n"
			printf "  \"specVersion\": \"1.5\",\n"
			printf "  \"version\": 1,\n"
			printf "  \"metadata\": {\n"
			printf "    \"component\": {\n"
			printf "      \"type\": \"application\",\n"
			printf "      \"bom-ref\": \"pkg:golang/github.com/s1ns3nz0/ssc-init@%s\",\n", version
			printf "      \"name\": \"ssc-init\",\n"
			printf "      \"version\": \"%s\",\n", version
			printf "      \"purl\": \"pkg:golang/github.com/s1ns3nz0/ssc-init@%s\",\n", version
			printf "      \"licenses\": [{\"license\": {\"id\": \"Apache-2.0\"}}],\n"
			printf "      \"properties\": [{\"name\": \"ssc-init:revision\", \"value\": \"%s\"}]\n", revision
			printf "    }\n"
			printf "  },\n"
			printf "  \"components\": ["
		}
		$1 == "dep" {
			if (count++) printf ","
			printf "\n    {"
			printf "\"type\": \"library\", "
			printf "\"bom-ref\": \"pkg:golang/%s@%s\", ", $2, $3
			printf "\"name\": \"%s\", ", $2
			printf "\"version\": \"%s\", ", $3
			printf "\"purl\": \"pkg:golang/%s@%s\"", $2, $3
			if ($4 != "") {
				printf ", \"properties\": [{\"name\": \"go:mod:h1\", \"value\": \"%s\"}]", $4
			}
			printf "}"
		}
		END {
			if (count) printf "\n  "
			printf "]\n}\n"
		}' > "$DIST_DIR/sbom.cdx.json"

(
	cd "$DIST_DIR"
	shasum -a 256 \
		ssc-init-adapter-claude.zip \
		ssc-init-adapter-codex.zip \
		ssc-init-adapter-cursor.zip \
		sbom.cdx.json \
		ssc-init-darwin-universal | sort -k 2 > checksums.txt
)

# Unsigned in-toto Statement wrapping a SLSA v1 provenance predicate: it names
# the commit, toolchain and flags that produced the digests, so a third party
# who clones the same commit and re-runs this script can confirm the digests
# match. It carries no wall-clock time and no invocation ID, both of which
# would destroy reproducibility and neither of which is verifiable without a
# hosted builder. This is the last step: the subjects are read out of
# checksums.txt, and nothing writes into checksums.txt afterwards, so the
# statement can never become a subject of itself.
GO_VERSION=$(go env GOVERSION)

awk -v version="$VERSION" \
	-v revision="$REVISION" \
	-v epoch="$SOURCE_DATE_EPOCH" \
	-v goversion="$GO_VERSION" \
	-v ldflags="$LINKER_FLAGS" '
	BEGIN {
		printf "{\n"
		printf "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
		printf "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n"
		printf "  \"subject\": ["
	}
	NF == 2 {
		name = $2
		if (count++) printf ","
		printf "\n    {\"name\": \"%s\", \"digest\": {\"sha256\": \"%s\"}}", name, $1
	}
	END {
		if (count) printf "\n  "
		printf "],\n"
		printf "  \"predicate\": {\n"
		printf "    \"buildDefinition\": {\n"
		printf "      \"buildType\": \"https://github.com/s1ns3nz0/ssc-init/scripts/build-darwin.sh@v1\",\n"
		printf "      \"externalParameters\": {\"version\": \"%s\", \"revision\": \"%s\", \"sourceDateEpoch\": \"%s\"},\n", version, revision, epoch
		printf "      \"internalParameters\": {\"goVersion\": \"%s\", \"cgoEnabled\": \"0\", \"goos\": \"darwin\", \"goarch\": \"arm64 amd64\", \"buildFlags\": \"-mod=readonly -trimpath -buildvcs=false\", \"ldflags\": \"%s\"},\n", goversion, ldflags
		printf "      \"resolvedDependencies\": [{\"uri\": \"git+https://github.com/s1ns3nz0/ssc-init\", \"digest\": {\"gitCommit\": \"%s\"}}]\n", revision
		printf "    },\n"
		printf "    \"runDetails\": {\n"
		printf "      \"builder\": {\"id\": \"https://github.com/s1ns3nz0/ssc-init/scripts/build-darwin.sh\"}\n"
		printf "    }\n"
		printf "  }\n"
		printf "}\n"
	}' "$DIST_DIR/checksums.txt" > "$DIST_DIR/provenance.json"
