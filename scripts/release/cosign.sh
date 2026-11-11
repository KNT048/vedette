#!/usr/bin/env bash
# Prints the absolute path of the pinned cosign (D-256), downloading it first when it is not in the cache.
# The pin is deploy/tools.env: COSIGN_VERSION, COSIGN_URL and the SHA-256 of the binary for each OS and architecture. The download
# is checked against its pinned hash before it is made executable and moved into place (an atomic rename, so two runs at once
# cannot leave a half-written binary); any mismatch is an error and nothing is left to run.
# Cache: $VEDETTE_COSIGN_CACHE or ~/.cache/vedette-cosign (on disk, never /tmp). Idempotent. macOS and Linux, amd64 and arm64.
# stdout: the path and nothing else; progress goes to stderr.
set -euo pipefail
cd "$(dirname "$0")/../.."

# deploy/tools.env is KEY=VALUE only (a test keeps it so: no spaces, quotes or $)
set -a
# shellcheck disable=SC1091
. deploy/tools.env
set +a
case $(uname -s) in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) echo "cosign.sh: no pinned cosign for $(uname -s)" >&2; exit 1 ;;
esac
case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "cosign.sh: no pinned cosign for $(uname -m)" >&2; exit 1 ;;
esac
var=COSIGN_$(echo "${os}_${arch}" | tr '[:lower:]' '[:upper:]')_SHA256
want=${!var}
cache=${VEDETTE_COSIGN_CACHE:-$HOME/.cache/vedette-cosign}
bin=$cache/$COSIGN_VERSION/cosign-$os-$arch
sha() { if command -v sha256sum > /dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

if [ -x "$bin" ] && [ "$(sha "$bin")" = "$want" ]; then
	echo "$bin"
	exit 0
fi

mkdir -p "$cache/$COSIGN_VERSION"
tmp=$(mktemp "$cache/$COSIGN_VERSION/download.XXXXXX")
trap 'rm -f "$tmp"' EXIT
echo "cosign.sh: downloading cosign $COSIGN_VERSION ($os/$arch)" >&2
curl --fail --silent --show-error --location --proto '=https' --max-time 300 -o "$tmp" "$COSIGN_URL/cosign-$os-$arch"
[ "$(sha "$tmp")" = "$want" ] || { echo "cosign.sh: the binary does not match the pinned SHA-256" >&2; exit 1; }
chmod 0755 "$tmp"
mv -f "$tmp" "$bin"
trap - EXIT
"$bin" version > /dev/null 2>&1 || { echo "cosign.sh: the pinned binary does not run here" >&2; exit 1; }
echo "$bin"
