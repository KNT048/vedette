#!/usr/bin/env bash
# Prints the absolute path of the pinned minisign (WP-08f, D-164), downloading it first when it is not in the cache.
# The pin is deploy/tools.env: MINISIGN_VERSION, MINISIGN_URL, the SHA-256 of the tarball and of the binary of each architecture,
# and the author's public key. The tarball is checked against its pinned hash before it is unpacked, the binary against its pinned
# hash before it is used, and the author's signature on the tarball is verified with the binary itself (a second, independent
# check made when the pin was taken). Any mismatch is an error and nothing is left to run.
# Cache: $VEDETTE_MINISIGN_CACHE or ~/.cache/vedette-minisign (on disk, never /tmp, which is RAM). Idempotent. Linux only: on macOS
# install minisign yourself (brew install minisign) and give its path to `release sign -minisign`.
# stdout: the path and nothing else; progress goes to stderr.
set -euo pipefail
cd "$(dirname "$0")/../.."

[ "$(uname -s)" = Linux ] || { echo "minisign.sh: the pinned binary is for Linux; on this OS install minisign yourself and pass its path" >&2; exit 1; }
# deploy/tools.env is KEY=VALUE only (a test keeps it so: no spaces, quotes or $)
set -a
# shellcheck disable=SC1091
. deploy/tools.env
set +a
case $(uname -m) in
	x86_64) arch=x86_64 want_bin=$MINISIGN_X86_64_SHA256 ;;
	aarch64 | arm64) arch=aarch64 want_bin=$MINISIGN_AARCH64_SHA256 ;;
	*) echo "minisign.sh: no pinned minisign for $(uname -m)" >&2; exit 1 ;;
esac
cache=${VEDETTE_MINISIGN_CACHE:-$HOME/.cache/vedette-minisign}
dir=$cache/$MINISIGN_VERSION
bin=$dir/minisign-linux/$arch/minisign
sha() { sha256sum "$1" | cut -d' ' -f1; }

if [ -x "$bin" ] && [ "$(sha "$bin")" = "$want_bin" ]; then
	echo "$bin"
	exit 0
fi

work=$(mktemp -d "$cache.XXXXXX" 2>/dev/null || { mkdir -p "$cache" && mktemp -d "$cache/work.XXXXXX"; })
trap 'rm -rf "$work"' EXIT
echo "minisign.sh: downloading minisign $MINISIGN_VERSION" >&2
curl --fail --silent --show-error --location --proto '=https' --max-time 120 -o "$work/m.tar.gz" "$MINISIGN_URL"
curl --fail --silent --show-error --location --proto '=https' --max-time 30 -o "$work/m.tar.gz.minisig" "$MINISIGN_URL.minisig"
[ "$(sha "$work/m.tar.gz")" = "$MINISIGN_TARBALL_SHA256" ] || { echo "minisign.sh: the tarball does not match the pinned SHA-256" >&2; exit 1; }
mkdir -p "$work/x"
tar xzf "$work/m.tar.gz" -C "$work/x" --exclude='._*' 2>/dev/null
unpacked=$work/x/minisign-linux/$arch/minisign
[ -f "$unpacked" ] || { echo "minisign.sh: the tarball has no $arch binary" >&2; exit 1; }
[ "$(sha "$unpacked")" = "$want_bin" ] || { echo "minisign.sh: the $arch binary does not match the pinned SHA-256" >&2; exit 1; }
chmod 0755 "$unpacked"
"$unpacked" -Vm "$work/m.tar.gz" -x "$work/m.tar.gz.minisig" -P "$MINISIGN_AUTHOR_KEY" >&2 || { echo "minisign.sh: the author's signature on the tarball does not verify" >&2; exit 1; }
rm -rf "$dir"
mkdir -p "$dir"
mv "$work/x/minisign-linux" "$dir/"
[ "$(sha "$bin")" = "$want_bin" ] || { echo "minisign.sh: installed binary does not match the pin" >&2; exit 1; }
echo "$bin"
