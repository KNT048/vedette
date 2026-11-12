#!/usr/bin/env bash
# make install-artifacts (WP-08h, D-166): build the TEST release that `install.sh --test-artifacts DIR` installs, into dist/install/.
# The real release keys and the published images do not exist yet, so this makes everything locally and signs it with throwaway keys:
#   1. throwaway keys + a Go build overlay (scripts/testchannel keys): the private halves live in a work folder that is deleted at the end (or in KEYS=<dir>, kept)
#   2. the vedette-host .deb, built with that overlay so that this one build trusts exactly those keys (the source tree is untouched); the core image gets
#      the same public keys (build arg TEST_KEYS_B64, -test. versions only) so that its update check verifies the test channel
#   3. the images (make images, one platform; FAST=1: core with a placeholder interface and sensor only, for install-check)
#   4. each image exported to an OCI layout; its digest is the digest of what a registry serves; the blobs are merged
#   5. index.json, release-manifest.json and their minisign signatures, checked back with internal/release (scripts/testchannel sign)
#   6. dist/install/: the package, the four signed documents, registry/ (the blobs), vedette-testchannel (the registry, static),
#      test-channel.env, SHA256SUMS and install.sh
# Variables: VERSION (SemVer without v, default 0.0.1-test.1), ARCH (amd64|arm64, default this machine), OUT (default dist/install),
# KEYS=<dir> (#469): keep the throwaway keys in <dir> and reuse them: a folder that has keys keeps them, an empty or missing one gets new keys that stay
# there, so a second build (VERSION=0.0.1-test.2 KEYS=<dir>) is trusted by a box installed from the first. The private halves are 0600 and TEST-ONLY; <dir> must
# not be under the output folder and, inside the repository, must be git-ignored. Without KEYS the keys are deleted at the end, as before.
# FAST=1, RELEASE=1 (keep the work folder and the local images; default: remove them, the build-artifacts rule). Uses podman.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
root=$PWD
version=${VERSION:-0.0.1-test.1}
case $(uname -m) in aarch64 | arm64) native=arm64 ;; *) native=amd64 ;; esac
arch=${ARCH:-$native}
out=${OUT:-dist/install}
fast=${FAST:-}
keep=${RELEASE:-}
c=${CONTAINER:-podman}
fail() { echo "install-artifacts: $*" >&2; exit 1; }
say() { echo "install-artifacts: $*"; }

[ "$c" = podman ] || fail "CONTAINER must be podman (the export uses podman manifest push)"
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+-test\.[0-9A-Za-z.-]{1,24}$' || fail "VERSION must be a SemVer prerelease that starts with test. and has no v (0.0.1-test.1): a test release must never look like a real one (D-166 M3), got '$version'"
case $arch in amd64 | arm64) ;; *) fail "ARCH must be amd64 or arm64" ;; esac
[ "$arch" = "$native" ] || say "note: ARCH=$arch is not this machine ($native): the images cross-compile, install-check cannot run them here"
case $out in /*) ;; *) out=$root/$out ;; esac

mkdir -p dist
work=$(mktemp -d "$root/dist/.install-work.XXXXXX")
built=()
# drop removes a local tag: a plain image, or a manifest list (make images) with its per-platform images; `rmi` of a list only says
# "tag not known" and leaves it behind.
drop() {
	if "$c" manifest exists "$1" 2>/dev/null; then
		local ds d id
		ds=$("$c" manifest inspect "$1" | sed -n 's/.*"digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1/p')
		"$c" manifest rm "$1" >/dev/null 2>&1 || true
		for d in $ds; do
			# awk reads to the end: an early exit would SIGPIPE podman and, under pipefail, stop the cleanup
			id=$("$c" images -a --digests --format '{{.Digest}} {{.ID}}' | awk -v d="$d" '$1 == d && id == "" { id = $2 } END { print id }') || id=
			[ -z "$id" ] || "$c" rmi -f "$id" >/dev/null 2>&1 || true
		done
	else
		"$c" rmi -f "$1" >/dev/null 2>&1 || true
	fi
}
cleanup() {
	rc=$?
	if [ -z "$keep" ]; then
		rm -rf "$work"
		for t in "${built[@]}"; do drop "$t"; done
		if [ -n "$fast" ]; then rm -rf "$root/internal/webui/dist" "$root/web/dist"; fi
	fi
	exit "$rc"
}
trap cleanup EXIT

say "1/6 throwaway keys"
keys=$work/keys
if [ -n "${KEYS:-}" ]; then
	case $KEYS in /*) keys=$KEYS ;; *) keys=$PWD/$KEYS ;; esac
	keys=$(realpath -m "$keys")
	rout=$(realpath -m "$out")
	case $keys/ in "$rout"/*) fail "KEYS must not be inside the output folder $out (the private keys would ship)" ;; esac
	case $rout/ in "$keys"/*) fail "the output folder $out is inside KEYS=$keys (the private keys would ship)" ;; esac
	case $keys/ in "$root"/*) git check-ignore -q "$keys" || fail "KEYS=$keys is inside the repository and not git-ignored: use a folder outside it (the private keys must never be committed)" ;; esac
	if [ -d "$keys" ] && [ -n "$(ls -A "$keys")" ] && [ ! -e "$keys/minisign-active.seed" ]; then fail "KEYS=$keys is not empty and holds no test keys (minisign-active.seed): use an empty or new folder"; fi
	mkdir -p "$keys" && chmod 0700 "$keys"
	if [ -e "$keys/minisign-active.seed" ]; then say "reusing the test keys in $keys"; else say "making test keys in $keys (kept; TEST-ONLY, never use them for a release)"; fi
fi
go run ./scripts/testchannel keys -out "$keys" -repo "$root"
test_keys_b64=$(base64 <"$keys/keys_prod.go" | tr -d '\n')

say "2/6 vedette-host $version ($arch), built with the test keys"
GOFLAGS="${GOFLAGS:+$GOFLAGS }-overlay=$keys/overlay.json" DEB_OUT="$work/deb" make --no-print-directory host-deb VERSION="$version" ARCH="$arch" MIN_SEQUENCE=0 >/dev/null
# nfpm (dpkg) writes a SemVer prerelease with a tilde in the file name; the asset and install.sh use the SemVer spelling
nfpm_deb=$work/deb/vedette-host_${version/-/\~}_${arch}.deb
deb=$work/deb/vedette-host_${version}_${arch}.deb
[ -s "$nfpm_deb" ] || fail "no package was built"
mv "$nfpm_deb" "$deb"
# the test host must hold the throwaway keys and nothing of the production constants: its own version check proves it runs
[ "$("$work/deb/host-deb/$arch/vedette-host" -version 2>/dev/null || echo cross)" = "$version" ] || [ "$arch" != "$native" ] || fail "the test vedette-host does not report $version"

say "3/6 images ($([ -n "$fast" ] && echo 'FAST: core with a placeholder interface, sensor' || echo 'core, sensor, scan-base'))"
declare -A localname=([core]=vedette-core [sensor]=vedette-sensor [scan]=vedette-scan-base [honeypot]=vedette-honeypot)
if [ -n "$fast" ]; then
	services="core sensor"
	mkdir -p internal/webui/dist
	printf '<!doctype html><title>Vedette TEST INSTALL placeholder</title><p>install-check placeholder interface</p>\n' >internal/webui/dist/index.html
	make --no-print-directory -o webui-dist sensor-image core-image IMAGE_TAG="$version" IMAGE_VERSION="$version" TEST_KEYS_B64="$test_keys_b64" >/dev/null
	built+=("localhost/vedette-sensor:$version" "localhost/vedette-core:$version")
else
	services="core sensor scan"
	make --no-print-directory images PLATFORMS="linux/$arch" IMAGE_TAG="$version" IMAGE_VERSION="$version" TEST_KEYS_B64="$test_keys_b64" >/dev/null
	built+=("localhost/vedette-sensor:$version" "localhost/vedette-scan-base:$version" "localhost/vedette-core:$version" "localhost/vedette-honeypot:$version") # make images builds the honeypot too
fi
# the honeypot image belongs to WP-08e: used when it was built with the same tag, else the install has no honeypot
if "$c" image exists "localhost/vedette-honeypot:$version" || "$c" manifest exists "localhost/vedette-honeypot:$version" 2>/dev/null; then
	services="$services honeypot"
else
	say "no localhost/vedette-honeypot:$version: the test release has no honeypot image (build it with the same tag to include it)"
fi

say "4/6 exporting the images"
mkdir -p "$work/blobs"
images=()
for s in $services; do
	ref=localhost/${localname[$s]}:$version
	if "$c" manifest exists "$ref" 2>/dev/null; then
		"$c" manifest push --all --format oci "$ref" "oci:$work/lay-$s" >/dev/null
	else
		"$c" push --format oci "$ref" "oci:$work/lay-$s" >/dev/null
	fi
	digest=$(sed -n 's/.*"digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$work/lay-$s/index.json" | head -n 1)
	[ -n "$digest" ] || fail "no digest in the layout of $s"
	cp -n "$work/lay-$s/blobs/sha256/"* "$work/blobs/"
	rm -rf "$work/lay-$s"
	images+=(-image "$s=$digest")
	say "  $s $digest"
done

say "5/6 signing the index and the manifest"
mkdir -p "$work/docs"
go run ./scripts/testchannel sign -keys "$keys" -out "$work/docs" -version "$version" -platform "linux/$arch" -blobs "$work/blobs" -deb "$deb" "${images[@]}"

say "6/6 assembling $out"
rm -rf "$out"
mkdir -p "$out/registry"
cp "$deb" "$work"/docs/* "$out/"
mv "$work"/blobs/* "$out/registry/"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags '-s -w' -o "$out/vedette-testchannel" ./scripts/testchannel
cp install.sh "$out/install.sh"
{
	echo "VERSION=$version"
	echo "ARCH=$arch"
	echo "SERVICES=$(echo "$services" | tr ' ' ',')"
} >"$out/test-channel.env"
(cd "$out" && find . -type f ! -name install.sh -printf '%P\n' | sort | xargs sha256sum >"$work/SHA256SUMS") && mv "$work/SHA256SUMS" "$out/SHA256SUMS"
chmod 0755 "$out/install.sh" "$out/vedette-testchannel"
say "done: $out ($(du -sh "$out" | cut -f1)). Install with: sh $out/install.sh --test-artifacts <absolute path of this folder>"
