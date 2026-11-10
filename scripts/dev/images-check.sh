#!/usr/bin/env bash
# make images-check (D-146): build the sensor and scan images one at a time and check each BY EFFECT, not by exit code of the build:
# the binary prints the SemVer it was built with, nuclei is the pinned binary and runs offline from an empty tmpfs HOME, the pack is where
# the worker looks, scan-base holds no nmap, and the on-box image holds the pinned nmap. Removes the images at the end (build-artifacts rule).
# CONTAINER=podman (default) or docker. Linux or macOS. No scan, no traffic besides the downloads of the builds.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
ver=${IMAGE_VERSION:-9.8.7}
tag=check
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; set +a
case $(uname -m) in aarch64 | arm64) arch=ARM64 ;; *) arch=AMD64 ;; esac
want_nuclei=NUCLEI_BIN_SHA256_$arch
want_nuclei=${!want_nuclei}
cleanup() { $c rmi -f "localhost/vedette-sensor:$tag" "localhost/vedette-scan-base:$tag" "localhost/vedette-scan-nmap:$tag" >/dev/null 2>&1 || true; }
trap cleanup EXIT
fail() { echo "images-check: FAIL $*" >&2; exit 1; }
ok() { echo "images-check: ok   $*"; }
mk() { make --no-print-directory "$@" CONTAINER="$c" IMAGE_TAG=$tag IMAGE_VERSION="$ver"; }

mk sensor-image
got=$($c run --rm "localhost/vedette-sensor:$tag" -version)
[ "$got" = "$ver" ] || fail "sensor -version printed '$got', want '$ver'"
ok "sensor: /vedette-sensor -version prints $got"
$c run --rm --network none --tmpfs /tmp "localhost/vedette-sensor:$tag" healthcheck && fail "sensor healthcheck must be unhealthy with no heartbeat"
ok "sensor: healthcheck fails without a heartbeat (exec form, no shell needed)"
$c image inspect "localhost/vedette-sensor:$tag" --format '{{.Config.User}}' | grep -qx '65532:65532' || fail "sensor image user"
ok "sensor: default user 65532:65532 (non-root)"

mk scan-base-image
got=$($c run --rm "localhost/vedette-scan-base:$tag" -version)
[ "$got" = "$ver" ] || fail "scan-base -version printed '$got', want '$ver'"
ok "scan-base: /vedette-sensor -version prints $got"
sum=$($c run --rm --entrypoint sha256sum "localhost/vedette-scan-base:$tag" /usr/local/bin/nuclei | cut -d' ' -f1)
[ "$sum" = "$want_nuclei" ] || fail "nuclei binary sha256 $sum, pinned $want_nuclei"
ok "scan-base: /usr/local/bin/nuclei sha256 $sum equals the pin"
out=$($c run --rm --network none --read-only --tmpfs /tmp --env HOME=/tmp/h --entrypoint /usr/local/bin/nuclei "localhost/vedette-scan-base:$tag" -version -duc 2>&1) || fail "nuclei -version -duc exited non-zero offline: $out"
echo "$out" | grep -q "Nuclei Engine Version: v$NUCLEI_VERSION" || fail "nuclei version line: $out"
ok "scan-base: nuclei -version -duc exits 0 offline on an empty tmpfs HOME: $(echo "$out" | grep 'Engine Version' | sed 's/\x1b\[[0-9;]*m//g')"
$c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'test -s /usr/local/share/vedette/nuclei-pack/index.json && ls /usr/share/vedette/nuclei-templates >/dev/null' || fail "pack index or templates missing"
n=$($c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'find /usr/share/vedette/nuclei-templates -type f | wc -l')
bad=$($c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'find /usr/share/vedette/nuclei-templates ! -type f ! -type d | wc -l')
[ "$bad" = 0 ] && [ "$n" -gt 0 ] || fail "pack tree: $n files, $bad entries that are neither files nor folders"
ok "scan-base: pack index present, $n template files, only plain files and folders"
if $c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'command -v nmap' >/dev/null 2>&1; then fail "scan-base holds nmap (D-4, D-113 (7))"; fi
ok "scan-base: no nmap (command -v nmap finds nothing)"

mk scan-image
got=$($c run --rm --entrypoint nmap "localhost/vedette-scan-nmap:$tag" --version | head -1)
echo "$got" | grep -q "Nmap version ${NMAP_VERSION%%+*} " || fail "nmap --version: $got"
ok "on-box image: $got"
