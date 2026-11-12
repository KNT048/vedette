#!/usr/bin/env bash
# make images-check (D-146): build the sensor and scan images one at a time and check each BY EFFECT, not by exit code of the build:
# the binary prints the SemVer it was built with, nuclei is built from the pinned source with the pinned Go and runs offline from an empty tmpfs HOME, the pack is where
# the worker looks, scan-base holds no nmap, and the on-box image holds the pinned nmap. Removes the images at the end (build-artifacts rule).
# CONTAINER=podman (default) or docker. Linux or macOS. No scan, no traffic besides the downloads of the builds.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
ver=${IMAGE_VERSION:-9.8.7}
tag=check
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; set +a
# nuclei is built from source (D-319): the check is what the binary carries, its Go version and the patched module versions in its build info.
want_go=${GOLANG_IMAGE#*golang:}; want_go=${want_go%%-*}
want_net=$(awk '$1 == "golang.org/x/net" {print $2; exit}' deploy/containers/scan-base/nuclei/go.mod)
[ -n "$want_go" ] && [ -n "$want_net" ] || { echo "images-check: FAIL cannot read the Go version of GOLANG_IMAGE or x/net of scan-base/nuclei/go.mod" >&2; exit 1; }
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
$c run --rm --entrypoint grep "localhost/vedette-scan-base:$tag" -aq "go$want_go" /usr/local/bin/nuclei || fail "nuclei was not built with the pinned Go $want_go"
$c run --rm --entrypoint grep "localhost/vedette-scan-base:$tag" -aq "golang.org/x/net.$want_net" /usr/local/bin/nuclei || fail "nuclei does not carry the patched golang.org/x/net $want_net"
ok "scan-base: /usr/local/bin/nuclei is built with Go $want_go and the patched golang.org/x/net $want_net"
out=$($c run --rm --network none --read-only --tmpfs /tmp --env HOME=/tmp/h --entrypoint /usr/local/bin/nuclei "localhost/vedette-scan-base:$tag" -version -duc 2>&1) || fail "nuclei -version -duc exited non-zero offline: $out"
echo "$out" | grep -q "Nuclei Engine Version: v$NUCLEI_VERSION" || fail "nuclei version line: $out"
ok "scan-base: nuclei -version -duc exits 0 offline on an empty tmpfs HOME: $(echo "$out" | grep 'Engine Version' | sed 's/\x1b\[[0-9;]*m//g')"
pv=$($c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'cat /usr/local/share/vedette/nuclei-pack/index.json' | grep -o '"version": "[^"]*"' | head -1 | cut -d'"' -f4)
[ "$pv" = "$SCAN_PACK_VERSION" ] || fail "pack index version '$pv', pinned '$SCAN_PACK_VERSION' (stale pack)"
ok "scan-base: pack index version $pv equals the pin"
$c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'test -s /usr/local/share/vedette/nuclei-pack/index.json && ls /usr/share/vedette/nuclei-templates >/dev/null' || fail "pack index or templates missing"
n=$($c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'find /usr/share/vedette/nuclei-templates -type f | wc -l')
bad=$($c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'find /usr/share/vedette/nuclei-templates ! -type f ! -type d | wc -l')
[ "$bad" = 0 ] && [ "$n" -gt 0 ] || fail "pack tree: $n files, $bad entries that are neither files nor folders"
ok "scan-base: pack index present, $n template files, only plain files and folders"
if $c run --rm --entrypoint sh "localhost/vedette-scan-base:$tag" -c 'command -v nmap' >/dev/null 2>&1; then fail "scan-base holds nmap (D-4, D-113 (7))"; fi
ok "scan-base: no nmap (command -v nmap finds nothing)"

mk scan-image
got=$($c run --rm --entrypoint nmap "localhost/vedette-scan-nmap:$tag" --version | head -1)
have=$(echo "$got" | sed -n 's/^Nmap version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
[ -n "$have" ] && [ "$(printf '%s\n%s\n' "$NMAP_MIN_VERSION" "$have" | sort -V | head -1)" = "$NMAP_MIN_VERSION" ] || fail "nmap --version '$got' is below the floor $NMAP_MIN_VERSION"
ok "on-box image: $got (floor $NMAP_MIN_VERSION)"

# core (D-149): the image embeds the interface. Run it with a tmpfs data folder and check by effect: GET / is HTML with the root element, and
# an asset that index.html names is 200 with an immutable cache header and a JavaScript type; an unknown asset is 404, not HTML.
mk core-image
cn=vedette-core-check-$$
trap 'cleanup; $c rm -f "$cn" >/dev/null 2>&1 || true; $c rmi -f "localhost/vedette-core:$tag" >/dev/null 2>&1 || true' EXIT
$c run -d --name "$cn" -p 127.0.0.1::8443 --tmpfs /var/lib/vedette:rw,mode=1777 "localhost/vedette-core:$tag" -listen 0.0.0.0:8443 -host-socket "" >/dev/null
port=$($c port "$cn" 8443/tcp | head -1 | sed 's/.*://')
# D-345: the pack folder is readable by core's user (65532): a 0755 folder of 0644 files, owned by root
packs=$($c export "$cn" | tar -tvf - opt/vedette/content/mitigation 2>/dev/null) || fail "core: no /opt/vedette/content/mitigation in the image"
grep -Eq '^drwxr-xr-x .*opt/vedette/content/mitigation/?$' <<<"$packs" || fail "core: the pack folder is not 0755: $packs"
bad=$(grep -v '/$' <<<"$packs" | grep -Ev '^-rw-r--r-- ' || true) # here-strings, no early-closing pipe under pipefail
[ -z "$bad" ] || fail "core: a pack file is not 0644: $bad"
ok "core: the signed pack folder is 0755 with 0644 files"
cget() { curl -sk --max-time 5 --resolve "localhost:$port:127.0.0.1" "$@"; }
page=
for _ in $(seq 1 30); do
	page=$(cget "https://localhost:$port/") && [ -n "$page" ] && break
	sleep 1
done
echo "$page" | grep -q '<div id="root"></div>' || fail "core: GET / is not the interface: $(echo "$page" | head -c 200)"
ok "core: GET / answers HTML with the root element"
asset=$(echo "$page" | grep -o '/assets/[A-Za-z0-9._-]*\.js' | head -1)
[ -n "$asset" ] || fail "core: index.html names no /assets/*.js"
hdr=$(cget -o /dev/null -D - "https://localhost:$port$asset" | tr -d '\r')
echo "$hdr" | head -1 | grep -q ' 200' || fail "core: $asset is not 200: $(echo "$hdr" | head -1)"
echo "$hdr" | grep -iq '^cache-control: public, max-age=31536000, immutable$' || fail "core: $asset has no immutable cache header: $hdr"
echo "$hdr" | grep -iq '^content-type: text/javascript' || fail "core: $asset is not served as JavaScript: $hdr"
ok "core: $asset is 200, immutable, text/javascript"
code=$(cget -o /dev/null -w '%{http_code}' "https://localhost:$port/assets/does-not-exist.js")
[ "$code" = 404 ] || fail "core: a missing asset answered $code, want 404"
ok "core: a missing asset is 404, not index.html"
