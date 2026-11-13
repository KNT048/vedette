#!/usr/bin/env bash
# make sbom / make vuln-scan (WP-08i, D-159): CycloneDX SBOMs and the vulnerability gate, with trivy run from its official container image
# (pinned by digest in deploy/tools.env), on the LOCAL images of `make images` (tag IMAGE_TAG, every platform of PLATFORMS) and on the source tree.
#   supply-chain.sh sbom   writes dist/sbom/<image>-<arch>.cdx.json for core, sensor, scan-base, honeypot and dist/sbom/source.cdx.json
#   supply-chain.sh scan   prints every finding (all severities), then fails when an image or the source has a HIGH or CRITICAL vulnerability
#                          with a fix that .trivyignore.yaml does not except (the file is checked by scripts/trivyignore before this runs)
# Env (set by the Makefile): CONTAINER (podman|docker), IMAGE_TAG, PLATFORMS, TRIVY_IMAGE, TRIVY_CACHE_DIR (the vulnerability database, 1.7 GB, lives there: on disk, never /tmp, which is RAM),
# RELEASE=1 keeps dist/sbom and dist/vuln for the release job. The image archives made for trivy are always removed (rules/build-artifacts.md).
# Needs: podman or docker, jq (to pick one platform out of a manifest list), git; checked first. macOS: podman runs in a podman machine,
# whose server cannot write an OCI layout on the Mac: podman-oci.sh runs that one export inside the machine (the checkout under $HOME).
# The database download is this machine's own egress (ghcr.io); no image, source or SBOM leaves the machine. Linux or macOS.
set -euo pipefail
for t in git jq "${CONTAINER:-podman}"; do
	command -v "$t" >/dev/null || { echo "supply-chain: FAIL needs $t (macOS: brew install $t; Debian/Ubuntu: apt-get install $t)" >&2; exit 1; }
done
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/dev/podman-oci.sh
. scripts/dev/podman-oci.sh
mode=${1:-}
case $mode in sbom | scan) ;; *) echo "usage: supply-chain.sh sbom|scan" >&2; exit 2 ;; esac
c=${CONTAINER:-podman}
tag=${IMAGE_TAG:-dev}
platforms=${PLATFORMS:-linux/amd64,linux/arm64}
: "${TRIVY_IMAGE:?TRIVY_IMAGE is not set (deploy/tools.env, via make)}" "${TRIVY_CACHE_DIR:?TRIVY_CACHE_DIR is not set (via make)}"
names="core sensor scan-base honeypot"
work=dist/supply-work
sbom=dist/sbom
vuln=dist/vuln
fail() { echo "supply-chain: FAIL $*" >&2; exit 1; }
say() { echo "supply-chain: $*"; }

# Each mode replaces and removes only its own output, so `make vuln-scan` after `make sbom` (both RELEASE=1, make release-gates) keeps the SBOMs.
out=$sbom
[ "$mode" = scan ] && out=$vuln
cleanup() {
	rm -rf "$work"
	if [ "${RELEASE:-}" != 1 ]; then rm -rf "$out"; fi
	rmdir dist 2>/dev/null || true
}
trap cleanup EXIT
rm -rf "$work" "$out"
case $TRIVY_CACHE_DIR in /tmp | /tmp/*) fail "TRIVY_CACHE_DIR must be on disk, not under /tmp (tmpfs: the database would fill RAM)" ;; esac
mkdir -p "$work" "$TRIVY_CACHE_DIR"
[ "$mode" = sbom ] && mkdir -p "$sbom"
[ "$mode" = scan ] && mkdir -p "$vuln"

# trivy in a container: the source read-only at /src, dist/ at /dist, the database cache at /cache; the user is ours so the files are ours.
# podman rootless needs keep-id for that; docker takes --user as it is.
userargs=(--user "$(id -u):$(id -g)")
[ "$c" = podman ] && userargs=(--userns=keep-id "${userargs[@]}")
trivy() {
	"$c" run --rm "${userargs[@]}" -e HOME=/tmp -e TRIVY_CACHE_DIR=/cache \
		-v "$TRIVY_CACHE_DIR:/cache" -v "$PWD:/src:ro" -v "$PWD/dist:/dist" -w /src "$TRIVY_IMAGE" "$@" --skip-version-check
}

# One archive per image, holding every platform that was built. podman: the manifest list written as an OCI layout folder (a plain
# image, one platform, as an OCI archive; a list that fails to export stops here, never falls back to one platform). docker: the OCI
# archive that `make images` made (a multi-platform buildx build), or the daemon's image when one platform was built and loaded.
export_image() {
	local n=$1 img=localhost/vedette-$1:$tag
	case $c in
	podman)
		"$c" image exists "$img" || fail "$img is not in the local storage: run make images first (PLATFORMS=$platforms IMAGE_TAG=$tag)"
		if "$c" manifest exists "$img" 2>/dev/null; then
			podman_oci_push "$c" manifest push --all -q "$img" "oci:$work/$n" >/dev/null || fail "cannot export $img"
		else
			"$c" save --format oci-archive -o "$work/$n.tar" "$img" || fail "cannot export $img"
		fi
		;;
	docker)
		if [ -f "dist/images/vedette-$n-$tag.tar" ]; then
			cp "dist/images/vedette-$n-$tag.tar" "$work/$n.tar"
		else
			"$c" image inspect "$img" >/dev/null 2>&1 || fail "$img is not in the local storage: run make images first (PLATFORMS=$platforms IMAGE_TAG=$tag)"
			"$c" save -o "$work/$n.tar" "$img"
		fi
		;;
	*) fail "CONTAINER must be podman or docker, got $c" ;;
	esac
}

# The path (inside the trivy container) of the image of one architecture. trivy ignores --platform for a local --input, so it would scan
# the same variant twice (measured: identical layers in the amd64 and arm64 SBOMs): for the OCI layout of a manifest list, a copy of the
# layout (hard links, no extra disk) whose index.json names only that platform's manifest. An archive (docker, or the podman fallback) is
# passed as it is, with --platform; there the per-architecture result is NOT verified.
image_input() { # $1 = image name, $2 = arch
	local n=$1 arch=$2 idx digest size
	if [ ! -d "$work/$n" ]; then echo "/dist/supply-work/$n.tar"; return; fi
	if [ "$(jq -r '.manifests[0].mediaType' "$work/$n/index.json")" = application/vnd.oci.image.manifest.v1+json ]; then # one platform only
		echo "/dist/supply-work/$n"
		return
	fi
	idx=$work/$n/blobs/sha256/$(jq -r '.manifests[0].digest | ltrimstr("sha256:")' "$work/$n/index.json")
	read -r digest size < <(jq -r --arg a "$arch" '.manifests[] | select(.platform.architecture == $a) | "\(.digest) \(.size)"' "$idx")
	[ -n "${digest:-}" ] || fail "$n has no linux/$arch variant: run make images with PLATFORMS=$platforms"
	rm -rf "$work/$n-$arch"
	cp -al "$work/$n" "$work/$n-$arch"
	printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%s}]}\n' "$digest" "$size" >"$work/$n-$arch/index.json.new"
	mv -f "$work/$n-$arch/index.json.new" "$work/$n-$arch/index.json"
	echo "/dist/supply-work/$n-$arch"
}

src_flags=(--skip-dirs /src/dist --skip-dirs '**/node_modules' --skip-dirs /src/tools --skip-dirs /src/.git)

if [ "$mode" = sbom ]; then
	for n in $names; do
		export_image "$n"
		for p in ${platforms//,/ }; do
			arch=${p#linux/}
			in=$(image_input "$n" "$arch")
			trivy image --input "$in" --platform "$p" --format cyclonedx --output "/dist/sbom/$n-$arch.cdx.json"
			[ -s "$sbom/$n-$arch.cdx.json" ] || fail "no SBOM for $n $arch"
			say "ok   sbom $n $arch: $(grep -c '"bom-ref"' "$sbom/$n-$arch.cdx.json") components"
		done
	done
	trivy fs "${src_flags[@]}" --format cyclonedx --output /dist/sbom/source.cdx.json /src
	[ -s "$sbom/source.cdx.json" ] || fail "no SBOM for the source"
	say "ok   sbom source: $(grep -c '"bom-ref"' "$sbom/source.cdx.json") components"
	exit 0
fi

# scan: per target, (1) the full JSON report, every severity, no exception applied (kept with RELEASE=1); (2) a summary of every severity, the
# rest the gate lets through; (3) the gate: HIGH or CRITICAL with a fix, minus the exceptions of .trivyignore.yaml (trivy ignores an entry
# until its expired_at date and scripts/trivyignore has already refused a missing or past date). Each pass is its own trivy run on the cached database.
bad=0
scan_one() { # $1 = label, rest = the trivy scan command
	local label=$1
	shift
	# the report gets its name <label>.json only once its gate is green: `release gates` requires that name (and the source's), so a
	# red gate (<label>.gate-failed.json) or a run stopped before its gate (<label>.unchecked.json) leaves nothing it accepts (D-410)
	"$@" --scanners vuln --format json --output "/dist/vuln/$label.unchecked.json" >/dev/null
	say "report $label: every severity, fixed or not (full list: dist/vuln/$label.json with RELEASE=1)"
	"$@" --scanners vuln --format table --report summary 2>/dev/null | sed 's/^/    /'
	if "$@" --scanners vuln --format table --severity HIGH,CRITICAL --ignore-unfixed --ignorefile /src/.trivyignore.yaml --exit-code 1 >"$work/gate.txt"; then
		mv -f "$vuln/$label.unchecked.json" "$vuln/$label.json"
		say "ok   $label: no fixable HIGH or CRITICAL"
	else
		cat "$work/gate.txt"
		mv -f "$vuln/$label.unchecked.json" "$vuln/$label.gate-failed.json"
		say "FAIL $label: fixable HIGH or CRITICAL (above; report dist/vuln/$label.gate-failed.json with RELEASE=1)"
		bad=1
	fi
}
for n in $names; do
	export_image "$n"
	for p in ${platforms//,/ }; do
		arch=${p#linux/}
		in=$(image_input "$n" "$arch")
		scan_one "$n-$arch" trivy image --input "$in" --platform "$p"
	done
done
scan_one source trivy fs "${src_flags[@]}" /src
[ "$bad" = 0 ] || fail "the vulnerability gate failed: bump the dependency, or add a dated, reasoned entry to .trivyignore.yaml"
say "ok   vulnerability gate"
