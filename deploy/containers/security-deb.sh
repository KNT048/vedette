#!/bin/sh
# Lays ONE Debian security update, pinned by version and SHA-256 (deploy/containers/pins.env), over the base image of DEBIAN_IMAGE when
# the pinned base still carries the vulnerable version (D-594). Runs on the BUILD machine (a stage with --platform=$BUILDPLATFORM) for
# the TARGET architecture, so the target stage only COPYs the result and nothing runs on a foreign CPU (D-158). The same way
# distroless assembles its Debian layers: a .deb from snapshot.debian.org checked against a hash in a lock file, unpacked, no apt run.
#
#   security-deb.sh <package> <source> <version> <snapshot> <sha256> <arch> <target dpkg status> <out rootfs>
#
# * the .deb is http://deb.debian.org/debian-security/pool/... and, once Debian drops it from there, the permanent copy at
#   http://snapshot.debian.org/archive/debian-security/<snapshot>/pool/... (plain http like apt: the integrity is the pinned SHA-256);
# * its control fields must be exactly <package> <version> <arch>, and the base must hold <package> at an OLDER version: when a re-pin
#   of DEBIAN_IMAGE already carries the fix, the build fails and says to delete the pins and this step (never a silent downgrade);
# * the files are unpacked with `dpkg-deb -x` (no maintainer script runs; a library has none that matters) and must all land under /usr;
# * <out>/var/lib/dpkg/status is the base's status with the package's stanza replaced by the new one, and its dpkg info files (.list,
#   .md5sums) are the new package's, so scanners, `dpkg -l`, `dpkg --verify` and the apt run of the on-box scan image see the update.
set -eu
[ $# -eq 8 ] || { sed -n '2,8p' "$0" >&2; exit 2; }
pkg=$1 src=$2 ver=$3 snap=$4 sha=$5 arch=$6 status=$7 out=$8
die() { echo "security-deb: $pkg: $*" >&2; exit 1; }
printf '%s' "$pkg$src" | grep -Eq '^[a-z0-9][a-z0-9.+-]*$' || die "bad package or source name"
printf '%s' "$ver" | grep -Eq '^([0-9]+:)?[A-Za-z0-9.+~-]+$' || die "bad version '$ver'"
printf '%s' "$snap" | grep -Eq '^[0-9]{8}T[0-9]{6}Z$' || die "bad snapshot timestamp '$snap'"
printf '%s' "$sha" | grep -Eq '^[0-9a-f]{64}$' || die "bad SHA-256 '$sha'"
case "$arch" in amd64 | arm64) ;; *) die "unsupported architecture '$arch'" ;; esac

# the base's stanza of the package: it must be installed, for this architecture, at an older version
old=$(awk -v RS= -v p="$pkg" '$0 ~ "(^|\n)Package: " p "(\n|$)" { print; exit }' "$status")
[ -n "$old" ] || die "not in the base image's dpkg status"
printf '%s\n' "$old" | grep -qx "Architecture: $arch" || die "the base's $pkg is not for $arch"
have=$(printf '%s\n' "$old" | sed -n 's/^Version: //p')
dpkg --compare-versions "$have" lt "$ver" ||
	die "the base already has $have (pinned $ver): DEBIAN_IMAGE carries the fix, delete the ${pkg} pins of pins.env and this step (D-594)"

# the pinned .deb, by hash
case "$src" in lib?*) pool=$(printf '%s' "$src" | cut -c1-4) ;; *) pool=$(printf '%s' "$src" | cut -c1) ;; esac
file="${pkg}_${ver#*:}_${arch}.deb"
path="pool/updates/main/$pool/$src/$file"
deb=/tmp/security-deb-$pkg.deb
got=
for url in "http://deb.debian.org/debian-security/$path" "http://snapshot.debian.org/archive/debian-security/$snap/$path"; do
	rm -f "$deb"
	/usr/lib/apt/apt-helper download-file "$url" "$deb" >/dev/null 2>&1 || { echo "security-deb: $pkg: not at $url" >&2; continue; }
	if echo "$sha  $deb" | sha256sum -c - >/dev/null 2>&1; then got=$url; break; fi
	echo "security-deb: $pkg: $url is not the pinned SHA-256" >&2
done
[ -n "$got" ] || die "no source served $file with SHA-256 $sha"
[ "$(dpkg-deb -f "$deb" Package)" = "$pkg" ] && [ "$(dpkg-deb -f "$deb" Version)" = "$ver" ] && [ "$(dpkg-deb -f "$deb" Architecture)" = "$arch" ] ||
	die "the .deb is not $pkg $ver $arch"

# unpack (files under /usr only: the base is usr-merged and a real /lib in the COPY would replace its symlink)
mkdir -p "$out"
bad=$(dpkg-deb --fsys-tarfile "$deb" | tar -t | grep -Ev '^\./(usr(/.*)?)?$' || true)
[ -z "$bad" ] || die "ships files outside /usr: $bad"
dpkg-deb -x "$deb" "$out"

# the dpkg database of the result
ma=$(dpkg-deb -f "$deb" Multi-Arch)
info="$pkg"; [ "$ma" = same ] && info="$pkg:$arch"
mkdir -p "$out/var/lib/dpkg/info"
dpkg-deb --fsys-tarfile "$deb" | tar -t | sed 's#^\./#/#; s#/$##; s#^$#/.#' >"$out/var/lib/dpkg/info/$info.list"
ctl=/tmp/security-deb-$pkg.ctl
rm -rf "$ctl" && dpkg-deb -e "$deb" "$ctl"
[ -f "$ctl/md5sums" ] && cp "$ctl/md5sums" "$out/var/lib/dpkg/info/$info.md5sums"
{
	awk -v RS= -v ORS='\n\n' -v p="$pkg" '$0 !~ "(^|\n)Package: " p "(\n|$)"' "$status"
	dpkg-deb -f "$deb" | sed '/^Package: /a Status: install ok installed'
	echo
} >"$out/var/lib/dpkg/status.new"
mv "$out/var/lib/dpkg/status.new" "$out/var/lib/dpkg/status"
n=$(awk -v RS= -v p="$pkg" '$0 ~ "(^|\n)Package: " p "(\n|$)"' "$out/var/lib/dpkg/status" | grep -c "^Version: $ver$" || true)
[ "$n" = 1 ] || die "the written dpkg status does not hold exactly one $pkg $ver"
rm -rf "$deb" "$ctl"
echo "security-deb: $pkg $have -> $ver ($arch) from $got"
