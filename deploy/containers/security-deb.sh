#!/bin/sh
# Lays ONE Debian security update, pinned by version and SHA-256 (deploy/containers/pins.env), over the base image of DEBIAN_IMAGE when
# the pinned base still carries the vulnerable version. Runs on the BUILD machine (a stage with --platform=$BUILDPLATFORM) for
# the TARGET architecture, so the target stage only COPYs the result and nothing runs on a foreign CPU. The same way
# distroless assembles its Debian layers: a .deb from snapshot.debian.org checked against a hash in a lock file, unpacked, no apt run.
#
#   security-deb.sh <package> <source> <version> <snapshot> <sha256> <arch> <target dpkg status> <out rootfs>
#
# * the .deb is http://deb.debian.org/debian-security/pool/... (deb.debian.org is the CDN of security.debian.org, the host the base's
#   own debian.sources names) and, once Debian drops it from there, the permanent copy at
#   http://snapshot.debian.org/archive/debian-security/<snapshot>/pool/... (plain http like apt: the integrity is the pinned SHA-256,
#   checked before anything reads the file; a download is capped at 64 MiB);
# * the base must hold <package> for <arch> at an OLDER version, checked before any download: when a re-pin of DEBIAN_IMAGE already
#   carries the fix, the build fails and names every place to clean up (never a silent downgrade);
# * its control fields must be exactly <package> <version> <arch>; it may not have conffiles; every member must be a directory, a
#   regular file or a relative symlink (no "..", no absolute target) under ./usr, owned by root, with no setuid, setgid or sticky bit;
# * the files are unpacked with `dpkg-deb -x` (no maintainer script runs; a library's only one is the ldconfig trigger, and the soname
#   link is in the package);
# * <out>/var/lib/dpkg/status is the base's status with the package's stanza replaced by the new one, and <out>/var/lib/dpkg/info gets
#   every control member but `control` as <package>[:<arch>].<member>, plus the .list, as dpkg writes them, so scanners, `dpkg -l`,
#   `dpkg --verify` and the apt run of the on-box scan image see the update. ponytail: an info file of the base's version that the new
#   version no longer ships stays (a COPY cannot delete); the same members today (shlibs, symbols, triggers, md5sums).
set -eu
nl='
'
die() { echo "security-deb: ${pkg:-?}: $*" >&2; exit 1; }
[ $# -eq 8 ] || { sed -n '7p' "$0" >&2; exit 2; }
pkg=$1 src=$2 ver=$3 snap=$4 sha=$5 arch=$6 status=$7 out=$8
# one line each, then the shape (grep -E alone matches line by line)
for v in "$pkg" "$src" "$ver" "$snap" "$sha" "$arch" "$status" "$out"; do
	case $v in *"$nl"* | '') die "an argument is empty or holds a newline" ;; esac
done
printf '%s' "$pkg" | grep -Eqx '[a-z0-9][a-z0-9.+-]*' || die "bad package name"
printf '%s' "$src" | grep -Eqx '[a-z0-9][a-z0-9.+-]*' || die "bad source name '$src'"
printf '%s' "$ver" | grep -Eqx '([0-9]+:)?[A-Za-z0-9.+~-]+' || die "bad version '$ver'"
printf '%s' "$snap" | grep -Eqx '[0-9]{8}T[0-9]{6}Z' || die "bad snapshot timestamp '$snap'"
printf '%s' "$sha" | grep -Eqx '[0-9a-f]{64}' || die "bad SHA-256 '$sha'"
case "$arch" in amd64 | arm64) ;; *) die "unsupported architecture '$arch'" ;; esac

# the base's stanza of the package (the Package line compared as a string, not a regex): installed, for this arch, at an older version
stanza() { awk -v RS= -v want="Package: $1" '{ n = split($0, l, "\n"); for (i = 1; i <= n; i++) if (l[i] == want) { print; exit } }' "$2"; }
old=$(stanza "$pkg" "$status")
[ -n "$old" ] || die "not in the base image's dpkg status"
printf '%s\n' "$old" | grep -Fqx "Architecture: $arch" || die "the base's $pkg is not for $arch"
have=$(printf '%s\n' "$old" | sed -n 's/^Version: //p')
dpkg --compare-versions "$have" lt "$ver" ||
	die "the base already has $have (pinned $ver): DEBIAN_IMAGE carries the fix, so retire this update. Every place: (1) deploy/containers/pins.env, the LIBZSTD1_* lines and their comment; (2) scan-base/Containerfile, the security stage, its COPY --from=security and the header line; (3) honeypot/Containerfile, the LIBZSTD1_* ARGs, step 0, /target/updated-status (back to /target/status) and the header bullet; (4) Makefile PIN_ARGS; (5) deploy/compose/compose.yaml x-build-args; (6) .dockerignore (with this script, if no other update is left); (7) deploy/containers/containers_test.go, the LIBZSTD1_* pin checks and the security-deb tests; (8) scripts/dev/images-check.sh and honeypot-check.sh, the libzstd1 checks; (9) THIRD_PARTY_NOTICES.md, the base-images row and the honeypot Debian row"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
deb=$work/pkg.deb

# the pinned .deb, by hash, at most 64 MiB (ulimit -f in 512-byte blocks: the http method that writes the file inherits it)
case "$src" in lib?*) pool=$(printf '%s' "$src" | cut -c1-4) ;; *) pool=$(printf '%s' "$src" | cut -c1) ;; esac
file="${pkg}_${ver#*:}_${arch}.deb"
path="pool/updates/main/$pool/$src/$file"
got=
for url in "http://deb.debian.org/debian-security/$path" "http://snapshot.debian.org/archive/debian-security/$snap/$path"; do
	rm -f "$deb"
	if ! (ulimit -f 131072 && /usr/lib/apt/apt-helper download-file "$url" "$deb" "SHA256:$sha") >"$work/dl.log" 2>&1; then
		echo "security-deb: $pkg: $url failed:" >&2
		tail -n 5 "$work/dl.log" >&2
		continue
	fi
	if echo "$sha  $deb" | sha256sum -c - >/dev/null 2>&1; then got=$url; break; fi
	echo "security-deb: $pkg: $url is not the pinned SHA-256" >&2
done
[ -n "$got" ] || die "no source served $file with SHA-256 $sha"
[ "$(dpkg-deb -f "$deb" Package)" = "$pkg" ] && [ "$(dpkg-deb -f "$deb" Version)" = "$ver" ] && [ "$(dpkg-deb -f "$deb" Architecture)" = "$arch" ] ||
	die "the .deb is not $pkg $ver $arch"
ctl=$work/control
dpkg-deb -e "$deb" "$ctl"
[ ! -s "$ctl/conffiles" ] || die "has conffiles, which this overlay does not handle"

# every member: a directory, a regular file or a relative symlink, under ./usr, no "..", root-owned, no setuid/setgid/sticky bit.
# Names are restricted to a plain character set, so the fields of `tar -tv` split cleanly: mode owner size date time name [-> target].
bad=$(dpkg-deb --fsys-tarfile "$deb" | tar -tv | awk '
	function plain(p) { return p ~ /^[A-Za-z0-9._+~@:\/-]+$/ && p !~ /(^|\/)\.\.(\/|$)/ }
	{
		t = substr($1, 1, 1); ok = (t == "-" || t == "d") ? NF == 6 : (t == "l" && NF == 8 && $7 == "->")
		ok = ok && $1 !~ /[sStT]/ && $2 == "root/root" && plain($6) && ($6 == "./" || $6 ~ /^\.\/usr(\/|$)/)
		if (t == "l") ok = ok && plain($8) && $8 !~ /^\//
		if (!ok) print
	}')
[ -z "$bad" ] || die "a member is not a plain root-owned directory, file or relative symlink under /usr: $bad"
mkdir -p "$out"
dpkg-deb -x "$deb" "$out"

# the dpkg database of the result: status, and the info files dpkg would write (every control member but control, and the .list)
info="$pkg"
[ "$(dpkg-deb -f "$deb" Multi-Arch)" = same ] && info="$pkg:$arch"
mkdir -p "$out/var/lib/dpkg/info"
for m in "$ctl"/*; do
	[ "${m##*/}" = control ] || cp "$m" "$out/var/lib/dpkg/info/$info.${m##*/}"
done
dpkg-deb --fsys-tarfile "$deb" | tar -t | sed 's#^\./#/#; s#/$##; s#^$#/.#' >"$out/var/lib/dpkg/info/$info.list"
{
	awk -v RS= -v ORS='\n\n' -v want="Package: $pkg" '{ n = split($0, l, "\n"); for (i = 1; i <= n; i++) if (l[i] == want) next; print }' "$status"
	dpkg-deb -f "$deb" | sed '/^Package: /a Status: install ok installed'
	echo
} >"$out/var/lib/dpkg/status.new"
mv "$out/var/lib/dpkg/status.new" "$out/var/lib/dpkg/status"
[ "$(stanza "$pkg" "$out/var/lib/dpkg/status" | sed -n 's/^Version: //p')" = "$ver" ] || die "the written dpkg status does not hold $pkg $ver"
echo "security-deb: $pkg $have -> $ver ($arch) from $got"
