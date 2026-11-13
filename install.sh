#!/bin/sh
# Vedette installer for a fresh Ubuntu 24.04 / 26.04 or Debian 13 box (WP-08h, D-166). Run as root:
#
#   curl -fsSL https://github.com/KNT048/vedette/releases/download/v<version>/install.sh | sudo sh
#   sh install.sh [--network-handover] [--uninstall --yes [--keep-data]] [--test-artifacts DIR]
#
# What it does, in this order, and stops at the first thing it cannot do (a refusal in step 1 changes nothing):
#   1. preflight: OS, architecture, root, systemd, disk, ports 8443/8444/8765 and the syslog ports 514 and 6514, no other Vedette, a sane clock
#   2. installs the packages Vedette needs that are MISSING (podman, chrony, netplan.io, nftables, ...) with apt, never upgrading
#      a package that is already there
#   3. downloads the vedette-host .deb of THIS release, checks its sha256 against the value written into this script by the
#      release job, keeps it as /var/lib/vedette-host/selfupdate/packages/vedette-host_<version>_<arch>.deb (vedette-host goes
#      back to it when a later self-update fails, D-316) and installs it (the package makes the users, folders and the unit)
#   4. writes /etc/vedette/host.conf from the users' real ids and the network of the containers (chrony's own configuration is
#      left as it is)
#   5. optional, only with --network-handover and only when netplan holds nothing but one DHCP wired card: gives netplan to
#      vedette-host
#   6. vedette-host -bootstrap: verifies the signed release (keys built into vedette-host, not into this script) and pulls
#      the signed images by digest; then starts vedette-host and core, waits until core is healthy and prints the address
#      and the one-time setup code
# Running it again repairs (also after a run that stopped half way) or upgrades the host package and changes nothing that is
# already right. --uninstall --yes puts the box back as it was (--keep-data keeps the data and the users; running this script again
# then installs its release over them, and refuses a release older than the one that last ran on them); a podman that holds anything
# that is not Vedette's stays with its storage, and so does any podman with --keep-data (D-508). Nothing is read from the environment.
#
# The three values below are filled by the release job (WP-08k) and are empty in the repository: an empty value makes the
# customer path stop with a clear message, so a script that is not tied to a release can never install anything. A script that
# has them filled never installs test artifacts.
VEDETTE_VERSION=""
VEDETTE_DEB_SHA256_AMD64=""
VEDETTE_DEB_SHA256_ARM64=""
REPO_URL="https://github.com/KNT048/vedette"

set -eu
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
# One byte order for every tool: Ubuntu 26.04's uutils sort collates by the locale while its comm checks bytes, so under
# LANG=en_US.UTF-8 `sort | comm` failed on the accounts list (_apt, _chrony) and stopped every install and uninstall (#298).
LC_ALL=C
export LC_ALL
unset IFS

STATE=/var/lib/vedette-install
HOST_BIN=/usr/lib/vedette/vedette-host
HOST_STATE=/var/lib/vedette-host
UNIT_DIR=/etc/containers/systemd
NETWORK_FILE=$UNIT_DIR/vedette-int.network
MIRROR_FILE=/etc/containers/registries.conf.d/vedette-test-mirror.conf
REGISTRY_UNIT=vedette-testregistry
REGISTRY_ADDR=127.0.0.1:5077
CLOUD_FILE=/etc/cloud/cloud.cfg.d/99-vedette-network.cfg
# iptables: netavark 1.4 (Ubuntu 24.04) programs the firewall through it and fails with "No such file" without it (found by install-check)
# conntrack: vedette-host deletes the stale UDP conntrack entries of the published syslog port after core restarts (D-268)
PACKAGES="ca-certificates curl podman chrony netplan.io nftables iptables iproute2 procps unattended-upgrades passwd conntrack"
OPTIONAL_PACKAGES="netavark aardvark-dns catatonit"
MIN_FREE_KB=6291456 # 6 GiB under /var/lib and /var/tmp: the images are about 1 GB, the data grows
CLOCK_FLOOR=1793491200 # 2026-11-01: a clock before this is not set

MODE=install
HANDOVER=
KEEP_DATA=
KEEP_PODMAN=
KEPT_MANUAL=
PODMAN_OURS=
PODMAN_IN_USE=
HOST_STOPPED=
HP_STOPPED=
RELEASE=
SERVICES=
YES=
TEST_DIR=
ART=
TMP=
WANT=customer

say() { printf 'vedette-install: %s\n' "$*"; }
warn() { printf 'vedette-install: WARNING: %s\n' "$*" >&2; }
die() {
	printf 'vedette-install: ERROR: %s\n' "$*" >&2
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat <<'EOF'
usage: install.sh [options]
  (no option)            install, or repair/upgrade an install made by this script
  --network-handover     give netplan to vedette-host (only when netplan holds nothing but one DHCP wired card; default: leave the network alone)
  --uninstall --yes      remove Vedette and put the box back as it was; without --yes it only says what it would remove
  --keep-data            with --uninstall: keep /var/lib/vedette*, /etc/vedette and the users (the key and the database), and podman
  --test-artifacts DIR   TEST INSTALL from a folder made by `make install-artifacts`: not for customers
EOF
}

banner() {
	printf '\n'
	printf '#####################################################################\n'
	printf '#  TEST INSTALL - NOT FOR CUSTOMERS                                 #\n'
	printf '#  Signed with throwaway keys from %s\n' "$TEST_DIR"
	printf '#  The release keys and the published images are not used.          #\n'
	printf '#####################################################################\n\n'
}

cleanup() {
	rc=$?
	if [ -n "$TEST_DIR" ]; then
		systemctl stop "$REGISTRY_UNIT.service" >/dev/null 2>&1 || true
		rm -f "$MIRROR_FILE"
	fi
	[ -z "$TMP" ] || rm -rf "$TMP"
	# a run that stopped vedette-host for the bootstrap and then failed leaves it running again, as it was, with the honeypot (W2-10)
	if [ "$rc" -ne 0 ] && [ -n "$HOST_STOPPED" ]; then
		systemctl start vedette-host.service >/dev/null 2>&1 || true
		[ -z "$HP_STOPPED" ] || systemctl start vedette-honeypot.service >/dev/null 2>&1 || true
	fi
	[ -e "$STATE/owner" ] || rm -rf "$STATE/art" # a refusal before the first change leaves nothing behind
	rmdir "$STATE" 2>/dev/null || true
	if [ "$rc" -ne 0 ] && [ "$MODE" = install ] && [ -d "$STATE" ]; then
		say "stopped before the end. Run the script again to repair, or --uninstall --yes to remove what was made."
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- arguments -------------------------------------------------------------------------------------------------------

while [ $# -gt 0 ]; do
	case $1 in
	--uninstall) MODE=uninstall ;;
	--yes) YES=1 ;;
	--keep-data) KEEP_DATA=1 ;;
	--network-handover) HANDOVER=1 ;;
	--test-artifacts)
		[ $# -ge 2 ] || die "--test-artifacts needs a folder"
		TEST_DIR=$2
		WANT='test'
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "unknown option: $1"
		;;
	esac
	shift
done
[ "$MODE" = uninstall ] || [ -z "$KEEP_DATA$YES" ] || die "--yes and --keep-data belong to --uninstall"
[ "$MODE" = install ] || [ -z "$HANDOVER" ] || die "--network-handover belongs to the install"
[ -z "$TEST_DIR" ] || case $TEST_DIR in /*) ;; *) die "--test-artifacts needs an absolute path" ;; esac
[ -z "$TEST_DIR" ] || [ -z "$VEDETTE_VERSION" ] || die "this install.sh belongs to release $VEDETTE_VERSION and never installs test artifacts"

[ "$(id -u)" = 0 ] || die "run as root (sudo sh install.sh ...)"

# ---- small helpers ---------------------------------------------------------------------------------------------------

# kv <key> <file>: the value of KEY=value in a file this script's own build wrote; only a plain word is accepted
kv() {
	v=$(sed -n "s/^$1=//p" "$2" | head -n 1)
	printf '%s' "$v" | grep -Eq '^[A-Za-z0-9._,+-]*$' || die "$2: the value of $1 is not a plain word"
	printf '%s' "$v"
}

ip2int() (
	IFS=.
	# shellcheck disable=SC2086 # split on dots on purpose
	set -- $1
	echo $((($1 << 24) | ($2 << 16) | ($3 << 8) | $4))
)

# cidr_overlap a.b.c.d/n e.f.g.h/m: true when the two networks share an address
cidr_overlap() {
	_al=${1#*/}
	_bl=${2#*/}
	_l=$_al
	[ "$_bl" -ge "$_l" ] || _l=$_bl
	_mask=$(((0xFFFFFFFF << (32 - _l)) & 0xFFFFFFFF))
	[ $(($(ip2int "${1%/*}") & _mask)) -eq $(($(ip2int "${2%/*}") & _mask)) ]
}

port_listening() { ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"; }
# port_listening_any <port>: the same for TCP and UDP (the syslog port 514 is both; rootful podman publishes it for core)
port_listening_any() { ss -H -ltnu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]$1\$"; }

installed_pkg() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed; }

# host_version_ok <version>: the one name rule of a host package (host-api 6.14, D-316; release.ParseHostPackageName in Go, a test
# keeps the two the same): SemVer of at most 64 characters, no build metadata, and a prerelease of at most 32 characters made of
# dot-separated identifiers with no "-" inside, so that the Debian version (its first "-" turned into "~") is exact
host_version_ok() {
	case $1 in *[!0-9A-Za-z.-]* | '') return 1 ;; esac
	[ ${#1} -le 64 ] || return 1
	_pre=${1#*-}
	[ "$_pre" = "$1" ] || [ ${#_pre} -le 32 ] || return 1
	printf '%s\n' "$1" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z][0-9A-Za-z]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z][0-9A-Za-z]*))*)?'
}

# needrestart (Ubuntu) must only list, never restart a service behind the administrator's back
apt_run() {
	DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 apt-get -o DPkg::Lock::Timeout=180 -o Dpkg::Options::=--force-confold -y -q "$@"
}

# apt_sim <apt-get arguments>: the names apt would REMOVE for them, one per line
apt_sim() { apt-get -s -q "$@" 2>/dev/null | awk '/^(Remv|Purg) / {print $2}' | sort -u; } # a simulated purge prints Purg, not Remv

os_field() { sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d '"'; }

# add_line <file> <line>: append unless the exact line is there
add_line() {
	touch "$1"
	grep -qxF "$2" "$1" || printf '%s\n' "$2" >>"$1"
}

# ---- 1. preflight ----------------------------------------------------------------------------------------------------

# prepare_test: the test folder must be root's and closed, and is copied into the installer's own folder before anything is
# checked or used, so that nobody who can write the folder can change a file between the check and its use (L2 of review 1)
prepare_test() {
	[ -d "$TEST_DIR" ] || die "$TEST_DIR is not a folder"
	bad=$(find "$TEST_DIR" \( ! -user root -o -perm /022 -o -type l \) 2>/dev/null | head -n 1)
	[ -z "$bad" ] || die "$bad is not owned by root, is writable by group or others, or is a link. Copy the folder as root (rsync -a --chown=root:root, then chmod -R go-w) and run again."
	[ -d "$TEST_DIR/registry" ] || die "$TEST_DIR is not a folder made by make install-artifacts (no registry/)"
	ART=$STATE/art
	rm -rf "$ART"
	mkdir -m 0700 "$ART"
	for f in test-channel.env SHA256SUMS index.json index.json.minisig release-manifest.json release-manifest.json.minisig vedette-testchannel; do
		[ -f "$TEST_DIR/$f" ] || die "$TEST_DIR is not a folder made by make install-artifacts (no $f)"
		cp "$TEST_DIR/$f" "$ART/$f"
	done
	chmod 0755 "$ART/vedette-testchannel"
	RELEASE=$(kv VERSION "$ART/test-channel.env")
	SERVICES=$(kv SERVICES "$ART/test-channel.env")
	case $RELEASE in *-test.*) ;; *) die "the test release '$RELEASE' has no -test. prerelease: refusing (a test release must never look like a real one)" ;; esac
	host_version_ok "$RELEASE" || die "the test release '$RELEASE' cannot name a host package (SemVer, a prerelease of letters, digits and dots only): refusing"
	[ "$(kv ARCH "$ART/test-channel.env")" = "$ARCH" ] || die "the artifacts are for $(kv ARCH "$ART/test-channel.env"), this machine is $ARCH"
	[ -f "$TEST_DIR/vedette-host_${RELEASE}_${ARCH}.deb" ] || die "no vedette-host_${RELEASE}_${ARCH}.deb in $TEST_DIR"
	cp "$TEST_DIR/vedette-host_${RELEASE}_${ARCH}.deb" "$ART/"
	# the registry blobs are not copied (they are large); podman and vedette-host check every one of them against its digest
	(cd "$ART" && grep -v ' registry/' SHA256SUMS | sha256sum -c --quiet) || die "SHA256SUMS of $TEST_DIR does not match its files"
}

preflight() {
	rerun=
	say "preflight"
	[ "$(uname -s)" = Linux ] || die "Vedette installs only on Linux (Ubuntu 24.04, 26.04, Debian 13)"
	[ -r /etc/os-release ] || die "no /etc/os-release: cannot tell the OS; supported: Ubuntu 24.04, Ubuntu 26.04, Debian 13"
	id=$(os_field ID)
	ver=$(os_field VERSION_ID)
	case "$id:$ver" in
	ubuntu:24.04 | ubuntu:26.04 | debian:13) ;;
	*) die "unsupported OS '$id $ver'. Supported: Ubuntu 24.04, Ubuntu 26.04, Debian 13 (docs/DEPLOYMENT.md section 4). Nothing was changed." ;;
	esac
	have dpkg || die "dpkg is missing"
	ARCH=$(dpkg --print-architecture)
	case $ARCH in amd64 | arm64) ;; *) die "unsupported architecture '$ARCH' (amd64 and arm64 only)" ;; esac
	[ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] && [ -d /run/systemd/system ] || die "systemd is not PID 1 on this machine (a plain container?); Vedette needs a real systemd host"
	for t in ss ip awk sed grep sha256sum getent find; do have "$t" || die "$t is missing; install it first (iproute2, coreutils, libc-bin, findutils)"; done
	now=$(date -u +%s)
	[ "$now" -ge "$CLOCK_FLOOR" ] || die "the clock says $(date -u +%F): it is not set. Fix the date (timedatectl set-time) and run again."
	if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo yes)" = no ]; then
		warn "the clock is not synchronised yet; chrony will do it, but certificates are checked against it"
	fi
	# the two channels never mix: a test mirror is removed wherever it is found, and no other configuration may redirect our registry
	if [ -e "$MIRROR_FILE" ]; then
		systemctl stop "$REGISTRY_UNIT.service" >/dev/null 2>&1 || true
		rm -f "$MIRROR_FILE"
		warn "removed a test mirror ($MIRROR_FILE) left behind by an earlier run"
	fi
	redirect=$(grep -rl 'knt048' /etc/containers/registries.conf /etc/containers/registries.conf.d 2>/dev/null | head -n 1 || true)
	[ -z "$redirect" ] || die "$redirect redirects or restricts ghcr.io/knt048, the registry of Vedette's images. Remove that first. Nothing was changed."
	mkdir -p "$STATE"
	chmod 0700 "$STATE"
	free=$(df -Pk "$STATE" | awk 'NR==2 {print $4}')
	[ "${free:-0}" -ge "$MIN_FREE_KB" ] || die "less than 6 GiB free under /var ($((free / 1024)) MiB): free some space and run again"
	mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
	[ "${mem:-0}" -ge 3600000 ] || warn "only $((mem / 1024)) MiB of memory: the minimum is 4 GiB (8 GiB recommended)"
	if [ -s "$STATE/owner" ]; then
		# our own marker: a run that stopped half way, or a finished install: repair or upgrade it, in the same channel
		rerun=1
		have_channel=$(kv channel "$STATE/owner")
		[ "$have_channel" = "$WANT" ] || die "this box has a $have_channel install of Vedette, and this is the $WANT channel. Run sh install.sh --uninstall --yes (from the $have_channel channel) first. Nothing was changed."
	else
		# podman reserves the published ports for core (8444 and 8765 on 127.0.0.1): one held by another program stops core starting
		for p in 8443 8444 8765; do
			! port_listening "$p" || die "port $p is already in use by another program (ss -ltnp). Vedette needs 8443 (interface), 8444 (sensor link) and 8765 (MCP server, this machine only)."
		done
		# syslog: podman reserves 514 (udp+tcp) and 6514 (tcp, TLS) for core; rsyslog's imudp/imtcp usually holds them, and core
		# (and 8443 with it) would not start
		for p in 514 6514; do
			! port_listening_any "$p" || die "port $p is already in use by another program (ss -lntup). Vedette needs 514 (syslog, udp and tcp) and 6514 (syslog over TLS, tcp): stop rsyslog's network input (imudp, imtcp) or the other syslog service and run this again."
		done
		if [ -e /etc/vedette/host.conf ] || installed_pkg vedette-host || getent passwd vedette >/dev/null; then
			die "another Vedette install is here (host.conf, the package or the user vedette) that this script did not make. Remove it first (docs/RUNBOOK.md) or use --uninstall from the script that made it."
		fi
		if have podman && podman ps -a --format '{{.Names}}' 2>/dev/null | grep -Eq '^vedette-'; then
			die "containers named vedette-* exist already; refusing to mix with them"
		fi
		if have docker && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Eq '^vedette'; then
			die "a Docker container named vedette* exists (a container-only Vedette?); refusing to mix with it"
		fi
	fi
	if [ -n "$TEST_DIR" ]; then
		prepare_test
		banner
	else
		[ -n "$VEDETTE_VERSION" ] || die "this install.sh is not tied to a release: its version and package checksum are empty. Download install.sh from a Vedette release page (${REPO_URL}/releases). Nothing was changed."
		case $VEDETTE_VERSION in *-test.*) die "release $VEDETTE_VERSION has a -test. prerelease: that is a test version, never a release" ;; esac
		host_version_ok "$VEDETTE_VERSION" || die "release '$VEDETTE_VERSION' cannot name a host package (SemVer, a prerelease of letters, digits and dots only). Nothing was changed."
		RELEASE=$VEDETTE_VERSION
		case $ARCH in amd64) DEB_SUM=$VEDETTE_DEB_SHA256_AMD64 ;; arm64) DEB_SUM=$VEDETTE_DEB_SHA256_ARM64 ;; esac
		printf '%s' "$DEB_SUM" | grep -Eq '^[0-9a-f]{64}$' || die "this install.sh has no package checksum for $ARCH. Nothing was changed."
	fi
	kept_release_ok "$RELEASE"
	# a self-update of vedette-host under way (D-316) owns the package until it ends: installing over it would race its applier
	if [ -e "$HOST_STATE/selfupdate/journal.json" ]; then
		die "a self-update of vedette-host is under way or stopped half way ($HOST_STATE/selfupdate/journal.json): wait for it to end, or follow docs/RUNBOOK.md if it does not. Nothing was changed."
	fi
	case $(systemctl is-active vedette-host-upgrade.service 2>/dev/null || true) in
	inactive | failed | unknown | '') ;;
	*) die "a self-update of vedette-host is running (vedette-host-upgrade.service): wait for it to end. Nothing was changed." ;;
	esac
	# the last step before the first change: from here on a re-run repairs instead of refusing (H1 of review 1)
	[ -s "$STATE/owner" ] || printf 'channel=%s\n' "$WANT" >"$STATE/owner"
	if [ -n "$rerun" ]; then
		# a re-run does not check the ports: Vedette itself may hold them (the check above is for a fresh box only)
		say "ok: $id $ver $ARCH, $((free / 1048576)) GiB free, re-run of an earlier install (ports 8443, 8444, 8765, 514 and 6514 not checked)"
	else
		say "ok: $id $ver $ARCH, $((free / 1048576)) GiB free, ports 8443, 8444, 8765, 514 and 6514 free"
	fi
}

# ---- 2. packages -----------------------------------------------------------------------------------------------------

# record_new_packages <apt-get arguments>: every package (dependencies too) apt would newly install for them, before it does.
# A dependency that another installed package merely Recommends is never found by autoremove; this list lets --uninstall look
# at it again (purging it only when nothing else depends on it).
record_new_packages() {
	# only NEW packages: an upgrade of an installed one is "Inst name [old-version] (new ...)" and is not ours to remove (N1)
	apt-get -s -q "$@" 2>/dev/null | awk '/^Inst / && $3 !~ /^\[/ {print $2}' | while read -r p; do add_line "$STATE/installed-by-us" "$p"; done
	touch "$STATE/installed-by-us"
}

snapshot_accounts() {
	getent passwd | cut -d: -f1 | sort >"$TMP/passwd.before"
	getent group | cut -d: -f1 | sort >"$TMP/group.before"
}

# record_accounts: the system accounts the scripts of the packages of this run made (a purge keeps accounts)
record_accounts() {
	getent passwd | cut -d: -f1 | sort | comm -13 "$TMP/passwd.before" - >>"$STATE/added-users"
	getent group | cut -d: -f1 | sort | comm -13 "$TMP/group.before" - >>"$STATE/added-groups"
	for f in added-users added-groups; do
		touch "$STATE/$f"
		sort -u -o "$STATE/$f" "$STATE/$f"
	done
}

install_packages() {
	say "installing the missing packages (apt)"
	apt_run update >/dev/null || die "apt-get update failed: is the box online and are its apt sources reachable?"
	pkgs=$PACKAGES
	for p in $OPTIONAL_PACKAGES; do
		if apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [^(]'; then pkgs="$pkgs $p"; else warn "package $p is not available here; skipped"; fi
	done
	# only what is missing: a package that is already installed is not upgraded, not re-marked and not recorded (H2, M2)
	missing=
	for p in $pkgs; do installed_pkg "$p" || missing="$missing $p"; done
	if [ -n "$missing" ]; then
		# shellcheck disable=SC2086 # package names, one word each
		remv=$(apt_sim install --no-upgrade --no-install-recommends $missing)
		for r in $remv; do
			[ "$r" = systemd-timesyncd ] || die "installing $missing would remove the package $r; refusing (nothing was changed)"
		done
		# recorded BEFORE apt runs, so a failure in the middle is still undone by --uninstall
		for p in $missing; do add_line "$STATE/asked-packages" "$p"; done
		for r in $remv; do add_line "$STATE/removed-packages" "$r"; done
		# shellcheck disable=SC2086 # package names, one word each
		record_new_packages install --no-upgrade --no-install-recommends $missing
		snapshot_accounts
		# shellcheck disable=SC2086 # package names, one word each
		apt_run install --no-upgrade --no-install-recommends $missing >/dev/null || die "apt-get install failed (apt output above); run again after fixing it"
		record_accounts
	else
		say "every package it needs is already installed; nothing was installed or upgraded"
	fi
	touch "$STATE/asked-packages" "$STATE/removed-packages"
	podman_ver=$(podman --version | awk '{print $3}')
	[ "$(printf '4.8\n%s\n' "${podman_ver%%-*}" | sort -V | head -n 1)" = 4.8 ] || die "podman $podman_ver is older than 4.8 (Quadlet ContainersConfModule=)"
	say "podman $podman_ver"
	# effect, not exit code of apt: the tool vedette-host runs after core restarts (D-268) answers
	/usr/sbin/conntrack --version >/dev/null 2>&1 || die "conntrack is not usable at /usr/sbin/conntrack after the install"
}

# save_runtime_state: what netavark changes on the host when the first container network comes up, written down before it does
save_runtime_state() {
	[ ! -e "$STATE/runtime-saved" ] || return 0
	cat /proc/sys/net/ipv4/ip_forward >"$STATE/ip_forward.orig" 2>/dev/null || true
	cat /proc/sys/net/ipv6/conf/all/forwarding >"$STATE/ip6_forward.orig" 2>/dev/null || true
	if have nft; then nft list tables >"$STATE/nft.before" 2>/dev/null || : >"$STATE/nft.before"; fi
	: >"$STATE/runtime-saved"
}

# ---- 3. the package --------------------------------------------------------------------------------------------------

fetch() { # fetch <url> <file> <max bytes>
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 20 --max-time 900 --max-filesize "$3" -o "$2" "$1" || die "download failed: $1"
}

install_deb() {
	if [ -n "$TEST_DIR" ]; then
		DEB=$ART/vedette-host_${RELEASE}_${ARCH}.deb
		DOCS=$ART
	else
		RELEASE=$VEDETTE_VERSION
		SERVICES=
		DEB=$TMP/vedette-host.deb
		DOCS=$TMP
		say "downloading vedette-host $RELEASE ($ARCH)"
		fetch "$REPO_URL/releases/download/v$RELEASE/vedette-host_${RELEASE}_${ARCH}.deb" "$DEB" 209715200
		got=$(sha256sum "$DEB" | awk '{print $1}')
		[ "$got" = "$DEB_SUM" ] || die "the package checksum is $got, this script expects $DEB_SUM: refusing to install it"
	fi
	[ -s "$DEB" ] || die "no package at $DEB"
	# dpkg writes a SemVer prerelease with a tilde (0.1.0-beta.1 is 0.1.0~beta.1); the asset keeps the SemVer name. Exact, because
	# host_version_ok (preflight) refused a "-" inside the prerelease.
	debver=$(printf '%s' "$RELEASE" | sed 's/-/~/')
	[ "$(dpkg-deb -f "$DEB" Package)" = vedette-host ] && [ "$(dpkg-deb -f "$DEB" Version)" = "$debver" ] || die "$DEB is not vedette-host $RELEASE"
	# the package adds one containers: line to /etc/subuid and /etc/subgid when there is none: note whether it was ours (M5)
	for f in subuid subgid; do
		if [ ! -e "$STATE/$f-seen" ]; then
			: >"$STATE/$f-seen"
			if ! grep -q '^containers:' "/etc/$f" 2>/dev/null; then
				: >"$STATE/$f-added"
				[ -e "/etc/$f" ] || : >"$STATE/$f-absent"
			fi
		fi
	done
	installed_pkg vedette-host || add_line "$STATE/asked-packages" vedette-host
	record_new_packages install --no-install-recommends "$DEB"
	snapshot_accounts
	before=$(host_pkg_state)
	keep_package
	say "installing vedette-host $RELEASE"
	if ! apt_run install --no-install-recommends "$DEB" >/dev/null; then
		# a kept file of a version that is not installed is no way back: take it out again when this run put it there
		if [ -n "$KEPT_WROTE" ] && [ "$(host_pkg_state)" != "$debver|installed" ]; then rm -f "$KEPT"; fi
		die "installing the package failed (its message is above)"
	fi
	record_accounts
	[ -x "$HOST_BIN" ] || die "$HOST_BIN is missing after the install"
	[ "$("$HOST_BIN" -version)" = "$RELEASE" ] || die "vedette-host reports $("$HOST_BIN" -version), expected $RELEASE"
	for u in vedette vedette-sensor; do getent passwd "$u" >/dev/null || die "the package did not make the user $u"; done
	kept_ok || die "$KEPT is not the package just installed (0600 root, same sha256) after the install"
	# the same version was installed already, so apt changed nothing and postinst restarted nobody: a running host that has not
	# recorded this package (versions.json gone or naming another one) adopts it only at a start, so it gets one now. A host that
	# is not running starts later (start_and_wait) and adopts it then.
	if [ "$before" = "$debver|installed" ] && ! grep -qs "$DEB_GOT" "$HOST_STATE/selfupdate/versions.json"; then
		systemctl try-restart vedette-host.service || die "vedette-host did not restart (journalctl -u vedette-host)"
	fi
}

# host_pkg_state: <Debian version>|<status> of vedette-host, empty when dpkg does not know it
host_pkg_state() { dpkg-query -W -f='${Version}|${db:Status-Status}' vedette-host 2>/dev/null || true; }

# keep_package (D-316, host-api 6.14 "Nhận bản đầu"): the verified .deb is kept as
# selfupdate/packages/vedette-host_<SemVer>_<arch>.deb, the name of the release asset and of host.files[].name (never Debian's "~"),
# so that vedette-host can go back to this version when a later self-update fails. It goes there BEFORE apt installs it: on an
# upgrade the package's postinst restarts vedette-host inside that apt run, and the host adopts the file when it starts (a first
# install starts it later, in start_and_wait). Every install, repair and upgrade puts it there again when it is not already right.
keep_package() {
	KEPT=$HOST_STATE/selfupdate/packages/vedette-host_${RELEASE}_${ARCH}.deb
	KEPT_WROTE=
	DEB_GOT=$(sha256sum "$DEB" | awk '{print $1}')
	kept_ok && return 0
	install -d -m 0700 -o root -g root "$HOST_STATE" "$HOST_STATE/selfupdate" "$HOST_STATE/selfupdate/packages"
	# a temporary name, on disk before the rename, and the rename on disk too (spec 6.14): a power cut leaves the old file or the
	# whole new one, never a short one under the kept name
	rm -f "$KEPT.new"
	if ! { install -m 0600 -o root -g root "$DEB" "$KEPT.new" && sync -- "$KEPT.new"; }; then
		rm -f "$KEPT.new"
		die "could not copy the package to $KEPT (disk full?)"
	fi
	mv -fT "$KEPT.new" "$KEPT"
	sync -- "$(dirname "$KEPT")"
	KEPT_WROTE=1
	kept_ok || die "could not keep the package at $KEPT"
}

# kept_ok: the kept package is a plain file, 0600 root, with the sha256 of the package being installed
kept_ok() {
	[ -f "$KEPT" ] && [ ! -L "$KEPT" ] && [ "$(stat -c '%a %u' "$KEPT")" = "600 0" ] && [ "$(sha256sum "$KEPT" | awk '{print $1}')" = "$DEB_GOT" ]
}

# ---- 4. host.conf, chrony, the container network ---------------------------------------------------------------------

write_host_conf() {
	core_uid=$(getent passwd vedette | cut -d: -f3)
	core_gid=$(getent group vedette | cut -d: -f3)
	sensor_uid=$(getent passwd vedette-sensor | cut -d: -f3)
	sensor_gid=$(getent group vedette-sensor | cut -d: -f3)
	for n in "$core_uid" "$core_gid" "$sensor_uid" "$sensor_gid"; do
		printf '%s' "$n" | grep -Eq '^[1-9][0-9]*$' || die "an id of the vedette users is not a plain number: '$n'"
	done
	cat >"$TMP/host.conf" <<EOF
# Written by install.sh from the ids of the users the package made. Do not edit: run install.sh again.
core_uid = $core_uid
core_gid = $core_gid
socket_gid = $core_gid
sensor_uid = $sensor_uid
sensor_gid = $sensor_gid
core_unit = vedette-core.service
socket = /run/vedette/host.sock
core_data = /var/lib/vedette
EOF
	if [ -f /etc/vedette/host.conf ] && cmp -s "$TMP/host.conf" /etc/vedette/host.conf; then
		say "host.conf is already right"
	else
		install -m 0644 -o root -g root "$TMP/host.conf" /etc/vedette/host.conf.new
		mv -f /etc/vedette/host.conf.new /etc/vedette/host.conf
		say "wrote /etc/vedette/host.conf"
	fi
}

# chrony: its configuration is the distribution's (a default file already lists /etc/chrony/sources.d, where vedette-host writes
# vedette.sources when an NTP server is set in Box network) and is never rewritten or restarted here (M1 of review 1). This only checks.
check_chrony() {
	if ! systemctl is-active --quiet chrony.service 2>/dev/null; then
		warn "chrony is installed but not running; the clock is not kept in step (systemctl status chrony)"
		return 0
	fi
	n=0
	until [ "$(chronyc -n -c sources 2>/dev/null | wc -l)" -gt 0 ] || [ "$n" -ge 15 ]; do
		sleep 1
		n=$((n + 1))
	done
	if [ "$(chronyc -n -c sources 2>/dev/null | wc -l)" -gt 0 ]; then
		say "chrony has time sources (its own configuration, unchanged)"
	else
		warn "chrony lists no time source: the clock may not synchronise (chronyc sources). Its configuration was left as it is."
	fi
}

# gather_used <skip cidr> <skip address cidr>: every IPv4 network this box knows (routes, addresses, podman and docker networks), but our own
gather_used() {
	{
		ip -4 -o route show 2>/dev/null | awk '$1 ~ /^[0-9.]+\/[0-9]+$/ {print $1}'
		ip -4 -o addr show 2>/dev/null | awk '{print $4}'
		for c in podman docker; do
			have "$c" || continue
			ids=$($c network ls -q 2>/dev/null || true)
			[ -z "$ids" ] || {
				# shellcheck disable=SC2086 # network ids, one word each
				if [ "$c" = podman ]; then $c network inspect --format '{{range .Subnets}}{{.Subnet}} {{end}}' $ids; else $c network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $ids; fi 2>/dev/null | tr ' ' '\n'
			}
		done
	} | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | grep -vxF -e "$1" -e "$2" >"$TMP/used" || true
}

clash_with_used() { # clash_with_used <cidr>: the first used network that overlaps it
	while read -r u; do
		if cidr_overlap "$1" "$u"; then
			printf '%s' "$u"
			return 0
		fi
	done <"$TMP/used"
	return 1
}

pick_subnet() {
	if [ -e "$NETWORK_FILE" ]; then
		# an existing file is kept (a re-run changes nothing), but it is checked again: a network that appeared since may clash (L3)
		cur=$(sed -n 's/^Subnet=//p' "$NETWORK_FILE" | head -n 1)
		printf '%s' "$cur" | grep -Eq '^172\.30\.[0-9]{1,3}\.0/24$' || die "$NETWORK_FILE has an unexpected Subnet '$cur'"
		gather_used "$cur" "${cur%.0/24}.1/24"
		if clash=$(clash_with_used "$cur"); then
			die "the network of the containers ($cur, $NETWORK_FILE) clashes with $clash, which this box uses. Run --uninstall --yes and install again, or free that network."
		fi
		return 0
	fi
	gather_used none none
	i=77
	while [ "$i" -le 254 ]; do
		clash_with_used "172.30.$i.0/24" >/dev/null || break
		i=$((i + 1))
	done
	[ "$i" -le 254 ] || die "no free 172.30.x.0/24 network for the containers: every one clashes with a route or a container network"
	SUBNET=172.30.$i.0/24
	GATEWAY=172.30.$i.1
	cat >"$TMP/network" <<EOF
[Network]
NetworkName=vedette-int
Subnet=$SUBNET
Gateway=$GATEWAY
# The bridge has a fixed name so that vedette-host can bind its DOCKER-USER rules to it (D-267). PodmanArgs= is the key every supported Podman
# knows (4.9 on Ubuntu 24.04, 5.x on 26.04 and Debian 13); InterfaceName= is only in Podman 5.7 and newer.
PodmanArgs=--interface-name=vedette0
# Picked by install.sh so that it clashes with no route or container network of this box (docs/DEPLOYMENT.md 6.1)
EOF
	install -m 0644 -o root -g root "$TMP/network" "$NETWORK_FILE"
	say "container network vedette-int: $SUBNET"
}

# ---- 5. network hand-over (optional) ---------------------------------------------------------------------------------

# netplan_dhcp_only <iface>: netplan holds exactly one file, in /etc/netplan, and it says nothing but "this card, DHCP"
# (no match/set-name, no other card, no VLAN or bond, no dhcp-identifier, no nameservers, no routes): moving it loses nothing
netplan_dhcp_only() {
	n=0
	np_file=
	for f in /etc/netplan/*.yaml /run/netplan/*.yaml /lib/netplan/*.yaml /usr/lib/netplan/*.yaml; do
		[ -e "$f" ] || continue
		n=$((n + 1))
		np_file=$f
	done
	[ "$n" -eq 1 ] || return 1
	case $np_file in /etc/netplan/*) ;; *) return 1 ;; esac
	[ -f "$np_file" ] && [ ! -L "$np_file" ] || return 1
	sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; s/^dhcp4: yes$/dhcp4: true/' "$np_file" | grep -v '^$' | sort >"$TMP/np.have"
	for r in "renderer: networkd" ""; do
		{
			printf '%s\n' "network:" "version: 2" "ethernets:" "$1:" "dhcp4: true"
			[ -z "$r" ] || printf '%s\n' "$r"
		} | sort >"$TMP/np.want"
		if cmp -s "$TMP/np.have" "$TMP/np.want"; then return 0; fi
	done
	return 1
}

handover() {
	iface=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
	reason=
	if [ -z "$iface" ]; then
		reason="no default route"
	elif [ -d "/sys/class/net/$iface/wireless" ] || [ -d "/sys/class/net/$iface/phy80211" ]; then
		reason="the management interface $iface is Wi-Fi"
	elif [ ! -e "/sys/class/net/$iface/device" ]; then
		reason="the management interface $iface is not a wired network card"
	elif systemctl is-active --quiet NetworkManager 2>/dev/null; then
		reason="NetworkManager manages the network"
	elif ! systemctl is-active --quiet systemd-networkd 2>/dev/null; then
		reason="systemd-networkd is not running"
	elif ! ip -4 -o addr show dev "$iface" | grep -q dynamic; then
		reason="the address of $iface is not from DHCP (set it in Box network after the install instead)"
	fi
	if [ -n "$reason" ]; then
		say "Box network is not available on this box ($reason). The network was not touched."
		return 0
	fi
	if [ -z "$HANDOVER" ]; then
		say "network: left as it is. The Box network screen stays read-only until you run install.sh --network-handover (wired DHCP port: $iface)."
		return 0
	fi
	if [ -e "$STATE/netplan-handover" ]; then
		say "network: already handed over"
		return 0
	fi
	if ! netplan_dhcp_only "$iface"; then
		say "Box network is not available on this box (netplan holds more than one DHCP card, for example a rename, another card, a VLAN, a lease identifier, name servers or routes; moving it would lose that). The network was not touched."
		return 0
	fi
	say "network hand-over on $iface (DHCP): vedette-host gets netplan to itself"
	have netplan || die "netplan is missing"
	mkdir -p "$STATE/netplan-moved/etc"
	: >"$STATE/netplan-handover"
	cp -p /etc/netplan/*.yaml "$STATE/netplan-moved/etc/"
	printf '# Written by vedette-host. Do not edit: the host rewrites this file.\nnetwork:\n  version: 2\n  renderer: networkd\n  ethernets:\n    %s:\n      dhcp4: true\n' "$iface" >"$TMP/90-vedette.yaml"
	install -m 0600 -o root -g root "$TMP/90-vedette.yaml" /etc/netplan/90-vedette.yaml.new
	mv -f /etc/netplan/90-vedette.yaml.new /etc/netplan/90-vedette.yaml
	for f in "$STATE/netplan-moved/etc"/*.yaml; do rm -f "/etc/netplan/$(basename "$f")"; done
	if ! netplan generate; then
		restore_netplan
		die "netplan generate refused the new configuration; the old netplan file is back"
	fi
	if [ -d /etc/cloud/cloud.cfg.d ]; then printf 'network: {config: disabled}\n' >"$CLOUD_FILE"; fi
	say "netplan now holds only /etc/netplan/90-vedette.yaml (the old file: $STATE/netplan-moved). It applies at the next boot or when you confirm a change in Box network; nothing was applied now."
}

restore_netplan() {
	rm -f /etc/netplan/90-vedette.yaml "$CLOUD_FILE"
	if [ -d "$STATE/netplan-moved/etc" ]; then
		mkdir -p /etc/netplan
		for f in "$STATE/netplan-moved/etc"/*.yaml; do
			[ -e "$f" ] || continue
			cp -p "$f" /etc/netplan/
		done
	fi
	rm -f "$STATE/netplan-handover"
}

# ---- 6. bootstrap, start, wait ---------------------------------------------------------------------------------------

start_registry() {
	[ -n "$TEST_DIR" ] || return 0
	mkdir -p "$(dirname "$MIRROR_FILE")"
	cat >"$MIRROR_FILE" <<EOF
# TEST INSTALL ONLY (install.sh --test-artifacts): pulls of ghcr.io/knt048 go to the registry of the test folder. Removed when the install ends.
[[registry]]
prefix = "ghcr.io/knt048"
location = "ghcr.io/knt048"

[[registry.mirror]]
location = "$REGISTRY_ADDR"
insecure = true
EOF
	if port_listening "${REGISTRY_ADDR##*:}"; then die "port ${REGISTRY_ADDR##*:} (the test registry) is in use"; fi
	systemctl reset-failed "$REGISTRY_UNIT.service" >/dev/null 2>&1 || true
	systemd-run --quiet --unit="$REGISTRY_UNIT" --collect "$ART/vedette-testchannel" serve -dir "$TEST_DIR/registry" -listen "$REGISTRY_ADDR" || die "cannot start the test registry"
	n=0
	until curl -fs "http://$REGISTRY_ADDR/v2/" >/dev/null 2>&1; do
		n=$((n + 1))
		[ "$n" -lt 20 ] || die "the test registry does not answer on $REGISTRY_ADDR"
		sleep 1
	done
}

# vedette_units: a container unit of Vedette is in the Quadlet folder
vedette_units() {
	for s in core sensor scan honeypot; do
		if [ -e "$UNIT_DIR/vedette-$s.container" ] || [ -L "$UNIT_DIR/vedette-$s.container" ]; then return 0; fi
	done
	return 1
}

# kept_records: no unit of Vedette's containers is left, but the host recorded what they ran (containers/versions-<service>.json,
# written only with the units), or this script noted it in $STATE/kept-release before it cleared those records in a run that then
# stopped: the state an --uninstall --keep-data leaves (it removes the units and the images and keeps /var/lib/vedette-host and
# $STATE). The records say which release last ran on the kept data (W2-9, D-418).
kept_records() {
	! vedette_units || return 1
	if [ -e "$STATE/kept-release" ] || [ -L "$STATE/kept-release" ]; then return 0; fi
	for f in "$HOST_STATE"/containers/versions-*.json; do
		if [ -e "$f" ] || [ -L "$f" ]; then return 0; fi
	done
	return 1
}

# kept_release: the release core last ran on the kept data, as recorded (empty when there is no record that can be read)
kept_release() {
	f=$HOST_STATE/containers/versions-core.json
	v=
	if [ -f "$f" ] && [ ! -L "$f" ]; then
		# one line of JSON (Go's encoding); the current record holds only plain values, so it ends at its first }
		v=$(sed -n 's/.*"current":{\([^}]*\)}.*/\1/p' "$f" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n 1)
	fi
	if [ -z "$v" ] && [ -f "$STATE/kept-release" ] && [ ! -L "$STATE/kept-release" ]; then
		v=$(head -n 1 "$STATE/kept-release")
	fi
	if [ -n "$v" ] && host_version_ok "$v"; then printf '%s\n' "$v"; fi
}

# kept_release_ok <release>: a release older than the one core last ran on the kept data is refused before any change: core's
# migrations only go forward, so an older core would run on a newer database (D-418). A record that cannot be read is no record (the
# host ignores it too): a warning, and the install goes on.
kept_release_ok() {
	kept_records || return 0
	had=$(kept_release)
	if [ -z "$had" ]; then
		warn "the data of an earlier install is kept here, but the release that last ran on it cannot be read ($HOST_STATE/containers/versions-core.json or $STATE/kept-release); it is not compared with $1"
		return 0
	fi
	if dpkg --compare-versions "$(printf '%s' "$had" | sed 's/-/~/')" gt "$(printf '%s' "$1" | sed 's/-/~/')"; then
		die "this box keeps the data of Vedette $had (an --uninstall --keep-data), newer than the release of this script ($1): an older Vedette cannot open newer data. Run the install.sh of release $had or newer. Nothing was changed."
	fi
	if [ "$had" = "$1" ]; then
		say "the kept data last ran with release $had, the release of this script"
	else
		# the normal update (Settings -> Updates) takes a pre_update backup first; this path cannot (D-418)
		warn "the kept data last ran with release $had: core $1 moves it forward at its first start and it cannot go back to $had. A backup of $had made before the uninstall (Settings -> Backups) is the only way back."
	fi
}

# forget_containers: the host's records of what the containers ran (versions, pulled images, the journals of unit changes and the old
# unit texts) describe units and images that the uninstall removed. They are cleared, so that the bootstrap installs this release over
# the kept data and records what then runs (W2-9, D-418). The data, the backups, the release index and the host's package records stay.
# A link is removed, never followed.
forget_containers() {
	d=$HOST_STATE/containers
	[ -d "$d" ] && [ ! -L "$d" ] || return 0
	rm -f "$d"/versions-*.json "$d"/pulled-*.json "$d"/transition-*.json
	rm -rf "$d/units"
}

bootstrap() {
	# done when core has its unit and its record; a missing unit (an --uninstall --keep-data, or a unit removed by hand) is installed again
	if [ -e "$HOST_STATE/containers/versions-core.json" ] && [ -e "$UNIT_DIR/vedette-core.container" ]; then
		say "the release is already bootstrapped (containers are updated from Settings -> Updates); skipping"
		rm -f "$STATE/kept-release" # core has its record and its unit: the note of a run that stopped after writing them is done
		return 0
	fi
	if [ -z "$TEST_DIR" ]; then
		say "downloading the signed release documents"
		fetch "$REPO_URL/releases/download/index/index.json" "$DOCS/index.json" 1048576
		fetch "$REPO_URL/releases/download/index/index.json.minisig" "$DOCS/index.json.minisig" 4096
		fetch "$REPO_URL/releases/download/v$RELEASE/release-manifest.json" "$DOCS/release-manifest.json" 1048576
		fetch "$REPO_URL/releases/download/v$RELEASE/release-manifest.json.minisig" "$DOCS/release-manifest.json.minisig" 4096
	fi
	# the bootstrap runs only while vedette-host does not (one owner of the state and the units, D-142): a re-run finds it running when
	# the package install restarted it or an earlier run started it and then stopped (W2-10). start_and_wait starts it again, and so
	# does cleanup when this run fails.
	# The honeypot Requires= the host, so it stops with it and is started again with it.
	case $(systemctl is-active vedette-host.service 2>/dev/null || true) in
	inactive | failed | unknown | '') ;;
	*)
		say "stopping vedette-host for the bootstrap (it starts again below)"
		if systemctl is-active --quiet vedette-honeypot.service 2>/dev/null; then HP_STOPPED=1; fi
		HOST_STOPPED=1
		systemctl stop vedette-host.service || die "vedette-host did not stop (journalctl -u vedette-host)"
		;;
	esac
	if kept_records; then
		say "the data of an earlier install is kept here (--uninstall --keep-data) but none of its containers: installing release $RELEASE over it"
		# the release that last ran stays known until this release is bootstrapped, so a run that stops before that keeps the guard
		had=$(kept_release)
		if [ -n "$had" ]; then
			printf '%s\n' "$had" >"$STATE/kept-release.new"
			mv -f "$STATE/kept-release.new" "$STATE/kept-release"
		fi
		forget_containers
	fi
	systemctl daemon-reload
	# the scan image is built on vedette-int (#467): Quadlet makes the network only when its unit starts, and no container has started yet
	systemctl start vedette-int-network.service || die "the container network vedette-int could not be made (journalctl -u vedette-int-network)"
	say "bootstrap: verifying the release and pulling its images (several minutes; the scan image is built on the box)"
	set +e
	if [ -n "$SERVICES" ]; then
		"$HOST_BIN" -bootstrap -index "$DOCS/index.json" -index-sig "$DOCS/index.json.minisig" -manifest "$DOCS/release-manifest.json" -manifest-sig "$DOCS/release-manifest.json.minisig" -services "$SERVICES"
	else
		"$HOST_BIN" -bootstrap -index "$DOCS/index.json" -index-sig "$DOCS/index.json.minisig" -manifest "$DOCS/release-manifest.json" -manifest-sig "$DOCS/release-manifest.json.minisig"
	fi
	rc=$?
	set -e
	case $rc in
	0) ;;
	4) say "a release is already installed here; update the containers from Settings -> Updates" ;;
	3) die "vedette-host refused the release (its message is above): signature, platform or disk. Nothing was started." ;;
	5) die "a unit file in /etc/containers/systemd is not Vedette's own (unit_foreign), or a credential volume was made for other ids (unit_unsafe); the line above says which. Look at it; nothing was replaced." ;;
	*) die "vedette-host -bootstrap failed with exit $rc (its message is above); run this script again after fixing it" ;;
	esac
	[ -e "$UNIT_DIR/vedette-core.container" ] || die "core has no unit after the bootstrap (exit $rc, its message is above): this box records another release for it in $HOST_STATE/containers/versions-core.json. Run the install.sh of that release."
	rm -f "$STATE/kept-release" # the host's own record holds the release now
}

start_and_wait() {
	systemctl daemon-reload
	systemctl start vedette-host.service || die "vedette-host did not start (journalctl -u vedette-host)"
	[ -S /run/vedette/host.sock ] || die "vedette-host is running but /run/vedette/host.sock is missing"
	if [ -n "$HP_STOPPED" ]; then
		systemctl start vedette-honeypot.service || warn "the honeypot did not start again after the bootstrap (journalctl -u vedette-honeypot)"
		HP_STOPPED=
	fi
	systemctl start vedette-core.service || die "vedette-core did not start (journalctl -u vedette-core)"
	say "waiting for core to be healthy (up to 300 s)"
	n=0
	while [ "$n" -lt 60 ]; do
		st=$(podman inspect --format '{{.State.Health.Status}}' vedette-core 2>/dev/null || podman inspect --format '{{.State.Healthcheck.Status}}' vedette-core 2>/dev/null || echo none)
		if [ "$st" = healthy ] && curl -ksf -o /dev/null --max-time 5 https://127.0.0.1:8443/api/v1/setup; then
			break
		fi
		sleep 5
		n=$((n + 1))
	done
	[ "$n" -lt 60 ] || die "core is not healthy after 300 s (podman inspect vedette-core; journalctl -u vedette-core)"
	: >"$STATE/installed"
	# the effect a person depends on: the interface answers on the address of the box
	mgmt_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
	[ -n "$mgmt_ip" ] || mgmt_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4; exit}')
	if [ -n "$mgmt_ip" ]; then
		curl -ksf -o /dev/null --max-time 10 "https://$mgmt_ip:8443/api/v1/setup" || warn "core is healthy but https://$mgmt_ip:8443 does not answer from this box; check the firewall (ufw status)"
	fi
}

summary() {
	ip=$mgmt_ip
	[ -n "$ip" ] || ip="<address of this box>"
	# the core logs a code only while setup is open, but an old line stays in the journal after setup: ask the core first
	code=
	if ! curl -ksf --max-time 10 https://127.0.0.1:8443/api/v1/setup 2>/dev/null | grep -Eq '"complete" *: *true'; then
		code=$(journalctl -u vedette-core.service -o cat --no-pager 2>/dev/null | grep 'setup_code' | tail -n 1 | grep -Eo '[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}' | tail -n 1 || true)
	fi
	printf '\n'
	say "Vedette is running."
	say "  open:        https://$ip:8443   (the certificate is self-signed: accept it once)"
	if [ -n "$code" ]; then
		say "  setup code:  $code   (one time; it is also in: journalctl -u vedette-core)"
	else
		say "  setup code:  none printed: first-run setup was completed already"
	fi
	say "  remove:      sh install.sh --uninstall --yes"
	[ -z "$TEST_DIR" ] || banner
}

do_install() {
	preflight
	TMP=$(mktemp -d "$STATE/tmp.XXXXXX")
	install_packages
	save_runtime_state
	install_deb
	write_host_conf
	check_chrony
	pick_subnet
	handover
	start_registry
	bootstrap
	start_and_wait
	forward_check
	summary
}

# forward_check (D-267): Docker sets the iptables FORWARD policy to DROP, and an accept in netavark's nftables table does not undo that:
# without a rule in DOCKER-USER the LAN cannot reach 8443, 514 or 6514 and the containers cannot reach the internet. vedette-host keeps five
# fixed rules in DOCKER-USER for the container network while that chain exists, and above them one ACCEPT per uplink bridge of the box named
# br-… (D-396); here the five are checked, and a firewall that is not Docker's is only reported, never changed.
forward_check() {
	have iptables || return 0
	fw_net=$(sed -n 's/^Subnet=//p' "$NETWORK_FILE" | head -n 1)
	printf '%s' "$fw_net" | grep -Eq '^172\.30\.[0-9]{1,3}\.0/24$' || return 0
	if iptables -w 5 -S DOCKER-USER >/dev/null 2>&1; then
		if ! grep -qx 'PodmanArgs=--interface-name=vedette0' "$NETWORK_FILE"; then
			warn "$NETWORK_FILE is from an install that did not name the bridge vedette0, so vedette-host puts no rules in DOCKER-USER (D-267): run --uninstall --yes and install again"
			return 0
		fi
		# the file names the bridge, but Podman keeps the bridge of a network vedette-int that existed before (left by an earlier install
		# or made by hand): then there is no vedette0, and the rules below are written and found but never match a packet
		if ! ip -o link show dev vedette0 >/dev/null 2>&1; then
			warn "the container network vedette-int has no bridge named vedette0 (a network left by an earlier install keeps its old bridge; podman network inspect vedette-int shows it), so the DOCKER-USER rules of vedette-host never match: the LAN may not reach 8443, 514 or 6514 and the containers may not reach the internet. Run --uninstall --yes and install again (D-267)"
			return 0
		fi
		say "Docker is on this box: vedette-host keeps five rules in its DOCKER-USER chain for the bridge vedette0 and $fw_net, plus one ACCEPT per uplink bridge of the box named br-… (comment vedette-int; --uninstall removes them; D-267, D-396)"
		n=0
		while [ "$n" -lt 15 ]; do
			fwd_rules_present "$fw_net" && return 0
			sleep 2
			n=$((n + 1))
		done
		warn "the five DOCKER-USER rules for vedette0 and $fw_net are not there after 30 s: the LAN may not reach 8443, 514 or 6514, the containers may not reach the internet, and other containers may reach Vedette's unpublished ports (journalctl -u vedette-host)"
	elif iptables -w 5 -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
		warn "the iptables FORWARD policy is DROP and there is no DOCKER-USER chain (ufw DEFAULT_FORWARD_POLICY, firewalld or your own firewall): the LAN cannot reach 8443, 514 or 6514 and the containers cannot reach the internet. Allow forwarding to and from $fw_net in that firewall; Vedette does not change a firewall that is not Docker's."
	fi
}

# fwd_rules_present <subnet>: the five fixed rules of D-267 and D-396 are in DOCKER-USER (same words as fwdRules in host/ops/dockerfwd.go;
# TestInstallSh_ForwardRulesOfTheHost holds that); the ACCEPTs of the box's own bridges are the host's to keep and are not looked at here
fwd_rules_present() {
	iptables -w 5 -C DOCKER-USER -i vedette0 -o docker0 -m comment --comment vedette-int -j RETURN >/dev/null 2>&1 &&
		iptables -w 5 -C DOCKER-USER -i vedette0 -o 'br-+' -m comment --comment vedette-int -j RETURN >/dev/null 2>&1 &&
		iptables -w 5 -C DOCKER-USER -o vedette0 -d "$1" -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -m comment --comment vedette-int -j ACCEPT >/dev/null 2>&1 &&
		iptables -w 5 -C DOCKER-USER -i vedette0 -s "$1" -m comment --comment vedette-int -j ACCEPT >/dev/null 2>&1 &&
		iptables -w 5 -C DOCKER-USER ! -i vedette0 -o vedette0 -m comment --comment vedette-int -j DROP >/dev/null 2>&1
}

# remove_forward_rules: the rules vedette-host put in DOCKER-USER (D-267, D-396): the lines bound to the bridge vedette0 that carry the
# comment vedette-int and end in ACCEPT, RETURN or DROP (the fixed five and the ACCEPT of every bridge of the box, gone ones too); nothing
# else (iptables prints -i and -o after -s and -d, so they are not at a fixed place; the DROP prints "! -i vedette0", a word of its own)
remove_forward_rules() {
	have iptables || return 0
	iptables -w 5 -S DOCKER-USER >"$TMP/du.rules" 2>/dev/null || return 0
	grep -E '^-A DOCKER-USER .*-[io] vedette0 .*--comment vedette-int -j (ACCEPT|RETURN|DROP)$' "$TMP/du.rules" | sed 's/^-A /-D /' | while IFS= read -r l; do
		# shellcheck disable=SC2086 # the words of one rule iptables printed, none holds a space or a glob ("!" and "br-+" are not globs)
		iptables -w 5 $l >/dev/null 2>&1 || true
	done
}

# ---- uninstall -------------------------------------------------------------------------------------------------------

# remove_images: the images Vedette pulled or made, by their exact names (the services of host/api.Services): the registry names
# ghcr.io/knt048/vedette-<service>, the local names the host gives them (localhost/vedette-<service>:<version>) and the scan image the
# box builds (localhost/vedette-scan-nmap). Another localhost/vedette-* image may be the administrator's own and is never touched; an
# image of ours that also has a name of someone else is left too (rmi -f by ID would take that name and its containers with it). Then
# what the on-box scan build left without a name, found only by its label, and our released images that lost their name; never prune.
remove_images() {
	podman images --format '{{.ID}} {{.Repository}}' 2>/dev/null | awk '
		$2 ~ /^(ghcr\.io\/knt048|localhost)\/vedette-(core|sensor|honeypot|scan|greenbone)$/ || $2 == "localhost/vedette-scan-nmap" { ours[$1] = 1; next }
		$2 != "<none>" { other[$1] = 1 }
		END { for (id in ours) print id, (id in other) ? "shared" : "ours" }' | sort -u | while read -r id kind; do
		if [ "$kind" = ours ]; then
			podman rmi -f "$id" >/dev/null 2>&1 || true
		else
			warn "image $id is Vedette's but also has a name that is not Vedette's: left in place (podman images | grep $id)"
		fi
	done
	podman images -a --filter dangling=true --filter label=io.vedette.build=scan --format '{{.ID}}' 2>/dev/null | sort -u | while read -r id; do
		podman rmi -f "$id" >/dev/null 2>&1 || true
	done
	# a pulled vedette-scan-base after a failed build or an upgrade: untagged, with our source label and a vedette-* title; an image of
	# anyone else has neither and is never touched
	podman images -a --filter dangling=true --filter 'label=org.opencontainers.image.source=https://github.com/KNT048/vedette' --format '{{.ID}}' 2>/dev/null | sort -u | while read -r id; do
		title=$(podman image inspect --format '{{index .Labels "org.opencontainers.image.title"}}' "$id" 2>/dev/null) || continue
		case "$title" in vedette-*) podman rmi -f "$id" >/dev/null 2>&1 || true ;; esac
	done
}

# remove_subid <file> <state name>: the line the package added, and the file if the package made it; never the administrator's own line
remove_subid() {
	[ -e "$1" ] && [ -e "$STATE/$2-added" ] || return 0
	sed -i '/^containers:2147483647:2147483648$/d' "$1"
	if [ ! -s "$1" ] && [ -e "$STATE/$2-absent" ]; then rm -f "$1"; fi
}

# nft_table_is_netavark_only <family> <name>: true when the table has no chain but netavark's (NETAVARK*), and the other (base) chains only
# jump to those: nothing in it is anybody else's
nft_table_is_netavark_only() {
	nft list table "$1" "$2" 2>/dev/null | awk '
		/^[[:space:]]*chain / { c = $2; inchain = 1; if (c !~ /^NETAVARK/) base = 1; next }
		/^[[:space:]]*}/ { inchain = 0; next }
		inchain && c !~ /^NETAVARK/ && $0 !~ /^[[:space:]]*(type |#)/ && $0 !~ /NETAVARK/ && $0 !~ /^[[:space:]]*$/ { foreign = 1 }
		END { exit foreign }'
}

# forwarding_needed_elsewhere: true when something that is not ours wants IP forwarding on: a running Docker, a podman network that is
# neither the default nor ours, libvirt's bridge, or a sysctl file that sets it (then the value is the administrator's, not ours to undo)
forwarding_needed_elsewhere() {
	systemctl is-active --quiet docker.service 2>/dev/null && return 0
	systemctl is-active --quiet libvirtd.service 2>/dev/null && return 0
	[ -e /sys/class/net/virbr0 ] && return 0
	grep -qsE '^[[:space:]]*net\.ipv[46]\.(ip_forward|conf\.(all|default)\.forwarding)[[:space:]]*=[[:space:]]*1' /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf && return 0
	[ -z "$PODMAN_IN_USE" ] || return 0
	if have podman; then
		podman network ls --format '{{.Name}}' 2>/dev/null | grep -vxE 'podman|vedette-int' | grep -q . && return 0
	fi
	return 1
}

# restore_runtime: what netavark changed on the host: forwarding back to what it was, the nft tables it left, if they are not in use
restore_runtime() {
	if forwarding_needed_elsewhere; then
		say "left IP forwarding as it is: something else on this box needs it (Docker, other containers or container networks, libvirt or a sysctl file)"
	else
		if [ -s "$STATE/ip_forward.orig" ]; then
			o=$(cat "$STATE/ip_forward.orig")
			case $o in 0 | 1) sysctl -qw "net.ipv4.ip_forward=$o" >/dev/null 2>&1 || true ;; esac
		fi
		if [ -s "$STATE/ip6_forward.orig" ]; then
			o=$(cat "$STATE/ip6_forward.orig")
			case $o in 0 | 1) sysctl -qw "net.ipv6.conf.all.forwarding=$o" >/dev/null 2>&1 || true ;; esac
		fi
	fi
	if [ -n "$PODMAN_IN_USE" ]; then
		# netavark's tables carry the NAT and port forwards of those containers too (W4-1, D-508)
		say "left the nft tables of netavark as they are: podman containers or pods that are not Vedette's use them"
	elif [ -e "$STATE/nft.before" ] && have nft; then
		nft list tables 2>/dev/null | while read -r _ fam name; do
			if ! printf '%s' "$fam" | grep -Eq '^[a-z0-9]+$' || ! printf '%s' "$name" | grep -Eq '^[A-Za-z0-9_.-]+$'; then continue; fi
			if grep -qx "table $fam $name" "$STATE/nft.before"; then continue; fi
			# a table that did not exist before goes when it is netavark's own, empty, or holds only netavark's chains (iptables-nft makes
			# ip nat and ip filter for netavark 1.4 and leaves NETAVARK-* chains in them); a table with anything else in it stays
			if [ "$name" = netavark ] || nft_table_is_netavark_only "$fam" "$name"; then
				nft delete table "$fam" "$name" >/dev/null 2>&1 || true
			else
				warn "left the nft table $fam $name: it has rules that are not Vedette's"
			fi
		done
	fi
}

# podman_others: what the rootful podman of this box holds that is not Vedette's, read after Vedette's own containers, volumes, network
# and images are removed: containers (stopped ones too), pods, networks other than podman's default and vedette-int, volumes, and
# images with a name (a nameless layer is no one's to keep; podman's own localhost/podman-pause is not counted). One "<kind> <name>"
# line each in $TMP/others, in that order, the name cut to printable characters and 64 bytes (podman's output is not trusted). Returns 1
# when podman cannot be asked (then it is kept: fail closed). Rootless storage under /home is never read nor touched (W4-1, D-508).
podman_others() {
	: >"$TMP/others"
	have podman || return 1
	: >"$TMP/o.all"
	for q in "container ps -a --format {{.Names}}" "pod pod ps --format {{.Name}}" "network network ls --format {{.Name}}" "volume volume ls --format {{.Name}}" "image images --format {{.Repository}}"; do
		k=${q%% *}
		# shellcheck disable=SC2086 # fixed words of this script, none holds a space or a glob
		timeout 60 podman ${q#* } >"$TMP/o.one" 2>/dev/null || return 1
		sed "s/^/$k /" "$TMP/o.one" >>"$TMP/o.all"
	done
	awk '
		$1 == "container" && $2 ~ /^vedette-(core|sensor|scan|honeypot|greenbone)$/ { next }
		$1 == "network" && ($2 == "podman" || $2 == "vedette-int") { next }
		$1 == "volume" && $2 ~ /^vedette-(creds-passive|creds-active|hp-log)$/ { next }
		$1 == "image" && ($2 == "<none>" || $2 == "localhost/podman-pause" || $2 == "localhost/vedette-scan-nmap" || $2 ~ /^(ghcr\.io\/knt048|localhost)\/vedette-(core|sensor|honeypot|scan|greenbone)$/) { next }
		NF < 2 { next }
		{
			n = substr($0, length($1) + 2)
			gsub(/[^A-Za-z0-9_.:@\/-]/, "?", n)
			if (length(n) > 64) n = substr(n, 1, 64) "..."
			if (!seen[$1 " " n]++) print $1, n
		}' "$TMP/o.all" >"$TMP/others"
}

# others_text: $TMP/others in words, e.g. "21 containers, 20 images and 3 volumes that are not Vedette's use it (greenbone-gvmd, ...,
# and 39 more)"
others_text() {
	awk '
		{ n[$1]++; total++; if (shown < 5) { names = names (shown ? ", " : "") $2; shown++ } }
		END {
			split("container pod network volume image", order, " ")
			for (i = 1; i <= 5; i++) {
				k = order[i]
				if (!(k in n)) continue
				w = n[k] " " k (n[k] == 1 ? "" : "s")
				parts[++np] = w
			}
			s = parts[1]
			for (i = 2; i <= np; i++) s = s (i == np ? " and " : ", ") parts[i]
			more = total - shown
			printf "%s that %s not Vedette'"'"'s use%s it (%s%s)", s, total == 1 ? "is" : "are", total == 1 ? "s" : "", names, more ? ", and " more " more" : ""
		}' "$TMP/others"
}

# podman_stays (W4-1, D-508): podman stays, with the packages it runs with and /var/lib/containers, when it holds anything that is not
# Vedette's, when that cannot be read (fail closed), and always with --keep-data (Vedette comes back on it); KEEP_PODMAN says why.
# Only a podman this script added and that holds nothing else is purged and its storage removed (D-463). PODMAN_IN_USE: containers or
# pods of someone else, or no answer, so IP forwarding and netavark's nft tables stay too. PODMAN_OURS: this script or a self-update
# added podman (only then is the summary about it).
podman_stays() {
	if grep -qx podman "$STATE/asked-packages" 2>/dev/null || by_us_packages | grep -qx podman; then PODMAN_OURS=1; fi
	installed_pkg podman || have podman || return 0
	if ! podman_others; then
		PODMAN_IN_USE=1
		KEEP_PODMAN="could not check what else uses it (podman did not answer)"
	elif [ -s "$TMP/others" ]; then
		if grep -qE '^(container|pod) ' "$TMP/others"; then PODMAN_IN_USE=1; fi
		KEEP_PODMAN=$(others_text)
	elif [ -n "$KEEP_DATA" ]; then
		KEEP_PODMAN="--keep-data was given, and the next install runs Vedette on it again"
	fi
}

# podman_pkgs: podman and what it runs with: the runtime packages by name (also when apt-cache cannot answer), every installed package
# podman Depends on down the tree, and the installed ones it Recommends (ca-certificates for its pulls, catatonit, passt, uidmap; a purge
# of a Recommends is not stopped by apt). apt-cache reads the local cache only. One valid name per line, sorted.
podman_pkgs() {
	{
		printf '%s\n' podman crun runc conmon netavark aardvark-dns catatonit containers-common golang-github-containers-common
		apt-cache depends --recurse --installed --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances podman 2>/dev/null || true
		apt-cache depends --installed podman 2>/dev/null | sed -n 's/^ *|\{0,1\}Recommends: //p' || true
	} | grep -E '^[a-z0-9][a-z0-9+.-]*$' | sort -u
}

# by_us_packages: the packages apt newly installed for Vedette, one valid name per line, sorted: this script's own list and the one
# vedette-host keeps of what its self-updates added (D-316 (9); a plain file, never a link)
by_us_packages() {
	for f in "$STATE/installed-by-us" "$HOST_STATE/selfupdate/installed-by-us"; do
		if [ -f "$f" ] && [ ! -L "$f" ]; then cat "$f"; fi
	done | grep -E '^[a-z0-9][a-z0-9+.-]*$' | sort -u
}

# purge_added_packages: vedette-host first, then what the script asked apt for: marked auto, and only what apt then finds
# unneeded (and was not removable before) is purged. A package someone else installed on top of ours keeps ours (H2 of review 1).
purge_added_packages() {
	if installed_pkg vedette-host; then apt_run purge vedette-host >/dev/null || warn "apt could not purge vedette-host"; fi
	# a podman that stays (D-508) keeps every package it runs with: none of them is a candidate, and the ones this script asked for by
	# name are marked manual again (the install asked for them by name, so they were manual), so a later apt autoremove keeps them too
	: >"$TMP/keep"
	[ -z "$KEEP_PODMAN" ] || podman_pkgs >"$TMP/keep"
	asked=
	KEPT_MANUAL=
	if [ -s "$STATE/asked-packages" ]; then
		while read -r p; do
			if printf '%s' "$p" | grep -Eq '^[a-z0-9][a-z0-9+.-]*$' && installed_pkg "$p"; then
				if grep -qxF "$p" "$TMP/keep"; then KEPT_MANUAL="$KEPT_MANUAL $p"; else asked="$asked $p"; fi
			fi
		done <"$STATE/asked-packages"
	fi
	# shellcheck disable=SC2086 # package names, one word each
	[ -z "$asked" ] || apt-mark auto $asked >/dev/null
	# shellcheck disable=SC2086 # package names, one word each
	[ -z "$KEPT_MANUAL" ] || apt-mark manual $KEPT_MANUAL >/dev/null || warn "apt-mark manual$KEPT_MANUAL failed"
	# the only packages this script may remove: the ones it asked for, and the ones apt NEWLY installed for them (N1, N2), by this script
	# or by a self-update of vedette-host (a Depends a later release added; the host records them before it installs, D-316 (9)).
	# Whatever else became removable meanwhile (old kernels after an unattended upgrade) is the administrator's, and so is a package
	# marked manual.
	touch "$STATE/asked-packages" "$STATE/installed-by-us"
	by_us_packages >"$TMP/by-us"
	cat "$STATE/asked-packages" "$TMP/by-us" | sort -u >"$TMP/cand.all"
	apt-mark showmanual 2>/dev/null | sort -u >"$TMP/manual"
	comm -23 "$TMP/cand.all" "$TMP/manual" | comm -23 - "$TMP/keep" >"$TMP/cand"
	# a purge can leave a library nothing needs any more (its user was in the first set): go round until nothing is left
	pass=0
	while [ "$pass" -lt 6 ]; do
		pass=$((pass + 1))
		apt_sim autoremove --purge >"$TMP/rm.all"
		comm -12 "$TMP/cand" "$TMP/rm.all" >"$TMP/rm.ours"
		[ -s "$TMP/rm.ours" ] || break
		# shellcheck disable=SC2046 # package names, one word each
		apt_sim purge $(cat "$TMP/rm.ours") >"$TMP/rm.sim"
		extra=$(comm -13 "$TMP/rm.ours" "$TMP/rm.sim" | tr '\n' ' ')
		if [ -n "$extra" ]; then
			warn "not purging the packages the installer added: apt would also remove $extra"
			break
		fi
		# shellcheck disable=SC2046 # package names, one word each
		apt_run purge $(cat "$TMP/rm.ours") >/dev/null || {
			warn "apt could not purge some packages the installer added"
			break
		}
	done
	# what apt installed for us and autoremove keeps (a package another one only Recommends): purged when nothing depends on it
	left=
	while read -r p; do
		if installed_pkg "$p" && ! grep -qxF "$p" "$TMP/manual" && ! grep -qxF "$p" "$TMP/keep"; then left="$left $p"; fi
	done <"$TMP/by-us"
	if [ -n "$left" ]; then
		# a package goes when purging it removes nothing but packages of this list (tzdata-legacy needs tzdata: both go); one that
		# something else depends on (ufw needs iptables) stays, and so does everything that package needs
		# shellcheck disable=SC2086 # package names, one word each
		printf '%s\n' $left | sort -u >"$TMP/left"
		: >"$TMP/left.go"
		for p in $left; do
			apt_sim purge "$p" >"$TMP/left.sim"
			if [ -z "$(comm -13 "$TMP/left" "$TMP/left.sim")" ]; then
				echo "$p" >>"$TMP/left.go"
			else
				say "kept $p: another package depends on it"
			fi
		done
		if [ -s "$TMP/left.go" ]; then
			# shellcheck disable=SC2046 # package names, one word each
			apt_run purge $(cat "$TMP/left.go") >/dev/null || warn "apt could not purge: $(tr '\n' ' ' <"$TMP/left.go")"
		fi
	fi
	if [ -s "$STATE/removed-packages" ]; then
		# shellcheck disable=SC2046 # package names, one word each
		apt_run install --no-install-recommends $(grep -E '^[a-z0-9][a-z0-9+.-]*$' "$STATE/removed-packages" | tr '\n' ' ') >/dev/null || warn "apt could not put back the packages it removed: $(tr '\n' ' ' <"$STATE/removed-packages")"
	fi
}

do_uninstall() {
	if [ ! -d "$STATE" ] && ! installed_pkg vedette-host && [ ! -e /etc/vedette/host.conf ]; then
		say "nothing to remove: no Vedette install made by this script was found"
		return 0
	fi
	if [ -z "$YES" ]; then
		say "this would stop Vedette and remove: its containers, images, networks and volumes, the unit files, the package vedette-host,"
		say "the packages this script asked apt for (listed in $STATE/asked-packages) and the ones apt installed for them or for an update of"
		say "vedette-host ($STATE/installed-by-us, $HOST_STATE/selfupdate/installed-by-us), each when nothing else needs it${KEEP_DATA:+ (the data and the users are KEPT)}"
		[ -n "$KEEP_DATA" ] || say "and DELETE the database and the master key in /var/lib/vedette (no way back), /etc/vedette and the users vedette and vedette-sensor"
		say "podman, the packages it runs with and /var/lib/containers stay when podman holds anything that is not Vedette's (containers, pods,"
		say "networks, volumes, images)${KEEP_DATA:+ and always with --keep-data}; only Vedette's own containers, images, volumes and network are removed from it"
		die "run again with --yes to do it"
	fi
	if [ -d "$STATE" ]; then TMP=$(mktemp -d "$STATE/tmp.XXXXXX"); else TMP=$(mktemp -d /var/tmp/vedette-install.XXXXXX); fi
	say "stopping Vedette"
	# the containers first, then the Quadlet network and volume units (they stay "active" after their one-shot run and would stop a
	# later install from making the network again)
	for u in vedette-honeypot vedette-scan vedette-sensor vedette-core vedette-host "$REGISTRY_UNIT" vedette-int-network vedette-creds-passive-volume vedette-creds-active-volume vedette-hp-log-volume; do
		systemctl stop "$u.service" >/dev/null 2>&1 || true
	done
	if have podman; then
		for c in vedette-honeypot vedette-scan vedette-sensor vedette-core vedette-greenbone; do
			podman rm -f -t 5 "$c" >/dev/null 2>&1 || true
		done
	fi
	ip netns delete vedette-hp >/dev/null 2>&1 || true
	rm -f /etc/containers/systemd/vedette-* "$MIRROR_FILE"
	# a unit write of vedette-host cut short leaves .tmp-<16 lowercase hex> beside the units (host/ops writeAtomicIn); a regular file only
	for f in /etc/containers/systemd/.tmp-*; do
		n=${f##*/.tmp-}
		case $n in *[!0-9a-f]*) continue ;; esac
		if [ "${#n}" -eq 16 ] && [ -f "$f" ] && [ ! -L "$f" ]; then rm -f "$f"; fi
	done
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed >/dev/null 2>&1 || true
	remove_forward_rules
	if have podman; then
		podman network rm -f vedette-int >/dev/null 2>&1 || true
		podman volume rm -f vedette-creds-passive vedette-creds-active vedette-hp-log >/dev/null 2>&1 || true
		remove_images
	fi
	podman_stays
	restore_runtime
	say "removing packages"
	# a purge does not stop a daemon that is running
	if grep -qx chrony "$STATE/asked-packages" 2>/dev/null; then
		systemctl disable --now chrony.service >/dev/null 2>&1 || true
	fi
	# the purge of a package with an AppArmor profile (chrony) runs dh_apparmor's postrm, which also rmdirs the apparmor package's
	# own folders when they are empty (/etc/apparmor.d/disable on a fresh Ubuntu 24.04): one that was there before is put back
	# while the apparmor package is installed (a box without it had the folders only for the purged profiles, made by dpkg)
	aa_dirs=
	for d in /etc/apparmor.d /etc/apparmor.d/disable /etc/apparmor.d/force-complain /etc/apparmor.d/local; do
		if [ -d "$d" ] && [ ! -L "$d" ]; then aa_dirs="$aa_dirs $(stat -c %a "$d"):$d"; fi
	done
	purge_added_packages
	if installed_pkg apparmor; then
		for e in $aa_dirs; do
			[ -e "${e#*:}" ] || install -d -m "${e%%:*}" -o root -g root "${e#*:}" || warn "could not put back the folder ${e#*:}"
		done
	fi
	# what podman, when this script added it and apt then purged it, left behind: its storage and runtime files (a purge keeps them),
	# and the folders the package (/etc/containers, its systemd/) and podman for vedette-int (networks/, /var/lib/cni) made. A podman
	# that apt kept (another package needs it, or it is marked manual) is the administrator's: nothing of it is touched (D-463).
	if [ -z "$KEEP_PODMAN" ] && grep -qx podman "$STATE/asked-packages" 2>/dev/null && ! installed_pkg podman; then
		find /var/lib/containers -mindepth 1 -delete 2>/dev/null || true
		rmdir /var/lib/containers 2>/dev/null || true
		rm -rf /run/containers /root/.config/cni
		# rmdir only, deepest first, and never a folder an installed package owns (buildah's containers-common): a folder with anything
		# left in it is somebody else's and stays (N100)
		for d in /etc/containers/networks /etc/containers/systemd/users /etc/containers/systemd /etc/containers/registries.conf.d /etc/containers /var/lib/cni/networks /var/lib/cni /root/.config; do
			if [ -d "$d" ] && ! dpkg-query -S "$d" >/dev/null 2>&1; then rmdir "$d" 2>/dev/null || true; fi
		done
	fi
	if grep -qx netplan.io "$STATE/asked-packages" 2>/dev/null; then
		rm -f /run/systemd/system/netplan-ovs-cleanup.service /run/systemd/system/*.wants/netplan-ovs-cleanup.service
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	rm -f /etc/chrony/sources.d/vedette.sources
	if [ -e "$STATE/netplan-handover" ]; then
		restore_netplan
		say "netplan file restored from $STATE/netplan-moved (applies at the next boot; nothing was applied now)"
	fi
	rm -f "$CLOUD_FILE"
	if [ -n "$KEEP_DATA" ]; then
		# a kept podman and the packages it runs with stay on the lists, so that a later --uninstall without --keep-data decides about
		# them again (D-508); every other line is done with
		grep -xFf "$TMP/keep" "$STATE/asked-packages" >"$TMP/asked.kept" 2>/dev/null || true
		grep -xFf "$TMP/keep" "$TMP/by-us" >"$TMP/by-us.kept" 2>/dev/null || true
		cat "$TMP/asked.kept" >"$STATE/asked-packages"
		: >"$STATE/removed-packages"
		cat "$TMP/by-us.kept" >"$STATE/installed-by-us"
		# the host's list was handled above with ours; the data is kept, this list is not (a link is removed, never followed)
		rm -f "$HOST_STATE/selfupdate/installed-by-us"
		# the next install saves the forwarding and nft state again, as it will be then
		rm -f "$STATE/runtime-saved" "$STATE/ip_forward.orig" "$STATE/ip6_forward.orig" "$STATE/nft.before"
		say "kept: /var/lib/vedette*, /etc/vedette and the users. Running install.sh again (this release or a newer one) brings Vedette back with them."
	else
		rm -rf /var/lib/vedette /var/lib/vedette-host /var/lib/vedette-honeypot /var/lib/vedette-creds /etc/vedette /var/log/vedette-host /run/vedette
		remove_subid /etc/subuid subuid
		remove_subid /etc/subgid subgid
		for u in vedette vedette-sensor; do
			if getent passwd "$u" >/dev/null; then userdel "$u" >/dev/null 2>&1 || warn "could not delete the user $u"; fi
			if getent group "$u" >/dev/null; then groupdel "$u" >/dev/null 2>&1 || warn "could not delete the group $u"; fi
		done
		# the system accounts that the added packages' scripts made (recorded at install time, nothing else)
		while read -r u; do
			[ -z "$u" ] || ! getent passwd "$u" >/dev/null || [ "$(id -u "$u")" = 0 ] || userdel "$u" >/dev/null 2>&1 || true
		done <"$STATE/added-users" 2>/dev/null || true
		while read -r g; do
			[ -z "$g" ] || ! getent group "$g" >/dev/null || [ "$(getent group "$g" | cut -d: -f3)" = 0 ] || groupdel "$g" >/dev/null 2>&1 || true
		done <"$STATE/added-groups" 2>/dev/null || true
		[ -z "$TMP" ] || rm -rf "$TMP"
		TMP=
		rm -rf "$STATE"
	fi
	for p in 8443 8444 8765; do
		if port_listening "$p"; then warn "port $p still listens (another program?)"; fi
	done
	if [ -n "$KEEP_PODMAN" ] && [ -n "$PODMAN_OURS" ]; then
		say "kept podman, the packages it runs with and /var/lib/containers: $KEEP_PODMAN"
		[ -z "$KEPT_MANUAL" ] || say "  marked$KEPT_MANUAL as installed by hand (apt-mark manual), so apt autoremove keeps them"
		[ -n "$KEEP_DATA" ] || say "  to remove podman too, once nothing else needs it: podman system reset, then apt-get purge podman, then apt-get autoremove"
	fi
	say "Vedette is removed."
}

case $MODE in
install) do_install ;;
uninstall) do_uninstall ;;
esac
