#!/bin/sh
# Vedette installer for a fresh Ubuntu 24.04 / 26.04 or Debian 13 box (WP-08h, D-166). Run as root:
#
#   curl -fsSL https://github.com/KNT048/vedette/releases/download/v<version>/install.sh | sudo sh
#   sh install.sh [--network-handover] [--uninstall [--yes] [--keep-data]] [--test-artifacts DIR]
#
# What it does, in this order, and stops at the first thing it cannot do (a refusal before step 3 changes nothing):
#   1. preflight: OS, architecture, root, systemd, disk, ports 8443/8444, no other Vedette, a sane clock
#   2. installs the packages Vedette needs (podman, chrony, netplan.io, nftables, ...) with apt
#   3. downloads the vedette-host .deb of THIS release, checks its sha256 against the value written into this script by the
#      release job, and installs it (the package makes the users, folders and the unit)
#   4. writes /etc/vedette/host.conf from the users' real ids, the chrony configuration and the network of the containers
#   5. optional, only with --network-handover and only on a wired DHCP management port: gives netplan to vedette-host
#   6. vedette-host -bootstrap: verifies the signed release (keys built into vedette-host, not into this script) and pulls
#      the signed images by digest; then starts vedette-host and core, waits until core is healthy and prints the address
#      and the one-time setup code
# Running it again repairs or upgrades the host package and changes nothing that is already right. --uninstall --yes puts
# the box back as it was (--keep-data keeps the data and the users). Nothing is read from the environment.
#
# The three values below are filled by the release job (WP-08k) and are empty in the repository: an empty value makes the
# customer path stop with a clear message, so a script that is not tied to a release can never install anything.
VEDETTE_VERSION=""
VEDETTE_DEB_SHA256_AMD64=""
VEDETTE_DEB_SHA256_ARM64=""
REPO_URL="https://github.com/KNT048/vedette"

set -eu
umask 022
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset IFS

STATE=/var/lib/vedette-install
HOST_BIN=/usr/lib/vedette/vedette-host
HOST_STATE=/var/lib/vedette-host
NETWORK_FILE=/etc/containers/systemd/vedette-int.network
MIRROR_FILE=/etc/containers/registries.conf.d/vedette-test-mirror.conf
REGISTRY_UNIT=vedette-testregistry
REGISTRY_ADDR=127.0.0.1:5077
CLOUD_FILE=/etc/cloud/cloud.cfg.d/99-vedette-network.cfg
# iptables: netavark 1.4 (Ubuntu 24.04) programs the firewall through it and fails with "No such file" without it (found by install-check)
PACKAGES="ca-certificates curl podman chrony netplan.io nftables iptables iproute2 procps unattended-upgrades passwd"
OPTIONAL_PACKAGES="netavark aardvark-dns catatonit"
MIN_FREE_KB=6291456 # 6 GiB under /var/lib and /var/tmp: the images are about 1 GB, the data grows
CLOCK_FLOOR=1793491200 # 2026-11-01: a clock before this is not set

MODE=install
HANDOVER=
KEEP_DATA=
YES=
TEST_DIR=
TMP=

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
  --network-handover     give netplan to vedette-host (wired DHCP management port only; default: leave the network alone)
  --uninstall --yes      remove Vedette and put the box back as it was; without --yes it only says what it would remove
  --keep-data            with --uninstall: keep /var/lib/vedette*, /etc/vedette and the users (the key and the database)
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
	rmdir "$STATE" 2>/dev/null || true # a refusal in the preflight leaves nothing behind
	if [ "$rc" -ne 0 ] && [ "$MODE" = install ] && [ -d "$STATE" ]; then
		say "stopped before the end. Run the script again to repair, or --uninstall --yes to remove what was made."
	fi
	exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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

installed_pkg() { dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed; }

pkg_list() { dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u; }

apt_run() {
	DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 -o Dpkg::Options::=--force-confold -y -q "$@"
}

os_field() { sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d '"'; }

# ---- 1. preflight ----------------------------------------------------------------------------------------------------

preflight() {
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
	for t in ss ip awk sed grep sha256sum getent; do have "$t" || die "$t is missing; install it first (iproute2, coreutils, libc-bin)"; done
	now=$(date -u +%s)
	[ "$now" -ge "$CLOCK_FLOOR" ] || die "the clock says $(date -u +%F): it is not set. Fix the date (timedatectl set-time) and run again."
	if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo yes)" = no ]; then
		warn "the clock is not synchronised yet; chrony will do it, but certificates are checked against it"
	fi
	mkdir -p "$STATE"
	chmod 0700 "$STATE"
	free=$(df -Pk "$STATE" | awk 'NR==2 {print $4}')
	[ "${free:-0}" -ge "$MIN_FREE_KB" ] || die "less than 6 GiB free under /var ($((free / 1024)) MiB): free some space and run again"
	mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
	[ "${mem:-0}" -ge 3600000 ] || warn "only $((mem / 1024)) MiB of memory: the minimum is 4 GiB (8 GiB recommended)"
	if [ ! -e "$STATE/installed" ]; then
		for p in 8443 8444; do
			! port_listening "$p" || die "port $p is already in use by another program (ss -ltnp). Vedette needs 8443 (interface) and 8444 (sensor link)."
		done
		if [ -e /etc/vedette/host.conf ] || installed_pkg vedette-host || getent passwd vedette >/dev/null; then
			rmdir "$STATE" 2>/dev/null || true
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
		banner
		[ -s "$TEST_DIR/test-channel.env" ] && [ -s "$TEST_DIR/SHA256SUMS" ] || die "$TEST_DIR is not a folder made by make install-artifacts"
		[ "$(kv ARCH "$TEST_DIR/test-channel.env")" = "$ARCH" ] || die "the artifacts are for $(kv ARCH "$TEST_DIR/test-channel.env"), this machine is $ARCH"
		if port_listening "${REGISTRY_ADDR##*:}"; then die "port ${REGISTRY_ADDR##*:} (the test registry) is in use"; fi
	else
		[ -n "$VEDETTE_VERSION" ] || die "this install.sh is not tied to a release: its version and package checksum are empty. Download install.sh from a Vedette release page (${REPO_URL}/releases). Nothing was changed."
		case $ARCH in amd64) DEB_SUM=$VEDETTE_DEB_SHA256_AMD64 ;; arm64) DEB_SUM=$VEDETTE_DEB_SHA256_ARM64 ;; esac
		printf '%s' "$DEB_SUM" | grep -Eq '^[0-9a-f]{64}$' || die "this install.sh has no package checksum for $ARCH. Nothing was changed."
	fi
	say "ok: $id $ver $ARCH, $((free / 1048576)) GiB free, ports 8443 and 8444 free"
}

# ---- 2. packages -----------------------------------------------------------------------------------------------------

install_packages() {
	say "installing packages (apt)"
	apt_run update >/dev/null || die "apt-get update failed: is the box online and are its apt sources reachable?"
	pkgs=$PACKAGES
	for p in $OPTIONAL_PACKAGES; do
		if apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [^(]'; then pkgs="$pkgs $p"; else warn "package $p is not available here; skipped"; fi
	done
	snapshot_before
	[ -e "$STATE/subuid-existed" ] || { [ -e /etc/subuid ] && : >"$STATE/subuid-existed" || : >"$STATE/subuid-absent"; }
	[ -e "$STATE/subgid-existed" ] || { [ -e /etc/subgid ] && : >"$STATE/subgid-existed" || : >"$STATE/subgid-absent"; }
	if [ ! -e "$STATE/chrony-conf-seen" ]; then
		: >"$STATE/chrony-conf-seen"
		[ -e /etc/chrony/chrony.conf ] && cp -p /etc/chrony/chrony.conf "$STATE/chrony.conf.orig" || true
	fi
	# shellcheck disable=SC2086 # a list of package names
	apt_run install --no-install-recommends $pkgs >/dev/null || die "apt-get install failed (apt output above); run again after fixing it"
	record_packages
	podman_ver=$(podman --version | awk '{print $3}')
	[ "$(printf '4.4\n%s\n' "${podman_ver%%-*}" | sort -V | head -n 1)" = 4.4 ] || die "podman $podman_ver is older than 4.4 (no Quadlet)"
	say "podman $podman_ver"
}

snapshot_before() {
	pkg_list >"$TMP/pkgs.before"
	getent passwd | cut -d: -f1 | sort >"$TMP/passwd.before"
	getent group | cut -d: -f1 | sort >"$TMP/group.before"
}

# record_packages: what this run's apt added or removed (packages, and the system accounts their scripts made), appended to the
# lists --uninstall works from. It never removes an account or a package that somebody else made after this run.
record_packages() {
	pkg_list >"$TMP/pkgs.after"
	comm -13 "$TMP/pkgs.before" "$TMP/pkgs.after" >>"$STATE/added-packages"
	comm -23 "$TMP/pkgs.before" "$TMP/pkgs.after" >>"$STATE/removed-packages"
	getent passwd | cut -d: -f1 | sort | comm -13 "$TMP/passwd.before" - >>"$STATE/added-users"
	getent group | cut -d: -f1 | sort | comm -13 "$TMP/group.before" - >>"$STATE/added-groups"
	for f in added-packages removed-packages added-users added-groups; do
		touch "$STATE/$f"
		sort -u -o "$STATE/$f" "$STATE/$f"
	done
}

# ---- 3. the package --------------------------------------------------------------------------------------------------

fetch() { # fetch <url> <file> <max bytes>
	curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 20 --max-time 900 --max-filesize "$3" -o "$2" "$1" || die "download failed: $1"
}

install_deb() {
	if [ -n "$TEST_DIR" ]; then
		say "checking the test artifacts"
		(cd "$TEST_DIR" && sha256sum -c --quiet SHA256SUMS) || die "SHA256SUMS of $TEST_DIR does not match its files"
		RELEASE=$(kv VERSION "$TEST_DIR/test-channel.env")
		SERVICES=$(kv SERVICES "$TEST_DIR/test-channel.env")
		DEB=$TEST_DIR/vedette-host_${RELEASE}_${ARCH}.deb
	else
		RELEASE=$VEDETTE_VERSION
		SERVICES=
		DEB=$TMP/vedette-host.deb
		say "downloading vedette-host $RELEASE ($ARCH)"
		fetch "$REPO_URL/releases/download/v$RELEASE/vedette-host_${RELEASE}_${ARCH}.deb" "$DEB" 209715200
		got=$(sha256sum "$DEB" | awk '{print $1}')
		[ "$got" = "$DEB_SUM" ] || die "the package checksum is $got, this script expects $DEB_SUM: refusing to install it"
	fi
	[ -s "$DEB" ] || die "no package at $DEB"
	# dpkg writes a SemVer prerelease with a tilde (0.1.0-beta.1 is 0.1.0~beta.1); the asset keeps the SemVer name
	debver=$(printf '%s' "$RELEASE" | sed 's/-/~/')
	[ "$(dpkg-deb -f "$DEB" Package)" = vedette-host ] && [ "$(dpkg-deb -f "$DEB" Version)" = "$debver" ] || die "$DEB is not vedette-host $RELEASE"
	snapshot_before
	say "installing vedette-host $RELEASE"
	apt_run install --no-install-recommends "$DEB" >/dev/null || die "installing the package failed (its message is above)"
	record_packages
	[ -x "$HOST_BIN" ] || die "$HOST_BIN is missing after the install"
	[ "$("$HOST_BIN" -version)" = "$RELEASE" ] || die "vedette-host reports $("$HOST_BIN" -version), expected $RELEASE"
	for u in vedette vedette-sensor; do getent passwd "$u" >/dev/null || die "the package did not make the user $u"; done
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

# chrony: this script owns chrony.conf (only sourcedir, no distro pool); vedette-host owns sources.d/vedette.sources (D-106).
# The default source is written here in the form the host writes, so the clock syncs before anyone opens the interface.
configure_chrony() {
	mkdir -p /etc/chrony/sources.d
	cat >"$TMP/chrony.conf" <<'EOF'
# Written by Vedette's install.sh (D-106). Time sources live in /etc/chrony/sources.d (vedette-host writes vedette.sources).
sourcedir /etc/chrony/sources.d
driftfile /var/lib/chrony/chrony.drift
makestep 1.0 3
rtcsync
EOF
	changed=
	if ! cmp -s "$TMP/chrony.conf" /etc/chrony/chrony.conf 2>/dev/null; then
		install -m 0644 -o root -g root "$TMP/chrony.conf" /etc/chrony/chrony.conf
		changed=1
	fi
	if [ ! -e /etc/chrony/sources.d/vedette.sources ]; then
		printf '# Written by vedette-host. Do not edit: the host rewrites this file.\npool pool.ntp.org iburst\n' >/etc/chrony/sources.d/vedette.sources
		changed=1
	fi
	systemctl enable chrony.service >/dev/null 2>&1 || true
	# a second run restarts nothing that already runs with this configuration
	if [ -n "$changed" ] || ! systemctl is-active --quiet chrony.service; then
		systemctl restart chrony.service || warn "chrony did not restart; check systemctl status chrony"
	fi
	n=0
	until [ "$(chronyc -n -c sources 2>/dev/null | wc -l)" -gt 0 ] || [ "$n" -ge 15 ]; do
		sleep 1
		n=$((n + 1))
	done
	if [ "$(chronyc -n -c sources 2>/dev/null | wc -l)" -gt 0 ]; then say "chrony has time sources"; else warn "chrony lists no time source yet (is pool.ntp.org reachable?)"; fi
}

pick_subnet() {
	[ -e "$NETWORK_FILE" ] && return 0
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
	} | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' >"$TMP/used" || true
	i=77
	while [ "$i" -le 254 ]; do
		cand=172.30.$i.0/24
		clash=
		while read -r u; do
			if cidr_overlap "$cand" "$u"; then
				clash=1
				break
			fi
		done <"$TMP/used"
		[ -n "$clash" ] || break
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
# Picked by install.sh so that it clashes with no route or container network of this box (docs/DEPLOYMENT.md 6.1)
EOF
	install -m 0644 -o root -g root "$TMP/network" "$NETWORK_FILE"
	say "container network vedette-int: $SUBNET"
}

# ---- 5. network hand-over (optional) ---------------------------------------------------------------------------------

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
	say "network hand-over on $iface (DHCP): vedette-host gets netplan to itself"
	have netplan || die "netplan is missing"
	mkdir -p "$STATE/netplan-moved/etc" "$STATE/netplan-moved/run"
	: >"$STATE/netplan-handover"
	for d in etc run; do
		for f in "/$d/netplan"/*.yaml; do
			[ -e "$f" ] || continue
			cp -p "$f" "$STATE/netplan-moved/$d/"
		done
	done
	printf '# Written by vedette-host. Do not edit: the host rewrites this file.\nnetwork:\n  version: 2\n  renderer: networkd\n  ethernets:\n    %s:\n      dhcp4: true\n' "$iface" >"$TMP/90-vedette.yaml"
	install -m 0600 -o root -g root "$TMP/90-vedette.yaml" /etc/netplan/90-vedette.yaml.new
	mv -f /etc/netplan/90-vedette.yaml.new /etc/netplan/90-vedette.yaml
	for d in etc run; do
		for f in "/$d/netplan"/*.yaml; do
			[ -e "$f" ] || continue
			[ "$f" = /etc/netplan/90-vedette.yaml ] || rm -f "$f"
		done
	done
	if ! netplan generate; then
		restore_netplan
		die "netplan generate refused the new configuration; the old netplan files are back"
	fi
	if [ -d /etc/cloud/cloud.cfg.d ]; then printf 'network: {config: disabled}\n' >"$CLOUD_FILE"; fi
	say "netplan now holds only /etc/netplan/90-vedette.yaml (the old files: $STATE/netplan-moved). It applies at the next boot or when you confirm a change in Box network; nothing was applied now."
}

restore_netplan() {
	rm -f /etc/netplan/90-vedette.yaml "$CLOUD_FILE"
	for d in etc run; do
		[ -d "$STATE/netplan-moved/$d" ] || continue
		mkdir -p "/$d/netplan"
		for f in "$STATE/netplan-moved/$d"/*.yaml; do
			[ -e "$f" ] || continue
			cp -p "$f" "/$d/netplan/"
		done
	done
	rm -f "$STATE/netplan-handover"
}

# ---- 6. bootstrap, start, wait ---------------------------------------------------------------------------------------

start_registry() {
	[ -n "$TEST_DIR" ] || return 0
	[ -x "$TEST_DIR/vedette-testchannel" ] || die "$TEST_DIR/vedette-testchannel is missing"
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
	systemctl reset-failed "$REGISTRY_UNIT.service" >/dev/null 2>&1 || true
	systemd-run --quiet --unit="$REGISTRY_UNIT" --collect "$TEST_DIR/vedette-testchannel" serve -dir "$TEST_DIR/registry" -listen "$REGISTRY_ADDR" || die "cannot start the test registry"
	n=0
	until curl -fs "http://$REGISTRY_ADDR/v2/" >/dev/null 2>&1; do
		n=$((n + 1))
		[ "$n" -lt 20 ] || die "the test registry does not answer on $REGISTRY_ADDR"
		sleep 1
	done
}

bootstrap() {
	if [ -e "$HOST_STATE/containers/versions-core.json" ]; then
		say "the release is already bootstrapped (containers are updated from Settings -> Updates); skipping"
		return 0
	fi
	if [ -n "$TEST_DIR" ]; then
		docs=$TEST_DIR
	else
		docs=$TMP
		say "downloading the signed release documents"
		fetch "$REPO_URL/releases/download/index/index.json" "$docs/index.json" 1048576
		fetch "$REPO_URL/releases/download/index/index.json.minisig" "$docs/index.json.minisig" 4096
		fetch "$REPO_URL/releases/download/v$RELEASE/release-manifest.json" "$docs/release-manifest.json" 1048576
		fetch "$REPO_URL/releases/download/v$RELEASE/release-manifest.json.minisig" "$docs/release-manifest.json.minisig" 4096
	fi
	systemctl daemon-reload
	say "bootstrap: verifying the release and pulling its images (several minutes; the scan image is built on the box)"
	set +e
	if [ -n "$SERVICES" ]; then
		"$HOST_BIN" -bootstrap -index "$docs/index.json" -index-sig "$docs/index.json.minisig" -manifest "$docs/release-manifest.json" -manifest-sig "$docs/release-manifest.json.minisig" -services "$SERVICES"
	else
		"$HOST_BIN" -bootstrap -index "$docs/index.json" -index-sig "$docs/index.json.minisig" -manifest "$docs/release-manifest.json" -manifest-sig "$docs/release-manifest.json.minisig"
	fi
	rc=$?
	set -e
	case $rc in
	0) ;;
	4) say "a release is already installed here; update the containers from Settings -> Updates" ;;
	3) die "vedette-host refused the release (its message is above): signature, platform or disk. Nothing was started." ;;
	5) die "a unit file in /etc/containers/systemd is not Vedette's own (unit_foreign). Look at it; nothing was replaced." ;;
	*) die "vedette-host -bootstrap failed with exit $rc (its message is above); run this script again after fixing it" ;;
	esac
}

start_and_wait() {
	systemctl daemon-reload
	systemctl start vedette-host.service || die "vedette-host did not start (journalctl -u vedette-host)"
	[ -S /run/vedette/host.sock ] || die "vedette-host is running but /run/vedette/host.sock is missing"
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
	# the effect a person depends on: the interface answers on the address of the box (the port is published by netavark rules, so ss does not list it)
	mgmt_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
	[ -n "$mgmt_ip" ] || mgmt_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4; exit}')
	if [ -n "$mgmt_ip" ]; then
		curl -ksf -o /dev/null --max-time 10 "https://$mgmt_ip:8443/api/v1/setup" || warn "core is healthy but https://$mgmt_ip:8443 does not answer from this box; check the firewall (ufw status)"
	fi
}

summary() {
	ip=$mgmt_ip
	[ -n "$ip" ] || ip="<address of this box>"
	code=$(journalctl -u vedette-core.service -o cat --no-pager 2>/dev/null | grep 'setup_code' | tail -n 1 | grep -Eo '[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}' | tail -n 1 || true)
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
	install_deb
	write_host_conf
	configure_chrony
	pick_subnet
	handover
	start_registry
	bootstrap
	start_and_wait
	summary
}

# ---- uninstall -------------------------------------------------------------------------------------------------------

do_uninstall() {
	if [ ! -d "$STATE" ] && ! installed_pkg vedette-host && [ ! -e /etc/vedette/host.conf ]; then
		say "nothing to remove: no Vedette install made by this script was found"
		return 0
	fi
	if [ -z "$YES" ]; then
		say "this would stop Vedette and remove: its containers, images, networks and volumes, the unit files, the package vedette-host,"
		say "the packages this script added (listed in $STATE/added-packages)${KEEP_DATA:+ (the data and the users are KEPT)}"
		[ -n "$KEEP_DATA" ] || say "and DELETE the database and the master key in /var/lib/vedette (no way back), /etc/vedette and the users vedette and vedette-sensor"
		die "run again with --yes to do it"
	fi
	[ ! -d "$STATE" ] || TMP=$(mktemp -d "$STATE/tmp.XXXXXX")
	say "stopping Vedette"
	for u in vedette-honeypot vedette-scan vedette-sensor vedette-core vedette-host "$REGISTRY_UNIT"; do
		systemctl stop "$u.service" >/dev/null 2>&1 || true
	done
	if have podman; then
		for c in vedette-honeypot vedette-scan vedette-sensor vedette-core vedette-greenbone; do
			podman rm -f -t 5 "$c" >/dev/null 2>&1 || true
		done
	fi
	ip netns delete vedette-hp >/dev/null 2>&1 || true
	rm -f /etc/containers/systemd/vedette-* "$MIRROR_FILE"
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl reset-failed >/dev/null 2>&1 || true
	if have podman; then
		podman network rm -f vedette-int >/dev/null 2>&1 || true
		podman volume rm -f vedette-creds-passive vedette-creds-active >/dev/null 2>&1 || true
		podman images --format '{{.ID}} {{.Repository}}' 2>/dev/null | awk '$2 ~ /^(ghcr\.io\/knt048\/vedette-|localhost\/vedette-scan-nmap)/ {print $1}' | sort -u | while read -r id; do
			podman rmi -f "$id" >/dev/null 2>&1 || true
		done
	fi
	say "removing packages"
	# a purge does not stop a daemon that is running
	if grep -qx chrony "$STATE/added-packages" 2>/dev/null; then
		systemctl disable --now chrony.service >/dev/null 2>&1 || true
	fi
	if installed_pkg vedette-host; then apt_run purge vedette-host >/dev/null || warn "apt could not purge vedette-host"; fi
	if [ -s "$STATE/added-packages" ]; then
		# a package another package still needs is kept by apt; the rest goes
		# shellcheck disable=SC2046 # package names, one word each
		apt_run purge $(grep -E '^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$' "$STATE/added-packages" | grep -vx vedette-host | tr '\n' ' ') >/dev/null || warn "apt could not purge some added packages"
	fi
	if [ -s "$STATE/removed-packages" ]; then
		# shellcheck disable=SC2046 # package names, one word each
		apt_run install --no-install-recommends $(grep -E '^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$' "$STATE/removed-packages" | tr '\n' ' ') >/dev/null || warn "apt could not put back the packages it removed: $(tr '\n' ' ' <"$STATE/removed-packages")"
	fi
	# what the packages this script added left behind (a purge keeps accounts, runtime files and podman's storage)
	if grep -qx podman "$STATE/added-packages" 2>/dev/null; then
		find /var/lib/containers -mindepth 1 -delete 2>/dev/null || true
		rmdir /var/lib/containers 2>/dev/null || true
		rm -rf /run/containers /etc/containers/systemd /root/.config/cni
		rmdir /etc/containers /root/.config 2>/dev/null || true
	fi
	if grep -qx netplan.io "$STATE/added-packages" 2>/dev/null; then
		rm -f /run/systemd/system/netplan-ovs-cleanup.service /run/systemd/system/*.wants/netplan-ovs-cleanup.service
		systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	rm -f /etc/chrony/sources.d/vedette.sources
	if [ -e "$STATE/chrony.conf.orig" ]; then
		install -m 0644 -o root -g root "$STATE/chrony.conf.orig" /etc/chrony/chrony.conf
		systemctl restart chrony.service >/dev/null 2>&1 || true
	fi
	if [ -e "$STATE/netplan-handover" ]; then
		restore_netplan
		say "netplan files restored from $STATE/netplan-moved (applies at the next boot; nothing was applied now)"
	fi
	rm -f "$CLOUD_FILE"
	if [ -n "$KEEP_DATA" ]; then
		: >"$STATE/added-packages"
		: >"$STATE/removed-packages"
		say "kept: /var/lib/vedette*, /etc/vedette and the users"
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
	for p in 8443 8444; do
		if port_listening "$p"; then warn "port $p still listens (another program?)"; fi
	done
	say "Vedette is removed."
}

# remove_subid <file> <state name>: the line the package added; the file itself if the package made it
remove_subid() {
	[ -e "$1" ] || return 0
	grep -vx 'containers:2147483647:2147483648' "$1" >"$TMP/subid.new" || true
	if [ ! -s "$TMP/subid.new" ] && [ -e "$STATE/$2-absent" ]; then rm -f "$1"; else cat "$TMP/subid.new" >"$1"; fi
}

case $MODE in
install) do_install ;;
uninstall) do_uninstall ;;
esac
