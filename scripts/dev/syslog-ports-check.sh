#!/usr/bin/env bash
# make syslog-ports-check (#266 item 1, D-167): does a PUBLISHED port keep the real sender address for UDP and TCP? logs identifies a source
# by that address, so a port that rewrites it (loopback, a bridge gateway) would make every device an unknown sender.
# Runs a tiny listener (scripts/dev/syslogpeer) in a container with the flags of core's unit (all capabilities dropped, no-new-privileges, a
# user that is not root, a podman bridge network, `-p <hostport>:5514/udp` and `/tcp` like PublishPort=514:5514/udp|tcp), then sends from
#   * the host, to the box's own LAN address            (peer must be that address);
#   * a second container on its own podman network      (peer is logged as information: a sender behind the host is NAT-ed by design).
# Only podman's own networks are used; the host's interfaces, netplan and firewall are never touched. Rootless podman cannot bind a port
# below 1024, so the host side is VEDETTE_SYSLOG_HOSTPORT (default 15514); the mechanism (published port -> container port) is the same.
# The real appliance unit is ROOTFUL (vedette-host's Quadlet): run this as root (CONTAINER="sudo podman" is not supported, run the whole
# script under sudo) to measure that one; rootless answers for a dev box only. Work folder under ~/.cache, containers and networks removed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
hostport=${VEDETTE_SYSLOG_HOSTPORT:-15514}
id=$$
name=vedette-syslog-check-$id
net=vedette-syslog-net-$id
net2=vedette-syslog-net2-$id
snd=vedette-syslog-send-$id
root=${VEDETTE_SYSLOG_WORK:-$HOME/.cache/vedette-syslog-check}
mkdir -p "$root"
work=$(mktemp -d "$root/check.XXXXXX")
cleanup() {
	$c rm -f "$name" "$snd" >/dev/null 2>&1 || true
	$c network rm -f "$net" "$net2" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "syslog-ports-check: FAIL $*" >&2; { $c logs --tail 20 "$name" 2>&1 || true; } | sed 's/^/    container: /' >&2; exit 1; }
ok() { echo "syslog-ports-check: ok   $*"; }

lan=$(ip -4 route get 192.0.2.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
[ -n "$lan" ] || fail "no LAN address (ip route get)"
mkdir -p "$work/rootfs"
CGO_ENABLED=0 go build -o "$work/rootfs/peer" ./scripts/dev/syslogpeer
chmod 0755 "$work/rootfs" "$work/rootfs/peer"
$c network create "$net" >/dev/null
$c network create --subnet 10.231.77.0/24 "$net2" >/dev/null

$c run -d --name "$name" --network "$net" -p "$hostport:5514/udp" -p "$hostport:5514/tcp" --cap-drop=ALL --security-opt no-new-privileges --user 1000:1000 \
	--rootfs "$work/rootfs" /peer listen 5514 >/dev/null
for _ in $(seq 1 30); do
	case "$($c logs "$name" 2>&1)" in *ready*) break ;; esac
	[ "$($c inspect -f '{{.State.Running}}' "$name")" = true ] || fail "the listener stopped"
	sleep 1
done
ok "listener up as uid 1000, no capability, publishing $hostport -> 5514 udp+tcp (rootless=$($c info --format '{{.Host.Security.Rootless}}'), network backend $($c info --format '{{.Host.NetworkBackend}}'))"

"$work/rootfs/peer" send udp "$lan:$hostport"
"$work/rootfs/peer" send tcp "$lan:$hostport"
"$c" run --rm --name "$snd" --network "$net2" --ip 10.231.77.9 --cap-drop=ALL --user 1000:1000 --rootfs "$work/rootfs" /peer send udp "$lan:$hostport"
"$c" run --rm --name "$snd" --network "$net2" --ip 10.231.77.9 --cap-drop=ALL --user 1000:1000 --rootfs "$work/rootfs" /peer send tcp "$lan:$hostport"
sleep 1
log=$($c logs "$name" 2>&1)
echo "$log" | sed 's/^/syslog-ports-check: listener saw: /'

for p in udp tcp; do
	echo "$log" | grep -qx "$p $lan" || fail "$p from the host ($lan) was seen by the listener as something else: the sender address is NOT kept"
	ok "$p from $lan arrives as $lan"
done
for p in udp tcp; do
	seen=$(echo "$log" | grep -c "^$p 10\.231\.77\.9$" || true)
	if [ "$seen" -gt 0 ]; then ok "$p from 10.231.77.9 (second container) arrives as 10.231.77.9"; else echo "syslog-ports-check: info $p from the second container (10.231.77.9) arrives masqueraded (see the lines above)"; fi
done
echo "syslog-ports-check: PASS"
