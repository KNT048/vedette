#!/usr/bin/env bash
# make syslog-ports-check (#266 item 1, D-167): does core's PUBLISHED syslog port keep the real sender address, for UDP and TCP, on the path a
# device's packets really take? logs identifies a source by that address, so a port that rewrites it (a gateway, loopback, a masquerade)
# would turn every device into an unknown sender (dropped, D-203).
#
# RUN IT AS ROOT FROM YOUR OWN ACCOUNT:  sudo scripts/dev/syslog-ports-check.sh   (rootful podman, like the appliance's core unit)
# It starts the listener the way core's unit does (all capabilities dropped, no-new-privileges, uid 1000, a podman bridge network, the
# published ports bound to the box's LAN address) and sends from OUTSIDE the host, so the packets enter through PREROUTING and FORWARD:
#   default: a throwaway network namespace joined to the host by a veth pair (a /30 of 10.231.77.0/24) sends to the LAN address;
#   VEDETTE_SYSLOG_PEER=<ip>: you send from another machine on the LAN with that address (e.g. `logger -n <box> -P 514 -d x` and
#            `logger -n <box> -P 514 -T x`); the script waits VEDETTE_SYSLOG_WAIT seconds (default 90) for both a udp and a tcp line from it.
# PASS only if the listener prints exactly the peer's address for udp and for tcp (any other source, the gateway, 10.88.x, 127.0.0.1, is a
# FAIL with the line printed), and (default mode) lines from a sender that keeps ONE source port reach the new container within 10 s of
# a `podman restart` followed by the delete of the UDP conntrack entries of port 514 (M1: a stale entry pins the flow to the old container; the
# script runs `conntrack -D -f ipv4 -p udp --orig-port-dst 514` itself, which emulates what vedette-host does after core starts, D-268). Needs
# the `conntrack` package (/usr/sbin/conntrack) in the default mode; without it the script stops at the preflight with "install conntrack".
#
# WHAT IT CHANGES ON THE HOST while it runs (the EXIT trap undoes all of it; a SIGKILL skips the trap, see "leftovers" below):
#   * podman: one network (a bridge, /etc/containers/networks/<name>.json, a /24 chosen by netavark) and one container, with the nftables
#     rules netavark adds for them (DNAT of <LAN address>:514 only);
#   * default mode: the netns vedette-slc-peer, the veth pair vslc-h/vslc-p, 10.231.77.1/30 on vslc-h (refuses to run if a route already
#     overlaps that /30 or the names exist);
#   * default mode, step 5: ONCE it deletes the UDP conntrack entries whose destination port is 514 (conntrack -D; on a box that receives real
#     syslog over UDP those devices' flows are re-created by their next datagram; nothing else is touched);
#   * net.ipv4.ip_forward is read first and written back at the end (netavark turns it on);
#   * a work folder under /tmp (the helper binary), removed at the end;
#   * only when iptables' FORWARD policy is DROP and a DOCKER-USER chain exists (Docker is installed, D-266; the product side is D-267): two ACCEPT rules at the top of
#     DOCKER-USER, published (conntrack DNAT) packets to the test network's subnet and their replies (Docker's policy drops forwarded
#     packets that netavark's own nftables table accepts), deleted by the trap. FORWARD DROP without DOCKER-USER (ufw?): the script stops with a message, changes nothing.
# It never touches netplan, NetworkManager, the LAN interface, or firewall rules other than the two above and what netavark adds for the test container.
# Leftovers after a kill: `ip netns del vedette-slc-peer; ip link del vslc-h; podman rm -f vedette-syslog-check; podman network rm
# vedette-syslog-net`. Port 514 must be free on the host (podman holds it for the container): the script refuses to run if it is not.
set -euo pipefail

name=vedette-syslog-check
net=vedette-syslog-net
ns=vedette-slc-peer
hveth=vslc-h
pveth=vslc-p
hip=10.231.77.1
pip=10.231.77.2
sport=40514
wait=${VEDETTE_SYSLOG_WAIT:-90}
peer=${VEDETTE_SYSLOG_PEER:-}
fail() { echo "syslog-ports-check: FAIL $*" >&2; exit 1; }
ok() { echo "syslog-ports-check: ok   $*"; }

[ "$(id -u)" = 0 ] || fail "run as root from your own account: sudo $0"
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || fail "run it with sudo from your own account (the helper is built as that user, never as root)"
repo=$(sudo -u "$SUDO_USER" git -C "$(dirname "$0")" rev-parse --show-toplevel)
[ -z "$peer" ] || [[ $peer =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "VEDETTE_SYSLOG_PEER is not an IPv4 address"

work=
fwd_old=
loop_pid=
made_podman= # set once this run created the podman objects
made_ns= # set once this run created the netns and the veth: the trap never touches a name it did not create
fw_rules=() # DOCKER-USER rules this run inserted (each one a word list for iptables -D)
cleanup() {
	[ -z "$loop_pid" ] || kill "$loop_pid" >/dev/null 2>&1 || true
	if [ -n "$made_podman" ]; then
		podman rm -f "$name" >/dev/null 2>&1 || true
		podman network rm -f "$net" >/dev/null 2>&1 || true
	fi
	for r in "${fw_rules[@]}"; do
		# shellcheck disable=SC2086 # a rule is a word list on purpose
		iptables -D DOCKER-USER $r >/dev/null 2>&1 || true
	done
	if [ -n "$made_ns" ]; then
		ip netns del "$ns" >/dev/null 2>&1 || true
		ip link del "$hveth" >/dev/null 2>&1 || true
	fi
	[ -z "$fwd_old" ] || echo "$fwd_old" >/proc/sys/net/ipv4/ip_forward 2>/dev/null || true
	[ -z "$work" ] || rm -rf "$work"
}
trap cleanup EXIT

# 1. the helper, built by the invoking user (root's PATH may have no go, or an older one)
work=$(sudo -u "$SUDO_USER" mktemp -d /tmp/vedette-slc.XXXXXX)
chmod 0755 "$work"
sudo -u "$SUDO_USER" mkdir "$work/rootfs" # the helper is built by the invoking user into it
gobin=$(sudo -u "$SUDO_USER" bash -lc 'command -v go' 2>/dev/null || true)
[ -n "$gobin" ] || gobin=/usr/local/go/bin/go
sudo -u "$SUDO_USER" env CGO_ENABLED=0 "$gobin" -C "$repo" build -o "$work/rootfs/peer" ./scripts/dev/syslogpeer
chmod 0755 "$work/rootfs" "$work/rootfs/peer"

# 2. preflight: nothing here may clash with the host
lan=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1) # asks the routing table, sends nothing
[ -n "$lan" ] || fail "no primary LAN address (ip route get)"
if ss -H -lunt 'sport = :514' | grep -q .; then
	fail "port 514 is already in use on this host (rsyslog imudp/imtcp?): podman could not publish it; free it first (docs/DEPLOYMENT.md, syslog port)"
fi
if [ -z "$peer" ]; then
	[ -x /usr/sbin/conntrack ] || fail "install conntrack (sudo apt-get install conntrack): the restart step runs it the way vedette-host does after core restarts (D-268)"
	if [ -n "$(ip -4 route show to match "$hip/30" | grep -v "^default")$(ip -4 route show to root "$hip/30")" ] || [ "$(ip netns list | grep -c "^$ns\b")" -gt 0 ] || ip link show "$hveth" >/dev/null 2>&1; then
		fail "10.231.77.0/30, the netns $ns or the link $hveth already exists on this host; nothing was changed"
	fi
fi
fwd_old=$(cat /proc/sys/net/ipv4/ip_forward)

# 3. the listener, published like core's unit (host 514 -> container 5514, udp and tcp) but on the LAN address only
[ -z "$(podman network ls -q --filter name=^$net\$)$(podman ps -aq --filter name=^$name\$)" ] || fail "a podman network or container named $net/$name already exists; nothing was changed"
made_podman=1
podman network create "$net" >/dev/null
podman run -d --name "$name" --network "$net" -p "$lan:514:5514/udp" -p "$lan:514:5514/tcp" \
	--cap-drop=ALL --security-opt no-new-privileges --user 1000:1000 --rootfs "$work/rootfs" /peer listen 5514 >/dev/null
for _ in $(seq 1 30); do
	[ "$(podman logs "$name" 2>&1 | grep -c -x ready)" -gt 0 ] && break
	[ "$(podman inspect -f '{{.State.Running}}' "$name")" = true ] || break
	sleep 1
done
[ "$(podman logs "$name" 2>&1 | grep -c -x ready)" -gt 0 ] || fail "the listener did not print ready: $(podman logs --tail 5 "$name" 2>&1 | tr '\n' ' ')"
ok "listener up (uid 1000, no capability), host $lan:514 -> container 5514 udp+tcp, ip_forward was $fwd_old"
# Docker sets iptables' FORWARD policy to DROP; in nftables a packet netavark's table accepts is still dropped there (D-266)
if command -v iptables >/dev/null 2>&1 && [ "$(iptables -S FORWARD 2>/dev/null | grep -c -x -- '-P FORWARD DROP')" -gt 0 ]; then
	iptables -S DOCKER-USER >/dev/null 2>&1 || fail "iptables' FORWARD policy is DROP and there is no DOCKER-USER chain (ufw's forward policy?): forwarded packets to the test container would be dropped; nothing was changed by this step"
	sub=$(podman network inspect "$net" --format '{{range .Subnets}}{{.Subnet}}{{end}}')
	[[ $sub =~ ^[0-9.]+/[0-9]+$ ]] || fail "cannot read the subnet of $net ('$sub')"
	for r in "-d $sub -m conntrack --ctstate DNAT -j ACCEPT" "-s $sub -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"; do
		# shellcheck disable=SC2086
		iptables -I DOCKER-USER 1 $r
		fw_rules+=("$r")
	done
	ok "Docker's FORWARD DROP found: DOCKER-USER accepts published (DNAT) traffic to $sub and its replies, for this run only"
fi

seen() { podman logs "$name" 2>&1 | grep -v -x ready || true; } # every source line so far
has() { [ "$(seen | grep -c -x -- "$1")" -gt 0 ]; } # grep -c reads everything: no SIGPIPE under pipefail
# strict: every source line must be the peer (any other source is the failure this check exists for)
only_peer() { # $1 = peer ip
	local bad
	bad=$(seen | grep -v -x -e "udp $1" -e "tcp $1" || true)
	[ -z "$bad" ] || fail "the listener saw a sender that is not $1:
$(echo "$bad" | sed 's/^/    /')
the sender address is NOT kept"
}

if [ -n "$peer" ]; then
	echo "syslog-ports-check: waiting up to ${wait}s for a udp and a tcp line from $peer (send to $lan:514)"
	for _ in $(seq 1 "$wait"); do
		has "udp $peer" && has "tcp $peer" && break
		sleep 1
	done
	only_peer "$peer"
	for p in udp tcp; do has "$p $peer" || fail "no $p line from $peer within ${wait}s"; ok "$p from $peer arrives as $peer"; done
	echo "syslog-ports-check: PASS (LAN peer $peer; the restart step needs the default mode)"
	exit 0
fi

# 4. the peer: a netns behind a veth, so its packets enter the host (PREROUTING + FORWARD), not locally generated ones
made_ns=1
ip netns add "$ns"
ip link add "$hveth" type veth peer name "$pveth"
ip link set "$pveth" netns "$ns"
ip addr add "$hip/30" dev "$hveth"
ip link set "$hveth" up
ip -n "$ns" addr add "$pip/30" dev "$pveth"
ip -n "$ns" link set "$pveth" up
ip -n "$ns" link set lo up
ip -n "$ns" route add default via "$hip"
peerbin="$work/rootfs/peer"
send() { ip netns exec "$ns" "$peerbin" send "$1" "$lan:514"; }

send udp || fail "udp send from the peer"
send tcp || fail "tcp send from the peer"
for _ in $(seq 1 10); do
	has "udp $pip" && has "tcp $pip" && break
	sleep 1
done
only_peer "$pip"
for p in udp tcp; do has "$p $pip" || fail "no $p line from the peer ($pip) reached the listener"; ok "$p from $pip (entered the host through veth) arrives as $pip"; done

# 5. M1: a device that never pauses (one fixed source port) while core restarts: UDP conntrack must not keep sending to the old container
ip netns exec "$ns" "$peerbin" loop "$lan:514" "$sport" &
loop_pid=$!
sleep 3
podman restart -t 2 "$name" >/dev/null
# what vedette-host does once it sees core run again (D-268): delete the UDP conntrack entries of port 514, fixed argv, exit 1 = nothing to delete
rc=0
ctout=$(/usr/sbin/conntrack -D -f ipv4 -p udp --orig-port-dst 514 2>&1 >/dev/null) || rc=$?
[ "$rc" -le 1 ] || fail "conntrack -D exited $rc (needs root and the nf_conntrack netlink; vedette-host runs it as root): $ctout"
ok "conntrack -D after the restart: $(printf '%s' "$ctout" | grep -o '[0-9]* flow entries have been deleted' || echo "no count printed (exit $rc)")"
got=
for _ in $(seq 1 10); do # lines after the LAST "ready" are the new container's
	if [ "$(podman logs "$name" 2>&1 | tac | sed '/^ready$/q' | grep -c -x "udp $pip")" -gt 0 ]; then got=1; break; fi
	sleep 1
done
kill "$loop_pid" >/dev/null 2>&1 || true
loop_pid=
[ -n "$got" ] || fail "after 'podman restart' no datagram from the peer (fixed source port $sport, 1/s) reached the new container in 10 s even after conntrack -D: the delete did not clear the entry that pins the flow to the old one (D-268)"
only_peer "$pip"
ok "after a restart, a sender that never pauses reaches the new container within 10 s"
echo "syslog-ports-check: PASS"
