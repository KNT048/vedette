#!/usr/bin/env bash
# make install-check (WP-08h, D-166): run install.sh end to end, TEST channel, in a systemd container per target OS (Ubuntu 24.04,
# Ubuntu 26.04, Debian 13; the pinned images of deploy/deb/check-pins.env and deploy/containers/pins.env) and check the EFFECTS:
# refusals that change nothing; a fresh install (vedette-host active, socket, core healthy, interface answers, host.conf from getent,
# a non-clashing container network, chrony sources, no leftover mirror or registry); a second run that changes nothing; --uninstall
# without --yes that changes nothing; --uninstall --yes that leaves the box as before (users, groups, units, listening ports,
# ip link, packages, files). Needs dist/install from `make install-artifacts` (FAST=1 is enough). ROOTLESS podman only: the
# container is privileged inside the user namespace; the script refuses to run as root. Opt-in, pulls base images and runs apt in
# them, never in `make check` or CI. Never scans or probes anything outside the containers.
# What a container cannot show (macvlan decoys on a real wire, netplan, a reboot, a real second NIC) is the on-box plan,
# docs/INSTALL-TEST.md. Everything it created (containers, volumes, built images, base images it pulled) is removed at the end.
# Variables: ART (default dist/install), TARGETS (default "ubuntu2404 ubuntu2604 debian13"), KEEP_ON_FAIL=1 (leave the failed container).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
art=${ART:-dist/install}
[ -s "$art/test-channel.env" ] || { echo "install-check: no $art: run make install-artifacts first (FAST=1 is enough)" >&2; exit 1; }
art=$(cd "$art" && pwd)
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; . deploy/deb/check-pins.env; set +a
declare -A images=([ubuntu2404]=$UBUNTU_2404_IMAGE [ubuntu2604]=$UBUNTU_2604_IMAGE [debian13]=$DEBIAN_IMAGE)
targets=${TARGETS:-ubuntu2404 ubuntu2604 debian13}
work=$(mktemp -d)
name=setup
pulled=""
fail() { echo "install-check: FAIL [$name] $*" >&2; exit 1; }
ok() { echo "install-check: ok   [$name] $*"; }
cleanup() {
	if [ -n "${KEEP_ON_FAIL:-}" ] && [ "$name" != finished ]; then
		echo "install-check: KEEP_ON_FAIL: left the container vic-$name and its volume for inspection ($c exec -it vic-$name bash); remove them with $c rm -f vic-$name; $c volume rm vic-$name-containers" >&2
		rm -rf "$work"
		return
	fi
	for n in $targets; do
		"$c" rm -f -t 0 "vic-$n" >/dev/null 2>&1 || true
		"$c" volume rm -f "vic-$n-containers" >/dev/null 2>&1 || true
		"$c" rmi -f "localhost/vedette-installcheck-$n:check" >/dev/null 2>&1 || true
	done
	for i in $pulled; do "$c" rmi "$i" >/dev/null 2>&1 || true; done
	rm -rf "$work"
}
trap cleanup EXIT

[ "$($c info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = true ] || fail "$c is not rootless: run this check as a normal user, never as root"
case $(uname -m) in aarch64 | arm64) native=arm64 ;; *) native=amd64 ;; esac
[ "$(sed -n 's/^ARCH=//p' "$art/test-channel.env")" = "$native" ] || fail "the artifacts are for another architecture than this machine ($native)"
services=$(sed -n 's/^SERVICES=//p' "$art/test-channel.env")

for n in $targets; do
	name=$n
	image=${images[$n]:-}
	[ -n "$image" ] || fail "unknown target $n"
	ctr=vic-$n
	x() { "$c" exec "$ctr" sh -c "$1"; }
	"$c" image exists "$image" || pulled="$pulled $image"

	mkdir -p "$work/$n"
	cat >"$work/$n/Containerfile" <<EOT
FROM $image
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends systemd systemd-sysv ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOT
	"$c" build -q -t "localhost/vedette-installcheck-$n:check" "$work/$n" >/dev/null || fail "image build"
	"$c" volume create "vic-$n-containers" >/dev/null
	"$c" run -d --name "$ctr" --privileged --systemd=always -v "vic-$n-containers:/var/lib/containers" "localhost/vedette-installcheck-$n:check" >/dev/null || fail "cannot start a systemd container"
	for _ in $(seq 1 60); do
		s=$(x 'systemctl is-system-running 2>/dev/null' || true)
		case $s in running | degraded) break ;; esac
		sleep 1
	done
	case $s in running | degraded) ok "systemd is PID 1 ($s)" ;; *) fail "systemd did not come up: '$s'" ;; esac
	"$c" cp "$art" "$ctr:/root/art" >/dev/null
	"$c" cp install.sh "$ctr:/root/art/install.sh" >/dev/null # the script of the working tree, so that a change is checked without rebuilding the images
	x 'chmod 0755 /root/art/install.sh /root/art/vedette-testchannel && chmod -R go-w /root/art'
	# debian13 starts with chrony already installed and an administrator's line in its configuration: the installer must not touch either (M1)
	prechrony=
	if [ "$n" = debian13 ]; then
		prechrony=1
		x 'DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -q chrony >/dev/null 2>&1 && echo "# the administrator was here" >>/etc/chrony/chrony.conf' || fail "cannot pre-install chrony"
	fi
	conf_sum() { x 'sha256sum /etc/chrony/chrony.conf 2>/dev/null || echo none'; }
	chrony_conf_before=$(conf_sum)

	# the state a box can be compared by: accounts, unit files, listening sockets, links, packages, files (volatile paths left out).
	# Left out on purpose: the account _chrony and UDP 323. chronyd cannot be signalled inside a rootless container ("Permission denied"
	# from kill, even for root), so it outlives its own purge here; on a real box --uninstall stops it first (install.sh, "a purge does not stop a daemon").
	state() {
		x '
		echo "## passwd"; getent passwd | grep -v "^_chrony:" | sort; echo "## group"; getent group | grep -v "^_chrony:" | sort
		echo "## units"; systemctl list-unit-files --no-legend --no-pager | awk "{print \$1, \$2}" | sort
		echo "## sockets"; ss -H -ltnu | awk "{print \$1, \$5}" | grep -v ":323\$" | sort
		echo "## sysctl"; cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding
		echo "## chrony.conf"; sha256sum /etc/chrony/chrony.conf 2>/dev/null || echo none
		echo "## links"; ip -o link | awk "{print \$2}" | sort
		echo "## netns"; ls /run/netns 2>/dev/null | sort
		echo "## packages"; dpkg-query -W -f="\${binary:Package} \${Version}\n" | sort
		echo "## files"; find /etc /opt /srv /usr/lib/vedette /var/lib /var/log /root /run/vedette /run/containers -xdev -printf "%p %y %m %u:%g\n" 2>/dev/null \
			| grep -Ev "^(/var/lib/(apt|dpkg|systemd|ucf|pam|private|containers/)|/etc/(ssl|ld.so.cache|alternatives|machine-id|\.pwd.lock)|/root/(art|\.cache|\.local)|/var/log/(apt|dpkg|alternatives|journal|README|lastlog|wtmp|btmp|faillog|bootstrap)|/etc/(passwd|group|shadow|gshadow)[-]? )" | sort
		'
	}
	snap_files() { state >"$1"; }
	same() { # same <before> <after> <message>
		if ! diff -u "$1" "$2" >"$work/diff.txt"; then head -150 "$work/diff.txt" >&2; fail "$3"; fi
	}

	snap_files "$work/$n.before"
	ok "snapshot of the clean box taken ($(wc -l <"$work/$n.before") lines)"

	# ---- refusals change nothing ---------------------------------------------------------------------------------------
	x 'sh /root/art/install.sh' >"$work/o.txt" 2>&1 && fail "install.sh without a release installed something"
	grep -q 'not tied to a release' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no 'not tied to a release' message"; }
	x 'f=$(readlink -f /etc/os-release); cp "$f" /root/os-release.bak && sed -i "s/^VERSION_ID=.*/VERSION_ID=\"22.04\"/" "$f" && sh /root/art/install.sh --test-artifacts /root/art; r=$?; cp /root/os-release.bak "$f"; rm /root/os-release.bak; exit $r' >"$work/o.txt" 2>&1 && fail "an unsupported OS was accepted"
	grep -q 'unsupported OS' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no 'unsupported OS' message"; }
	x 'systemd-run -q --unit=vic-blocker /root/art/vedette-testchannel serve -dir /tmp -listen 127.0.0.1:8443 && sleep 1; sh /root/art/install.sh --test-artifacts /root/art; r=$?; systemctl stop vic-blocker; exit $r' >"$work/o.txt" 2>&1 && fail "a busy port 8443 was accepted"
	grep -q 'port 8443 is already in use' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no busy-port message"; }
	x 'sh /root/art/install.sh --bogus' >/dev/null 2>&1 && fail "an unknown option was accepted"
	# a release script (version filled in) never installs test artifacts (M3)
	x 'sed "s/^VEDETTE_VERSION=\"\"/VEDETTE_VERSION=\"1.2.3\"/" /root/art/install.sh >/root/rel.sh; sh /root/rel.sh --test-artifacts /root/art; r=$?; rm -f /root/rel.sh; exit $r' >"$work/o.txt" 2>&1 && fail "a release install.sh accepted --test-artifacts"
	grep -q 'never installs test artifacts' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no 'never installs test artifacts' message"; }
	# the test folder must be root's and closed (L2)
	x 'chmod g+w /root/art/index.json; sh /root/art/install.sh --test-artifacts /root/art; r=$?; chmod g-w /root/art/index.json; exit $r' >"$work/o.txt" 2>&1 && fail "a group-writable test folder was accepted"
	grep -q 'writable by group or others' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no 'writable by group or others' message"; }
	# a test mirror left behind by a killed run is removed by the next run of either channel (M4); registries.conf.d is not ours, so its folder goes again
	x 'mkdir -p /etc/containers/registries.conf.d && echo "# stale" >/etc/containers/registries.conf.d/vedette-test-mirror.conf; sh /root/art/install.sh >/dev/null 2>&1; r=$?; rmdir -p /etc/containers/registries.conf.d 2>/dev/null; exit 0'
	x '! test -e /etc/containers/registries.conf.d/vedette-test-mirror.conf' || fail "a stale test mirror was not removed"
	snap_files "$work/$n.refused"
	same "$work/$n.before" "$work/$n.refused" "a refused install changed the box"
	ok "refusals (no release, unsupported OS, busy port 8443, bad option, release script + test folder, open test folder, stale mirror) change nothing"

	# ---- an install that stops half way is repaired by the next run (H1) ------------------------------------------------
	x 'cp -a /root/art /root/art-bad && cd /root/art-bad && printf x >>index.json.minisig && grep -v " registry/" SHA256SUMS | grep -v " index.json.minisig\$" >/root/s && sha256sum index.json.minisig >>/root/s && grep " registry/" SHA256SUMS >>/root/s && cp /root/s SHA256SUMS && rm /root/s'
	x 'sh /root/art-bad/install.sh --test-artifacts /root/art-bad' >"$work/half.log" 2>&1 && fail "an install with a bad signature succeeded"
	grep -q 'refused the release' "$work/half.log" || { tail -20 "$work/half.log" >&2; fail "the bad signature was not refused by vedette-host"; }
	x 'test -s /var/lib/vedette-install/owner && test -f /etc/vedette/host.conf && dpkg -s vedette-host >/dev/null 2>&1' || fail "the half install left no marker, host.conf or package: nothing to repair"
	x '! test -e /etc/containers/registries.conf.d/vedette-test-mirror.conf && ! systemctl is-active -q vedette-testregistry.service' || fail "the failed install left its mirror or registry"
	x 'rm -rf /root/art-bad'
	ok "H1: an install that stopped after the package and host.conf left our marker; mirror and registry are gone"

	# ---- fresh install (the re-run of the half install) ------------------------------------------------------------------
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/install.log" 2>&1 || { tail -40 "$work/install.log" >&2; fail "the re-run after the half install failed"; }
	ok "H1: the re-run after the half install succeeded (no 'another Vedette install' refusal)"
	grep -q 'TEST INSTALL - NOT FOR CUSTOMERS' "$work/install.log" || fail "no test-install warning in the output"
	code=$(sed -n 's/.*setup code:  \([A-Z0-9-]*\).*/\1/p' "$work/install.log" | head -n 1)
	printf '%s' "$code" | grep -Eq '^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$' || { tail -15 "$work/install.log" >&2; fail "no setup code in the output"; }
	grep -q 'open:        https://' "$work/install.log" || fail "no address in the output"
	ok "installed; the output has the test warning, the address and a setup code"
	[ "$(x 'systemctl is-active vedette-host.service')" = active ] || fail "vedette-host is not active"
	x '[ "$(stat -c "%a %U:%G" /run/vedette)" = "750 root:vedette" ] && [ "$(stat -c "%a %U:%G" /run/vedette/host.sock)" = "660 root:vedette" ]' || fail "socket or its folder has the wrong mode or owner"
	ok "vedette-host active (Type=notify); /run/vedette 750 and host.sock 660, root:vedette"
	[ "$(x 'podman inspect --format "{{.State.Health.Status}}" vedette-core')" = healthy ] || fail "core is not healthy"
	[ "$(x 'curl -ks -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/api/v1/setup')" = 200 ] || fail "the interface does not answer 200 on 8443"
	ok "core healthy; https://127.0.0.1:8443/api/v1/setup answers 200"
	x 'journalctl -u vedette-core.service -o cat --no-pager | grep -q "'"$code"'"' || fail "the printed setup code is not in core's log"
	ok "the setup code printed is the one in core's log"
	x 'u=$(id -u vedette); g=$(id -g vedette); su=$(id -u vedette-sensor); sg=$(id -g vedette-sensor)
	   grep -qx "core_uid = $u" /etc/vedette/host.conf && grep -qx "core_gid = $g" /etc/vedette/host.conf && grep -qx "socket_gid = $g" /etc/vedette/host.conf &&
	   grep -qx "sensor_uid = $su" /etc/vedette/host.conf && grep -qx "sensor_gid = $sg" /etc/vedette/host.conf &&
	   [ "$(stat -c "%a %U:%G" /etc/vedette/host.conf)" = "644 root:root" ]' || fail "host.conf does not hold the ids of the users"
	ok "host.conf holds the real ids of vedette and vedette-sensor (getent), 644 root:root"
	x 'grep -qx "Subnet=172.30.77.0/24" /etc/containers/systemd/vedette-int.network' || fail "vedette-int.network has no subnet"
	[ "$(x 'podman network inspect vedette-int --format "{{range .Subnets}}{{.Subnet}}{{end}}"')" = 172.30.77.0/24 ] || fail "podman's vedette-int is not on the subnet of the file"
	ok "vedette-int on 172.30.77.0/24 (no clash on this box); the file and podman agree"
	[ "$(conf_sum)" != none ] || fail "no chrony.conf after the install"
	if [ -n "$prechrony" ]; then
		[ "$(conf_sum)" = "$chrony_conf_before" ] || fail "the administrator's chrony.conf was changed (M1)"
		x 'grep -qx "# the administrator was here" /etc/chrony/chrony.conf' || fail "the administrator's line is gone from chrony.conf"
		x '! grep -qx chrony /var/lib/vedette-install/asked-packages' || fail "chrony was installed by the administrator and is recorded as ours"
		ok "M1: the administrator's chrony.conf is byte for byte the same; chrony is not recorded as ours"
	else
		x '! dpkg -V chrony 2>&1 | grep -q "/etc/chrony/chrony.conf"' || fail "the distribution's chrony.conf was changed"
		x '! test -e /etc/chrony/sources.d/vedette.sources' || fail "the installer wrote vedette.sources (it belongs to vedette-host)"
		ok "M1: chrony.conf is the distribution's (dpkg -V is clean) and the installer wrote no vedette.sources"
	fi
	# a customer run over a test install is refused and says why (M3)
	x 'sh /root/art/install.sh' >"$work/o.txt" 2>&1 && fail "a customer run over a test install was accepted"
	grep -q 'has a test install of Vedette' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no 'has a test install' message"; }
	ok "M3: a customer run over a test install is refused"
	x '! test -e /etc/containers/registries.conf.d/vedette-test-mirror.conf && ! systemctl is-active -q vedette-testregistry.service' || fail "the test mirror or the test registry was left behind"
	ok "the test mirror and the test registry are gone after the install"
	x 'test ! -e /etc/netplan/90-vedette.yaml && test ! -e /etc/cloud/cloud.cfg.d/99-vedette-network.cfg' || fail "the network was handed over without --network-handover"
	ok "no --network-handover: netplan and cloud-init untouched"
	for s in ${services//,/ }; do
		x "grep -q '^Image=' /etc/containers/systemd/vedette-$s.container" || fail "no unit for $s"
	done
	ok "Quadlet units written for: $services"
	[ "$(x 'systemctl cat vedette-host.service | grep -c "^ExecStart=/usr/lib/vedette/vedette-host$"')" = 1 ] || fail "vedette-host.service is not the packaged unit"
	snap_files "$work/$n.installed"
	core_id=$(x 'podman inspect --format "{{.Id}} {{.State.StartedAt}}" vedette-core')

	# ---- second run changes nothing ------------------------------------------------------------------------------------
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/rerun.log" 2>&1 || { tail -40 "$work/rerun.log" >&2; fail "the second run failed"; }
	grep -q 'host.conf is already right' "$work/rerun.log" && grep -q 'already bootstrapped' "$work/rerun.log" || { tail -30 "$work/rerun.log" >&2; fail "the second run did not recognise the finished state"; }
	snap_files "$work/$n.rerun"
	same "$work/$n.installed" "$work/$n.rerun" "the second run changed the box"
	[ "$(x 'podman inspect --format "{{.Id}} {{.State.StartedAt}}" vedette-core')" = "$core_id" ] || fail "the second run restarted or replaced core"
	ok "second run: same state; core was not restarted"

	# ---- uninstall -----------------------------------------------------------------------------------------------------
	x 'sh /root/art/install.sh --uninstall' >"$work/o.txt" 2>&1 && fail "--uninstall without --yes removed something"
	snap_files "$work/$n.noyes"
	same "$work/$n.installed" "$work/$n.noyes" "--uninstall without --yes changed the box"
	ok "--uninstall without --yes only says what it would do"
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/un.log" 2>&1 || { tail -40 "$work/un.log" >&2; fail "--uninstall --yes failed"; }
	snap_files "$work/$n.after"
	same "$work/$n.before" "$work/$n.after" "after --uninstall the box is not as before (diff above)"
	x '! ss -H -ltn | grep -Eq "[:.](8443|8444)\$" && ! getent passwd vedette vedette-sensor >/dev/null && ! getent group vedette vedette-sensor >/dev/null && ! test -e /etc/vedette && ! test -e /var/lib/vedette && ! test -e /etc/containers/systemd/vedette-core.container' || fail "something of Vedette is left"
	ok "uninstall: users, groups, units, listening sockets, links, namespaces, packages and files are exactly as before; 8443 and 8444 closed"

	# ---- H2: a package somebody installed on top of ours keeps ours; netavark's nft tables are gone ------------------------
	pkgnames() { x 'dpkg-query -W -f="\${binary:Package}\n"' | sort; }
	before_pkgs() { awk '/^## packages/ {f = 1; next} /^## / {f = 0} f {print $1}' "$work/$n.before" | sort; }
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/install2.log" 2>&1 || { tail -40 "$work/install2.log" >&2; fail "the second fresh install (H2 cycle) failed"; }
	x 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ufw >/dev/null 2>&1' || fail "cannot install ufw (it depends on iptables, which the installer added)"
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/un2.log" 2>&1 || { tail -40 "$work/un2.log" >&2; fail "--uninstall --yes failed in the H2 cycle"; }
	x 'dpkg -s ufw >/dev/null 2>&1 && dpkg -s iptables >/dev/null 2>&1' || { tail -20 "$work/un2.log" >&2; fail "H2: the uninstall removed ufw or the iptables it needs"; }
	x '! dpkg -s podman >/dev/null 2>&1 && ! dpkg -s vedette-host >/dev/null 2>&1' || fail "H2: the uninstall left podman or vedette-host"
	ok "H2: ufw (needs iptables) was installed after ours; --uninstall kept ufw and iptables and removed podman and vedette-host"
	x 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends nftables >/dev/null 2>&1' || fail "cannot install nftables to look at the tables"
	[ -z "$(x 'nft list tables')" ] || { x 'nft list ruleset' >&2; fail "nft tables were left behind by the uninstall"; }
	ok "no nft table is left behind by the uninstall (looked at with nft after it)"
	# put the box back the way it was, by the names that were not there before, then it must equal the first snapshot
	# shellcheck disable=SC2046 # package names, one word each
	x "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q $(comm -13 <(before_pkgs) <(pkgnames) | tr '\n' ' ') >/dev/null 2>&1" || fail "cannot remove the test packages again"
	snap_files "$work/$n.after2"
	same "$work/$n.before" "$work/$n.after2" "after the H2 cycle and the removal of the test packages the box is not as before"
	ok "the H2 cycle ends with the box as before (users, units, sockets, forwarding sysctl, packages, files)"

	# ---- N1: a package that was installed and only UPGRADED as a dependency is not ours to remove ------------------------
	# A local apt repository (trusted, in /opt so that apt's sandbox user can read it) holds a made-up vic-lib 2.0 and a made-up
	# catatonit 99:1 (a package the installer asks for when it is missing) that depends on vic-lib (>= 2.0). vic-lib 1.0 is installed
	# first and marked automatic, so installing catatonit upgrades vic-lib as a dependency: an "Inst vic-lib [1.0] (2.0)" line.
	# Only the filter on that line stands between vic-lib and the uninstall.
	x 'set -e; rm -rf /opt/vicrepo /root/b; mkdir -p /opt/vicrepo /root/b
	   mk() { d=/root/b/$1_$2; mkdir -p $d/DEBIAN; { printf "Package: $1\nVersion: $2\nArchitecture: all\nMaintainer: x <x@example.invalid>\nDescription: install-check N1\n"; [ -z "$3" ] || printf "Depends: $3\n"; } >$d/DEBIAN/control; dpkg-deb -b $d /opt/vicrepo/$1_$2_all.deb >/dev/null; }
	   mk vic-lib 1.0 ""; mk vic-lib 2.0 ""; mk catatonit 99:1 "vic-lib (>= 2.0)"
	   cd /opt/vicrepo
	   for f in *.deb; do dpkg-deb -f $f; printf "Filename: ./$f\nSize: $(stat -c %s $f)\nSHA256: $(sha256sum $f | cut -d" " -f1)\n\n"; done >Packages
	   printf "Origin: vic\nLabel: vic\nSuite: vic\nDate: Wed, 11 Nov 2026 00:00:00 UTC\nSHA256:\n $(sha256sum Packages | cut -d" " -f1) $(stat -c %s Packages) Packages\n" >Release
	   chmod -R a+rX /opt/vicrepo; rm -rf /root/b
	   echo "deb [trusted=yes] file:/opt/vicrepo ./" >/etc/apt/sources.list.d/vic.list
	   apt-get update -q >/dev/null 2>&1; dpkg -i /opt/vicrepo/vic-lib_1.0_all.deb >/dev/null 2>&1; apt-mark auto vic-lib >/dev/null' || fail "cannot make the local repository of the N1 case"
	! x 'dpkg -s catatonit >/dev/null 2>&1' || fail "N1: catatonit is installed before the case, the made-up one would not be asked for"
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/install3.log" 2>&1 || { tail -40 "$work/install3.log" >&2; fail "the N1 install failed"; }
	[ "$(x 'dpkg-query -W -f="\${Version}" vic-lib')" = 2.0 ] || fail "N1: apt did not upgrade vic-lib as a dependency of catatonit, the case does not reproduce an upgrade"
	x '! grep -qx vic-lib /var/lib/vedette-install/installed-by-us' || fail "N1: an upgraded package is recorded as installed by us"
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/un3.log" 2>&1 || { tail -40 "$work/un3.log" >&2; fail "--uninstall --yes failed in the N1 case"; }
	x 'dpkg -s vic-lib >/dev/null 2>&1' || fail "N1: the uninstall removed a package that was only upgraded"
	! x 'dpkg -s catatonit >/dev/null 2>&1' || fail "N1: the uninstall left the package it asked for"
	ok "N1: vic-lib was upgraded 1.0 -> 2.0 as a dependency of catatonit (ours) and survived the uninstall; catatonit went"
	# the box is not compared again after this case (an upgrade is never undone); only the test's own leftovers are removed
	x 'rm -rf /etc/apt/sources.list.d/vic.list /opt/vicrepo; dpkg --purge vic-lib >/dev/null 2>&1; true'
	# shellcheck disable=SC2046 # package names, one word each
	x "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q $(comm -13 <(before_pkgs) <(pkgnames) | tr '\n' ' ') >/dev/null 2>&1; true"
	"$c" rm -f -t 0 "$ctr" >/dev/null
	"$c" volume rm -f "vic-$n-containers" >/dev/null 2>&1 || true
	"$c" rmi -f "localhost/vedette-installcheck-$n:check" >/dev/null 2>&1 || true
done
name="finished"
ok "all targets passed"
