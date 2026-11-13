#!/usr/bin/env bash
# make install-check (WP-08h, D-166): run install.sh end to end, TEST channel, in a systemd container per target OS (Ubuntu 24.04,
# Ubuntu 26.04, Debian 13; the pinned images of deploy/deb/check-pins.env and deploy/containers/pins.env) and check the EFFECTS:
# refusals that change nothing; a fresh install (vedette-host active, socket, core healthy, interface answers, host.conf from getent,
# a non-clashing container network, chrony sources, no leftover mirror or registry); a second run that changes nothing; --uninstall
# without --yes that changes nothing; --uninstall --yes that leaves the box as before (users, groups, units, listening ports,
# ip link, packages, files); a box set up through the API, uninstalled with --keep-data and installed again (core healthy, setup still
# done, the administrator signs in, an older release refused), then repaired with vedette-host running (W2-9, W2-10, D-418). Needs dist/install from `make install-artifacts` (FAST=1 is enough). ROOTLESS podman only: the
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
	# a real admin shell has a UTF-8 locale: under it Ubuntu 26.04's uutils sort and comm disagree unless install.sh sets LC_ALL=C (#298)
	x() { "$c" exec -e LANG=en_US.UTF-8 "$ctr" sh -c "$1"; }
	"$c" image exists "$image" || pulled="$pulled $image"

	mkdir -p "$work/$n"
	# dbus: every real box has the system bus, and Podman's systemd cgroup manager needs it ("cannot open sd-bus" in crun otherwise), which
	# the on-box scan build (podman build ... RUN, run by vedette-host from a unit) depends on
	cat >"$work/$n/Containerfile" <<EOT
FROM $image
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
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
	# Also left out: the run records of vedette-host (/var/lib/vedette-host/runs/): core makes them on its own, e.g. a "busy" refusal when its
	# module reconcile at start meets the host's own AfterReady, so the second run of the installer is not what creates them
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
			| grep -Ev "^(/var/lib/(apt|dpkg|systemd|ucf|pam|private|containers/|vedette-host/runs/)|/etc/(ssl|ld.so.cache|alternatives|machine-id|\.pwd.lock)|/root/(art|\.cache|\.local)|/var/log/(apt|dpkg|alternatives|journal|README|lastlog|wtmp|btmp|faillog|bootstrap)|/etc/(passwd|group|shadow|gshadow)[-]? )" | sort
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
	x 'systemd-run -q --unit=vic-blocker /root/art/vedette-testchannel serve -dir /tmp -listen 127.0.0.1:6514 && sleep 1; sh /root/art/install.sh --test-artifacts /root/art; r=$?; systemctl stop vic-blocker; exit $r' >"$work/o.txt" 2>&1 && fail "a busy syslog TLS port 6514 was accepted"
	grep -q 'port 6514 is already in use' "$work/o.txt" || { cat "$work/o.txt" >&2; fail "no busy-port message for 6514"; }
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
	ok "refusals (no release, unsupported OS, busy port 8443 or 6514, bad option, release script + test folder, open test folder, stale mirror) change nothing"

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
	# the JSON log lines of vedette-host -bootstrap go to the journal, not to the person's terminal (N100)
	! grep -n '^{"time"' "$work/install.log" >&2 || fail "the installer output has raw log lines of vedette-host (above); they belong in the journal"
	# through the syslog socket: the bootstrap's own line, not one of the daemon (stdout of vedette-host.service)
	x 'journalctl -t vedette-host _TRANSPORT=syslog --no-pager -o cat | grep -q "\"msg\":\"release index stored\""' || fail "the WARN 'release index stored' of the bootstrap is not in the journal (journalctl -t vedette-host _TRANSPORT=syslog)"
	ok "installed; the output has the test warning, the address and a setup code, and no raw log line (the bootstrap's WARN is in the journal)"
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
	x '/usr/sbin/conntrack --version >/dev/null 2>&1' || fail "conntrack does not run at /usr/sbin/conntrack (vedette-host clears stale syslog UDP flows with it, D-268)"
	ok "conntrack runs at /usr/sbin/conntrack"
	# D-316: the installed .deb is kept under its SemVer name (the self-update's way back) and vedette-host adopted it when it started
	rel=$(sed -n 's/^VERSION=//p' "$art/test-channel.env")
	kdir=/var/lib/vedette-host/selfupdate/packages
	[ "$(x "ls -A $kdir")" = "vedette-host_${rel}_${native}.deb" ] || { x "ls -la $kdir" >&2; fail "D-316: $kdir does not hold exactly vedette-host_${rel}_${native}.deb"; }
	x "[ \"\$(stat -c '%a %U:%G %F' $kdir/vedette-host_${rel}_${native}.deb $kdir /var/lib/vedette-host/selfupdate | tr '\n' ';')\" = '600 root:root regular file;700 root:root directory;700 root:root directory;' ]" || fail "D-316: the kept package is not 0600 root or its folders are not 0700 root"
	ksum=$(sha256sum "$art/vedette-host_${rel}_${native}.deb" | cut -d' ' -f1)
	[ "$(x "sha256sum $kdir/vedette-host_${rel}_${native}.deb" | cut -d' ' -f1)" = "$ksum" ] || fail "D-316: the kept package is not the .deb of the release"
	x "grep -q '$ksum' /var/lib/vedette-host/selfupdate/versions.json" || { x 'cat /var/lib/vedette-host/selfupdate/versions.json' >&2; fail "D-316: vedette-host did not adopt the kept package (its sha256 is not in versions.json)"; }
	ok "D-316: vedette-host_${rel}_${native}.deb kept (0600 root, folders 0700, the release's sha256) and adopted by vedette-host (versions.json)"
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
	# core starts the sensor and scan containers by itself a little after the install (its module reconcile), so the box is only compared once
	# the containers have stopped coming: the same set of containers, none still "starting", on three looks 10 s apart
	x 'prev=; same=0; i=0; while [ $i -lt 40 ] && [ $same -lt 3 ]; do cur=$(podman ps -a --format "{{.ID}} {{.Status}}" | sort | tr "\n" ";"); case $cur in *starting*) same=0 ;; *) if [ "$cur" = "$prev" ]; then same=$((same + 1)); else same=0; fi ;; esac; prev=$cur; sleep 10; i=$((i + 1)); done; [ $same -ge 3 ]' || fail "the containers did not settle within 400 s of the install"
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
	# the folders the package and podman made for vedette-int (N100), named before the whole-box diff below
	for d in /etc/containers /etc/containers/networks /var/lib/cni /etc/apparmor.d/disable; do
		b=$(grep -c "^$d " "$work/$n.before" || true)
		a=$(grep -c "^$d " "$work/$n.after" || true)
		[ "$b" = "$a" ] || fail "N100: $d is not as before after --uninstall (there before: $b, there after: $a)"
	done
	same "$work/$n.before" "$work/$n.after" "after --uninstall the box is not as before (diff above)"
	x '! ss -H -ltn | grep -Eq "[:.](8443|8444)\$" && ! getent passwd vedette vedette-sensor >/dev/null && ! getent group vedette vedette-sensor >/dev/null && ! test -e /etc/vedette && ! test -e /var/lib/vedette && ! test -e /etc/containers/systemd/vedette-core.container' || fail "something of Vedette is left"
	ok "uninstall: users, groups, units, listening sockets, links, namespaces, packages and files are exactly as before; 8443 and 8444 closed"

	# ---- H2: a package somebody installed on top of ours keeps ours; netavark's nft tables are gone ------------------------
	pkgnames() { x 'dpkg-query -W -f="\${binary:Package}\n"' | sort; }
	before_pkgs() { awk '/^## packages/ {f = 1; next} /^## / {f = 0} f {print $1}' "$work/$n.before" | sort; }
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/install2.log" 2>&1 || { tail -40 "$work/install2.log" >&2; fail "the second fresh install (H2 cycle) failed"; }
	# the bridge of vedette-int has the fixed name vedette0 on this Podman (PodmanArgs=--interface-name; D-267): by effect, in the kernel
	x 'ip link show vedette0 >/dev/null 2>&1' || { x 'cat /etc/containers/systemd/vedette-int.network; podman network inspect vedette-int; ip -br link' >&2; fail "D-267: there is no bridge vedette0 (the network file's PodmanArgs=--interface-name=vedette0 did not take effect on this Podman: $(x 'podman --version'))"; }
	[ "$(x "podman network inspect vedette-int --format '{{.NetworkInterface}}'")" = vedette0 ] || fail "D-267: podman does not report vedette0 as the interface of vedette-int"
	ok "D-267: the bridge of vedette-int is named vedette0 by $(x 'podman --version') (PodmanArgs=--interface-name; the link exists in the kernel)"
	# ---- images: --uninstall removes every image of Vedette's (registry names, the localhost/vedette-<service> tags bootstrap makes, the
	# unnamed leftover of the on-box scan build, found by its label) and nothing else. The storage goes with podman afterwards, so a
	# podman wrapper records what --uninstall asks it to remove, and the images are looked up by ID in that record.
	x 'set -e; d=$(mktemp -d); cd "$d"
	   mk() { printf "FROM scratch\nLABEL %s\n" "$2" >Containerfile; podman build -q -t "$1" . >"/root/img.$3"; }
	   mk localhost/vedette-core:0.0.1 a=core core; mk ghcr.io/knt048/vedette-sensor:0.0.1 a=sensor ghcrimg
	   mk localhost/other-app:1 a=other other
	   mk localhost/vic-tmp:1 io.vedette.build=scan scanleft; podman untag localhost/vic-tmp:1
	   mk localhost/vic-tmp:2 a=foreign foreignleft; podman untag localhost/vic-tmp:2
	   printf "#!/bin/sh\ncase \"\$1\" in rmi) echo \"\$*\" >>/root/rmi.log ;; esac\nexec /usr/bin/podman \"\$@\"\n" >/usr/local/bin/podman; chmod 0755 /usr/local/bin/podman
	   rm -f /root/rmi.log; cd /; rm -rf "$d"' >/dev/null 2>&1 || fail "cannot make the test images of the image case"
	x 'podman images -a --format "{{.ID}} {{.Repository}}:{{.Tag}}" | grep -q "localhost/vedette-core:0.0.1"' || fail "the image case did not make its images"
	ok "image case: five test images made (a localhost/vedette-core tag, a ghcr.io/knt048/vedette- tag, an unrelated tag, a dangling image with the scan label, a dangling one without)"
	# ---- D-267, D-396: a Docker-like box (a DOCKER-USER chain and FORWARD DROP): vedette-host puts its rules in, --uninstall takes them out.
	# Before the chain, the box gets an uplink bridge br-lan (its port a VLAN or, without the 8021q module, a macvlan on a veth: both have
	# a lower_* link, as the host looks for) and a bridge br-app holding only a veth (a custom-named Docker network): the first must get its
	# ACCEPT above the RETURNs, the second none. The bridges are read here the way the host reads them (host/ops/dockerfwd.go boxBridges).
	if x 'command -v iptables >/dev/null 2>&1'; then
		fwd_subnet=$(x "sed -n 's/^Subnet=//p' /etc/containers/systemd/vedette-int.network")
		x 'ip link add br-app type bridge && ip link add vic-app type veth peer name vic-app-p && ip link set vic-app master br-app && ip link add br-lan type bridge && ip link add vic-up type veth peer name vic-up-p' ||
			fail "D-396: cannot make the test bridges br-app and br-lan in the check container"
		if x 'ip link add link vic-up name vic-up.7 type vlan id 7 2>/dev/null && ip link set vic-up.7 master br-lan || { ip link add link vic-up name vic-upm type macvlan mode bridge && ip link set vic-upm master br-lan; }'; then
			fwd_uplink=1
		else
			fwd_uplink=
			echo "install-check: note [$name] D-396: neither a VLAN nor a macvlan could be made here (8021q and macvlan modules not loaded on this machine): br-lan has no uplink port, so it must get no ACCEPT" >&2
		fi
		# boxBridges in sh: br- + 1-12 of [A-Za-z0-9_.-], not br- + 12 hex (Docker's), with a port that has device, bonding or a lower_* link
		# (lstat: -e or -L); sorted bytewise like Go's os.ReadDir
		# shellcheck disable=SC2016 # the $ expand in the container's sh, not here
		fwd_box=$(x 'export LC_ALL=C; for d in /sys/class/net/br-*; do b=${d##*/}; printf "%s\n" "$b" | grep -Eqx "br-[A-Za-z0-9_.-]{1,12}" || continue; ! printf "%s\n" "$b" | grep -Eqx "br-[0-9a-f]{12}" || continue; for p in "$d"/brif/*; do p=/sys/class/net/${p##*/}; up=; for f in "$p/device" "$p/bonding" "$p"/lower_*; do if [ -e "$f" ] || [ -L "$f" ]; then up=1; fi; done; if [ -n "$up" ]; then echo "$b"; break; fi; done; done | sort' | tr '\n' ' ')
		case " $fwd_box" in *" br-app "*) fail "D-396: the bridge reader of this check calls br-app (only a veth) an uplink" ;; esac
		if [ -n "$fwd_uplink" ]; then
			case " $fwd_box" in *" br-lan "*) ;; *) fail "D-396: the bridge reader of this check does not see br-lan, which holds a VLAN or macvlan port" ;; esac
		fi
		fwd_want=
		for b in $fwd_box; do fwd_want="${fwd_want}ACCEPT:$b "; done
		fwd_want="${fwd_want}RETURN RETURN ACCEPT ACCEPT DROP "
		# the whole sequence of our lines in -S: a bridge's ACCEPT as ACCEPT:<bridge>, every other line by its target
		fwd_seq() { x 'iptables -S DOCKER-USER | grep -- "--comment vedette-int" | sed -e "s/.* -o \(br-[^ +]*\) .* -j ACCEPT\$/ACCEPT:\1/" -e "s/.* -j //" | tr "\n" " "'; }
		x 'iptables -N DOCKER-USER && iptables -P FORWARD DROP' || fail "D-267: cannot make a fake DOCKER-USER chain in the check container (needs NET_ADMIN)"
		# the host looks every 30 s
		x "i=0; while [ \$i -lt 40 ]; do iptables -w 5 -C DOCKER-USER -i vedette0 -o docker0 -m comment --comment vedette-int -j RETURN 2>/dev/null && iptables -w 5 -C DOCKER-USER -i vedette0 -o 'br-+' -m comment --comment vedette-int -j RETURN 2>/dev/null && iptables -w 5 -C DOCKER-USER -o vedette0 -d $fwd_subnet -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -m comment --comment vedette-int -j ACCEPT 2>/dev/null && iptables -w 5 -C DOCKER-USER -i vedette0 -s $fwd_subnet -m comment --comment vedette-int -j ACCEPT 2>/dev/null && iptables -w 5 -C DOCKER-USER ! -i vedette0 -o vedette0 -m comment --comment vedette-int -j DROP 2>/dev/null && exit 0; sleep 2; i=\$((i + 1)); done; exit 1" || { x 'iptables -S DOCKER-USER' >&2; fail "D-267: vedette-host did not put its five fixed rules in DOCKER-USER within 80 s"; }
		[ "$(fwd_seq)" = "$fwd_want" ] || { x 'iptables -S DOCKER-USER' >&2; fail "D-396: DOCKER-USER holds '$(fwd_seq)', want exactly '$fwd_want'"; }
		# one more look of the host (30 s): nothing is added, so -C finds the rules as the host writes them
		sleep 35
		[ "$(fwd_seq)" = "$fwd_want" ] || { x 'iptables -S DOCKER-USER' >&2; fail "D-396: after another look DOCKER-USER holds '$(fwd_seq)', want exactly '$fwd_want'"; }
		# an unrelated rule of the administrator in the same chain must survive the uninstall
		x 'iptables -A DOCKER-USER -s 192.0.2.0/24 -j RETURN'
		ok "D-267, D-396: with a DOCKER-USER chain and FORWARD DROP, vedette-host keeps exactly '${fwd_want% }' for vedette0 and $fwd_subnet (uplink bridges of the box: ${fwd_box:-none})"
		fwd_checked=1
	fi
	x 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ufw >/tmp/ufw.log 2>&1 || { tail -20 /tmp/ufw.log; exit 1; }' >&2 || fail "cannot install ufw (it depends on iptables, which the installer added)"
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/un2.log" 2>&1 || { tail -40 "$work/un2.log" >&2; fail "--uninstall --yes failed in the H2 cycle"; }
	for i in core ghcrimg scanleft; do
		x "grep -q \"\$(cut -c1-12 /root/img.$i)\" /root/rmi.log" || { x 'cat /root/rmi.log' >&2; fail "image case: --uninstall did not remove the image '$i' (a Vedette name, or the dangling image with the scan label)"; }
	done
	for i in other foreignleft; do
		! x "grep -q \"\$(cut -c1-12 /root/img.$i)\" /root/rmi.log" || fail "image case: --uninstall removed the image '$i', which is not Vedette's"
	done
	x 'rm -f /usr/local/bin/podman /root/rmi.log /root/img.*'
	ok "image case: --uninstall removed the localhost/vedette-*, the ghcr.io/knt048/vedette-* and the dangling scan-labelled image, and left the unrelated tag and the dangling image without the label"
	if [ -n "${fwd_checked:-}" ]; then
		[ "$(x 'iptables -S DOCKER-USER | grep -c -- "--comment vedette-int"')" = 0 ] || { x 'iptables -S DOCKER-USER' >&2; fail "D-267: --uninstall left a vedette-int rule in DOCKER-USER"; }
		x 'iptables -S DOCKER-USER | grep -q -- "-s 192.0.2.0/24 -j RETURN"' || fail "D-267: --uninstall removed a rule that is not Vedette's"
		ok "D-267, D-396: --uninstall removed every vedette-int rule (the five fixed ones, the DROP among them, and the bridge ACCEPTs) and left the administrator's own rule"
		# the fake Docker and the test bridges go again, so that the checks below see the box as it was (a veth takes its peer and the
		# VLAN or macvlan on it along)
		x 'iptables -P FORWARD ACCEPT; iptables -F DOCKER-USER; iptables -X DOCKER-USER; ip link del vic-up; ip link del vic-app; ip link del br-lan; ip link del br-app; true'
		fwd_checked=
		# the chain was made by this case, so the uninstall rightly kept the nft table "ip filter" (warning: left the nft table); it goes
		# once nft is there to remove it (below)
		fwd_table=1
	fi
	x 'dpkg -s ufw >/dev/null 2>&1 && dpkg -s iptables >/dev/null 2>&1' || { tail -20 "$work/un2.log" >&2; fail "H2: the uninstall removed ufw or the iptables it needs"; }
	x '! dpkg -s vedette-host >/dev/null 2>&1' || fail "H2: the uninstall left vedette-host"
	# W4-1, D-508: the image case left localhost/other-app in podman, which is not Vedette's: podman, its packages and its storage stay
	# and the summary says why (the first uninstall above, with nothing else in podman, proved the purge of podman and its storage)
	x 'dpkg -s podman >/dev/null 2>&1 && podman image exists localhost/other-app:1' || { tail -20 "$work/un2.log" >&2; fail "W4-1: the uninstall removed podman or the image localhost/other-app that is not Vedette's"; }
	grep -qF "kept podman, the packages it runs with and /var/lib/containers: 1 image that is not Vedette's uses it (localhost/other-app)" "$work/un2.log" || { tail -20 "$work/un2.log" >&2; fail "W4-1: the uninstall did not say it kept podman for localhost/other-app"; }
	ok "H2: ufw (needs iptables) was installed after ours; --uninstall kept ufw and iptables, removed vedette-host, and kept podman with the image localhost/other-app (W4-1)"
	x 'DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends nftables >/dev/null 2>&1' || fail "cannot install nftables to look at the tables"
	if [ -n "${fwd_table:-}" ]; then
		grep -q "left the nft table ip filter" "$work/un2.log" || fail "D-267: the uninstall did not say it left the table of the fake Docker chain"
		x 'nft delete table ip filter' || fail "cannot remove the nft table of the fake Docker chain"
		fwd_table=
	fi
	[ -z "$(x 'nft list tables')" ] || { x 'nft list ruleset' >&2; fail "nft tables were left behind by the uninstall"; }
	ok "no nft table is left behind by the uninstall (looked at with nft after it)"
	# put the box back the way it was, by the names that were not there before, then it must equal the first snapshot; the podman the
	# uninstall kept goes as the summary tells the administrator (podman system reset, then apt), and so do the folders the uninstall
	# removes when it purges podman itself (install.sh, D-463)
	x 'podman system reset -f >/dev/null 2>&1' || fail "cannot reset the podman the uninstall kept"
	# shellcheck disable=SC2046 # package names, one word each
	x "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q $(comm -13 <(before_pkgs) <(pkgnames) | tr '\n' ' ') >/dev/null 2>&1" || fail "cannot remove the test packages again"
	x 'rm -rf /var/lib/containers /run/containers /root/.config/cni; for d in /etc/containers/networks /etc/containers/systemd/users /etc/containers/systemd /etc/containers/registries.conf.d /etc/containers /var/lib/cni/networks /var/lib/cni /root/.config; do if [ -d "$d" ] && ! dpkg-query -S "$d" >/dev/null 2>&1; then rmdir "$d" 2>/dev/null || true; fi; done'
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
	   mk vic-lib 1.0 ""; mk vic-lib 2.0 ""; mk catatonit 99:1 "vic-lib (>= 2.0)"; mk vic-dep 1.0 ""; mk vic-orphan 1.0 ""
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
	# D-316 (9), same uninstall: vic-dep stands for a Depends that a self-update of vedette-host had apt install (automatic, listed by
	# the host in its selfupdate/installed-by-us before it installs); vic-orphan is automatic and unneeded too, but on no list (N2)
	x 'set -e; DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends vic-dep vic-orphan >/dev/null 2>&1
	   apt-mark auto vic-dep vic-orphan >/dev/null; echo vic-dep >>/var/lib/vedette-host/selfupdate/installed-by-us' || fail "D-316 (9): cannot set up the self-update dependency case"
	x 'sh /root/art/install.sh --uninstall' >"$work/o3.txt" 2>&1 && fail "--uninstall without --yes removed something"
	grep -qF '/var/lib/vedette-host/selfupdate/installed-by-us' "$work/o3.txt" || fail "D-316 (9): --uninstall without --yes does not name the host's list"
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/un3.log" 2>&1 || { tail -40 "$work/un3.log" >&2; fail "--uninstall --yes failed in the N1 case"; }
	x 'dpkg -s vic-lib >/dev/null 2>&1' || fail "N1: the uninstall removed a package that was only upgraded"
	! x 'dpkg -s catatonit >/dev/null 2>&1' || fail "N1: the uninstall left the package it asked for"
	ok "N1: vic-lib was upgraded 1.0 -> 2.0 as a dependency of catatonit (ours) and survived the uninstall; catatonit went"
	! x 'dpkg -s vic-dep >/dev/null 2>&1' || fail "D-316 (9): the uninstall left a package a self-update of vedette-host installed"
	x 'dpkg -s vic-orphan >/dev/null 2>&1' || fail "D-316 (9): the uninstall removed an automatic package that is on no list of ours"
	ok "D-316 (9): the dependency on the host's list went with the uninstall; the unlisted automatic package stayed"
	# the box is not compared again after this case (an upgrade is never undone); only the test's own leftovers are removed
	x 'rm -rf /etc/apt/sources.list.d/vic.list /opt/vicrepo; dpkg --purge vic-lib vic-orphan vic-dep >/dev/null 2>&1; true'
	# shellcheck disable=SC2046 # package names, one word each
	x "DEBIAN_FRONTEND=noninteractive apt-get purge -y -q $(comm -13 <(before_pkgs) <(pkgnames) | tr '\n' ' ') >/dev/null 2>&1; true"

	# ---- W2-9, W2-10 (D-418): --uninstall --keep-data, then install again: Vedette comes back with its data and its users -----------
	# A box set up by a person (first-run setup done, an administrator), uninstalled keeping the data, then installed again: core healthy,
	# setup still complete, the same administrator signs in, the same key and ids. Then the repair path with vedette-host running: core's
	# unit removed by hand, install.sh run again (it must stop vedette-host for the bootstrap, W2-10).
	kd_healthy() { # kd_healthy <what>
		[ "$(x 'podman inspect --format "{{.State.Health.Status}}" vedette-core')" = healthy ] || fail "$1: core is not healthy"
		x 'curl -ksf --max-time 10 https://127.0.0.1:8443/api/v1/setup | grep -Eq "\"complete\" *: *true"' || fail "$1: first-run setup is not complete any more (the data was not kept)"
		x 'n=0; while [ $n -lt 40 ]; do s=$(curl -ks -o /dev/null -w "%{http_code}" --max-time 30 -H "Content-Type: application/json" --data-binary @/root/kd-login.json https://127.0.0.1:8443/api/v1/auth/login); [ "$s" = 503 ] || break; sleep 1; n=$((n + 1)); done; [ "$s" = 200 ]' || fail "$1: the administrator made before the uninstall cannot sign in"
	}
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/kd1.log" 2>&1 || { tail -40 "$work/kd1.log" >&2; fail "the install of the keep-data case failed"; }
	kcode=$(sed -n 's/.*setup code:  \([A-Z0-9-]*\).*/\1/p' "$work/kd1.log" | head -n 1)
	[ -n "$kcode" ] || { tail -15 "$work/kd1.log" >&2; fail "keep-data case: no setup code in the output"; }
	kpw=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 || true)
	printf '{"org":"Keep Data Check","admin":{"name":"Keep Data","email":"keepdata@vedette.test","password":"%s"},"lan":["192.168.250.0/24"],"commitment":false,"bundle":"custom","modules":[],"setup_code":"%s"}' "$kpw" "$kcode" >"$work/kd-setup.json"
	printf '{"email":"keepdata@vedette.test","password":"%s"}' "$kpw" >"$work/kd-login.json"
	"$c" cp "$work/kd-setup.json" "$ctr:/root/kd-setup.json" >/dev/null
	"$c" cp "$work/kd-login.json" "$ctr:/root/kd-login.json" >/dev/null
	rm -f "$work/kd-setup.json" "$work/kd-login.json"
	[ "$(x 'curl -ks -o /root/kd-setup.out -w "%{http_code}" --max-time 60 -H "Content-Type: application/json" --data-binary @/root/kd-setup.json https://127.0.0.1:8443/api/v1/core/setup')" = 200 ] || { x 'cat /root/kd-setup.out' >&2; fail "keep-data case: first-run setup through the API failed"; }
	kd_healthy "keep-data case, before the uninstall"
	kkey=$(x 'sha256sum /var/lib/vedette/vedette.key')
	kids=$(x 'id vedette; id vedette-sensor')
	x 'sh /root/art/install.sh --uninstall --yes --keep-data' >"$work/kd-un.log" 2>&1 || { tail -40 "$work/kd-un.log" >&2; fail "--uninstall --yes --keep-data failed"; }
	x '! test -e /etc/containers/systemd/vedette-core.container && ! dpkg -s vedette-host >/dev/null 2>&1 && ! systemctl is-active -q vedette-host.service' || fail "--uninstall --keep-data left core's unit, the package or a running vedette-host"
	x 'test -s /var/lib/vedette/vedette.key && test -f /etc/vedette/host.conf && test -f /var/lib/vedette-host/containers/versions-core.json' || fail "--uninstall --keep-data did not keep the key, host.conf or the record of the release that ran"
	x 'dpkg -s podman >/dev/null 2>&1 && test -d /var/lib/containers/storage' || fail "D-508: --uninstall --keep-data purged podman or its storage"
	grep -qF -- "/var/lib/containers: --keep-data was given" "$work/kd-un.log" || { tail -20 "$work/kd-un.log" >&2; fail "D-508: --uninstall --keep-data did not say it kept podman"; }
	ok "--uninstall --keep-data: Vedette is stopped and its units and package are gone; the key, host.conf, the record of the release that ran, podman and its storage are kept"
	# an older release than the one that ran on the kept data is refused before any change (D-418): the record says 99.0.0 for a moment
	x 'cp -p /var/lib/vedette-host/containers/versions-core.json /root/kd-versions.bak && sed -i "s/\"current\":{\"service\":\"core\",\"version\":\"[^\"]*\"/\"current\":{\"service\":\"core\",\"version\":\"99.0.0\"/" /var/lib/vedette-host/containers/versions-core.json'
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/o.txt" 2>&1 && fail "D-418: an install older than the release that ran on the kept data was accepted"
	grep -q 'keeps the data of Vedette 99.0.0' "$work/o.txt" || { tail -20 "$work/o.txt" >&2; fail "D-418: no 'keeps the data of Vedette 99.0.0' refusal"; }
	x '! dpkg -s vedette-host >/dev/null 2>&1 && ! test -e /etc/containers/systemd/vedette-core.container' || fail "D-418: the refused install changed the box"
	x 'cp -p /root/kd-versions.bak /var/lib/vedette-host/containers/versions-core.json && rm -f /root/kd-versions.bak'
	ok "D-418: an install older than the release that last ran on the kept data is refused and changes nothing"
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/kd2.log" 2>&1 || { tail -40 "$work/kd2.log" >&2; fail "W2-9: the install after --uninstall --keep-data failed"; }
	grep -q 'none of its containers: installing release' "$work/kd2.log" || { tail -30 "$work/kd2.log" >&2; fail "W2-9: the install did not see the kept data without containers"; }
	! grep -q 'already bootstrapped' "$work/kd2.log" || fail "W2-9: the install skipped the bootstrap over the kept data"
	grep -q 'first-run setup was completed already' "$work/kd2.log" || { tail -15 "$work/kd2.log" >&2; fail "W2-9: the summary does not say setup was done"; }
	kd_healthy "W2-9, install after --uninstall --keep-data"
	[ "$(x 'sha256sum /var/lib/vedette/vedette.key')" = "$kkey" ] && [ "$(x 'id vedette; id vedette-sensor')" = "$kids" ] || fail "W2-9: the key or the ids of the users changed"
	x '! test -e /var/lib/vedette-install/kept-release' || fail "W2-9: the note of the release that ran is still there after the bootstrap"
	ok "W2-9: install after --uninstall --keep-data: core healthy, setup still complete, the administrator signs in, same key and user ids"
	# W2-10: the repair path with vedette-host running: core's unit removed by hand, then install.sh again
	# the honeypot Requires= the host: it stops with it for the bootstrap and must be running again afterwards when it was before
	hp_before=$(x 'systemctl is-active vedette-honeypot.service' || true)
	x 'systemctl is-active -q vedette-host.service && systemctl stop vedette-core.service && rm -f /etc/containers/systemd/vedette-core.container && systemctl daemon-reload' || fail "W2-10: cannot set up the case (vedette-host not running?)"
	x 'sh /root/art/install.sh --test-artifacts /root/art' >"$work/kd3.log" 2>&1 || { tail -40 "$work/kd3.log" >&2; fail "W2-10: the re-run with vedette-host running and core's unit missing failed"; }
	grep -q 'stopping vedette-host for the bootstrap' "$work/kd3.log" || { tail -30 "$work/kd3.log" >&2; fail "W2-10: the re-run did not stop vedette-host before the bootstrap"; }
	! grep -q 'daemon_running' "$work/kd3.log" || fail "W2-10: the bootstrap still met a running vedette-host"
	[ "$(x 'systemctl is-active vedette-host.service')" = active ] || fail "W2-10: vedette-host is not running after the re-run"
	[ "$hp_before" != active ] || [ "$(x 'systemctl is-active vedette-honeypot.service' || true)" = active ] || fail "W2-10: the honeypot ran before the re-run and does not after it"
	kd_healthy "W2-10, re-run with vedette-host running"
	ok "W2-10: the re-run stopped vedette-host for the bootstrap, wrote core's unit again and started both; the data is still there"
	x 'rm -f /root/kd-setup.json /root/kd-setup.out /root/kd-login.json'
	x 'sh /root/art/install.sh --uninstall --yes' >"$work/kd-un2.log" 2>&1 || { tail -40 "$work/kd-un2.log" >&2; fail "--uninstall --yes after the keep-data case failed"; }
	x '! getent passwd vedette >/dev/null && ! test -e /var/lib/vedette && ! test -e /var/lib/vedette-host && ! test -e /etc/vedette' || fail "--uninstall --yes after the keep-data case left Vedette's users or data"
	# D-508: the kept podman stayed on the installer's lists, so the full uninstall (nothing else in podman) still purges it
	x '! dpkg -s podman >/dev/null 2>&1 && ! test -e /var/lib/containers' || fail "D-508: the full --uninstall after the keep-data case left podman or /var/lib/containers"
	ok "keep-data case: a full --uninstall --yes afterwards removes the data, the users, podman and its storage"

	"$c" rm -f -t 0 "$ctr" >/dev/null
	"$c" volume rm -f "vic-$n-containers" >/dev/null 2>&1 || true
	"$c" rmi -f "localhost/vedette-installcheck-$n:check" >/dev/null 2>&1 || true
done
name="finished"
ok "all targets passed"
