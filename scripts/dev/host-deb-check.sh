#!/usr/bin/env bash
# make host-deb-check (WP-08g, D-155): install the vedette-host .deb TWICE in a systemd container per target OS (Debian 13 and Ubuntu 24.04,
# pinned by digest) and check the EFFECTS: the same users, groups, /etc/subuid lines, directories, modes, owners and file hashes after the
# second install; the unit enabled and NOT started; remove and purge keep the data, the users and the ids. Uses podman (rootless is enough;
# the container is privileged only inside the user namespace). Pulls images and runs apt in them: opt-in, not in `make check` or CI.
# Linux only. Never scans or probes anything. Removes the containers, the images and dist/ at the end (build-artifacts rule).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
ver=9.8.7
case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; . deploy/deb/check-pins.env; set +a
targets="debian13=$DEBIAN_IMAGE ubuntu2404=$UBUNTU_2404_IMAGE"
deb=dist/vedette-host_${ver}_${arch}.deb
work=$(mktemp -d)
cleanup() {
	for t in $targets; do
		n=${t%%=*}
		$c rm -f -t 0 "vdc-$n" >/dev/null 2>&1 || true
		$c rmi -f "localhost/vedette-debcheck-$n:check" >/dev/null 2>&1 || true
	done
	rm -rf "$work" dist/host-deb "dist/vedette-host_${ver}_${arch}.deb"
	rmdir dist 2>/dev/null || true
}
trap cleanup EXIT
fail() { echo "host-deb-check: FAIL [$name] $*" >&2; exit 1; }
ok() { echo "host-deb-check: ok   [$name] $*"; }
name=setup

make --no-print-directory host-deb VERSION="$ver" ARCH="$arch" >/dev/null
[ -s "$deb" ] || fail "no $deb"

for t in $targets; do
	name=${t%%=*}
	image=${t#*=}
	ctr=vdc-$name
	x() { $c exec "$ctr" sh -c "$1"; }

	# an image with systemd as init and nothing of the package's Depends: apt must resolve them from the .deb
	mkdir -p "$work/$name"
	cat >"$work/$name/Containerfile" <<EOT
FROM $image
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends systemd systemd-sysv ca-certificates && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOT
	$c build -q -t "localhost/vedette-debcheck-$name:check" "$work/$name" >/dev/null || fail "image build"
	$c run -d --name "$ctr" --privileged --systemd=always "localhost/vedette-debcheck-$name:check" >/dev/null || fail "cannot start a systemd container (podman $($c --version))"
	for _ in $(seq 1 60); do
		s=$(x 'systemctl is-system-running 2>/dev/null' || true)
		case $s in running | degraded) break ;; esac
		sleep 1
	done
	case $s in running | degraded) ok "systemd is PID 1 ($s)" ;; *) fail "systemd did not come up: '$s'" ;; esac
	$c cp "$deb" "$ctr:/root/vedette-host.deb"

	install() { x 'apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q '"$1"' /root/vedette-host.deb >/tmp/apt.log 2>&1 || { tail -30 /tmp/apt.log; exit 1; }'; }
	# the state the package makes: users, groups, subid lines, tree (paths, types, modes, owners, sizes), file hashes, unit state
	state() {
		x '
		getent passwd vedette vedette-sensor; getent group vedette vedette-sensor
		grep -H "^containers:" /etc/subuid /etc/subgid
		find /usr/lib/vedette /usr/lib/systemd/system/vedette-host.service /usr/share/doc/vedette-host /etc/vedette /etc/containers/systemd /var/lib/vedette /var/lib/vedette-host /var/lib/vedette-honeypot \
			-printf "%p %y %m %u:%g %s\n" | sort
		sha256sum /usr/lib/vedette/vedette-host /usr/lib/systemd/system/vedette-host.service
		echo "is-enabled=$(systemctl is-enabled vedette-host.service 2>&1)"
		echo "active=$(systemctl show -p ActiveState --value vedette-host.service)"
		echo "wants=$(ls /etc/systemd/system/multi-user.target.wants/ | grep -c "^vedette-host.service$")"
		'
	}
	want() { # want <description> <regex>: the state has a line that matches
		grep -Eq "$2" <<<"$s1" || { echo "$s1" >&2; fail "$1 (no line matches $2)"; }
		ok "$1"
	}

	install ""
	# the data that must survive everything below: a marker in core_data and the honeypot config, and a host.conf (the installer's file)
	x 'echo keep >/var/lib/vedette/marker && echo keep >/etc/vedette/host.conf && echo keep >/var/lib/vedette-honeypot/config/marker'
	s1=$(state)
	want "group vedette exists" '^vedette:x:[0-9]+:'
	want "group vedette-sensor exists" '^vedette-sensor:x:[0-9]+:'
	want "user vedette is a system user without a login shell" '^vedette:x:[0-9]{1,3}:[0-9]+:[^:]*:/nonexistent:/usr/sbin/nologin$'
	want "user vedette-sensor is a system user without a login shell" '^vedette-sensor:x:[0-9]{1,3}:[0-9]+:[^:]*:/nonexistent:/usr/sbin/nologin$'
	[ "$(grep -Ec '^/etc/sub[ug]id:containers:2147483647:2147483648$' <<<"$s1")" = 2 ] || { echo "$s1" >&2; fail "want one containers: line in /etc/subuid and one in /etc/subgid"; }
	ok "one containers:2147483647:2147483648 line in /etc/subuid and /etc/subgid"
	want "/usr/lib/vedette/vedette-host 755 root:root" '^/usr/lib/vedette/vedette-host f 755 root:root '
	want "unit in /usr/lib/systemd/system 644 root:root" '^/usr/lib/systemd/system/vedette-host.service f 644 root:root '
	want "/etc/vedette 755 root:root" '^/etc/vedette d 755 root:root '
	want "/etc/containers/systemd 755 root:root" '^/etc/containers/systemd d 755 root:root '
	want "/var/lib/vedette-host 700 root:root" '^/var/lib/vedette-host d 700 root:root '
	want "core_data /var/lib/vedette 700 vedette:vedette" '^/var/lib/vedette d 700 vedette:vedette '
	want "/var/lib/vedette-honeypot 755 root:root" '^/var/lib/vedette-honeypot d 755 root:root '
	want "honeypot config/ 755 vedette:vedette" '^/var/lib/vedette-honeypot/config d 755 vedette:vedette '
	want "honeypot log/ 750 vedette:vedette" '^/var/lib/vedette-honeypot/log d 750 vedette:vedette '
	want "the unit is enabled" '^is-enabled=enabled$'
	want "the unit is NOT started" '^active=inactive$'
	want "the enable link is in multi-user.target.wants" '^wants=1$'
	out=$(x 'systemd-analyze verify /usr/lib/systemd/system/vedette-host.service 2>&1' || true)
	if grep -Eq 'Unknown (key|section)|Failed to parse|Invalid' <<<"$out"; then echo "$out" >&2; fail "systemd-analyze verify finds a problem in the unit"; fi
	ok "systemd-analyze verify: the unit parses"
	[ "$(x '/usr/lib/vedette/vedette-host -version')" = "$ver" ] || fail "vedette-host -version is not $ver"
	ok "vedette-host -version prints $ver"

	install "--reinstall"
	s2=$(state)
	[ "$s1" = "$s2" ] || { diff <(echo "$s1") <(echo "$s2") >&2 || true; fail "the second install changed the state"; }
	ok "second install: users, groups, subid lines, tree, modes, owners, hashes and unit state are identical"

	x 'apt-get remove -y -q vedette-host >/tmp/apt.log 2>&1' || fail "apt-get remove"
	x 'test ! -e /usr/lib/vedette/vedette-host && test ! -e /usr/lib/systemd/system/vedette-host.service' || fail "remove left the binary or the unit"
	x 'test ! -e /etc/systemd/system/multi-user.target.wants/vedette-host.service' || fail "remove left the enable link"
	x 'test "$(cat /var/lib/vedette/marker /etc/vedette/host.conf /var/lib/vedette-honeypot/config/marker | tr -d "\n")" = keepkeepkeep && test -d /var/lib/vedette-host && test -d /var/lib/vedette-honeypot/log' || fail "remove deleted data"
	x 'getent passwd vedette vedette-sensor >/dev/null && getent group vedette vedette-sensor >/dev/null' || fail "remove deleted a user or group"
	ok "remove: binary, unit and enable link gone; data, host.conf, users and groups stay"

	x 'apt-get purge -y -q vedette-host >/tmp/apt.log 2>&1' || fail "apt-get purge"
	x 'test "$(cat /var/lib/vedette/marker /etc/vedette/host.conf /var/lib/vedette-honeypot/config/marker | tr -d "\n")" = keepkeepkeep && test -d /var/lib/vedette-host' || fail "purge deleted data"
	x 'getent passwd vedette vedette-sensor >/dev/null && getent group vedette vedette-sensor >/dev/null && grep -q "^containers:" /etc/subuid /etc/subgid' || fail "purge deleted a user, a group or a subid line"
	ok "purge: data (core_data, host.conf, honeypot folders, state), users, groups and subid lines stay"

	install ""
	s3=$(state)
	[ "$s1" = "$s3" ] || { diff <(echo "$s1") <(echo "$s3") >&2 || true; fail "install after purge differs from the first install (ids, modes or state)"; }
	ok "install after purge: same ids and the same state as the first install (the unit is enabled again, not started)"

	$c rm -f -t 0 "$ctr" >/dev/null
	$c rmi -f "localhost/vedette-debcheck-$name:check" >/dev/null 2>&1 || true
done
name=done
ok "all targets passed"
