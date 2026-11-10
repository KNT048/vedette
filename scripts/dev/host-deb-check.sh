#!/usr/bin/env bash
# make host-deb-check (WP-08g, D-155): install the vedette-host .deb in a systemd container per target OS (Debian 13 and Ubuntu 24.04,
# pinned by digest) and check the EFFECTS: refusals (a normal user named vedette, a symbolic link, a foreign core_data, a foreign range in
# /etc/subuid) that leave nothing half-made; the same users, groups, /etc/subuid lines, directories, modes, owners and file hashes after a
# second install; the unit enabled and NOT started, and still disabled after an upgrade when the administrator disabled it; an existing
# containers: line kept; remove and purge keep the data, the users and the ids; the binary is static. Uses ROOTLESS podman (the container
# is privileged only inside the user namespace; the script refuses to run with real root). Pulls images and runs apt in them: opt-in, not in
# `make check` or CI. Linux only. Never scans or probes anything.
# Removes its containers, the images it built, the base images it pulled (not ones that were there before) and its own temp folder (never
# the shared dist/) at the end (build-artifacts rule).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
ver=9.8.7
case $(uname -m) in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; . deploy/deb/check-pins.env; set +a
targets="debian13=$DEBIAN_IMAGE ubuntu2404=$UBUNTU_2404_IMAGE"
work=$(mktemp -d)
out=$work/out
deb=$out/vedette-host_${ver}_${arch}.deb
bin=$out/host-deb/$arch/vedette-host
pulled=""
name=setup
fail() { echo "host-deb-check: FAIL [$name] $*" >&2; exit 1; }
ok() { echo "host-deb-check: ok   [$name] $*"; }
cleanup() {
	for t in $targets; do
		n=${t%%=*}
		$c rm -f -t 0 "vdc-$n" >/dev/null 2>&1 || true
		$c rmi -f "localhost/vedette-debcheck-$n:check" >/dev/null 2>&1 || true
	done
	for i in $pulled; do $c rmi "$i" >/dev/null 2>&1 || true; done
	rm -rf "$work"
}
trap cleanup EXIT

[ "$($c info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = true ] || fail "$c is not rootless: run this check as a normal user, never as root"

DEB_OUT=$out make --no-print-directory host-deb VERSION="$ver" ARCH="$arch" >/dev/null
[ -s "$deb" ] && [ -s "$out/host-deb/$arch/third-party-licenses" ] || fail "no package or no license file in $out"
ok "built $(basename "$deb")"
st=$(VEDETTE_HOST_BINARY=$bin go test -count=1 -v -run '^TestBinaryIsStatic$' ./deploy/deb 2>&1) || { echo "$st" >&2; fail "the binary is not static"; }
grep -q -- '--- PASS: TestBinaryIsStatic' <<<"$st" || { echo "$st" >&2; fail "TestBinaryIsStatic did not run"; }
ok "the binary is static (no PT_INTERP, no shared library)"

for t in $targets; do
	name=${t%%=*}
	image=${t#*=}
	ctr=vdc-$name
	x() { $c exec "$ctr" sh -c "$1"; }
	$c image exists "$image" || pulled="$pulled $image"

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

	# install [--reinstall]: apt resolves the Depends from the package; prints the tail of apt's log and fails when the install fails
	install() { x 'apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q '"$1"' /root/vedette-host.deb >/tmp/apt.log 2>&1 || { tail -30 /tmp/apt.log; exit 1; }'; }
	# refuses <description> <message regex>: the install fails, says why, and nothing of the package's accounts or directories was made
	# after a refusal the package stays half-configured and apt cannot reinstall a file it has no index for: dpkg configures it again
	# (the first call goes through apt, which installs the Depends)
	deps=
	dpkg_install() { x 'dpkg -i /root/vedette-host.deb >/tmp/apt.log 2>&1 || { tail -30 /tmp/apt.log; exit 1; }'; }
	try_install() {
		if [ -z "$deps" ]; then deps=1; install "--reinstall" || return 1; else dpkg_install; fi
	}
	refuses() {
		# not in a subshell: try_install remembers that the Depends are installed
		if try_install >"$work/refuse.log" 2>&1; then fail "$1: the install succeeded"; fi
		grep -Eq "vedette-host: .*$2" "$work/refuse.log" || { cat "$work/refuse.log" >&2; fail "$1: no message that matches $2"; }
		ok "refused: $1"
	}
	nothing_made() {
		x '! getent passwd vedette-sensor >/dev/null && ! getent group vedette-sensor >/dev/null && ! test -e /var/lib/vedette-host && ! test -e /etc/vedette' || fail "$1: the refused install left accounts or directories behind"
	}
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

	# ---- refusals, before the first good install: each leaves nothing behind ------------------------------------------------
	x 'useradd -m -u 1500 -s /bin/bash vedette'
	refuses "a normal user (uid 1500, shell bash) named vedette is not adopted" "(group|user) vedette exists with (gid|uid) 1500, outside the system range"
	nothing_made "normal user"
	x 'userdel -r vedette >/dev/null 2>&1; ! getent passwd vedette >/dev/null && ! getent group vedette >/dev/null' || fail "could not remove the planted user"

	x 'groupadd -g 1501 vedette-sensor'
	refuses "a normal group (gid 1501) named vedette-sensor is not adopted" "group vedette-sensor exists with gid 1501, outside the system range"
	x 'groupdel vedette-sensor'

	x 'groupadd --system vedette && usermod -a -G vedette root 2>/dev/null || gpasswd -a root vedette >/dev/null'
	refuses "a group vedette that has members is not adopted" "group vedette has members"
	x 'groupdel vedette'

	x 'useradd --system -s /bin/bash vedette'
	refuses "a system user vedette with a login shell is not adopted" "user vedette has a login shell"
	x 'userdel vedette; ! getent passwd vedette >/dev/null && ! getent group vedette >/dev/null' || fail "could not remove the planted user"

	x 'groupadd --system other && useradd --system -g other -s /usr/sbin/nologin vedette'
	refuses "a user vedette whose primary group is not vedette is not adopted" "primary group of user vedette is not the group vedette"
	x 'userdel vedette; groupdel other; ! getent group vedette >/dev/null' || fail "could not remove the planted user"
	nothing_made "accounts"

	for link in /var/lib/vedette-host /var/lib/vedette; do
		x "mkdir -p /var/lib/target && chmod 0711 /var/lib/target && ln -s /var/lib/target $link"
		refuses "a symbolic link at $link is not followed" "$link is a symbolic link"
		x "[ \"\$(stat -c %a /var/lib/target)\" = 711 ] && [ -z \"\$(ls -A /var/lib/target)\" ] && rm $link && rmdir /var/lib/target" || fail "the install touched the target of the link at $link"
		nothing_made "link at $link"
	done

	x 'install -d -m 0755 /var/lib/vedette'
	refuses "a foreign core_data (root:root 755) is not re-owned" "/var/lib/vedette exists with mode and owner '755 root:root'"
	x '[ "$(stat -c "%a %U:%G" /var/lib/vedette)" = "755 root:root" ] && rmdir /var/lib/vedette' || fail "the refused install changed the foreign core_data"

	# ---- the good install --------------------------------------------------------------------------------------------------
	dpkg_install
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
	# /usr/share/doc/vedette-host/{NOTICE,third-party-licenses} are not checked here: the container images exclude /usr/share/doc (dpkg path-exclude); deploy/deb/deb_test.go checks them in the package
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
	o=$(x 'systemd-analyze verify /usr/lib/systemd/system/vedette-host.service 2>&1' || true)
	if grep -Eq 'Unknown (key|section)|Failed to parse|Invalid' <<<"$o"; then echo "$o" >&2; fail "systemd-analyze verify finds a problem in the unit"; fi
	ok "systemd-analyze verify: the unit parses"
	# host.conf is there (the marker file), so the condition holds; starting would run the helper: not done here. Without host.conf the unit is skipped.
	x 'mv /etc/vedette/host.conf /etc/vedette/host.conf.off && systemctl start vedette-host.service; r=$?; mv /etc/vedette/host.conf.off /etc/vedette/host.conf; [ "$(systemctl show -p ActiveState --value vedette-host.service)" = inactive ] && [ "$(systemctl show -p ConditionResult --value vedette-host.service)" = no ]' || fail "an enabled unit without host.conf was not skipped by its condition"
	ok "without /etc/vedette/host.conf a start is skipped by ConditionPathExists (inactive, no failure)"
	[ "$(x '/usr/lib/vedette/vedette-host -version')" = "$ver" ] || fail "vedette-host -version is not $ver"
	ok "vedette-host -version prints $ver"

	install "--reinstall"
	s2=$(state)
	[ "$s1" = "$s2" ] || { diff <(echo "$s1") <(echo "$s2") >&2 || true; fail "the second install changed the state"; }
	ok "second install: users, groups, subid lines, tree, modes, owners, hashes and unit state are identical"

	# ---- an administrator's choices survive an upgrade --------------------------------------------------------------------
	x 'systemctl disable vedette-host.service >/dev/null 2>&1'
	install "--reinstall"
	[ "$(x 'systemctl is-enabled vedette-host.service 2>&1 || true')" = disabled ] || fail "an upgrade re-enabled a unit the administrator disabled"
	ok "an administrator-disabled unit stays disabled after an upgrade (update-state, not enable)"
	x 'systemctl enable vedette-host.service >/dev/null 2>&1'

	x 'printf "containers:100000:65536\n" | tee /etc/subuid >/etc/subgid'
	install "--reinstall"
	[ "$(x 'cat /etc/subuid /etc/subgid')" = "$(printf 'containers:100000:65536\ncontainers:100000:65536')" ] || fail "an existing containers: line was changed or doubled"
	ok "an existing containers: line is kept as it is (no second line)"

	x 'printf "other:2147483648:65536\n" | tee /etc/subuid >/etc/subgid'
	refuses "another owner's range overlapping 2147483647-4294967294 is refused" "overlaps 2147483647-4294967294"
	[ "$(x 'cat /etc/subuid')" = "other:2147483648:65536" ] || fail "the refused install changed /etc/subuid"
	x 'printf "containers:2147483647:2147483648\n" | tee /etc/subuid >/etc/subgid'
	dpkg_install # the refused install left the package half-configured
	s4=$(state)
	[ "$s1" = "$s4" ] || { diff <(echo "$s1") <(echo "$s4") >&2 || true; fail "the state after the administrator cases differs from the first install"; }
	ok "back to the standard lines: the state equals the first install again"

	# ---- remove and purge --------------------------------------------------------------------------------------------------
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
name="done"
ok "all targets passed"
