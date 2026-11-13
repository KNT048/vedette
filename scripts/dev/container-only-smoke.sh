#!/usr/bin/env bash
# make container-only-smoke (WP-08m slice 3, D-168): bring the container-only install up the way docs/INSTALL-CONTAINER.md tells a customer
# (deploy/compose/container-only/*, a vedette.env with the address and the images filled in), once per runtime, check BY EFFECT, tear everything
# down and leave the box as it was. Opt-in: slow (builds the images), not in `make check`, not in CI. Run it through the heavy lock:
#   ~/vedette-wt/heavy make container-only-smoke
#
# Runtimes: docker (`docker compose`) and podman (`podman compose`, rootless); SMOKE_RUNTIMES="docker" picks one. A runtime that cannot be
# used (no daemon access, a Vedette container name or port already taken) is SKIPPED with the reason, never forced. Exit 0 when nothing
# failed and at least one runtime ran.
# Checks, per runtime: core answers on 8443 of the address given and 421s a wrong Host; setup through the API with the code from the log;
# the box-only endpoints answer 409 not_appliance; the data volume holds vedette.key owned 65532:65532 mode 0600; the published ports are
# the address given for 8443 and 127.0.0.1 for 8444 (and ss agrees); core runs as 65532:65532 with no capability and no new privileges,
# read-only root; syslog compose publishes 514 -> 5514 on the address (where the engine may publish 514); sensor compose (rootful engine
# only): sensor uid 0 / gid 65532 with only NET_RAW, scan 65532 with none, both healthy; and the sensor reads its credentials and its
# heartbeat reaches core over 8444: GET /inventory/sensors reports the passive sensor `online` with the cards it saw (waited on that state,
# not on the clock).
# macOS (Podman machine, a Linux VM): only podman, and only the checks that do not need the host's kernel (no ss, no 514, bind
# 127.0.0.1); Docker Desktop has no host network, so it is skipped with that reason. The machine must be rootful for the sensor part
# (`podman machine set --rootful`, needs a stop and start); a rootless machine runs everything but the sensor and says so. The sensor part
# is also skipped, with the reason, when the machine cannot start a container with `network_mode: host` + NET_RAW.
# Safety: everything is in the compose project vedette-smoke-<pid> and images tagged smoke-<pid>; nothing else is touched (no prune, no
# netplan, no firewall, no scan: the sensor is passive and no module that reaches out is switched on). Linux or macOS. Needs curl, jq, ss (Linux) or lsof (macOS), make, go.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
umask 022

mac=0
[ "$(uname -s)" = Darwin ] && mac=1
runtimes=${SMOKE_RUNTIMES:-docker podman}
if [ "$mac" = 1 ]; then
	runtimes=${SMOKE_RUNTIMES:-podman}
	bind=${SMOKE_BIND_IP:-127.0.0.1} # macOS has no 127.0.0.77; the busy-port check keeps a running Vedette safe
else
	bind=${SMOKE_BIND_IP:-127.0.0.77} # a loopback address of its own, so a running Vedette on 127.0.0.1 is never in the way
fi
work=${SMOKE_WORK:-$HOME/.cache/vedette-smoke}/run-$$ # on disk, /tmp is RAM
p=vedette-smoke-$$
tag=smoke-$$
base="https://$bind:8443/api/v1"
failed=0
ran=0
started_socket=0
cur_rt=
declare -a files=()

say() { echo "smoke[${cur_rt:-all}]: $*"; }
ok() { say "ok   $*"; }
skip() { say "skip $*"; }
bad() {
	say "FAIL $*"
	failed=1
}
die() { # a failure that makes the rest of this runtime meaningless
	bad "$*"
	return 1
}

# the debian image the project pins (also what INSTALL-CONTAINER.md uses for backups); a helper that only reads
debian=$(grep '^DEBIAN_IMAGE=' deploy/containers/pins.env | cut -d= -f2-)

# retry: rootless container DNS blips ("Temporary failure resolving") are not code bugs.
retry() {
	local n
	for n in 1 2 3; do
		"$@" && return 0
		say "attempt $n of '$1 $2' failed, retrying" >&2
		sleep 5
	done
	return 1
}

dc() { timeout 240 "$cur_rt" compose -p "$p" --env-file "$work/vedette.env" "${files[@]}" "$@"; }

teardown() { # idempotent; touches only this run's project, tag and work folder
	[ -n "$cur_rt" ] || return 0
	if [ "${#files[@]}" -gt 0 ]; then
		dc down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
	# `podman compose down -v` can leave volumes behind: remove, by exact project prefix only, what this run created
	local v
	for v in $(timeout 30 "$cur_rt" volume ls -q 2>/dev/null | grep "^${p}_" || true); do
		timeout 30 "$cur_rt" volume rm -f "$v" >/dev/null 2>&1 || true
	done
	for v in $(timeout 30 "$cur_rt" network ls --format '{{.Name}}' 2>/dev/null | grep "^${p}_" || true); do
		timeout 30 "$cur_rt" network rm -f "$v" >/dev/null 2>&1 || true
	done
	timeout 120 "$cur_rt" rmi -f "localhost/vedette-core:$tag" "localhost/vedette-sensor:$tag" "localhost/vedette-scan-base:$tag" >/dev/null 2>&1 || true
}
final() {
	trap '' EXIT INT TERM
	teardown
	rm -rf "$work"
	if [ "$started_socket" = 1 ]; then # only a socket this script started
		timeout 30 systemctl --user stop podman.socket podman.service >/dev/null 2>&1 || true
	fi
	exit "$failed"
}
trap final EXIT INT TERM
interrupted() {
	failed=1
	exit 1
}
trap interrupted INT TERM

# what the box has of this run after teardown (must be nothing)
leftovers() {
	{
		timeout 30 "$cur_rt" ps -a --format '{{.Names}}' | grep -E '^vedette-(core|sensor|scan)$' || true
		timeout 30 "$cur_rt" volume ls -q | grep "^${p}_" || true
		timeout 30 "$cur_rt" network ls --format '{{.Name}}' | grep "^${p}_" || true
		timeout 30 "$cur_rt" image ls --format '{{.Repository}}:{{.Tag}}' | grep ":${tag}\$" || true
	}
}

code_of() { curl -ksS -m 15 -o /dev/null -w '%{http_code}' "$@" || echo 000; }

# one process' status, read from a helper that shares the container's pid namespace (the images have no shell)
pstatus() { # container pid
	timeout 60 "$cur_rt" run --rm --network none --cap-drop ALL --pid "container:$1" "$debian" cat "/proc/$2/status" 2>/dev/null || true
}
# every process of the container except the helper's own cat: all must have this uid and capability set (at least two: init and worker)
want_all() { # container uid capeff label
	local st res
	st=$(timeout 60 "$cur_rt" run --rm --network none --cap-drop ALL --pid "container:$1" "$debian" sh -c 'cat /proc/[0-9]*/status' 2>/dev/null || true)
	res=$(awk -v u="$2" -v c="$3" '
		/^Name:/ {name=$2}
		/^Uid:/ {uid=$2}
		/^CapEff:/ {cap=$2}
		/^NoNewPrivs:/ {if (name != "cat" && name != "sh") {n++; if (uid != u || cap != c || $2 != 1) bad++}}
		END {print n+0, bad+0}' <<<"$st")
	if [ "${res% *}" -ge 2 ] && [ "${res#* }" = 0 ]; then
		ok "$4: all ${res% *} processes uid $2 CapEff=$3 no-new-privileges"
	else
		bad "$4: processes seen / wrong = $res (want at least 2 / 0)"
	fi
}
want_proc() { # container pid uid gid capeff label
	local st uid gid cap nnp
	st=$(pstatus "$1" "$2")
	[ -n "$st" ] || {
		bad "$6: cannot read /proc/$2/status of $1"
		return
	}
	uid=$(awk '/^Uid:/{print $2}' <<<"$st")
	gid=$(awk '/^Gid:/{print $2}' <<<"$st")
	cap=$(awk '/^CapEff:/{print $2}' <<<"$st")
	nnp=$(awk '/^NoNewPrivs:/{print $2}' <<<"$st")
	local bnd
	bnd=$(awk '/^CapBnd:/{print $2}' <<<"$st")
	if [ "$uid:$gid:$cap:$bnd:$nnp" = "$3:$4:$5:$5:1" ]; then
		ok "$6: uid $uid gid $gid CapEff=CapBnd=$cap no-new-privileges"
	else
		bad "$6: uid:gid:CapEff:CapBnd:NoNewPrivs = $uid:$gid:$cap:$bnd:$nnp, want $3:$4:$5:$5:1"
	fi
}

# is something listening on this TCP port on the host? (ss on Linux, lsof on macOS, where any address counts)
port_busy() { # port [address]
	if [ "$mac" = 1 ]; then
		[ -n "$(lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true)" ]
	else
		[ -n "$(ss -H -ltn "sport = :$1" | grep -F "${2:-}:" || true)" ]
	fi
}

listening() { # port expected-address: every listener of the port is on that address
	local out
	out=$(ss -H -ltn "sport = :$1" | awk '{print $4}')
	[ -n "$out" ] && [ "$(sort -u <<<"$out")" = "$2:$1" ]
}

run_runtime() {
	cur_rt=$1
	files=()
	local rootful=1 syslog=0 sensors=0 jar code out
	command -v "$cur_rt" >/dev/null || {
		skip "$cur_rt is not installed"
		return 0
	}
	if ! timeout 20 "$cur_rt" info >/dev/null 2>&1; then
		if [ "$cur_rt" = docker ]; then
			skip "docker: cannot talk to the daemon (is user $(id -un) in the docker group? run: sudo usermod -aG docker $(id -un), then log in again)"
		else
			skip "podman: 'podman info' fails"
		fi
		return 0
	fi
	# `podman compose` hands over to the docker-compose provider, which talks to podman's API socket: rootless needs podman.socket active
	if [ "$cur_rt" = podman ] && [ "$mac" = 0 ] && [ "$(id -u)" != 0 ] && ! systemctl --user is-active --quiet podman.socket; then
		if timeout 30 systemctl --user start podman.socket; then
			started_socket=1
			say "started podman.socket (user) for this run; it is stopped again at the end"
		else
			skip "podman: podman.socket is not active and could not be started (systemctl --user enable --now podman.socket)"
			return 0
		fi
	fi
	timeout 30 "$cur_rt" compose version >/dev/null 2>&1 || {
		skip "$cur_rt compose is not available (needs Compose v2 or a compose provider)"
		return 0
	}
	# rootless engines cannot read a real card from a container nor publish 514 below the machine's unprivileged-port limit
	if [ "$cur_rt" = podman ] && [ "$mac" = 1 ]; then
		[ "$(timeout 20 podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = false ] || rootful=0
	elif [ "$cur_rt" = podman ]; then
		[ "$(id -u)" = 0 ] || rootful=0
	else
		timeout 20 docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless && rootful=0
	fi
	# fixed container names (the customer's compose file): if the box already runs a Vedette, leave it alone
	if timeout 30 "$cur_rt" ps -a --format '{{.Names}}' | grep -qE '^vedette-(core|sensor|scan)$'; then
		skip "$cur_rt: a container named vedette-core/sensor/scan already exists on this box; not touching it"
		return 0
	fi
	if port_busy 8444 127.0.0.1 || port_busy 8443 "$bind"; then
		skip "$cur_rt: port 8444 on 127.0.0.1 or 8443 on $bind is already in use"
		return 0
	fi
	ran=$((ran + 1))

	# the customer's files, copied, and a vedette.env filled in the way the doc says (images = local builds, see INSTALL-CONTAINER.md section 1)
	# 0700: the cookie jar of the admin session lives here (curl writes it 0644 under the umask 022 the build keeps)
	mkdir -p "$work"
	chmod 0700 "$work"
	cp deploy/compose/container-only/compose*.yaml "$work/"
	local with_sensors=0
	[ "$rootful" = 1 ] && with_sensors=1
	{
		grep -vE '^(VEDETTE_BIND_IP|VEDETTE_HOSTS|VEDETTE_CORE_IMAGE|VEDETTE_SENSOR_IMAGE|VEDETTE_SCAN_IMAGE)=' deploy/compose/container-only/vedette.env
		echo "VEDETTE_BIND_IP=$bind"
		echo "VEDETTE_HOSTS=$bind"
		echo "VEDETTE_CORE_IMAGE=localhost/vedette-core:$tag"
		echo "VEDETTE_SENSOR_IMAGE=localhost/vedette-sensor:$tag"
		echo "VEDETTE_SCAN_IMAGE=localhost/vedette-scan-base:$tag"
	} >"$work/vedette.env"
	files=(-f "$work/compose.yaml")
	if [ "$mac" = 1 ]; then
		skip "syslog part: 514 is a privileged port on the Mac host"
	elif [ "$cur_rt" = docker ] || [ "$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start)" -le 514 ] || [ "$rootful" = 1 ]; then
		syslog=1
		files+=(-f "$work/compose.syslog.yaml")
	else
		skip "syslog part: rootless $cur_rt cannot publish port 514 here (ip_unprivileged_port_start=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start))"
	fi

	# images: built here from the repo like the existing targets (no registry pull of Vedette images, no push)
	local targets=core-image
	[ "$with_sensors" = 1 ] && targets="core-image sensor-image scan-base-image"
	mkdir -p "$work"
	say "building $targets with $cur_rt (tag $tag)"
	# shellcheck disable=SC2086
	retry timeout 900 make --no-print-directory $targets CONTAINER="$cur_rt" IMAGE_TAG="$tag" >"$work/build.log" 2>&1 || {
		tail -25 "$work/build.log"
		die "image build failed (log kept until exit above)" || return 0
	}
	ok "images built: $targets"

	# 1. start the way the doc says; core is healthy
	retry dc up -d --wait --wait-timeout 150 core || {
		dc logs --no-log-prefix core 2>&1 | tail -20
		die "core did not become healthy" || return 0
	}
	ok "core is healthy ($cur_rt compose up -d --wait)"

	# 2. answers on the published 8443 of the address given, and only for the names it was told
	code=$(code_of "$base/setup")
	if [ "$code" = 200 ]; then ok "GET /api/v1/setup on $bind:8443 answers 200"; else bad "GET /api/v1/setup answered $code, want 200"; fi
	code=$(code_of -H 'Host: evil.example' "$base/setup")
	if [ "$code" = 421 ]; then ok "a Host that is not in VEDETTE_HOSTS gets 421"; else bad "wrong Host answered $code, want 421"; fi

	# 3. ports: where they are published, by the engine and by the kernel
	out=$(timeout 30 "$cur_rt" port vedette-core 2>&1 || true)
	if grep -q "8443/tcp -> $bind:8443" <<<"$out" && grep -q '8444/tcp -> 127.0.0.1:8444' <<<"$out" && ! grep -qE '0\.0\.0\.0|\[::\]' <<<"$out"; then
		ok "published: 8443 on $bind, 8444 on 127.0.0.1, nothing on all addresses"
	else
		bad "published ports are not what the compose file says: $out"
	fi
	if [ "$mac" = 1 ]; then
		skip "ss check: the listeners on macOS are the machine's port forwarder, not the container engine"
	elif listening 8443 "$bind" && listening 8444 127.0.0.1; then
		ok "ss: 8443 listens only on $bind, 8444 only on 127.0.0.1"
	else
		bad "ss: unexpected listeners on 8443/8444: $(ss -H -ltn 'sport = :8443 or sport = :8444' | awk '{print $4}' | tr '\n' ' ')"
	fi
	if [ "$syslog" = 1 ]; then
		if grep -q "5514/udp -> $bind:514" <<<"$out" && grep -q "5514/tcp -> $bind:514" <<<"$out"; then
			ok "syslog compose publishes udp+tcp 514 -> 5514 on $bind"
		else
			bad "syslog ports not published as 514 -> 5514 on $bind: $out"
		fi
	fi

	# 4. first-run setup with the code from the log, then the box-only endpoints say not_appliance
	code=
	for _ in $(seq 1 30); do
		code=$(dc logs --no-log-prefix core 2>/dev/null | grep -o '"setup_code":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
		[ -n "$code" ] && break
		sleep 1
	done
	[ -n "$code" ] || {
		dc logs --no-log-prefix core 2>&1 | tail -10
		die "core never printed its setup code" || return 0
	}
	ok "the setup code is in the log"
	jar="$work/jar"
	local pass mods
	api() { curl -ksS -m 20 -c "$jar" -b "$jar" -H 'Content-Type: application/json' "$@"; }
	pass='smoke-only-Passw0rd-123'
	mods='"core"'
	[ "$with_sensors" = 1 ] && mods='"core","feeds","inventory","sensor-passive","sensor-active"'
	# the bodies go on stdin (printf is a builtin): the setup code and the password never stand in curl's argv (/proc/<pid>/cmdline)
	out=$(printf '{"org":"Smoke","admin":{"name":"Smoke Admin","email":"smoke@example.com","password":"%s"},"lan":["192.168.10.0/24"],"commitment":true,"bundle":"custom","modules":[%s],"setup_code":"%s"}' "$pass" "$mods" "$code" |
		api -w ' %{http_code}' -X POST "$base/core/setup" --data-binary @- || true)
	[[ $out == *' 2'?? ]] || {
		die "setup through the API failed: ${out:0:300}" || return 0
	}
	printf '{"email":"smoke@example.com","password":"%s"}' "$pass" | api -f -X POST "$base/auth/login" --data-binary @- >/dev/null || {
		die "login failed" || return 0
	}
	ok "setup and login through the API"
	local ep
	for ep in core/updates/os core/network core/data/backup; do
		out=$(api -o - -w ' %{http_code}' "$base/$ep" || true)
		if [[ $out == *' 409' ]] && [[ $out == *not_appliance* ]]; then
			ok "GET /$ep answers 409 not_appliance"
		else
			bad "GET /$ep: $out (want 409 not_appliance)"
		fi
	done

	# 5. the data volume: the master key, its owner and mode (read from a helper, root of the volume is not ours to read on the host)
	out=$(retry timeout 90 "$cur_rt" run --rm --network none -v "${p}_data:/data:ro" "$debian" stat -c '%u:%g %a %n' /data /data/vedette.key 2>&1) || true
	if grep -qx '65532:65532 750 /data' <<<"$out" && grep -qx '65532:65532 600 /data/vedette.key' <<<"$out"; then
		ok "data volume: /data 65532:65532 0750, vedette.key 65532:65532 0600"
	else
		bad "data volume owner/mode: $out"
	fi

	# 6. who core runs as
	if [ "$(timeout 30 "$cur_rt" inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}}' vedette-core)" = '65532:65532 true false' ]; then
		ok "core: configured user 65532:65532, read-only root, not privileged"
	else
		bad "core inspect: $(timeout 30 "$cur_rt" inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Privileged}}' vedette-core)"
	fi
	want_proc vedette-core 1 65532 65532 0000000000000000 "core process"

	# 7. sensors (rootful engine only): sensor uid 0 gid 65532 with only NET_RAW (0x2000), scan 65532 with none
	sensors=$with_sensors
	if [ "$sensors" = 1 ]; then
		files+=(-f "$work/compose.sensors.yaml")
		if ! retry dc up -d --wait --wait-timeout 150 sensor scan; then
			dc logs --no-log-prefix sensor scan 2>&1 | tail -20
			if [ "$mac" = 1 ]; then # a VM may not give a container the host network or NET_RAW: say so, do not fail the smoke for it
				skip "sensor part: this Podman machine could not run the sensor/scan with network_mode: host + NET_RAW (log above)"
				sensors=0
			else
				die "sensor/scan did not become healthy" || return 0
			fi
		fi
	fi
	if [ "$sensors" = 1 ]; then
		ok "sensor and scan are healthy"
		want_proc vedette-sensor 1 0 65532 0000000000002000 "sensor process (NET_RAW only)"
		want_all vedette-scan 65532 0000000000000000 "scan (init and worker)"
		# the heartbeat by effect: the sensor (uid 0, group 65532, NET_RAW only) must have read its credentials through the group and
		# reached core over 8444, or core keeps it never_connected. Wait on that state (a heartbeat is every 30 s), not on a fixed sleep.
		local st=
		for _ in $(seq 1 24); do
			st=$(api "$base/inventory/sensors" 2>/dev/null | jq -r '.sensors[0] | "\(.status) cards=\(.interfaces | length) last_seen=\(.last_seen)"' 2>/dev/null || true)
			[[ $st == online* ]] && break
			sleep 5
		done
		if [[ $st == online* ]] && [[ $st != *' cards=0 '* ]]; then
			ok "core reports the passive sensor online over 8444 ($st)"
		else
			dc logs --no-log-prefix sensor 2>&1 | tail -15
			bad "core never saw the sensor's heartbeat (GET /inventory/sensors: ${st:-no answer}): it could not read its credentials or reach 8444"
		fi
	elif [ "$with_sensors" = 1 ]; then
		:
	else
		skip "sensor part skipped: needs root (rootless $cur_rt cannot give the sensor a real card or NET_RAW)"
	fi

	# 8. tear down and prove the box is as it was
	teardown
	files=()
	out=$(leftovers)
	if [ -z "$out" ]; then ok "teardown: no container, volume, network or image of this run is left"; else bad "left behind: $out"; fi
}

if [ "$(uname -s)" != Linux ] && [ "$mac" = 0 ]; then
	echo "smoke: Linux, or macOS with a Podman machine (the sensor part needs a host network)" >&2
	exit 2
fi
command -v jq >/dev/null || {
	echo "smoke: needs jq" >&2
	exit 2
}
if [ "$mac" = 1 ] && [[ " $runtimes " == *" docker "* ]]; then
	echo "smoke[docker]: skip Docker Desktop has no host network (the sensor needs one); use a Linux box or the Podman machine" >&2
	runtimes=${runtimes/docker/}
fi
for rt in $runtimes; do
	case $rt in docker | podman) ;; *)
		echo "smoke: unknown runtime '$rt' (docker or podman)" >&2
		exit 2
		;;
	esac
	run_runtime "$rt" || failed=1
	cur_rt=$rt
	teardown
	rm -rf "$work"
	cur_rt=
done
cur_rt=
if [ "$ran" = 0 ]; then
	say "FAIL no runtime could be exercised"
	failed=1
fi
say "done: $ran runtime(s) exercised, $([ "$failed" = 0 ] && echo PASS || echo FAIL)"
