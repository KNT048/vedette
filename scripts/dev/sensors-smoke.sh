#!/usr/bin/env bash
# make dev-sensors-smoke (D-146): bring up the compose dev stack (core + sensor replaying a pcap + scan with fake nmap and nuclei), finish the
# first-run setup through the API, and wait (bounded) until a device that only the sensor can have seen is in the inventory and the scan
# container reports healthy. Tears the stack down and removes its volumes whatever happens. Exit 0 only when the device appeared.
# Nothing is scanned and nothing leaves the machine: the replay reads a fixture, the fakes are scripts. Assumes Linux or macOS and
# docker compose (COMPOSE=... to change; podman compose works with the docker socket).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
compose=${COMPOSE:-docker compose}
port=${VEDETTE_DEV_PORT:-18443}
export VEDETTE_DEV_PORT=$port
base="https://127.0.0.1:$port/api/v1"
bound=${SMOKE_BOUND_SECONDS:-180}
file=deploy/compose/compose.yaml
# shellcheck disable=SC2086
dc() { $compose --env-file deploy/containers/pins.env -f "$file" --profile dev "$@"; }
jar=$(mktemp)
down() {
	trap '' EXIT INT TERM
	rm -f "$jar"
	dc down --rmi local --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap down EXIT INT TERM
dc down --volumes --remove-orphans >/dev/null 2>&1 || true # a stack left by an earlier run would keep an old database
dc up --build -d --wait --wait-timeout 300 core
code=
for _ in $(seq 1 30); do
	code=$(dc logs --no-log-prefix core 2>/dev/null | grep -o '"setup_code":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
	[ -n "$code" ] && break
	sleep 1
done
[ -n "$code" ] || { echo "smoke: core never printed its setup code"; dc logs core | tail -20; exit 1; }
curl_api() { curl -ksS -m 15 -c "$jar" -b "$jar" -H 'Content-Type: application/json' "$@"; }
pass='dev-only-Passw0rd-123'
curl_api -f -X POST "$base/core/setup" -d "{\"org\":\"Dev\",\"admin\":{\"name\":\"Dev Admin\",\"email\":\"dev@example.com\",\"password\":\"$pass\"},\"lan\":[\"192.168.10.0/24\"],\"commitment\":true,\"bundle\":\"custom\",\"modules\":[\"core\",\"feeds\",\"inventory\",\"sensor-passive\",\"sensor-active\"],\"setup_code\":\"$code\"}" >/dev/null
curl_api -f -X POST "$base/auth/login" -d "{\"email\":\"dev@example.com\",\"password\":\"$pass\"}" >/dev/null
dc up -d --wait --wait-timeout 120 sensor scan
deadline=$((SECONDS + bound))
while [ $SECONDS -lt "$deadline" ]; do
	# a device with a MAC that is not the box itself can only have come through the sensor link
	n=$(curl_api -f "$base/inventory/devices" | grep -o '"is_box":false' | wc -l || true)
	if [ "$n" -gt 0 ]; then
		echo "smoke: ok, $n device(s) seen by the sensor appeared in the inventory"
		exit 0
	fi
	sleep 3
done
echo "smoke: no device appeared within ${bound}s"
dc logs --no-log-prefix sensor core | tail -30
exit 1
