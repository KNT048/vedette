#!/usr/bin/env bash
# Test of lab-vm.sh (D-315) without QEMU, root or network: shellcheck, argument parsing, the one-VM rule, the memory guard and the
# lan-up refusals (fake sysfs), all with --dry-run or before any change. HOME points at a private temp dir, so nothing touches
# ~/.cache/vedette-lab. Linux only (lab-vm.sh reads /proc). Run by `make check` when scripts/dev/lab-vm* changes and by
# `make verify-go-static` (CI), where shellcheck is required.
set -u
umask 022
here=$(cd "$(dirname "$0")" && pwd)
s=$here/lab-vm.sh
if [ "$(uname -s)" != Linux ]; then echo "lab-vm-test: skipped (Linux only)"; exit 0; fi
tmp=$(mktemp -d)
sleeper=""
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap (SC2317 on shellcheck < 0.10, SC2329 after)
cleanup() {
	[ -z "$sleeper" ] || kill -KILL "$sleeper" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
# expect <name> <exit code> <grep -E pattern or ''> -- <lab-vm.sh args...>
expect() {
	local name=$1 code=$2 pat=$3 out rc
	shift 4
	out=$(HOME=$tmp/home LAB_MEMINFO=$tmp/meminfo LAB_SYSFS=$tmp/sys "$s" "$@" 2>&1)
	rc=$?
	if [ "$rc" != "$code" ]; then bad "$name: exit $rc, want $code: $out"; return; fi
	if [ -n "$pat" ] && ! printf '%s\n' "$out" | grep -Eq -- "$pat"; then bad "$name: output lacks /$pat/: $out"; return; fi
	ok "$name"
}
meminfo() { printf 'MemTotal: %s kB\nMemAvailable: %s kB\n' "$(($1 * 1024))" "$(($2 * 1024))" >"$tmp/meminfo"; }

if command -v shellcheck >/dev/null; then
	if shellcheck "$s" "$0"; then ok "shellcheck"; else bad "shellcheck"; fi
elif [ -n "${CI:-}" ]; then
	bad "shellcheck is required on CI"
else
	echo "skip shellcheck (not installed)"
fi

mkdir -p "$tmp/home"
meminfo 11000 9000
expect "no command" 2 'usage' --
expect "help" 0 'lan-up <nic>' -- help
expect "unknown command" 2 "unknown command 'boot'" -- boot
expect "unknown vm" 2 "unknown vm 'centos'" -- create centos
expect "create needs one vm" 2 'usage' -- create
expect "start needs a vm" 2 "unknown vm ''" -- start
expect "start rejects a flag" 2 'usage' -- start ubuntu2404 --wifi
expect "start of a vm never created" 1 'is not created' -- --dry-run start debian13
expect "ssh with no VM up" 1 'no lab VM runs' -- ssh true
expect "stop with no VM up" 0 'no lab VM runs' -- stop
expect "status" 0 'ubuntu2404 +not created' -- status
expect "fetch dry-run (ubuntu: signature)" 0 'SHA256SUMS \+ SHA256SUMS.gpg' -- --dry-run fetch ubuntu2404
expect "fetch dry-run (debian: sha512)" 0 'debian-13-generic-amd64.qcow2, check sha512' -- --dry-run fetch debian13
expect "setup dry-run changes nothing" 0 'would apt-get install' -- --dry-run setup
expect "setup refuses a normal user" 1 'needs root' -- setup
expect "destroy of a missing vm" 0 'does not exist' -- destroy debian13

# a created VM (files only)
for vm in ubuntu2404 debian13; do
	d=$tmp/home/.cache/vedette-lab/$vm
	mkdir -p "$d"
	: >"$d/disk.qcow2"
	: >"$d/seed.iso"
	echo /base.qcow2 >"$d/base"
done
expect "start dry-run: passt on loopback only" 0 '-netdev passt,id=n0,tcp-ports=127\.0\.0\.1/22404:22 ' -- --dry-run start ubuntu2404
expect "start dry-run: 2 vCPU, 2560 MiB, KVM" 0 'qemu-system-x86_64 -name vedette-lab-ubuntu2404 -machine q35,accel=kvm -cpu host -smp 2 -m 2560' -- --dry-run start ubuntu2404
expect "start dry-run: overlay + seed + qmp" 0 "file=$tmp/home/.cache/vedette-lab/debian13/disk.qcow2,format=qcow2.*seed.iso,format=raw,readonly=on.*-qmp unix:.*/debian13/qmp.sock" -- --dry-run start debian13
out=$(HOME=$tmp/home LAB_MEMINFO=$tmp/meminfo "$s" --dry-run start ubuntu2404 2>&1)
if printf '%s' "$out" | grep -q 'tap'; then bad "start without --lan has no tap: $out"; else ok "start without --lan has no tap"; fi
expect "start --lan without lan-up" 1 'no vlab0 link' -- --dry-run start ubuntu2404 --lan
meminfo 11000 3800
expect "memory guard: MemAvailable below 2.5 + 1.5 GiB" 1 'memory: MemAvailable 3800 MiB < 4096 MiB' -- --dry-run start ubuntu2404
meminfo 20000 4200
expect "memory guard: box over 90% with the VM" 1 'would use 18360 of 20000 MiB' -- --dry-run start ubuntu2404
meminfo 11000 9000

# one VM at a time: a process whose command line names ubuntu2404's disk stands in for its QEMU
bash -c 'exec -a "$0" sleep 300' "file=$tmp/home/.cache/vedette-lab/ubuntu2404/disk.qcow2," </dev/null >/dev/null 2>&1 &
sleeper=$!
echo "$sleeper" >"$tmp/home/.cache/vedette-lab/ubuntu2404/qemu.pid"
sleep 0.2
expect "status shows the running VM" 0 "ubuntu2404 +running pid $sleeper, ssh 127.0.0.1:22404" -- status
expect "start of the running VM is a no-op" 0 'already runs' -- --dry-run start ubuntu2404
expect "second VM refused" 1 'another lab VM runs: ubuntu2404' -- --dry-run start debian13
expect "stop dry-run" 0 "would send system_powerdown .* kill pid $sleeper" -- --dry-run stop
expect "destroy dry-run" 0 'would stop ubuntu2404 and remove' -- --dry-run destroy ubuntu2404
kill -KILL "$sleeper" 2>/dev/null
wait "$sleeper" 2>/dev/null
sleeper=""
# a stale pidfile (process gone, or a reused pid that is not ours) is not a running VM
echo "$$" >"$tmp/home/.cache/vedette-lab/ubuntu2404/qemu.pid"
expect "a reused pid is not the VM" 0 'ubuntu2404 +stopped' -- status

# lan-up refusals on a fake sysfs (as a normal user; root always reads /sys)
nic() { # nic <name> <carrier|-> <kind: wired|wifi|phy|virtual>
	mkdir -p "$tmp/sys/$1"
	[ "$2" = - ] || echo "$2" >"$tmp/sys/$1/carrier"
	case $3 in
	wired) mkdir -p "$tmp/sys/$1/device" ;;
	wifi) mkdir -p "$tmp/sys/$1/device" "$tmp/sys/$1/wireless" ;;
	phy) mkdir -p "$tmp/sys/$1/device"; ln -s ../../phy0 "$tmp/sys/$1/phy80211" ;;
	esac
}
nic eth9 1 wired
nic wlp3s0 1 wifi
nic wlan7 1 phy
nic enp2s0 0 wired
nic enp4s0 - wired
nic br0 1 virtual
expect "lan-up: bad name" 1 'bad interface name' -- lan-up 'eth0;id'
expect "lan-up: missing NIC" 1 'no interface eth5' -- lan-up eth5
expect "lan-up: Wi-Fi refused (wireless/)" 1 'wlp3s0 is wireless: refused' -- lan-up wlp3s0
expect "lan-up: Wi-Fi refused (phy80211)" 1 'wlan7 is wireless: refused' -- --dry-run lan-up wlan7
expect "lan-up: no carrier refused" 1 'enp2s0 has no carrier' -- --dry-run lan-up enp2s0
expect "lan-up: link down refused" 1 'enp4s0 has no carrier' -- --dry-run lan-up enp4s0
expect "lan-up: virtual NIC refused" 1 'br0 is not a physical NIC' -- --dry-run lan-up br0
expect "lan-up: wired NIC needs root" 1 'lan-up needs root' -- lan-up eth9
expect "lan-up dry-run: macvtap passthru" 0 'ip link add link eth9 name vlab0 type macvtap mode passthru' -- --dry-run lan-up eth9
expect "lan-up dry-run: macvtap bridge" 0 'ip link add link eth9 name vlab0 type macvtap mode bridge' -- --dry-run lan-up eth9 --bridge
expect "lan-up --bridge: Wi-Fi still refused" 1 'wlp3s0 is wireless: refused' -- --dry-run lan-up wlp3s0 --bridge
expect "lan-up --bridge: no carrier refused" 1 'enp2s0 has no carrier' -- --dry-run lan-up enp2s0 --bridge
expect "lan-up: unknown flag" 2 'usage' -- --dry-run lan-up eth9 --tap
expect "lan-up: the lab link itself" 1 'is the lab link itself' -- lan-up vlab0

if [ "$fail" = 0 ]; then echo "lab-vm-test: PASS"; else echo "lab-vm-test: FAIL"; fi
exit "$fail"
