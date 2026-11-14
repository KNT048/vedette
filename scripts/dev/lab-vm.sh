#!/usr/bin/env bash
# Lab VMs for the LAB checks (D-315, docs/LAB-VM.md): Ubuntu 24.04 and Debian 13 cloud images under plain QEMU/KVM, no libvirt.
# One VM up at a time, 2 vCPU / 2.5 GiB, a qcow2 overlay on a verified base image, a cloud-init NoCloud seed (user `lab`, a dedicated
# SSH key, passwordless sudo). Network: passt (user mode, no host network change), SSH on 127.0.0.1:<port>; optional `lan` mode adds a
# second NIC on a macvtap over a WIRED host NIC, made by the root subcommand `lan-up` and never over Wi-Fi: passthru (the NIC is the
# VM's alone, the host must not use it) or, with --bridge, bridge mode (the host keeps its link, address and routes; the VM gets its
# own MAC on the wire; host<->VM traffic does not pass, a macvtap limit).
# Dev tooling, not product code. Host: Debian/Ubuntu (apt, dpkg), x86_64, Linux with /dev/kvm; other hosts are refused.
# Root only for `setup` (apt + kvm group) and `lan-up`/`lan-down` (one macvtap link); never iptables/nft, netplan or the host's
# addresses and routes. State under ~/.cache/vedette-lab/ (never /tmp); `destroy` removes only that VM's directory.
set -euo pipefail
umask 077

prog=lab-vm.sh
VMS="ubuntu2404 ubuntu2604 debian13"
MEM_MB=2560
CPUS=2
DISK_SIZE=20G
MEM_HEADROOM_MB=1536   # start refuses below MEM_MB + this of MemAvailable
MEM_MAX_PCT=90         # and when the box would pass this share of its memory with the VM up
LAN_LINK=vlab0         # the only link lan-up/lan-down ever create or delete
# Minimum versions (D-155 style floors): Ubuntu 24.04's packages, the oldest supported host; Debian 13 is above all of them.
# qemu >= 10.1 is needed for `-netdev passt` (QEMU starts passt itself over a socketpair).
FLOORS="qemu-system-x86=1:10.1.0 qemu-utils=1:8.2.2 cloud-image-utils=0.33 passt=0.0~git20240220"
# Packages setup installs when missing: the floors above, plus what this script calls (nc for QMP, ssh, curl, gpg).
PACKAGES="qemu-system-x86 qemu-utils cloud-image-utils passt netcat-openbsd openssh-client curl gpg gpgv"
# Ubuntu cloud images: SHA256SUMS.gpg is signed by "UEC Image Automatic Signing Key <cdimage@ubuntu.com>" (read from the signature's
# issuer subpacket, 2026-11-12). The key comes from /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg or keyserver.ubuntu.com; either
# way only a good signature by THIS primary key fingerprint is accepted.
UBUNTU_KEY_FPR=D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
# Timeouts (seconds).
T_QUICK=15 T_NET=60 T_IMAGE=3600 T_HASH=300 T_APT=1200 T_BOOT=300 T_CLOUDINIT=600 T_POWERDOWN=90
T_SSH=${LAB_SSH_TIMEOUT:-900}   # `ssh <cmd>` only; an interactive shell has keepalives instead

die() { echo "$prog: $*" >&2; exit 1; }
say() { echo "$prog: $*"; }

usage() {
	cat <<EOF
usage: $prog [--dry-run] <command>
  setup                 (root, once) install qemu, qemu-utils, cloud-image-utils, passt; add \$SUDO_USER to kvm
  fetch <vm>            download and verify the base image (no root)
  create <vm>           base image + overlay disk + cloud-init seed
  start <vm> [--lan]    boot (one lab VM at a time); --lan adds the NIC made by lan-up
  stop [vm]             ACPI power-down, kill after ${T_POWERDOWN}s
  destroy <vm>          stop, then remove only ~/.cache/vedette-lab/<vm>
  ssh [cmd...]          SSH to the running VM as lab (a command times out after ${T_SSH}s)
  status                VMs, ports, base images, lan link
  lan-up <nic> [--bridge]  (root) macvtap link $LAN_LINK over a WIRED NIC with carrier, tap handed to \$SUDO_USER: passthru
                        (a NIC the host does not use) or --bridge (the host keeps using the NIC; host<->VM traffic does not pass)
  lan-down              (root) delete $LAN_LINK
vm: ${VMS// / | }
--dry-run prints what would run and changes nothing.
EOF
	exit "${1:-2}"
}

DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi

# --- paths and checks --------------------------------------------------------------------------------------------------------

lab_dir() {
	[ -n "${HOME:-}" ] || die "HOME is not set"
	LAB=$HOME/.cache/vedette-lab
	# Paths go into QEMU option strings (commas split options) and into `sg -c` (a shell string): allow only plain characters.
	case $LAB in /*) ;; *) die "HOME must be an absolute path" ;; esac
	if printf '%s' "$LAB" | LC_ALL=C grep -q '[^A-Za-z0-9/._-]'; then die "unsupported character in $LAB (allowed: A-Z a-z 0-9 / . _ -)"; fi
	# A unix socket path is limited to 108 bytes; the longest one is <vm dir>/qmp.sock.
	[ "${#LAB}" -le 70 ] || die "$LAB is too long for the QEMU unix sockets"
}

check_vm() {
	case " $VMS " in *" ${1:-} "*) ;; *) echo "$prog: unknown vm '${1:-}' (one of: $VMS)" >&2; usage 2 ;; esac
}

vm_port() { case $1 in ubuntu2404) echo 22404 ;; ubuntu2604) echo 22604 ;; debian13) echo 22013 ;; esac; }
vm_nat_mac() { case $1 in ubuntu2404) echo 52:54:00:76:6c:01 ;; ubuntu2604) echo 52:54:00:76:6c:03 ;; debian13) echo 52:54:00:76:6c:02 ;; esac; }
vm_lan_mac() { case $1 in ubuntu2404) echo 52:54:00:76:6d:01 ;; ubuntu2604) echo 52:54:00:76:6d:03 ;; debian13) echo 52:54:00:76:6d:02 ;; esac; }

need() {
	local b
	for b in "$@"; do command -v "$b" >/dev/null 2>&1 || die "$b is missing: run  sudo $0 setup"; done
}

host_ok() {
	[ "$(uname -s)" = Linux ] || die "Linux only (QEMU/KVM host)"
	[ "$(uname -m)" = x86_64 ] || die "x86_64 hosts only (the images and qemu-system-x86 are amd64)"
}

# pid of the VM's QEMU when it runs (pidfile checked against the process's command line, so a reused pid is not ours)
vm_pid() {
	local d=$LAB/$1 p
	[ -f "$d/qemu.pid" ] || return 1
	p=$(tr -dc 0-9 <"$d/qemu.pid")
	[ -n "$p" ] && [ -r "/proc/$p/cmdline" ] || return 1
	tr '\0' '\n' <"/proc/$p/cmdline" | grep -qF "file=$d/disk.qcow2," || return 1
	echo "$p"
}

running_vm() {
	local vm
	for vm in $VMS; do
		if vm_pid "$vm" >/dev/null; then echo "$vm"; return 0; fi
	done
	return 1
}

ssh_cmd() {
	local vm=$1 d=$LAB/$1
	SSH=(ssh -F /dev/null -i "$LAB/id_ed25519" -p "$(vm_port "$vm")" -o IdentitiesOnly=yes -o IdentityAgent=none
		-o UserKnownHostsFile="$d/known_hosts" -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 -o BatchMode=yes
		-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o LogLevel=ERROR lab@127.0.0.1)
}

# --- root: setup -------------------------------------------------------------------------------------------------------------

root_user() {
	[ "$(id -u)" -eq 0 ] || die "$1 needs root: sudo $0 $1"
	local u=${SUDO_USER:-}
	if [ -z "$u" ] || [ "$u" = root ]; then die "$1: run it with sudo from your own account (SUDO_USER is the user who gets access)"; fi
	printf '%s' "$u" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "unexpected SUDO_USER '$u'"
	id "$u" >/dev/null 2>&1 || die "no such user $u"
	RUSER=$u
}

cmd_setup() {
	[ $# -eq 0 ] || usage 2
	host_ok
	if [ "$DRY" = 1 ]; then
		say "dry-run: would apt-get install the missing ones of: $PACKAGES; check floors: $FLOORS; add \$SUDO_USER to kvm"
		return 0
	fi
	root_user setup
	if ! command -v apt-get >/dev/null || ! command -v dpkg-query >/dev/null; then die "Debian/Ubuntu hosts only (apt, dpkg)"; fi
	local p missing="" changed="" f pkg floor v
	for p in $PACKAGES; do
		[ "$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true)" = "install ok installed" ] || missing="$missing $p"
	done
	if [ -n "$missing" ]; then
		say "installing:$missing"
		DEBIAN_FRONTEND=noninteractive timeout "$T_APT" apt-get -q update
		# shellcheck disable=SC2086 # word splitting of the package list is intended
		DEBIAN_FRONTEND=noninteractive timeout "$T_APT" apt-get -q -y install --no-install-recommends $missing
		changed="installed:$missing"
	fi
	for f in $FLOORS; do
		pkg=${f%%=*} floor=${f#*=}
		v=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null) || die "$pkg is not installed"
		dpkg --compare-versions "$v" ge "$floor" || die "$pkg $v is below the floor $floor"
		say "ok $pkg $v (floor $floor)"
	done
	# Effects, not exit codes: the binaries this script runs exist.
	for p in qemu-system-x86_64 qemu-img cloud-localds passt nc ssh ssh-keygen curl gpgv sg; do
		command -v "$p" >/dev/null || die "$p is still missing after the install"
	done
	getent group kvm >/dev/null || die "group kvm does not exist (it comes with udev/qemu)"
	[ -c /dev/kvm ] || die "/dev/kvm is missing: enable virtualization (VT-x/AMD-V) in the firmware"
	if id -nG "$RUSER" | tr ' ' '\n' | grep -qx kvm; then
		say "$RUSER is already in kvm"
	else
		timeout "$T_QUICK" usermod -aG kvm "$RUSER"
		id -nG "$RUSER" | tr ' ' '\n' | grep -qx kvm || die "usermod did not add $RUSER to kvm"
		changed="${changed:+$changed; }added $RUSER to group kvm"
	fi
	say "changed: ${changed:-nothing}"
	say "the network was not touched; $RUSER needs no re-login ($prog runs QEMU under 'sg kvm')"
}

# --- images ------------------------------------------------------------------------------------------------------------------

image_source() {
	case $1 in
	ubuntu2404)
		IMG_URL=https://cloud-images.ubuntu.com/noble/current IMG_FILE=noble-server-cloudimg-amd64.img
		IMG_SUMS=SHA256SUMS IMG_SIG=SHA256SUMS.gpg IMG_HASH=sha256sum IMG_HEXLEN=64 ;;
	ubuntu2604)
		IMG_URL=https://cloud-images.ubuntu.com/resolute/current IMG_FILE=resolute-server-cloudimg-amd64.img
		IMG_SUMS=SHA256SUMS IMG_SIG=SHA256SUMS.gpg IMG_HASH=sha256sum IMG_HEXLEN=64 ;;
	debian13)
		# Debian publishes no signature for cloud images (latest/ and the dated build directories hold only SHA512SUMS, read
		# 2026-11-12): the checksum file comes over HTTPS from cloud.debian.org, which is the trust anchor (D-315).
		IMG_URL=https://cloud.debian.org/images/cloud/trixie/latest IMG_FILE=debian-13-generic-amd64.qcow2
		IMG_SUMS=SHA512SUMS IMG_SIG="" IMG_HASH=sha512sum IMG_HEXLEN=128 ;;
	esac
}

get() { # get <url> <file> <max seconds>
	timeout "$(($3 + 10))" curl -fsSL --proto =https --proto-redir =https --tlsv1.2 --retry 3 --connect-timeout 20 \
		--max-time "$3" -o "$2" "$1" || die "download failed: $1"
}

verify_ubuntu_sig() { # verify_ubuntu_sig <dl dir>
	local dl=$1 kr=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg st
	mkdir -p "$dl/gnupg"
	if [ ! -f "$kr" ]; then
		get "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$UBUNTU_KEY_FPR" "$dl/key.asc" "$T_NET"
		GNUPGHOME=$dl/gnupg timeout "$T_QUICK" gpg --batch --quiet --dearmor -o "$dl/key.gpg" "$dl/key.asc" || die "cannot read the Ubuntu key"
		kr=$dl/key.gpg
	fi
	st=$(GNUPGHOME=$dl/gnupg timeout "$T_QUICK" gpgv --status-fd 1 --keyring "$kr" "$dl/$IMG_SIG" "$dl/$IMG_SUMS" 2>/dev/null) ||
		die "bad or missing signature on $IMG_URL/$IMG_SUMS"
	# VALIDSIG <signing key fpr> ... <primary key fpr>: accept only the pinned primary key.
	printf '%s\n' "$st" | awk -v f="$UBUNTU_KEY_FPR" '$2=="VALIDSIG" && ($3==f || $12==f) {ok=1} END {exit !ok}' ||
		die "$IMG_SUMS is not signed by the pinned Ubuntu key $UBUNTU_KEY_FPR"
	say "signature ok: $IMG_SUMS signed by $UBUNTU_KEY_FPR (keyring $kr)"
}

# fetch_image <vm>: sets BASE to a verified, read-only base image under ~/.cache/vedette-lab/images/. Bases are never overwritten
# (named by hash), so an overlay keeps its base when the vendor publishes a new image.
fetch_image() {
	local vm=$1 dir=$LAB/images dl want n got
	image_source "$vm"
	if [ "$DRY" = 1 ]; then
		say "dry-run: would download $IMG_URL/$IMG_SUMS${IMG_SIG:+ + $IMG_SIG} and $IMG_URL/$IMG_FILE, check ${IMG_HASH%sum}${IMG_SIG:+ and the signature}"
		BASE=$dir/$vm-DRYRUN.qcow2
		return 0
	fi
	need curl "$IMG_HASH" gpgv
	mkdir -p "$dir"
	dl=$dir/.dl-$vm
	rm -rf "$dl"
	mkdir "$dl"
	get "$IMG_URL/$IMG_SUMS" "$dl/$IMG_SUMS" "$T_NET"
	if [ -n "$IMG_SIG" ]; then
		get "$IMG_URL/$IMG_SIG" "$dl/$IMG_SIG" "$T_NET"
		verify_ubuntu_sig "$dl"
	fi
	n=$(awk -v f="$IMG_FILE" '$2==f || $2=="*"f' "$dl/$IMG_SUMS" | wc -l)
	[ "$n" -eq 1 ] || die "$IMG_SUMS has $n lines for $IMG_FILE (want 1)"
	want=$(awk -v f="$IMG_FILE" '$2==f || $2=="*"f {print $1}' "$dl/$IMG_SUMS")
	printf '%s' "$want" | grep -Eq "^[0-9a-f]{$IMG_HEXLEN}\$" || die "bad checksum line for $IMG_FILE"
	BASE=$dir/$vm-${want:0:16}.qcow2
	if [ -f "$BASE" ] && [ "$(cut -d' ' -f1 "$BASE.$IMG_HASH" 2>/dev/null)" = "$want" ]; then
		say "have $BASE (verified at download)"
	else
		say "downloading $IMG_URL/$IMG_FILE"
		get "$IMG_URL/$IMG_FILE" "$dl/image" "$T_IMAGE"
		got=$(timeout "$T_HASH" "$IMG_HASH" "$dl/image" | cut -d' ' -f1)
		[ "$got" = "$want" ] || die "checksum mismatch for $IMG_FILE: got $got, want $want"
		chmod 0444 "$dl/image"
		mv -f "$dl/image" "$BASE"
		echo "$want  $IMG_URL/$IMG_FILE" >"$BASE.$IMG_HASH"
		say "checksum ok (${IMG_HASH%sum}): $BASE"
	fi
	rm -rf "$dl"
}

cmd_fetch() {
	[ $# -eq 1 ] || usage 2
	check_vm "$1"
	lab_dir
	fetch_image "$1"
}

# --- create ------------------------------------------------------------------------------------------------------------------

write_seed_files() { # write_seed_files <vm> <dir>
	local vm=$1 t=$2 host=vedette-lab-$1
	{
		echo "#cloud-config"
		echo "hostname: $host"
		echo "manage_etc_hosts: true"
		echo "users:"
		echo "  - name: lab"
		echo "    gecos: Vedette lab"
		echo "    shell: /bin/bash"
		echo "    lock_passwd: true"
		echo "    sudo: \"ALL=(ALL) NOPASSWD:ALL\""
		echo "    ssh_authorized_keys:"
		echo "      - $(cat "$LAB/id_ed25519.pub")"
		echo "disable_root: true"
		echo "ssh_pwauth: false"
		echo "ssh_keys:"
		echo "  ed25519_private: |"
		sed 's/^/    /' "$t/host_ed25519"
		echo "  ed25519_public: $(cut -d' ' -f1,2 "$t/host_ed25519.pub")"
	} >"$t/user-data"
	printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$host" "$(date +%s)" "$host" >"$t/meta-data"
	# Both NICs by MAC: the passt NIC always, the lan NIC only when `start --lan` attaches it (optional, lower priority route).
	cat >"$t/network-config" <<EOF
version: 2
ethernets:
  nat:
    match:
      macaddress: "$(vm_nat_mac "$vm")"
    dhcp4: true
  lan:
    match:
      macaddress: "$(vm_lan_mac "$vm")"
    dhcp4: true
    optional: true
    dhcp4-overrides:
      route-metric: 200
EOF
}

cmd_create() {
	[ $# -eq 1 ] || usage 2
	check_vm "$1"
	host_ok
	lab_dir
	local vm=$1 d=$LAB/$1 t
	if [ -f "$d/disk.qcow2" ]; then say "$vm exists ($d); destroy it first to start over"; return 0; fi
	if [ "$DRY" = 1 ]; then
		fetch_image "$vm"
		say "dry-run: would write $d/{disk.qcow2 (qcow2 overlay, $DISK_SIZE, backing $BASE), seed.iso, known_hosts}"
		return 0
	fi
	need qemu-img cloud-localds ssh-keygen
	mkdir -p "$LAB"
	chmod 0700 "$LAB"
	fetch_image "$vm"
	if [ ! -f "$LAB/id_ed25519" ]; then
		timeout "$T_QUICK" ssh-keygen -q -t ed25519 -N '' -C vedette-lab -f "$LAB/id_ed25519"
		say "made the lab SSH key $LAB/id_ed25519 (used only for the lab VMs)"
	fi
	t=$LAB/.$vm.new
	rm -rf "$t"
	mkdir "$t"
	timeout "$T_QUICK" ssh-keygen -q -t ed25519 -N '' -C "vedette-lab-$vm" -f "$t/host_ed25519"
	write_seed_files "$vm" "$t"
	timeout "$T_QUICK" cloud-localds -N "$t/network-config" "$t/seed.iso" "$t/user-data" "$t/meta-data"
	timeout "$T_QUICK" qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$t/disk.qcow2" "$DISK_SIZE"
	# The host key is known before the first boot: StrictHostKeyChecking=yes from the first connection, no trust on first use.
	echo "[127.0.0.1]:$(vm_port "$vm") $(cut -d' ' -f1,2 "$t/host_ed25519.pub")" >"$t/known_hosts"
	rm -f "$t/host_ed25519" "$t/host_ed25519.pub" "$t/user-data" # the private host key stays only inside seed.iso
	echo "$BASE" >"$t/base"
	mv "$t" "$d"
	say "created $vm in $d (base $BASE); next: $0 start $vm"
}

# --- start / stop ------------------------------------------------------------------------------------------------------------

mem_guard() {
	local f=${LAB_MEMINFO:-/proc/meminfo} total avail need used_after # LAB_MEMINFO: lab-vm-test.sh only
	total=$(awk '$1=="MemTotal:" {print int($2/1024)}' "$f")
	avail=$(awk '$1=="MemAvailable:" {print int($2/1024)}' "$f")
	if [ -z "$total" ] || [ -z "$avail" ]; then die "cannot read MemTotal/MemAvailable from $f"; fi
	need=$((MEM_MB + MEM_HEADROOM_MB))
	[ "$avail" -ge "$need" ] || die "memory: MemAvailable ${avail} MiB < ${need} MiB (VM ${MEM_MB} + headroom ${MEM_HEADROOM_MB}); refused"
	used_after=$((total - avail + MEM_MB))
	[ $((used_after * 100)) -le $((total * MEM_MAX_PCT)) ] ||
		die "memory: with the VM up the box would use ${used_after} of ${total} MiB (> ${MEM_MAX_PCT}%); refused"
	say "memory ok: MemAvailable ${avail} MiB, ${used_after}/${total} MiB with the VM up"
}

# sh-safe single quoting for `sg kvm -c` (the arguments are our own validated paths and constants; refuse a quote anyway)
shq() {
	local a out=""
	for a in "$@"; do
		case $a in *"'"*) die "unexpected quote in argument: $a" ;; esac
		out="$out '$a'"
	done
	printf '%s' "${out# }"
}

kvm_launcher() { # sets LAUNCH: direct when /dev/kvm is usable, `sg kvm` when the user is in kvm but this login predates it
	[ -c /dev/kvm ] || die "/dev/kvm is missing (KVM not available on this host)"
	if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then LAUNCH=direct; return 0; fi
	if getent group kvm | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"; then LAUNCH=sg; return 0; fi
	die "$(id -un) cannot open /dev/kvm and is not in group kvm: run  sudo $0 setup"
}

lan_tap() { # sets TAP to the char device of the lan-up macvtap; checks it is ours to open
	local idx
	[ -d "/sys/class/net/$LAN_LINK" ] || die "--lan: no $LAN_LINK link; run  sudo $0 lan-up <wired nic>"
	idx=$(cat "/sys/class/net/$LAN_LINK/ifindex")
	TAP=/dev/tap$idx
	[ -c "$TAP" ] || die "--lan: $TAP is missing (is $LAN_LINK a macvtap?)"
	if [ ! -r "$TAP" ] || [ ! -w "$TAP" ]; then die "--lan: $TAP is not readable/writable by $(id -un); rerun  sudo $0 lan-up <nic>"; fi
}

cmd_start() {
	local vm="" lan=0 a
	for a in "$@"; do
		case $a in --lan) lan=1 ;; -*) usage 2 ;; *) [ -z "$vm" ] || usage 2; vm=$a ;; esac
	done
	check_vm "$vm"
	lab_dir
	local d=$LAB/$vm port other p
	port=$(vm_port "$vm")
	if [ ! -f "$d/disk.qcow2" ] || [ ! -f "$d/seed.iso" ]; then die "$vm is not created: $0 create $vm"; fi
	if p=$(vm_pid "$vm"); then say "$vm already runs (pid $p); ssh: $0 ssh"; return 0; fi
	if other=$(running_vm); then die "another lab VM runs: $other (one at a time; $0 stop)"; fi
	if p=$(pgrep -f '^qemu-system-x86_64 -name vedette-lab-' | tr '\n' ' '); [ -n "$p" ]; then
		die "a lab QEMU without a pidfile runs (pid $p); stop it first"
	fi
	mem_guard
	[ "$lan" = 0 ] || lan_tap
	if [ "$DRY" = 0 ] && [ -n "$(ss -Htln "sport = :$port" 2>/dev/null)" ]; then die "port 127.0.0.1:$port is in use"; fi

	# QEMU starts passt itself (`-netdev passt`) and hands it one end of a socketpair; passt exits when QEMU does. Not a passt of
	# our own on a unix socket: passt's AppArmor profile makes its accept() of QEMU's connection fail with EACCES (no audit line),
	# so the guest never gets a DHCP answer (measured 2026-11-12, Ubuntu 26.04, kernel 7.0, passt git20260120, QEMU 10.2.1).
	local qemu_argv=(qemu-system-x86_64 -name "vedette-lab-$vm"
		-machine "q35,accel=kvm" -cpu host -smp "$CPUS" -m "$MEM_MB" -nodefaults -display none
		-vga std # Debian 13's image resets right after GRUB when there is no display device (measured 2026-11-12); Ubuntu does not care
		-serial "file:$d/console.log"
		-drive "if=virtio,file=$d/disk.qcow2,format=qcow2,discard=unmap"
		-drive "if=virtio,file=$d/seed.iso,format=raw,readonly=on"
		-netdev "passt,id=n0,tcp-ports=127.0.0.1/$port:22"
		-device "virtio-net-pci,netdev=n0,mac=$(vm_nat_mac "$vm"),romfile="
		-device virtio-rng-pci
		-qmp "unix:$d/qmp.sock,server=on,wait=off"
		-pidfile "$d/qemu.pid" -daemonize)
	[ "$lan" = 0 ] || qemu_argv+=(-netdev "tap,id=n1,fd=3" -device "virtio-net-pci,netdev=n1,mac=$(vm_lan_mac "$vm"),romfile=")
	if [ "$DRY" = 1 ]; then
		echo "+ ${qemu_argv[*]}${TAP:+ 3<>$TAP}"
		return 0
	fi
	need qemu-system-x86_64 passt ss nc
	kvm_launcher
	rm -f "$d/qmp.sock" "$d/qemu.pid"
	[ "$lan" = 0 ] || exec 3<>"$TAP"
	if [ "$LAUNCH" = direct ]; then
		timeout "$T_NET" "${qemu_argv[@]}" || die "QEMU did not start (console: $d/console.log)"
	else
		timeout "$T_NET" sg kvm -c "exec $(shq "${qemu_argv[@]}")" || die "QEMU did not start under sg kvm"
	fi
	[ "$lan" = 0 ] || exec 3>&-
	p=$(vm_pid "$vm") || die "QEMU exited right away (console: $d/console.log)"
	say "$vm runs (pid $p, ${CPUS} vCPU, ${MEM_MB} MiB${TAP:+, lan via $LAN_LINK}); waiting for SSH on 127.0.0.1:$port"
	ssh_cmd "$vm"
	local end=$((SECONDS + T_BOOT))
	until timeout "$T_QUICK" "${SSH[@]}" true 2>/dev/null; do
		[ "$SECONDS" -lt "$end" ] || die "no SSH after ${T_BOOT}s (console: $d/console.log); the VM keeps running, $0 stop"
		vm_pid "$vm" >/dev/null || die "$vm stopped during boot (console: $d/console.log)"
		sleep 5
	done
	local rc=0
	timeout "$T_CLOUDINIT" "${SSH[@]}" sudo cloud-init status --wait >/dev/null || rc=$?
	case $rc in
	0) say "cloud-init done" ;;
	2) say "cloud-init finished with recoverable errors (see: $0 ssh sudo cloud-init status --long)" ;;
	*) die "cloud-init status --wait failed ($rc)" ;;
	esac
	say "ready: $0 ssh   (console log: $d/console.log)"
}

wait_gone() { # wait_gone <pid> <seconds>
	local end=$((SECONDS + $2))
	while [ -e "/proc/$1" ]; do
		[ "$SECONDS" -lt "$end" ] || return 1
		sleep 1
	done
}

cmd_stop() {
	[ $# -le 1 ] || usage 2
	lab_dir
	local vm=${1:-} p
	if [ -z "$vm" ]; then vm=$(running_vm) || { say "no lab VM runs"; return 0; }; fi
	check_vm "$vm"
	local d=$LAB/$vm
	if ! p=$(vm_pid "$vm"); then
		say "$vm is not running"
		[ "$DRY" = 1 ] || rm -f "$d/qmp.sock"
		return 0
	fi
	if [ "$DRY" = 1 ]; then say "dry-run: would send system_powerdown to $d/qmp.sock, kill pid $p after ${T_POWERDOWN}s"; return 0; fi
	need nc
	say "ACPI power-down of $vm (pid $p)"
	printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_powerdown"}' |
		timeout "$T_QUICK" nc -N -w 5 -U "$d/qmp.sock" >/dev/null 2>&1 || say "QMP did not answer"
	if ! wait_gone "$p" "$T_POWERDOWN"; then
		say "no power-off after ${T_POWERDOWN}s: SIGTERM"
		if vm_pid "$vm" >/dev/null; then kill -TERM "$p" 2>/dev/null || true; fi
		if ! wait_gone "$p" 10; then
			if vm_pid "$vm" >/dev/null; then kill -KILL "$p" 2>/dev/null || true; fi
			wait_gone "$p" 5 || die "pid $p does not exit"
		fi
	fi
	rm -f "$d/qmp.sock" "$d/qemu.pid"
	say "$vm stopped"
}

cmd_destroy() {
	[ $# -eq 1 ] || usage 2
	check_vm "$1"
	lab_dir
	local d=$LAB/$1
	[ -d "$d" ] || { say "$1 does not exist"; return 0; }
	if [ "$DRY" = 1 ]; then say "dry-run: would stop $1 and remove $d (base images stay)"; return 0; fi
	cmd_stop "$1"
	rm -rf "${LAB:?}/$1"
	say "removed $d (base images in $LAB/images stay)"
}

cmd_ssh() {
	lab_dir
	local vm
	vm=$(running_vm) || die "no lab VM runs ($0 start <vm>)"
	ssh_cmd "$vm"
	if [ $# -eq 0 ]; then exec "${SSH[@]}"; fi
	exec timeout --foreground "$T_SSH" "${SSH[@]}" "$@" # ssh stops option parsing at the destination
}

cmd_status() {
	[ $# -eq 0 ] || usage 2
	lab_dir
	local vm d p
	for vm in $VMS; do
		d=$LAB/$vm
		if [ ! -f "$d/disk.qcow2" ]; then printf '%-11s not created\n' "$vm"; continue; fi
		if p=$(vm_pid "$vm"); then
			printf '%-11s running pid %s, ssh 127.0.0.1:%s, base %s\n' "$vm" "$p" "$(vm_port "$vm")" "$(cat "$d/base")"
		else
			printf '%-11s stopped, base %s\n' "$vm" "$(cat "$d/base")"
		fi
	done
	if [ -d "/sys/class/net/$LAN_LINK" ]; then
		printf 'lan: %s on %s, /dev/tap%s\n' "$LAN_LINK" "$(basename "$(readlink -f "/sys/class/net/$LAN_LINK/lower_"* 2>/dev/null || echo '?')")" \
			"$(cat "/sys/class/net/$LAN_LINK/ifindex")"
	else
		echo "lan: no $LAN_LINK (passt only)"
	fi
	awk '$1=="MemAvailable:" {printf "memory: MemAvailable %d MiB\n", $2/1024}' /proc/meminfo
}

# --- root: lan mode ----------------------------------------------------------------------------------------------------------

cmd_lan_up() {
	local nic="" mode=passthru sys=/sys/class/net a
	for a in "$@"; do
		case $a in --bridge) mode=bridge ;; -*) usage 2 ;; *) [ -z "$nic" ] || usage 2; nic=$a ;; esac
	done
	[ -n "$nic" ] || usage 2
	printf '%s' "$nic" | grep -Eq '^[A-Za-z0-9_.-]{1,15}$' || die "bad interface name '$nic'"
	[ "$nic" != "$LAN_LINK" ] || die "$nic is the lab link itself"
	# A test points this at a fake sysfs; root always reads the real one.
	[ "$(id -u)" -eq 0 ] || sys=${LAB_SYSFS:-$sys}
	[ -d "$sys/$nic" ] || die "no interface $nic"
	if [ -e "$sys/$nic/wireless" ] || [ -e "$sys/$nic/phy80211" ] || [ -L "$sys/$nic/phy80211" ]; then
		die "$nic is wireless: refused. An 802.11 station may only send frames with its own associated MAC; the AP drops frames from the VM's MAC (and the decoys' MACs), so macvtap over Wi-Fi cannot work (D-315). Use a wired NIC."
	fi
	[ -e "$sys/$nic/device" ] || die "$nic is not a physical NIC (no device link): refused"
	[ "$(cat "$sys/$nic/carrier" 2>/dev/null || echo 0)" = 1 ] || die "$nic has no carrier (cable unplugged or link down): refused"
	if [ "$DRY" = 1 ]; then
		say "dry-run: would run  ip link add link $nic name $LAN_LINK type macvtap mode $mode; ip link set $LAN_LINK up; chown \$SUDO_USER /dev/tap<ifindex>"
		return 0
	fi
	root_user lan-up
	command -v ip >/dev/null || die "ip (iproute2) is missing"
	if [ -d "/sys/class/net/$LAN_LINK" ]; then
		ip -d -o link show "$LAN_LINK" | grep -q " macvtap mode $mode " || die "$LAN_LINK exists and is not our macvtap in $mode mode: refused (lan-down first)"
		[ "$(basename "$(readlink -f /sys/class/net/$LAN_LINK/lower_* 2>/dev/null)")" = "$nic" ] || die "$LAN_LINK exists on another NIC; lan-down first"
	else
		if [ "$mode" = passthru ]; then
			# Passthru hands every frame of the NIC to the VM: the host must not be using it (--bridge is for a NIC the host uses).
			[ -z "$(timeout "$T_QUICK" ip -o route show default dev "$nic")$(timeout "$T_QUICK" ip -6 -o route show default dev "$nic")" ] ||
				die "$nic carries a default route of this host: refused (passthru needs a NIC the host does not use; --bridge keeps the host's use)"
			[ -z "$(timeout "$T_QUICK" ip -o addr show dev "$nic" scope global)" ] ||
				die "$nic has a global address on this host: refused (passthru would cut the host's traffic on it; --bridge keeps the host's use)"
		fi
		# bridge: a second MAC on the NIC; the host's own link, addresses and routes are not touched (no address, no route is added)
		timeout "$T_QUICK" ip link add link "$nic" name "$LAN_LINK" type macvtap mode "$mode"
		timeout "$T_QUICK" ip link set "$LAN_LINK" up
	fi
	local idx tap
	idx=$(cat "/sys/class/net/$LAN_LINK/ifindex")
	tap=/dev/tap$idx
	for _ in 1 2 3 4 5 6 7 8 9 10; do [ -c "$tap" ] && break; sleep 0.5; done
	[ -c "$tap" ] || die "$tap did not appear"
	chown "$RUSER:" "$tap"
	chmod 0600 "$tap"
	say "lan: $LAN_LINK (macvtap $mode on $nic), $tap owned by $RUSER; start a VM with --lan"
}

cmd_lan_down() {
	[ $# -eq 0 ] || usage 2
	if [ ! -d "/sys/class/net/$LAN_LINK" ]; then say "no $LAN_LINK"; return 0; fi
	if [ "$DRY" = 1 ]; then say "dry-run: would run  ip link del $LAN_LINK"; return 0; fi
	root_user lan-down
	ip -d -o link show "$LAN_LINK" | grep -q ' macvtap ' || die "$LAN_LINK is not a macvtap: refused"
	local tap f
	tap=/dev/tap$(cat "/sys/class/net/$LAN_LINK/ifindex")
	for f in /proc/[0-9]*/fd/*; do
		[ "$(readlink "$f" 2>/dev/null)" = "$tap" ] && die "$tap is open by pid $(echo "$f" | cut -d/ -f3): stop the VM first"
	done
	timeout "$T_QUICK" ip link del "$LAN_LINK"
	[ ! -d "/sys/class/net/$LAN_LINK" ] || die "$LAN_LINK is still there"
	say "deleted $LAN_LINK"
}

# --- main --------------------------------------------------------------------------------------------------------------------

cmd=${1:-}
[ -n "$cmd" ] || usage 2
shift
case $cmd in
setup) cmd_setup "$@" ;;
fetch) cmd_fetch "$@" ;;
create) cmd_create "$@" ;;
start) cmd_start "$@" ;;
stop) cmd_stop "$@" ;;
destroy) cmd_destroy "$@" ;;
ssh) cmd_ssh "$@" ;;
status) cmd_status "$@" ;;
lan-up) cmd_lan_up "$@" ;;
lan-down) cmd_lan_down "$@" ;;
-h | --help | help) usage 0 ;;
*) echo "$prog: unknown command '$cmd'" >&2; usage 2 ;;
esac
