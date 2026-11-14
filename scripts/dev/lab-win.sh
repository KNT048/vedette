#!/usr/bin/env bash
# A Windows Server 2025 lab VM (WIN-LAB, docs/LAB-VM.md "Windows"): Microsoft's 180-day Evaluation ISO, installed unattended under
# plain QEMU/KVM like scripts/dev/lab-vm.sh (no libvirt), so osquery on Windows can be enrolled into a test box and walked (TUNE-5/5b,
# agent-intake INV-2: Windows Server x64). Only inbox drivers: SATA (AHCI) disk and CD-ROMs, e1000e NIC; network passt (user mode, no
# host network change), SSH (Windows' own OpenSSH Server, turned on by the first-logon script) on 127.0.0.1:22050 with the lab key.
# Dev tooling, not product code. Host: Linux with /dev/kvm, qemu >= 10.1 (-netdev passt), genisoimage. State under
# ~/.cache/vedette-lab/winlab (never /tmp). The evaluation must be activated over the Internet within 10 days (the VM reaches it
# through passt); it runs 180 days, then `destroy` + `create` makes a new one.
set -euo pipefail
umask 077

prog=lab-win.sh
MEM_MB=${LAB_MEM_MB:-4096}
CPUS=${LAB_CPUS:-2}
DISK_SIZE=60G
MEM_HEADROOM_MB=1536
PORT=22050
# Microsoft Evaluation Center, Windows Server 2025 (64-bit ISO, en-us), resolved from
# https://go.microsoft.com/fwlink/?linkid=2293312&clcid=0x409&culture=en-us&country=us on 2026-11-14.
ISO_URL=https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso
# Microsoft publishes no hash for the Evaluation ISO: this is the sha256 measured on the HTTPS download from its CDN (2026-11-14,
# 6014152704 bytes); Setup then checks the signatures of what it installs.
ISO_SHA256=d0ef4502e350e3c6c53c15b1b3020d38a5ded011bf04998e950720ac8579b23d
# Index 2 of install.wim = "Windows Server 2025 Standard Evaluation (Desktop Experience)" (1 Standard core, 3/4 Datacenter).
IMAGE_INDEX=2
T_QUICK=15 T_BOOT=${LAB_WIN_BOOT:-5400} T_POWERDOWN=180

say() { echo "$prog: $*"; }
die() { echo "$prog: $*" >&2; exit 1; }
usage() {
	cat <<EOF
usage: $prog <command>
  fetch     download and verify the Evaluation ISO (6 GB, sha256 pinned)
  create    disk (qcow2 $DISK_SIZE) + answer ISO (Autounattend.xml, first-logon script, lab SSH key, random Administrator password)
  start [--lan]  boot; the first start installs Windows unattended (20-40 min) and waits for SSH; --lan adds a NIC of its own on
            the LAN (vlabw0, see start)
  stop      ACPI power-down, kill after ${T_POWERDOWN}s
  destroy   stop, then remove the VM (the ISO stays)
  ssh [cmd] SSH to the VM as Administrator (cmd.exe; use: powershell -NoProfile -Command "...")
  status
EOF
	exit "${1:-2}"
}

[ -n "${HOME:-}" ] || die "HOME is not set"
LAB=$HOME/.cache/vedette-lab
D=$LAB/winlab
ISO=$LAB/images/ws2025-eval-26100.1742.iso
case $D in /*) ;; *) die "HOME must be an absolute path" ;; esac
if printf '%s' "$D" | LC_ALL=C grep -q '[^A-Za-z0-9/._-]'; then die "unsupported character in $D"; fi

need() { local b; for b in "$@"; do command -v "$b" >/dev/null 2>&1 || die "$b is missing"; done; }
pid() { local p; p=$(cat "$D/qemu.pid" 2>/dev/null) || return 1; kill -0 "$p" 2>/dev/null && grep -q vedette-winlab "/proc/$p/cmdline" 2>/dev/null && echo "$p"; }
ssh_argv() {
	SSH=(ssh -F /dev/null -i "$LAB/id_ed25519" -p "$PORT" -o IdentitiesOnly=yes -o IdentityAgent=none -o UserKnownHostsFile="$D/known_hosts"
		-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR Administrator@127.0.0.1)
}

cmd_fetch() {
	need curl sha256sum
	[ "$ISO_SHA256" != "@ISO_SHA256@" ] || die "ISO_SHA256 is not pinned in $0"
	mkdir -p "$LAB/images"
	if [ ! -f "$ISO" ]; then
		say "downloading the Evaluation ISO (6 GB) to $ISO"
		timeout 3600 curl -fL --retry 3 -o "$ISO.part" "$ISO_URL"
		mv "$ISO.part" "$ISO"
	fi
	echo "$ISO_SHA256  $ISO" | sha256sum -c --quiet - || { mv "$ISO" "$ISO.bad"; die "sha256 mismatch: moved to $ISO.bad"; }
	say "have $ISO (sha256 ok)"
}

# answer_iso writes $D/answer.iso: Autounattend.xml (found by Windows Setup on any removable drive) and setup.ps1 (run at the first
# logon: OpenSSH Server on with the lab key, firewall rule, no Server Manager at logon). The password is the VM's own, random.
answer_iso() {
	local t pw key
	t=$(mktemp -d "$D/answer.XXXX")
	pw=$(cat "$D/admin-password")
	key=$(cat "$LAB/id_ed25519.pub")
	cat >"$t/Autounattend.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>500</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System</Label><Active>true</Active></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage>
        <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>$IMAGE_INDEX</Value></MetaData></InstallFrom>
        <InstallTo><DiskID>0</DiskID><PartitionID>2</PartitionID></InstallTo>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>WINLAB01</ComputerName><TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts><AdministratorPassword><Value>$pw</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>Administrator</Username><Password><Value>$pw</Value><PlainText>true</PlainText></Password></AutoLogon>
      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><ProtectYourPC>3</ProtectYourPC></OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order>
          <CommandLine>cmd /c for %d in (D E F G H) do @if exist %d:\setup.ps1 powershell -NoProfile -ExecutionPolicy Bypass -File %d:\setup.ps1</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
EOF
	cat >"$t/setup.ps1" <<EOF
\$ErrorActionPreference = 'Stop'
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }
Set-Service sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name vedette-lab-ssh -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name vedette-lab-ssh -DisplayName 'SSH (vedette lab)' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
}
\$k = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -Path \$k -Value '$key' -Encoding ascii
icacls \$k /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
# --lan: the LAN NIC (MAC ...6e:02) carries the default route; the passt NIC (...6e:01) only SSH from the host
Get-NetAdapter | ? MacAddress -eq '52-54-00-76-6E-02' | Set-NetIPInterface -InterfaceMetric 10 -ErrorAction SilentlyContinue
Get-NetAdapter | ? MacAddress -eq '52-54-00-76-6E-01' | Set-NetIPInterface -InterfaceMetric 500 -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Set-Content -Path C:\vedette-lab-ready.txt -Value (Get-Date -Format o)
EOF
	genisoimage -quiet -J -r -V VEDETTE_ANSWER -o "$D/answer.iso" "$t/Autounattend.xml" "$t/setup.ps1"
	rm -rf "$t"
}

cmd_create() {
	need qemu-img genisoimage openssl
	[ -f "$ISO" ] || die "no ISO: $0 fetch"
	[ ! -e "$D/disk.qcow2" ] || die "$D exists: $0 destroy first"
	[ -f "$LAB/id_ed25519.pub" ] || die "no lab key $LAB/id_ed25519.pub (scripts/dev/lab-vm.sh create makes it)"
	mkdir -p "$D"
	# 20 characters of A-Za-z0-9 plus a fixed tail for Windows' complexity rule; kept 0600 for the console (VNC on 127.0.0.1:5950)
	printf '%sAa1!' "$(openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | head -c 20)" >"$D/admin-password"
	answer_iso
	qemu-img create -q -f qcow2 "$D/disk.qcow2" "$DISK_SIZE"
	say "created $D; next: $0 start (the first start installs Windows, 20-40 min)"
}

cmd_start() {
	local lan=0 tap=""
	[ "${1:-}" != --lan ] || lan=1
	need qemu-system-x86_64 passt ss
	[ -f "$D/disk.qcow2" ] || die "not created: $0 create"
	local p avail
	if p=$(pid); then say "runs (pid $p)"; return 0; fi
	[ -z "$(ss -Htln "sport = :$PORT" 2>/dev/null)" ] || die "127.0.0.1:$PORT is in use"
	avail=$(awk '$1=="MemAvailable:" {print int($2/1024)}' /proc/meminfo)
	[ "$avail" -ge $((MEM_MB + MEM_HEADROOM_MB)) ] || die "memory: MemAvailable $avail MiB < $((MEM_MB + MEM_HEADROOM_MB)) MiB; refused"
	# shellcheck disable=SC2054 # QEMU option strings hold commas
	local argv=(qemu-system-x86_64 -name vedette-winlab -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM_MB" -nodefaults
		-vga std -display none -vnc 127.0.0.1:50 -device ahci,id=ahci
		-drive "id=d0,if=none,file=$D/disk.qcow2,format=qcow2,discard=unmap" -device ide-hd,drive=d0,bus=ahci.0
		-netdev "passt,id=n0,tcp-ports=127.0.0.1/$PORT:22$([ "$lan" = 0 ] || echo ,param=--address=10.0.2.15,param=--netmask=24,param=--gateway=10.0.2.2)"
		-device "e1000e,netdev=n0,mac=52:54:00:76:6e:01"
		-qmp "unix:$D/qmp.sock,server=on,wait=off" -pidfile "$D/qemu.pid" -daemonize)
	if [ ! -f "$D/installed" ]; then # the first boot: Setup from the ISO, answers from the second CD-ROM
		# shellcheck disable=SC2054
		argv+=(-drive "id=cd0,if=none,media=cdrom,readonly=on,file=$ISO" -device ide-cd,drive=cd0,bus=ahci.1
			-drive "id=cd1,if=none,media=cdrom,readonly=on,file=$D/answer.iso" -device ide-cd,drive=cd1,bus=ahci.2 -boot order=cd)
	fi
	if [ "$lan" = 1 ]; then
		# --lan: a NIC of its own on the LAN through the bridge-mode macvtap vlabw0 that
		#   sudo LAB_LAN_LINK=vlabw0 scripts/dev/lab-vm.sh lan-up <wired nic> --bridge winlab
		# made with this MAC (a bridge macvtap only receives frames for its own MAC). passt then has 10.0.2.15/24 and only carries SSH
		# from the host: the box must see the VM's own LAN address, because agent-intake binds an agent by its source IP (INV-12) and
		# behind passt that is the host's.
		[ -d /sys/class/net/vlabw0 ] || die "--lan: no vlabw0; run  sudo LAB_LAN_LINK=vlabw0 scripts/dev/lab-vm.sh lan-up <wired nic> --bridge winlab"
		[ "$(cat /sys/class/net/vlabw0/address)" = 52:54:00:76:6e:02 ] || die "--lan: vlabw0 does not carry winlab's MAC"
		tap=/dev/tap$(cat /sys/class/net/vlabw0/ifindex)
		[ -r "$tap" ] && [ -w "$tap" ] || die "--lan: $tap is not readable/writable by $(id -un)"
		# shellcheck disable=SC2054
		argv+=(-netdev tap,id=n1,fd=3 -device e1000e,netdev=n1,mac=52:54:00:76:6e:02)
	fi
	rm -f "$D/qmp.sock" "$D/qemu.pid"
	[ -z "$tap" ] || exec 3<>"$tap"
	if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then timeout 60 "${argv[@]}"; else timeout 60 sg kvm -c "$(printf '%q ' "${argv[@]}")"; fi
	[ -z "$tap" ] || exec 3>&-
	p=$(pid) || die "QEMU exited right away"
	say "runs (pid $p, $CPUS vCPU, $MEM_MB MiB, console VNC 127.0.0.1:5950); waiting for SSH on 127.0.0.1:$PORT (install: up to $((T_BOOT / 60)) min)"
	ssh_argv
	local end=$((SECONDS + T_BOOT))
	until timeout "$T_QUICK" "${SSH[@]}" 'type C:\vedette-lab-ready.txt' >/dev/null 2>&1; do
		[ "$SECONDS" -lt "$end" ] || die "no SSH after ${T_BOOT}s (VNC 127.0.0.1:5950 shows the screen); the VM keeps running"
		pid >/dev/null || die "the VM stopped"
		sleep 20
	done
	if [ ! -f "$D/installed" ]; then
		date -u +%FT%TZ >"$D/installed"
		rm -f "$D/answer.iso" # it holds the Administrator password in clear; the ISOs are detached from the next start on
	fi
	say "ready: $0 ssh"
}

cmd_stop() {
	local p
	p=$(pid) || { say "not running"; return 0; }
	printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"system_powerdown"}' | timeout "$T_QUICK" nc -N -w 5 -U "$D/qmp.sock" >/dev/null 2>&1 || true
	for _ in $(seq 1 "$T_POWERDOWN"); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
	if kill -0 "$p" 2>/dev/null; then kill -TERM "$p"; sleep 5; kill -KILL "$p" 2>/dev/null || true; fi
	rm -f "$D/qmp.sock" "$D/qemu.pid"
	say "stopped"
}

cmd=${1:-}
[ $# -eq 0 ] || shift
case $cmd in
fetch) cmd_fetch ;;
create) cmd_create ;;
start) cmd_start "$@" ;;
stop) cmd_stop ;;
destroy) cmd_stop; rm -rf "$D"; say "removed $D (the ISO stays in $LAB/images)" ;;
ssh) ssh_argv; if [ $# -eq 0 ]; then exec "${SSH[@]}"; else exec timeout 900 "${SSH[@]}" "$@"; fi ;;
status) if p=$(pid); then say "runs (pid $p), installed $(cat "$D/installed" 2>/dev/null || echo no)"; else say "stopped"; fi ;;
-h | --help | help) usage 0 ;;
*) usage 2 ;;
esac
