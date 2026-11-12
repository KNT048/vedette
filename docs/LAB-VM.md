# Lab VMs (D-315)

`scripts/dev/lab-vm.sh` runs Ubuntu 24.04 and Debian 13 cloud images under plain QEMU/KVM for the LAB checks (v1 criterion 3 in
`.ai/tasks/current.md`, the lab lines in `.ai/deferred/`). Only one VM runs at a time, with 2 vCPU and 2.5 GiB. Each VM has a qcow2
overlay on a verified base image and a cloud-init seed: user `lab`, passwordless sudo, and the dedicated key
`~/.cache/vedette-lab/id_ed25519`. All state lives under `~/.cache/vedette-lab/`. Host requirements: Debian/Ubuntu, x86_64, KVM.

## Once (root)

```sh
sudo scripts/dev/lab-vm.sh setup
```

This installs only the missing packages among `qemu-system-x86 qemu-utils cloud-image-utils passt netcat-openbsd openssh-client
curl gpg gpgv`. It refuses versions below the floors in the script, adds you to `kvm` and prints what changed. It does not touch the
network. You don't need to log in again because the script runs QEMU under `sg kvm`.

## Use

```sh
scripts/dev/lab-vm.sh create ubuntu2404      # or debian13; downloads + verifies the image (fetch <vm> does only that)
scripts/dev/lab-vm.sh start ubuntu2404       # waits for SSH and cloud-init
scripts/dev/lab-vm.sh ssh                    # shell; `ssh <cmd>` runs a command (times out after LAB_SSH_TIMEOUT, 900 s)
scripts/dev/lab-vm.sh status
scripts/dev/lab-vm.sh stop                   # ACPI power-down, kill after 90 s
scripts/dev/lab-vm.sh destroy ubuntu2404     # removes only ~/.cache/vedette-lab/ubuntu2404 (base images stay)
```

`--dry-run` before a command prints what would run. The `start` command has these guards:

- It refuses while another lab VM runs.
- It refuses when MemAvailable is below 4 GiB.
- It refuses when the box would pass 90% of its memory with the VM up.

The console log is `~/.cache/vedette-lab/<vm>/console.log`. To copy files in, run `scp` with the same options that `ssh` uses, or
pipe through `scripts/dev/lab-vm.sh ssh 'cat > f' < f`.

For the GUI, forward a port with ssh:
`ssh -i ~/.cache/vedette-lab/id_ed25519 -o UserKnownHostsFile=~/.cache/vedette-lab/<vm>/known_hosts -p <port> -L 8443:127.0.0.1:8443 lab@127.0.0.1`.
The port is 22404 for ubuntu2404 and 22013 for debian13.

## Network

**Default: passt** (user mode), started by QEMU itself (`-netdev passt`, QEMU 10.1 or newer, so the host is Ubuntu 26.04 or newer). There are no host bridges, firewall rules or routes. SSH listens on 127.0.0.1 only. The VM reaches
the LAN and the Internet through the host's sockets, so it can pull images, run apt, talk to Telegram/email and SSH to a lab
switch.

The VM has the host's IPv4 address. It cannot receive unsolicited traffic from the LAN, and it cannot reach the router at the
gateway address, which maps to the host's loopback. Nothing on the LAN sees it as a separate device.

**`lan` mode** gives the VM a real place on the LAN through a second NIC on a macvtap in passthru mode:

```sh
sudo scripts/dev/lab-vm.sh lan-up enp2s0     # a WIRED NIC with a cable (carrier) that the host does not use
scripts/dev/lab-vm.sh start ubuntu2404 --lan
sudo scripts/dev/lab-vm.sh lan-down          # after stop
```

`lan-up` refuses in these cases:

- The NIC is Wi-Fi. The access point drops frames from any MAC other than the host's, so macvtap over Wi-Fi cannot work.
- The NIC has no carrier.
- The NIC is virtual.
- The NIC carries the host's default route or a global address. Passthru takes every frame of the NIC.

On the Ubuntu dev box the uplink is Wi-Fi and `enp2s0` has no cable, so `lan` mode needs a cable. If NetworkManager configures
`enp2s0` once the cable is in, `lan-up` refuses. Making the NIC unmanaged on the host is a host network change, and only kien can
decide it.

## Which LAB checks need `lan` mode

These checks need a real L2 presence, so they need **`lan` mode (a wired cable)**:

- WP-31 M7: decoy MAC on the wire, a real machine taking a decoy IP.
- WP-31 L9: a decoy IP applied on the box and refused by `never_touch`. The decoy can be applied without `lan` mode, but the check is only realistic with it.
- WP-31 M5: nmap against a LAN machine that drops probes, compared with the passive kind.
- Decoy and honeypot lab lines (`feat-host-net-containers.md` "Lát 3-5", `feat-honeypot.md`): ARP probes from the box MAC, macvlan, `arp_ignore`/`rp_filter`, real ARP frame lengths.
- Live AF_PACKET capture seeing other devices (`feat-sensor-passive.md`, `feat-sensor-protocol.md` SP-5).
- SPAN/port mirror (`feat-container-only.md`).
- nmap/nuclei against lab devices, including a switched-off device with an ARP timeout (`feat-sensor-active.md`, `feat-scan-autostop.md`, `feat-scan-module.md`).
- Syslog sent from another LAN machine (`feat-logs-l2-syslog.md`).
- `net.apply` and Box network on the box's LAN NIC (`feat-core-network.md`).

These checks run on the **default passt network** (no cable):

- WP-31 L10: `/run/vedette` mode and owner, no crash loop on restart.
- WP-31 root boundary: `SO_PEERPIDFD`, the core cgroup under Quadlet, `NET_RAW` ambient for non-root sensor/scan, process-group kill and `Pdeathsig`.
- SYS-7: nuclei egress with tcpdump inside the VM.
- WP-31 L5: an emergency stop that cuts an SSH session to a real device. Outbound SSH works through passt.
- WP-31 L7: Telegram, Zalo and email (Internet only).
- WP-08: `install.sh` clean install, upgrade and rollback; `vedette-host -bootstrap`; Podman 4.9 Quadlet on noble (`feat-host-net-containers.md` 3-8a, a release blocker); cosign pulls from ghcr.io; health checks.
- `os.install`/apt output, `os.OpenRoot` and the systemd unit checks (`feat-host-os-commands.md`, `feat-host-framework.md`).
- `UserNS=auto` for the honeypot and the `/var/lib/vedette-honeypot/log` owner (`feat-host-deb.md`).
- Live nuclei recordings against a target inside the VM (`feat-sensor-nuclei.md`).

Not covered here: arm64 needs a real arm64 box (`feat-multiarch-images.md`), and Ubuntu 26.04 runs on Mlee's box (D-198).
