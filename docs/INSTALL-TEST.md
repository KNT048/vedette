# Install test on a real box (WP-08h, D-166)

The plan the Mac session follows to install Vedette on the test box **192.168.18.141** (Ubuntu, wired LAN, user `byn2`) the way a customer would: root, over SSH, one script, then the GUI. It uses the **test channel**: the release keys and the published images do not exist yet (WP-08k), so the install runs from a folder built on the dev box and signed with throwaway keys. The installer prints `TEST INSTALL - NOT FOR CUSTOMERS` at the start and at the end. The customer path (GitHub release plus `ghcr.io`) is the default of `install.sh` and stops with "not tied to a release" until the first release exists.

Nobody but the Mac session installs on that box. Do not SSH there from anywhere else.

## Safe install on this test box

**What it installs** (and `--uninstall --yes` removes again):

| Kind | What |
|---|---|
| Packages | `vedette-host` and, if the box lacks them, podman, netavark, aardvark-dns, catatonit, chrony, netplan.io, nftables, iptables, iproute2, procps, unattended-upgrades and what they pull in. The installer records exactly which packages it added or removed in `/var/lib/vedette-install/` and uninstall reverses only those. |
| Users | system users and groups `vedette` and `vedette-sensor` |
| Units | `vedette-host.service`; Quadlet units `/etc/containers/systemd/vedette-*` (core, sensor, scan, honeypot as present in the artifacts, and `vedette-int.network`, the two credential volumes); chrony `sources.d/vedette.sources`; a short-lived `vedette-testregistry.service` and `/etc/containers/registries.conf.d/vedette-test-mirror.conf` during the install only |
| Ports | TCP 8443 (interface and API), 8444 (sensor link, on 127.0.0.1) |
| Folders | `/etc/vedette`, `/var/lib/vedette` (database and key), `/var/lib/vedette-host`, `/var/lib/vedette-honeypot`, `/var/lib/vedette-install` (installer state), `/var/log/vedette-host`, `/run/vedette`, `/var/lib/containers` (podman, if podman was not there before) |
| Podman | images `ghcr.io/knt048/vedette-*` and `localhost/vedette-scan-nmap:*`, containers `vedette-*`, network `vedette-int`, volumes `vedette-creds-*` |
| Network namespace | `vedette-hp` (honeypot), with the decoy macvlan links inside it |

**What it must never touch** (the installer cannot: its default is no network hand-over; do not add `--network-handover`):

- `/etc/netplan/*`, NetworkManager and the LAN connection of the box. **No `--network-handover`, and no Box network apply or confirm in the GUI on this box**: losing its address loses the box. Looking at the Box network screen is fine; pressing Apply is not. (The decoy IPs of the honeypot do not change the address of the box; they are separate macvlan links.)
- the home directory of `byn2` (`~byn2/vedette*`, Mlee's worktrees, caches and tmux), the tmux session `claude`, the processes of `byn2`, `sshd` and its config, the apt sources. Everything is done as root outside `/home`: keep the test folder and the snapshots under `/root/vedette-test`.
- no reboot (a reboot would also test the boot-time path, but only with the supervisor's OK).
- no scan of anything outside the box: this plan runs no scan; active scanning stays off.

If the preflight refuses (for example port 8443 or 8444 is in use by Mlee's own dev run), that is the answer: do not stop her processes, report it to the supervisor.

**Before and after.** Take the snapshot first and compare after the uninstall; they must be identical:

```sh
snap() { d=$1; mkdir -p "$d"
  getent passwd | sort >"$d/passwd"; getent group | sort >"$d/group"
  systemctl list-unit-files --no-legend --no-pager | awk '{print $1,$2}' | sort >"$d/units"
  ss -H -ltnu | awk '{print $1,$5}' | sort >"$d/sockets"
  ip -o link | awk '{print $2}' | sort >"$d/links"; ls /run/netns 2>/dev/null | sort >"$d/netns"
  ip -4 -o addr | awk '{print $2,$4}' | sort >"$d/addr"; ip -4 route | sort >"$d/routes"
  dpkg-query -W -f='${binary:Package} ${Version}\n' | sort >"$d/packages"
  ls -la /etc/netplan >"$d/netplan" 2>&1; sha256sum /etc/netplan/* 2>/dev/null >>"$d/netplan"
  find /etc /usr/lib/vedette /var/lib /var/log /run/vedette -xdev -printf '%p %y %m %u:%g\n' 2>/dev/null \
    | grep -Ev '^/var/lib/(apt|dpkg|systemd|ucf|pam|private|snapd|logrotate)|^/var/log/(apt|dpkg|journal)|^/etc/(ssl|ld.so.cache|alternatives)' | sort >"$d/files"; }
mkdir -p /root/vedette-test; snap /root/vedette-test/before
# ... install, test ...
snap /root/vedette-test/after; diff -ru /root/vedette-test/before /root/vedette-test/after && echo IDENTICAL
```

`/var/lib/apt` lists and the apt/dpkg logs change by themselves and are left out. `addr`, `routes` and `netplan` prove the LAN connection was not touched. Any other difference is a bug of the installer: report it, do not clean up by hand.

## What to run (the Mac session, as root, `ssh root@192.168.18.141`)

0. **Build the artifacts on the dev box** (not on the test box): `make install-artifacts` (full: core with the real interface, sensor and scan; add the honeypot image of WP-08e built with the same tag if it is on `main`: `make install-artifacts` includes it when `localhost/vedette-honeypot:$TEST_VERSION` exists). The result is `dist/install/`. Copy it: `rsync -a dist/install/ root@192.168.18.141:/root/vedette-test/art/`.
1. **Snapshot** the box (above).
2. **Install**: `sh /root/vedette-test/art/install.sh --test-artifacts /root/vedette-test/art`. Expect: the warning, `preflight ... ok`, packages, `vedette-host`, `bootstrap` (several minutes; the scan image is built on the box and needs `deb.debian.org`), then `Vedette is running`, an address `https://192.168.18.141:8443` and a setup code. A refusal before the packages step changes nothing.
3. **Effects, from the box**: `systemctl is-active vedette-host`; `podman ps` (vedette-core healthy); `curl -ks https://127.0.0.1:8443/api/v1/setup` answers 200; `ss -ltn` shows 8443; `cat /etc/vedette/host.conf` matches `getent passwd vedette vedette-sensor`; `cat /etc/containers/systemd/vedette-int.network` (a `172.30.x.0/24` that clashes with nothing in `ip route`); `chronyc sources`; `ls /etc/netplan` and `ip -4 addr` unchanged from the snapshot; `ls /etc/containers/registries.conf.d/vedette-test-mirror.conf` does not exist.
4. **GUI**: open `https://192.168.18.141:8443`, accept the certificate, enter the setup code, finish the wizard (administrator with 2FA, LAN range, scan consent, modules, notifications).
5. **Modules**: turn on `sensor-passive` (the sensor container starts and a heartbeat shows), `honeypot` (the container starts; **decoy IPs**: add one decoy IP outside the DHCP range in the honeypot screen; on this wired LAN macvlan is expected to work: the decoy answers ARP and a connection to a decoy port is a hit in the GUI; from the Mac, one `nc -vz <decoy ip> 22` to the decoy is the whole test), and leave `sensor-active` off. **SPAN** (a second NIC in promiscuous mode) only if the box has one: `ip -o link` shows a second wired card without an address; otherwise write "SPAN skipped: no second NIC". Do not press Apply in Box network (see above).
6. **Re-run**: `sh /root/vedette-test/art/install.sh --test-artifacts /root/vedette-test/art` again. Expect `host.conf is already right` and `already bootstrapped`, and core not restarted (`podman inspect --format '{{.State.StartedAt}}' vedette-core` unchanged).
7. **Uninstall**: `sh /root/vedette-test/art/install.sh --uninstall` (only says what it would do), then `sh /root/vedette-test/art/install.sh --uninstall --yes`. This deletes the test box's Vedette database and key.
8. **After**: snapshot and the `diff` above must say IDENTICAL; `ss -ltn` has no 8443/8444; `ip -o link` has no leftover macvlan or decoy link; `ls /run/netns` has no `vedette-hp`.

## Not failures

The container run (`make install-check`) cannot show, and this plan checks on the box instead: macvlan decoys on a real wire, a second NIC and SPAN, `netplan` and the network hand-over (not exercised on this box on purpose), a reboot (the units come back after boot: only with the supervisor's OK). If the box has no second NIC, SPAN is skipped, not failed. The scan image build needs `deb.debian.org`; a box that cannot reach it installs without active scanning (the installer says so and goes on).

## Report

Send the supervisor: the install output (setup code removed), the result of step 3, the module and decoy checks of step 5, the second-run result, and the `diff` of step 8. Any difference, any step that did not behave as described: stop there and report; do not repair by hand.
