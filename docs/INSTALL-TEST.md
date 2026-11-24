# Test install from an unreleased build

How to install a build of your own branch on a real machine the way a customer installs a release (root, over SSH, one script, then
the web interface), and how to test the in-place update and rollback. It uses the **test channel**: `make install-artifacts` builds a
folder signed with throwaway keys, and `install.sh --test-artifacts <folder>` installs from it. Customers never use this channel.

- The installer prints `TEST INSTALL - NOT FOR CUSTOMERS` at the start and at the end.
- The two channels never mix. A test install and a release install are different builds that trust different keys; `install.sh`
  refuses to install over the other channel (run `--uninstall --yes` first), and a release `install.sh` refuses `--test-artifacts`.
- The `install.sh` in the repository is not tied to a release and stops with "not tied to a release" on the customer path. Customers
  take `install.sh` from a release page.

The examples use `192.0.2.10` for the test machine. Use a lab or spare machine: the install adds packages, users and containers, and
the uninstall removes them again (below).

## What the install changes, and how `--uninstall --yes` reverts it

Nothing else is changed.

| Change | Uninstall |
|---|---|
| Packages that are **missing** are added with apt: `vedette-host`, and out of podman, netavark, aardvark-dns, catatonit, chrony, netplan.io, nftables, iptables, conntrack, iproute2, procps, unattended-upgrades, passwd, curl, ca-certificates only those not installed yet, plus their dependencies. **No package that is already installed is upgraded on purpose** (`--no-upgrade` on the ones the installer names); a dependency can still be upgraded when a new package needs a newer version of it (that upgrade is not undone and the package is never removed), needrestart only lists, and the installer refuses if apt would remove anything but `systemd-timesyncd` (which chrony replaces). The installer records the packages it asked for in `/var/lib/vedette-install/asked-packages`. | `vedette-host` is purged; the recorded packages are marked automatic and apt removes those of them (and the ones apt newly installed for them) that nothing else needs now. Packages that became removable for other reasons, such as old kernels, and packages marked manual are never touched. A package somebody installed on top (for example `ufw`, which needs `iptables`) keeps what it needs. If apt would remove anything beyond that set the installer removes nothing more and says so. A replaced `systemd-timesyncd` is installed again. |
| The accounts the new packages make (`_chrony`), and the users `vedette`, `vedette-sensor` | removed (only the ones the installer saw appear) |
| `/etc/chrony/chrony.conf` is **not touched**, chrony is **not restarted**; an existing chrony keeps its configuration. The installer only checks that chrony lists time sources and says so if it does not. | nothing to revert (`vedette.sources`, written later by vedette-host from Box network, is removed) |
| Podman units and data: `/etc/containers/systemd/vedette-*` (units, `vedette-int.network`, two credential volumes; the honeypot unit loads `/usr/lib/vedette/honeypot-containers.conf`, a file of the `vedette-host` package that its purge removes; every unit loads `/usr/lib/vedette/apparmor-containers.conf`, which selects the AppArmor profile `/etc/apparmor.d/vedette-container`, both files of the package that its purge removes, the loaded profile stays in the kernel until the next boot), rootful images by exact name, `ghcr.io/knt048/vedette-<service>`, `localhost/vedette-<service>:*` and `localhost/vedette-scan-nmap:*` for the services core, sensor, honeypot, scan, greenbone (another `localhost/vedette-*` image is the administrator's and stays; an image of ours that also has another name stays, with a warning) (the scan image build also leaves its base layers in the rootful storage; a nameless image with our source label and a `vedette-*` title is removed too), containers `vedette-*`, network `vedette-int` (a `172.30.x.0/24` that clashes with nothing in `ip route`), `/var/lib/containers` if podman was added; the folders `/etc/containers` (with `networks/`, `systemd/`, `systemd/users/`, `registries.conf.d/`) and `/var/lib/cni` (with `networks/`) that the package and podman make for `vedette-int` | removed; when podman was added by the installer **and apt purged it**, also the storage folder, `/run/containers`, and those folders, each only if empty and owned by no installed package (`rmdir`, `dpkg-query -S`). A podman apt kept is the administrator's and its storage stays. A podman the installer added stays too, with its packages and storage, when it holds anything that is not Vedette's (containers, stopped ones too, pods, networks, volumes, named images), when it cannot be asked, and always with `--keep-data`; the summary says what was kept and why. The purge of an added `chrony` removes the empty `/etc/apparmor.d/disable` (and `local/`, `force-complain/`) of the `apparmor` package (dh_apparmor's postrm); the uninstall puts back the ones that were there, while `apparmor` is installed |
| `net.ipv4.ip_forward` (and IPv6 forwarding): netavark turns it on when the first container network comes up | the value recorded before the install is written back, unless something else needs forwarding now (Docker running, another podman network, libvirt, a sysctl file that sets it): then it is left and the installer says so |
| nft tables netavark leaves (`inet netavark`, and the empty `ip nat`/`ip filter` iptables-nft makes) | removed when they did not exist before and are empty or netavark's; a table with other rules is left and reported |
| `/etc/subuid` and `/etc/subgid`: one `containers:2147483647:2147483648` line when the box has no `containers:` line | removed only when the installer added it; an administrator's own line is never touched |
| Folders and users: `/etc/vedette`, `/var/lib/vedette` (database and key), `/var/lib/vedette-host`, `/var/lib/vedette-honeypot`, `/var/lib/vedette-install` (installer state), `/var/log/vedette-host`, `/run/vedette`, network namespace `vedette-hp` (honeypot decoy links live in it) | removed (`--keep-data` keeps the data and the users) |
| The installed `vedette-host` package is kept at `/var/lib/vedette-host/selfupdate/packages/vedette-host_<version>_<arch>.deb` (0600 root, its folders 0700 root; the SemVer name of the release asset, never Debian's `~`), written on every install, repair and upgrade before apt installs it (temporary name, synced, renamed; taken out again when apt fails; a reinstall of the same version restarts a running vedette-host that has not recorded it); the installer refuses to start while a self-update is under way (`selfupdate/journal.json`, `vedette-host-upgrade.service`); vedette-host records it in `selfupdate/versions.json` when it starts and goes back to it when a later self-update fails | removed with `/var/lib/vedette-host` (`--keep-data` keeps it with the rest of `/var/lib/vedette-host`) |
| TCP 8443 (interface, API) and 8444 (sensor link, on 127.0.0.1) | closed when the containers are removed |
| During the install only: `/etc/containers/registries.conf.d/vedette-test-mirror.conf` and the unit `vedette-testregistry.service` (a loopback registry on 127.0.0.1:5077). The mirror is system-wide, so it also redirects pulls of `ghcr.io/knt048/*` by any rootless podman on the machine for the minutes of the install; nothing else. | removed when the install ends, also when it fails or the SSH session drops (the next run of either channel removes a leftover one) |

**What it never touches** (the default is no network hand-over; do not add `--network-handover` on a machine you reach over SSH):

- `/etc/netplan/*`, NetworkManager and the machine's LAN connection. Do not press Apply in Settings → Box network on a machine you
  reach only over the network: losing its address loses the machine. The honeypot's decoy addresses do not change the machine's
  address; they are separate macvlan links inside the `vedette-hp` network namespace.
- Home directories, other users' processes, `sshd` and its configuration, the apt sources. Keep the test folder and the snapshots
  under `/root/vedette-test`.
- No reboot, and no scan of anything outside the machine: this procedure runs no scan; leave active scanning off.

If the preflight refuses (for example port 8443 or 8444 is already in use), that is the answer: the refusal changes nothing.

## Before and after snapshot

Take a snapshot before the install and compare it after the uninstall; the two must be identical apart from the noise listed below.

```sh
snap() { d=$1; mkdir -p "$d"
  getent passwd | sort >"$d/passwd"; getent group | sort >"$d/group"
  systemctl list-unit-files --no-legend --no-pager | awk '{print $1,$2}' | sort >"$d/units"
  # sockets: other programs on the machine may listen on ports of their own; only these are compared
  ss -H -ltnu | awk '{print $1,$5}' | grep -E ':(8443|8444|5077)$' | sort >"$d/sockets"
  ip -o link | awk '{print $2}' | sort >"$d/links"; ls /run/netns 2>/dev/null | sort >"$d/netns"
  ip -4 -o addr | awk '{print $2,$4}' | sort >"$d/addr"; ip -4 route | sort >"$d/routes"
  cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding >"$d/sysctl"
  (nft list tables 2>/dev/null || echo "no nft") | sort >"$d/nft"
  dpkg-query -W -f='${binary:Package} ${Version}\n' | sort >"$d/packages"
  sha256sum /etc/chrony/chrony.conf >"$d/chrony" 2>&1
  ls -la /etc/netplan >"$d/netplan" 2>&1; sha256sum /etc/netplan/* 2>/dev/null >>"$d/netplan"
  find /etc /usr/lib/vedette /var/lib /var/log /run/vedette -xdev -printf '%p %y %m %u:%g\n' 2>/dev/null \
    | grep -Ev '^/var/lib/(apt|dpkg|systemd|ucf|pam|private|snapd|logrotate|PackageKit|update-notifier)|^/var/log/(apt|dpkg|journal|syslog|auth|kern|cloud-init|unattended-upgrades)|^/etc/(ssl|ld.so.cache|alternatives|\.pwd.lock|mailcap)|\.(log|gz|old)( |$)' | sort >"$d/files"; }
mkdir -p /root/vedette-test; snap /root/vedette-test/before
# ... install, test ...
snap /root/vedette-test/after; diff -ru /root/vedette-test/before /root/vedette-test/after && echo IDENTICAL
```

Known noise that is not an installer fault: the apt lists and the apt, dpkg and journal logs (excluded above), `ip -o link` entries
of other containers or virtual machines that come and go, and the unit list if something else changed a unit meanwhile. In the
packages file only these lines may differ: a **dependency that apt upgraded** because a new package needed a newer version (the
package is still there, with a new version), packages that **apt or unattended-upgrades upgraded on their own** in that window, and
the base layers of the `scan` image build in podman's storage (with podman added by the installer and purged by the uninstall, the
folder is removed). When podman was already installed but had never run as root, its rootful storage is created by the install and
**stays** after the uninstall (`/var/lib/containers/storage`): the installer never deletes a container storage it did not create,
since other rootful containers may use it (#298). A package that is **missing** after the uninstall, or one that is **new** and not
in the installer's `asked-packages` or their dependencies, is a bug. `addr`, `routes`, `chrony` and `netplan` prove that the LAN
connection and the time configuration were not touched. Any other difference is an installer bug: report it with the diff instead of
cleaning up by hand.

## Install, check, uninstall

0. **Build the folder** on a Linux machine with podman and bash 4 or later (macOS has neither by default, #298):
   `make install-artifacts`. It builds core with the real interface, sensor and scan, and includes the honeypot image when
   `localhost/vedette-honeypot:$TEST_VERSION` exists. The architecture follows the build machine; for an amd64 test machine on an
   arm64 build machine use `make install-artifacts ARCH=amd64`. The result is `dist/install/`. Copy it to the test machine
   (`rsync -a dist/install/ root@192.0.2.10:/root/vedette-test/art/`), make root own it
   (`ssh root@192.0.2.10 'chown -R root:root /root/vedette-test/art && chmod -R go-w /root/vedette-test/art'`; the rsync of macOS has
   no `--chown`), and check it: `ssh root@192.0.2.10 'cd /root/vedette-test/art && sha256sum -c SHA256SUMS'`. The installer refuses a
   folder that is not root's or that group or others can write, and copies what it uses into a closed folder of its own before it
   checks anything.
1. **Snapshot** the machine (above).
2. **Install**: `sh /root/vedette-test/art/install.sh --test-artifacts /root/vedette-test/art`. Expect the warning,
   `preflight ... ok`, the packages, `vedette-host`, the bootstrap (several minutes: the `scan` image is built on the machine and needs
   `deb.debian.org`), then `Vedette is running.`, the address `https://192.0.2.10:8443` and a setup code. A refusal in the preflight
   changes nothing. If a step fails, run the same command again: it repairs what stopped; only `--uninstall --yes` removes.
3. **Effects, on the machine**: `systemctl is-active vedette-host`; `podman ps` (vedette-core healthy);
   `curl -ks https://127.0.0.1:8443/api/v1/setup` answers 200, and so does `curl -k https://192.0.2.10:8443/api/v1/setup` from your
   own computer; `ss -ltn` shows 8443 and `127.0.0.1:8444`; `cat /etc/vedette/host.conf` matches
   `getent passwd vedette vedette-sensor`; `cat /etc/containers/systemd/vedette-int.network` (a `172.30.x.0/24` that clashes with
   nothing in `ip route`); `chronyc sources`, with `sha256sum /etc/chrony/chrony.conf` equal to the snapshot; `ls /etc/netplan` and
   `ip -4 addr` unchanged; `/etc/containers/registries.conf.d/vedette-test-mirror.conf` no longer exists;
   `/proc/sys/net/ipv4/ip_forward` is probably 1 now (the uninstall restores it).
4. **Web interface**: open `https://192.0.2.10:8443`, accept the certificate, enter the setup code and finish the wizard
   (administrator with two-step sign-in, LAN range, scan commitment, modules, notifications).
5. **Modules**: turn on `sensor-passive` (the sensor container starts and its heartbeat shows) and `honeypot` (its container starts).
   For a decoy address, pick one outside the network's DHCP range, check that it is free with `arping -D -I <nic> <ip>` (no reply means
   free) and add it on the honeypot page; on a wired LAN the decoy answers ARP, and one `nc -vz <decoy ip> 22` from another machine
   shows a hit in the interface. Remove the decoy afterwards. Leave `sensor-active` off. Test SPAN capture only when the machine has a
   second wired card without an address (`ip -o link`); otherwise note "SPAN skipped: no second card".
6. **Run it again**: the install command of step 2 again. Expect `host.conf is already right` and
   `the release is already bootstrapped`, and core not restarted (`podman inspect --format '{{.State.StartedAt}}' vedette-core`
   unchanged).
7. **Reinstall keeping the data**: `sh /root/vedette-test/art/install.sh --uninstall --yes --keep-data`, then the install command of
   step 2 (the same folder, or a newer test build made with the same `KEYS=<dir>`: other keys do not verify against the kept release
   index, #469). Expect `the kept data last ran with release …` (a warning when the build is newer: core moves the data forward and
   only a backup goes back), `none of its containers: installing release … over it`, no `already bootstrapped`, and
   `first-run setup was completed already`; the administrator of step 4 signs in and the data is there. A build older than the one that
   last ran is refused before any change. Then the repair path with vedette-host running:
   `systemctl stop vedette-core && rm /etc/containers/systemd/vedette-core.container && systemctl daemon-reload`, and step 2 again:
   expect `stopping vedette-host for the bootstrap` and core healthy. `make install-check` runs both paths in systemd containers.
8. **Uninstall**: `sh /root/vedette-test/art/install.sh --uninstall` only says what it would do;
   `sh /root/vedette-test/art/install.sh --uninstall --yes` does it and deletes the test database and key.
9. **After**: the snapshot `diff` says IDENTICAL (apart from the noise above); `ss -ltn` has no 8443 or 8444; `ip -o link` has no
   leftover macvlan or decoy link; `ls /run/netns` has no `vedette-hp`; `ip_forward` and `nft list tables` are as in the snapshot.

## Update and rollback: install test.1, update to test.2 from the interface, roll back

This tests the real software update over the test channel: the host package (`host.self_update`) and the container images (#432),
signed with the same throwaway keys. A build reads the test update source below only when its version has a `-test.` prerelease, and
it still verifies every document with the keys compiled into it. The source runs on the tester's own LAN, so it is not a customer data
flow.

**On the build machine, with the same keys folder for both builds** (outside the repository and outside `dist/`; it holds the private
test keys, 0600, never to be committed or reused for a release):

1. `make install-artifacts TEST_VERSION=0.0.1-test.1 KEYS=$HOME/vedette-testkeys OUT=$HOME/vedette-art/test.1` (the first run says
   "making test keys").
2. `make install-artifacts TEST_VERSION=0.0.1-test.2 KEYS=$HOME/vedette-testkeys OUT=$HOME/vedette-art/test.2` ("reusing the test
   keys").
3. Copy both folders to the test machine as in step 0 (`/root/vedette-test/art-1`, `/root/vedette-test/art-2`; root-owned, no group or
   other write) and run `sha256sum -c SHA256SUMS` in each.

**On the test machine, as root:**

4. Install test.1 as in steps 1 to 4 above: `sh /root/vedette-test/art-1/install.sh --test-artifacts /root/vedette-test/art-1`.
   Settings → Updates shows `0.0.1-test.1` and no update.
5. Serve test.2 on the bridge of the containers (core runs in a container and cannot reach the machine's loopback). If the machine has
   a firewall (ufw, firewalld), allow `vedette0` to reach port 5078 first.
   `BR=$(ip -4 -o addr show vedette0 | awk '{print $4}' | cut -d/ -f1)` (172.30.x.1), then
   `systemd-run --unit=vedette-testupdate /root/vedette-test/art-2/vedette-testchannel serve -dir /root/vedette-test/art-2/registry -releases /root/vedette-test/art-2 -listen $BR:5078`
   (a transient unit: start it again after a reboot). Check it with
   `curl -fs http://$BR:5078/release/index/index.json | head -c 100` and `curl -fs http://$BR:5078/v2/` (`{}`).
6. Point core and podman at it:
   `echo "http://$BR:5078/release" > /var/lib/vedette/test-release-base` (core reads it on each check, no restart), and
   `printf '[[registry]]\nprefix = "ghcr.io/knt048"\nlocation = "ghcr.io/knt048"\n[[registry.mirror]]\nlocation = "%s:5078"\ninsecure = true\n' "$BR" > /etc/containers/registries.conf.d/vedette-test-mirror.conf`.
7. **In the interface**: Settings → Updates → Software channel → **Beta** (the test channel signs only a `beta` channel), then Check.
   Expect `0.0.1-test.2` offered. If nothing is offered or the source is unreachable: `journalctl -u vedette-testupdate` and
   `podman logs vedette-core | grep -i 'release\|test-release-base'` (a bad address in the file is ignored with one warning, and core
   then asks GitHub).
8. **Update** (host first, then core, then the other images). Before: `dpkg-query -W -f '${Version}\n' vedette-host`,
   `systemctl show -p MainPID vedette-host`, `podman ps --format '{{.Names}} {{.Image}}'`, and note something in the database
   (a user, a setting). During: `systemctl status vedette-host-upgrade`. After: the run is `succeeded` in the interface; `dpkg-query`
   shows `0.0.1~test.2`; vedette-host has a new MainPID; `/var/lib/vedette-host/selfupdate/packages` holds both packages; the images
   are the test.2 digests; the interface reconnects and shows `0.0.1-test.2`; the data from before is there; the honeypot, if on, came
   back.
9. **Roll back** (Settings → Updates → History → Roll back, where offered). The test channel signs `rollback.safe=false`, so it asks
   you to confirm the data loss. After: the version is test.1 again, the data is there, and `podman ps` shows the test.1 digests. The
   host package has no manual rollback, only the automatic one after a failed start.
10. **Clean up**: `systemctl stop vedette-testupdate; rm -f /etc/containers/registries.conf.d/vedette-test-mirror.conf /var/lib/vedette/test-release-base`,
    then uninstall (step 8 of the procedure above) and compare the snapshots.

Negative checks: build a third version with a different keys folder (leave out `KEYS`) and serve it the same way: Check must refuse
it (signature) and never offer it. A public address in `test-release-base` (for example `http://8.8.8.8/x`) is ignored.

## What this procedure cannot show

`make install-check` runs the installer in systemd containers and cannot show macvlan decoys on a real wire, a second card for SPAN,
netplan and the network hand-over, or a reboot; this procedure checks the decoys (and SPAN, with a second card) on the machine and
leaves the network hand-over and the reboot out on purpose.
The `scan` image build needs `deb.debian.org`: a machine that cannot reach it installs without active scanning (the installer says so
and goes on).

## Reporting a problem

Attach the install output (with the setup code removed), the result of step 3, the module checks of step 5, the second-run result
and the snapshot `diff`. When a step does not behave as described, stop there and report it rather than repairing by hand.
