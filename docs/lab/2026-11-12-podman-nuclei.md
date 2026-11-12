# Lab 2026-11-12: Podman 4.9.3, `vedette-host -bootstrap`, pinned nuclei

Lab VM `ubuntu2404` (`scripts/dev/lab-vm.sh`, D-315), passt network, one session. Ubuntu 24.04, systemd 255.4-1ubuntu8.18,
podman 4.9.3+ds1-1ubuntu0.2, netavark 1.4.0-4, aardvark-dns 1.4.0-5, conmon 2.1.10, crun 1.14.1. Source: `main` at 3f802b65.
The raw outputs the tests read are in `host/ops/testdata/podman49/` and `modules/scan/nucleiout/testdata/`.

## 1. Podman 4.9.3 output against host/ops (D-138, release blocker)

| Shape | Real output | host/ops before | Fake (`opstest`) before |
|---|---|---|---|
| `image ls --format json` | array; each entry has `Id` (64 hex), `Digest`, `Names`, `RepoTags: null`, `RepoDigests`, `Containers`, plus `ParentId`, `Size`, `Labels`, `History`, `Created`... A pulled release: `Names` = [`localhost/vedette-core:0.0.1-test.1`, `ghcr.io/knt048/vedette-core@sha256:<pulled>`], `RepoDigests` = the same digest under both repositories (the honeypot index also lists its platform manifest digest) | parsed right | `Names` held the local tags only, the pull reference only in `RepoDigests` |
| Image with only its digest name (a pull never tagged) | listed, `Names` = [`<repo>@sha256:<d>`] | kept as "owned" | same |
| Image with no name | listed, `Names: null`, `RepoDigests: []`, `Dangling: true` | skipped (left alone) | not modelled |
| `rmi <Id>`, one name | exit 0, `Untagged: <name>` / `Deleted: <id>` | | |
| `rmi <Id>`, no name | exit 0, `Deleted: <id>` | | |
| `rmi <Id>`, **two names** | **exit 125**, `Error: unable to delete image "<id>" by ID with more than one tag ([...]): please force removal` | **retention always failed for a pulled release** (both names), so old images were never removed | removed it (wrong) |
| `rmi <Id>`, used by a container | exit 2, `Error: image used by <ctr>: image is in use by a container...` | skipped earlier (`Containers` ≠ 0) | exit 2 (right) |
| `pull -q <repo>@<d>` | prints the 64-hex image ID | | |
| `image inspect --format json` | one-element array; `Digest` = the digest pulled by (the index digest for the releases and for busybox by digest), `RepoTags` = local tags, `Architecture: amd64`, `Os: linux`; 11.5 KB for core | parsed right | |
| `container inspect` | `ImageDigest` = pulled digest, `Image` = image ID, `State.Health.Status: healthy` (no `Healthcheck` key) | parsed right | |

**Fix:** retention now runs `podman untag <Id> <local tag>` for the local tags of an image with more than one name (keeping one
name), then `rmi <Id>`; a failed untag skips the rmi. New argv shape `untag <64 hex> <localhost/vedette-<service>:<version> |
localhost/vedette-scan-nmap:<version>>`, validated like the rest. The fake now prints the real `Names`, refuses `rmi` of an
image with two names (exit 125) and answers `untag`.

## 2. `vedette-host -bootstrap` on Ubuntu 24.04

The images are not on `ghcr.io` yet (an anonymous token for `knt048/vedette-core` is `DENIED`; WP-08k), so the run used the
test channel: `make install-artifacts FAST=1` on the dev box (core, sensor, honeypot; throwaway keys), copied into the VM,
`sh install.sh --test-artifacts /root/art`. Podman pulled `ghcr.io/knt048/vedette-<service>@sha256:<index digest>` through the
installer's loopback mirror (not the real registry).

- Bootstrap verified, pulled by digest, tagged `localhost/vedette-<service>:0.0.1-test.1`, wrote the three units, `pulled-*` and
  `versions-*`; the installer ran `daemon-reload` and started them. core and sensor `healthy`, `GET /api/v1/setup` 200,
  8443 and 127.0.0.1:8444 listening. Exit 0.
- `core_data` `/var/lib/vedette` 0700 999:988 (core), bound into core (`bind /var/lib/vedette -> /var/lib/vedette rw`),
  `Exec` has no `-key`; `vedette.key` 0600 999:988, 32 bytes. `systemctl restart vedette-core`: healthy again, same key hash,
  no key error in the log, setup 200.
- `vedette-host -bootstrap` again beside the running daemon: exit 6 `daemon_running`. `install.sh` again: "already
  bootstrapped; skipping", core `StartedAt` unchanged. `--uninstall --yes`: exit 0.

## 3. nuclei v3.11.1 (pins.env)

zip `ea63d4ae…5ab6` and binary `c4958814…0251` match `pins.env`; templates archive v10.5.1 `30fe1cfa…56eb` matches. Targets
only inside the VM: a dummy link `lab0` 192.168.10.21/24 (HTTP on :5000 shaped for CVE-2022-27593, FTP-like on :21 for
CVE-2015-3306; 192.168.10.22 drops everything) and a veth `lab1` 192.168.11.1/24 whose peer has no address (192.168.11.30: no
route to host). Argv exactly `nucleiargv.Build` (`-rl 5 -mhe 3`), empty HOME, read-only empty cwd.

- **`host` is the bare address with `port` apart** (`"host":"192.168.10.21","port":"5000","url":"http://192.168.10.21:5000"`),
  for http and tcp templates. `nucleiout.hostOf` refused it, so every real run was thrown away. Fix: `nucleiout.targetOf`
  (host + port; the older shapes still parse; a port that disagrees with the host's is refused). The "host was skipped as it
  was found unresponsive" line has no `port` and keeps `"host":"http://192.168.11.30:80"`; it parses as that target.
- `-ms` prints one line per template and target: 12 lines for 3 x 4; `template-encoded` makes a line up to ~3 KB.
- `-version -duc` in a namespace with no network: exit 0, stdout empty, stderr `[INF] Nuclei Engine Version: v3.11.1` (with
  colour codes around `INF`; the worker's regex matches).
- `nuclei -h` lists every flag of `fixedFlags` under these names: `-jsonl -silent -nc -duc -ni -ms -dr -nh -etags -pt -elog
  -c -bs -timeout -retries -rl -mhe -t -u`.
- `-etags dos,intrusive,fuzz` drops a template that `-t` names directly (CVE-2022-29078, tag intrusive), `-pt http,tcp,ssl` drops
  a dns template: no JSONL line for either; only the stderr line `[INF] Templates loaded for current scan: 1` (3 named) says so,
  and only without `-silent`.
- Egress (tcpdump on every interface, lab nets and SSH excluded) during the three runs: only the VM's own IPv6 router
  solicitations, DHCPv6, one NTP exchange of timesyncd and one ARP for the gateway. No DNS, no GitHub or projectdiscovery.io, no
  interactsh, no cloud upload. HOME after a run: `.config/nuclei/{config.yaml,.templates-config.json,reporting-config.yaml}`,
  `.config/uncover/provider-config.yaml`, `.cache/nuclei/index.gob`; no templates downloaded.
- `-elog`: a dropping target gives `network-temporary-error` for http templates but `unknown-error` ("context cancelled before
  establishing connection") for the tcp one; no route to host is `network-permanent-error` ("port closed or filtered"); a TLS
  error on a plain port has no `kind`. nuclei's own `-mhe` skipped the no-route target (permanent errors count there), not the
  dropping one.
