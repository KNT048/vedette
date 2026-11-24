# Deployment

This document describes how Vedette is deployed as built for v1. Values marked **(proposal)** are defaults that have not been measured on a real box yet. Everything ships as code: a new machine built from the repo must reach the same state, verified by **effect** (service running, port open, configuration correct), not by exit code.

Related: [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`specs/host-api.md`](specs/host-api.md) (`vedette-host` commands) · `specs/*.md` · [`UPDATES.md`](UPDATES.md) · [`DATA_MODEL.md`](DATA_MODEL.md) · `../PRIVACY.md`.

Shipped files in the repo: `install.sh` (at the repo root; a release carries the version and the sha256 of the `.deb` inside it), the `vedette-host` package (`deploy/deb/`, `deploy/systemd/`), the Quadlet units that `vedette-host` renders from the constant template in `host/ops/quadlet.go`, `deploy/containers/*/Containerfile`, `deploy/compose/` (the dev profile and the container-only install) and `deploy/greenbone/` (the OpenVAS compose project).

## 1. Principles

1. The box is **a host in the LAN**, not inline. Every connection to the Internet is opened by the box; no inbound port from the Internet is needed.
2. One Go codebase, packaged as several OCI images; the same images run on the appliance (Podman) and in dev/CI (Compose).
3. Configuration is generated from the DB/repo and never edited by hand on the machine: Quadlet units are rendered by `vedette-host` from a template + module state.
4. When a module is off, its container does not start (SYS-5).
5. Images are pinned by **digest** and cosign-signed; the host refuses unsigned images (fail-closed).

## 2. Container topology

```
 host (Ubuntu 24.04 / 26.04, Debian 13; netplan + networkd, chrony)
 ├─ vedette-host.service (root, Type=notify)  ◄── /run/vedette/host.sock (0660 root:vedette)
 ├─ Podman (rootful) ── Quadlet units: /etc/containers/systemd/*.container|*.network|*.volume
 │
 │   internal bridge network `vedette-int`  (subnet chosen not to collide with the LAN, proposal)
 │   ┌──────────────┐        ┌──────────────┐
 │   │ core         │        │ greenbone    │ (optional, internal bridge only)
 │   │ :8443 (pub.) │        └──────────────┘
 │   │ :8444 mTLS   │
 │   └─▲───────▲────┘
 │     │       │ 127.0.0.1:8444
 │     │     ┌─┴──────────┐  ┌──────────┐
 │     │     │ sensor     │  │ scan     │   host network (raw socket; capture/see the real LAN)
 │     │     └────────────┘  └──────────┘
 │     │ config/ (ro) + log/ files, no network port
 │   ┌─┴────────────────────────────────────────────┐
 │   │ honeypot  (netns `vedette-hp` held by the host, │
 │   │ one macvlan link + own MAC per decoy)           │
 │   └───────────────────────────────────────────────┘
 └─ management NIC (IP) · SPAN NIC (no IP, promisc) · decoys: macvlan on the management NIC, inside `vedette-hp`
```

Summary (each container in detail in §2.1–§2.4, the tools that run only the part Vedette uses in §2.5, resource limits in §2.6):

| Container | Image (proposal) | Network | Capability | On by default |
|---|---|---|---|---|
| `core` | `ghcr.io/knt048/vedette-core` | bridge `vedette-int`, publishes `8443:8443` and syslog `514:5514/udp`, `514:5514/tcp`, syslog over TLS `6514:5515/tcp` | none (drop ALL)  | always |
| `sensor` | `ghcr.io/knt048/vedette-sensor` | host | only `NET_RAW` (ambient, `User=<sensor_uid>`) | when `sensor-passive` is on |
| `honeypot` | `ghcr.io/knt048/vedette-honeypot` | the host's `vedette-hp` namespace (`Network=ns:`), macvlan with one MAC per IP | none (drop ALL; `ip_unprivileged_port_start=0` in the namespace) | when `honeypot` is on |
| `scan` | `localhost/vedette-scan-nmap:<version>` built on the box from the signed base image `ghcr.io/knt048/vedette-scan` | host | only `NET_RAW` (ambient, `User=<sensor_uid>`) | when `sensor-active` is on (later: `scan`/`exposure`) |
| `greenbone` | upstream Greenbone Community Containers, digest-pinned | bridge `vedette-int` | per upstream | when `scan-credentialed` is on |

Registry: `ghcr.io/knt048/vedette-<service>`, a constant in `vedette-host` (question A3 is closed); `ghcr.io` is already in `PRIVACY.md` flow 6. A box behind an HTTP(S) proxy: set `[engine] env = ["https_proxy=…", "no_proxy=…"]` in `/etc/containers/containers.conf` (or `containers.conf.d/`); `vedette-host` runs `podman pull` with a minimal environment, so it does not inherit the shell's proxy variables.

### 2.1 core

| Item | Value |
|---|---|
| Contents | A static Go binary + embedded SPA + confirmed skills/recommendation packs (shipped with the release); runs `vedette serve`. The SPA is served by `core` itself on port 8443, same origin as `/api/v1`: the image is built with `make core-image` (which runs `make webui-dist` first, builds the web on the maintainer's machine, embeds it with `-tags webui`; if `internal/webui/dist/index.html` is missing the build fails); `/assets/*` is cached immutably, `index.html` and `/approve/*` are `no-store`; no reverse proxy, no CDN |
| User | non-root, `User=<core_uid>:<core_gid>` **fixed** from `host.conf`, not `UserNS=auto` (the peer's uid must be stable for the `SO_PEERCRED` check and the ownership check); `cap_drop=ALL`; `no-new-privileges`; read-only rootfs + tmpfs `/tmp` |
| Network | bridge `vedette-int`; publishes `8443:8443` **without an IP**: the box's only LAN address is the management address (SPAN has no IP, decoys live in `vedette-hp`), so changing the address with `net.apply` does not require restarting `core` and the GUI is reachable at the new address to confirm; `8444` (sensor protocol, mTLS) is not published to the LAN, only `127.0.0.1:8444` for the host-network containers; `core` listens on it when given the flags `-sensor-listen :8444 -sensor-creds /var/lib/vedette-creds` (flags absent = no listener; the unit's `Exec=` gains these two flags when the sensor listener is wired in) |
| Volumes | `<core_data>` (the `host.conf` directory, bind) → `/var/lib/vedette` (SQLite WAL, **master key `vedette.key`**, RAG index, uploaded documents); `/run/vedette` (the **directory** holding the `vedette-host` socket; the socket file itself is not bind-mounted); `vedette-creds-passive`, `vedette-creds-active` → `/var/lib/vedette-creds/{passive,active}` (**read-write only in `core`**: the sensors' key bundles); configuration templates read-only. A constant `PodmanArgs=--group-add=<sensor_gid>` lets `core` write key files `0640 core_uid:sensor_gid` |
| Ports | 8443/tcp (UI, API, SSE, osquery intake, osquery install script, the email approval page, the blocklist URL); **514/udp and 514/tcp** (syslog of the `logs` module): the box's port 514 is published to port **5514** inside the container (`-syslog-port 5514`), so no capability is needed (`NET_BIND_SERVICE` or a sysctl); devices point their syslog at the box's port 514. **6514/tcp** (syslog over TLS, RFC 5425): published to port **5515** in the container (the TLS listener listens on `-syslog-port` + 1), TCP only; while the listener is not running (module off) connections to 6514 are refused. **Port 514 must be free on the host**: Podman (rootful) holds `0.0.0.0:514` for the container, so if the host already has `rsyslog` (`imudp`/`imtcp`) or another syslog service listening on 514, `vedette-core` cannot start (and 8443 goes with it). How to free it: turn off rsyslog's network-receiving modules (remove `module(load="imudp")`/`imtcp` and `systemctl restart rsyslog`) or `systemctl disable --now` that service; check with `ss -lunt 'sport = :514'`. **Port 6514/tcp must also be free** for the same reason: rsyslog's TLS receiver (`imtcp` with `StreamDriver.Mode="1"`) usually listens on 6514; check with `ss -lnt 'sport = :6514'`. On a new box `install.sh` checks both 514 (udp and tcp) and 6514 (tcp) first and refuses if another program is listening; re-run on a box that already has its own installation, it does not check the ports (Vedette itself may be holding them). **Measuring the sender**: when the rootful unit is running, the device's source address must reach `logs` intact; `make syslog-ports-check` (run as root) checks it with a packet entering through a veth; measured on a real rootful machine on 2026-11-12: PASS, the sender address is preserved for UDP and TCP. **Old UDP flows after `core` restarts**: a device that sends UDP from a fixed source port without pausing sticks to an old conntrack entry (DNAT to the old container, or an entry created while `core`'s rule did not exist yet; the rootful test shows which), so after `podman restart`/an upgrade/a crash and automatic restart no packet reaches the new `core` (TCP is unaffected). `vedette-host` deletes the UDP entries with destination port 514 (`conntrack -D -f ipv4 -p udp --orig-port-dst 514`, once, as soon as it sees `core` running again: after a start the host did, or within 30 s for a systemd automatic restart; and always once at the first look after the host starts, so also at machine boot); the `conntrack` package is installed by `install.sh`; if the package is missing the log reports it once and old flows are not deleted. |
| Health check | `vedette healthcheck`: `GET https://127.0.0.1:8443/api/v1/setup` (an existing public route that reads the `org` row, so a 200 means the server, router, Host check and DB all answer) must return 200 within 3 s; pins the box's own certificate at `/var/lib/vedette/vedette-selfsigned.crt` if it can be read, and skips certificate verification if it cannot (loopback only, sending nothing but a GET with no credentials); no proxy, does not open the DB, needs no master key. Interval 30 s, start-period 60 s, 3 failures = unhealthy |
| Depends on | none (starts first) |

**Where the master key lives.** The master key is at **`<core_data>/vedette.key`**, where the host's `backup.*` reads it and `backup.restore` writes it back; the `core` unit mounts the **directory** `core_data` of `host.conf` (path strictly checked: absolute, clean, only `[A-Za-z0-9._-]`, no `:`, whitespace or newline, so no line can be injected into the unit) at `/var/lib/vedette` and has **no** `-key` flag or separate key mount: `core` uses the defaults `-key /var/lib/vedette/vedette.key` and `-db /var/lib/vedette/vedette.db`, so the key `core` reads is exactly the key a backup contains and `backup.restore` writes back. There is no longer a `vedette-data.volume` or an `/etc/vedette/master.key`. `vedette-host -bootstrap` creates `core_data` (0700, `core_uid:core_gid`, under a checked root-owned parent) if missing and refuses an existing directory with the wrong owner/mode; `core` creates the key on first run. Changing `core_data` in `host.conf` makes the installed units "not the host's": re-running `-bootstrap -force-units` or `container.*` will refuse.

### 2.2 sensor

| Item | Value |
|---|---|
| Contents | `vedette-sensor passive`: the `capture` half of `sensor-passive` (DHCP/ARP/mDNS/SSDP/LLDP, SPAN metadata analyzer); receives `config` by long-poll, sends observations and heartbeats (`specs/sensor-protocol.md`). No nmap, no syslog (later, `logs` is not built), no DB (the binary does not link `database/sql`/SQLite) |
| Image | `deploy/containers/sensor/Containerfile`: multi-stage, a static `vedette-sensor` (`CGO_ENABLED=0`: pure-Go AF_PACKET, no libpcap) on a digest-pinned `distroless/static` (no shell, no apt), at `/vedette-sensor` exactly the `HealthCmd=` path, an exec-form `ENTRYPOINT`, default `USER 65532:65532` (the unit overrides it with `User=`), `-X main.version=<SemVer without v>`. All pins are in `deploy/containers/pins.env`; `make sensor-image`, effect check `make images-check` |
| User | `User=<sensor_uid>:<sensor_gid>` from `host.conf`, **no `UserNS`** (a child user namespace's capabilities do not cover the host's network namespace); `NoNewPrivileges`; read-only rootfs + tmpfs `/tmp` |
| Network | **host** (it needs to see the real LAN and the SPAN card) |
| Capability | `DropCapability=ALL`, **only** `AddCapability=NET_RAW` (AF_PACKET capture; Podman puts it in the ambient set for a non-root uid: **to be verified in the lab**, fallback UID 0 + `NET_RAW`). No `NET_BIND_SERVICE` until syslog exists; never `NET_ADMIN` (the SPAN card is set promisc, no IP, by `vedette-host`) |
| Volumes | `vedette-creds-passive` → `/var/lib/vedette-creds` **read-only** (the `passive` role key bundle, `0640 core_uid:sensor_gid`); no writable volume, in-memory queue |
| Ports | no listening port |
| Health check | `vedette-sensor healthcheck`: the process touches the file `/tmp/vedette-sensor.heartbeat` (tmpfs) after each heartbeat that `core` accepts; the check reads the file's age, which must be under 60 s (2 beats of 30 s). Needs no key or network. No beat yet within the start-period (30 s) means not healthy. It does not check for packets from SPAN (warning only, not unhealthy; later). With the module off, `core` returns 409 and the heartbeat stops so the sensor becomes unhealthy: the host runs `sensor` only when the module is on |
| Channel | mTLS, **the sensor calls out to `core`** (`https://127.0.0.1:8444`), role `passive` |

### 2.3 honeypot

| Item | Value |
|---|---|
| Contents | **one** OpenCanary (BSD-3) process listening on every address of the container + honey tokens; hits are written to `log/opencanary.jsonl`, configuration is read from `config/` |
| Network | the network namespace **`vedette-hp`**, created and owned by `vedette-host`; the unit has `Network=ns:/run/netns/vedette-hp` and no other network (no `vedette-int`, no path to `core`: hits go through a file). Each secondary IP/decoy is **one macvlan link with its own MAC** on the management card, added/removed by the host with `decoy_ip.*` without restarting the container. In the namespace: `arp_ignore=1`, `arp_announce=2`, `rp_filter=2`, `ip_unprivileged_port_start=0`, a separate routing table per IP, and an nft ruleset that blocks every new outbound connection (only replying to inbound connections) |
| Capability | **none** (`DropCapability=ALL`, no `AddCapability`): `ip_unprivileged_port_start=0` is a per-namespace sysctl so binding the trap's low ports (INV-2 of honeypot) needs no `NET_BIND_SERVICE`. Namespace sysctls are set only by `vedette-host`: the unit has `ContainersConfModule=/usr/lib/vedette/honeypot-containers.conf` (`[containers] default_sysctls = [{append=false}]`, a file of the `.deb` package) because from `UserNS=auto` crun may not write sysctls of a namespace that belongs to the host, so Ubuntu 26.04's default `net.ipv4.ping_group_range` kept the container from starting (#486). The image runs `USER 1000:0` from the first command (it does not start as root): `init.py` is process 1, reading Samba's audit from `smbd`'s stdout (`full_audit:syslog = false`, no `/dev/log`). The image contains OpenCanary + Samba (a separate process, GPL-3, not linked) + `init.py` |
| Volumes | `config/` mounted read-only, `log/` is a tmpfs volume `vedette-hp-log` (64 MiB, 1024 files) writable with `:U` (podman sets the owner to the image's uid 1000, since `UserNS=auto` picks its range at start; `init.py` sets mode 0755 so `core` reads through the "other" bit); the postinst still creates the old `log/` directory when absent (no longer used); no box certificate (`config/` has `https.pem` (the trap HTTPS's own key + self-signed certificate, one file) only when a Trap IP has HTTPS, made by core and removed when none remains or when the module is off), no DB. `podman inspect` reports `HostConfig.UsernsMode: private` for `UserNS=auto` (inspect has no "auto" value; the self-allocated range is in `HostConfig.IDMappings`; Podman 5.7.0) |
| Ports | 22, 80, 445, 1433, 3389 **only on the secondary/decoy IPs** (INV-2 of honeypot); not on the management IP |
| Health check | `/vedette honeypot healthcheck`: reads `opencanary.conf` (`/var/lib/vedette/honeypot/config/`, mounted read-only), takes the port of the first enabled service that has a `.port` key (`smb` has none: that port belongs to Samba), then connects TCP to `127.0.0.1:<port>` within 2 s (`lo` is up and `oif lo accept`; a connection from loopback is dropped by `core` as an impossible real source); if no OpenCanary service is enabled it is healthy (nothing to listen on). It does not call `core`. **The `honeypot` image must contain `/vedette`** (a static binary, 0755): the image is built by the project, it is not the stock OpenCanary image |
| Container count | **one** container for all IPs; the draft's "one container per IP" is dropped (question A5 is closed) |
| MAC | local-administered by default, generated with an HMAC of the IP and the installation's key; `oui` is optional for the vendor prefix of the fake role (`host-api.md` §6.6) |
| Constraints | The secondary IP must be outside the customer's DHCP range (guidance in the wizard); macvlan does not work on Wi-Fi and is blocked by the MAC policy of VMware/Hyper-V vSwitches (§4) |

### 2.4 scan and greenbone

`scan`:

| Item | Value |
|---|---|
| Contents | `vedette-sensor active`: the nmap worker of `sensor-active`; long-polls jobs `{shape, rate, targets, timeout_s}`, builds argv with `nmapargv` + `ValidateNmapArgs`, runs `/usr/bin/nmap` through `core/exec`, returns XML; one job at a time; 60 s lease. nuclei jobs run the pinned `/usr/local/bin/nuclei`, with the safe template pack in the image |
| Base image (signed, released) | `deploy/containers/scan-base/Containerfile`: digest-pinned Debian 13 slim + a static `vedette-sensor` at `/vedette-sensor` + **nuclei v3.11.1** built from source (a tag archive pinned by SHA-256, checked before extraction; pinned Go and a patched `go.mod`/`go.sum`; a mismatch turns the build red) at `/usr/local/bin/nuclei` + the template pack (`make scan-pack`, `scripts/scanpack`) at `/usr/share/vedette/nuclei-templates` and the index at `/usr/local/share/vedette/nuclei-pack/index.json`. **No nmap** (a test enforces it). The `scan` unit runs with `RunInit=true` (podman `--init`, catatonit reaps orphaned processes; `vedette-sensor` is not a subreaper) |
| Image | **built on the box** by `vedette-host`: a constant Containerfile (`deploy/containers/scan/Containerfile.onbox`; `vedette-host` carries a copy in its binary, `host/ops/scanbuild.go`, and a test keeps the two identical) `FROM` the digest of the signed base image `ghcr.io/knt048/vedette-scan` (Debian slim + `vedette-sensor` + nuclei + template pack) + `apt-get install --no-install-recommends nmap` (the **Debian** package repository `deb.debian.org`, from inside the build container, even on an Ubuntu box; the host's apt mirror does not apply; PRIVACY flow 6); tag `localhost/vedette-scan-nmap:<version>`; `container.pull scan` pulls the base image by digest (minisign and cosign checked like every service) and then runs `podman build` with fixed argv (`--pull=never --no-cache`, no build args from input) and checks by effect with `podman run --network none … nmap --version` (≥ `NMAP_MIN_VERSION`, recording the installed version in the pull record); if the build fails, the previous image is kept and the run is `failed` with code `scan_build_failed`. **The `scan` unit pins the image by ID** (`Image=<64 hex>`; there is no registry digest): the host's "digest" for `scan` is `sha256:<ID>` and the effect check reads `Image` from `container inspect`. If the box cannot reach `deb.debian.org` there is no active scanning (no image, no worker, `sensor-active` reports `unavailable`): `-bootstrap` skips `scan` (a `skipped scan` line, exit 0, `core`/`sensor`/`honeypot` are still installed) and a later `container.pull scan` tries to build again. The project does not distribute nmap (`LEGAL.md`) |
| User, capability | like `sensor` (§2.2): `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, `DropCapability=ALL` + `AddCapability=NET_RAW` (nmap `--privileged`), `NoNewPrivileges`, read-only rootfs + tmpfs |
| Network | host |
| Constraints | the worker holds no scope: `core` is the only consenting party and hands out only private IPv4 within three templates; each probe writes `sa_probe` before the job is handed out (INV-9) |
| Volumes | `vedette-creds-active` → `/var/lib/vedette-creds` **read-only**; tmpfs for temporary output; no durable volume |
| Health check | `vedette-sensor healthcheck`: like `sensor` (§2.2): the `active` role's heartbeat file is younger than 60 s (30 s heartbeat; job polling does not count, the heartbeat is the link's pulse) |


`greenbone` (optional; the customer sees the name **OpenVAS**; built for the deep scan of External exposure, exposure INV-25): **not** a Quadlet unit but Greenbone's official compose project (`greenbone-community-edition`), which `vedette-host` runs with `podman compose` (host-api §6.16): the official file digest-pinned + Vedette's override (`deploy/greenbone`, installed to `/usr/lib/vedette/greenbone/`); Greenbone's web interface (gsa, gsad, nginx) does not run so no port is published; the SCAP/CERT data (scap-data, cert-bund-data, dfn-cert-data) does not run, and what they left on a box that had run them is cleaned up on the next `up` (§2.5, host-api §6.16); `core` talks to `gvmd` with GMP over the socket in the host directory `/run/vedette-greenbone/gvmd` (the `core` unit mounts `/run/vedette-greenbone` read-only; that directory is `0750` root, `core`'s group, so only root and `core` reach the socket); the GMP password is in `core/secrets`. `vedette-host` turns on `podman.socket` (podman's API, root only) when it is not on and uninstall turns it off again in exactly that case. GPL/AGPL: a separate container, unmodified images. Authenticated scanning (S-SCAN-5) is still not built.

### 2.5 Lean tools

Each integrated tool runs only the part Vedette uses (LEAN-1/2/3). **The rule for a new tool:** list what Vedette asks of it, switch off the rest, and add a row to this table with measurements from a real test box. Numbers are measured only on a real box (measuring commands: the container cgroup's `memory.peak`, `du -sh` of volumes, PostgreSQL schema sizes, `podman system df -v`).

| Tool | Switched off | Why it is safe (source) | RAM idle / peak before → after | Disk before → after | Time/CPU before → after | Measured (date) |
|---|---|---|---|---|---|---|
| Greenbone CE | web GUI (gsa, gsad, gvm-config, nginx), gvm-tools, log tail (`openvas`) | Vedette speaks GMP to the gvmd socket itself (`modules/exposure/gmp.go`); gsad only turns HTTP into GMP for the browser; `openvas` only prints the config and tails a log (Greenbone's compose); nothing listens on 443/9392 | not measured (already off on the test box) | images never pulled: gsa 14.4 MB, gsad 116 MB, nginx 167 MB, gvm-config 89.5 MB, gvm-tools 180 MB (sizes of the old trial's images on the test box) | — | before 2026-11-14 18:29 UTC; after 20:00–20:05 UTC |
| Greenbone CE | SCAP + CERT data (scap-data, cert-bund-data, dfn-cert-data; gvmd's `scap`/`cert` schemas) | Vedette reads a result's CVE ids from the NVT's own refs; only `get_info`/`get_resource_names` need SCAP/CERT and Vedette never sends them (exposure test); gvmd without the feed files makes two empty schemas once and then reports them current, no lock loop (gvmd 26.43.0 source) | memory.peak during the feed load: scap-data 3430 MB, cert-bund-data 254 MB, dfn-cert-data 118 MB (with gvmd 1513 MB, pg-gvm 1079 MB, ospd-openvas 869 MB, notus-data 803 MB, vulnerability-tests 729 MB, redis 396 MB); now gvmd 556 MB, pg-gvm 232 MB, ospd 343 MB → the three data containers no longer run (their 3.8 GB of peaks gone); idle after the drop gvmd 388 MB, pg-gvm 215 MB, redis 153 MB, ospd-openvas 147 MB | PostgreSQL: scap 37 GB, cert 196 MB (public 977 MB, pg_toast 712 MB, vts 269 MB); volumes scap_data 11 GB, cert_data 182 MB (psql_data 26 GB, notus 736 MB, vt 639 MB); images scap-data 1.75 GB, cert-bund-data 135 MB, dfn-cert-data 64.8 MB → PostgreSQL scap 784 kB, cert 352 kB (the empty schemas gvmd makes once; public 989 MB, vts 272 MB, pg_toast 43 MB); volumes scap_data and cert_data removed, psql_data 2.1 GB; the three images removed; the box's free disk 61 GB → 85 GB | first feed load: not measured (enabled 12:32 UTC, did not finish before the old 20-minute login wait gave up) → gvmd rebuilt the empty SCAP/CERT schemas once (19:57 UTC, aborted in seconds, no second rebuild after that) and took the GMP login at once; a Full-and-fast scan of a lab host (port 22) took 210 s with 3 Low results at QoD ≥ 70, CVE-1999-0524 on one, as in the trial (202 s, 3 Low); a first load from empty volumes was not measured (an upgraded box); weekly update: 7 images → 4 | 2026-11-14 18:29 UTC (an OpenVAS scan running) |

### 2.6 Resource limits and health (proposal, for a 4-core / 8 GB box)

| Container | CPU | RAM | PIDs | Notes |
|---|---|---|---|---|
| `core` | 2 | 2 GiB | 512 | SQLite + RAG FTS5 |
| `sensor` | 1 | 512 MiB | 256 | the cap is adjustable in Box network; target ≤5% of one core at 100 Mbps |
| `honeypot` | 0.5 | 256 MiB | 128 | one container for all decoys |
| `scan` | 2, low `CPUWeight` | 1 GiB | 512 | bursts per job; time window + rate (S-SCAN-4) |
| `greenbone` (the whole group) | 2 | ~3 GiB (re-measure) | per upstream | with it on, 16 GB of RAM is advisable (proposal) |

`core`'s argon2 password-hashing gate (`core/auth/hashgate.go`): the number of concurrent runs = `max(1, GOMAXPROCS/2)`, at most 1/4 of `GOMEMLIMIT` divided by 64 MiB per run. With `--cpus=2` Go 1.26 sets GOMAXPROCS = 2, so on the box only **1 run, 64 MiB** at a time; a second login request queues (queue of 4, waits at most 2 s) and then gets 503 `server_busy` with `Retry-After`. `Config.MaxHashing` is not in `core`'s configuration or flags (`cmd/vedette`), so it cannot be tuned on the box; to allow more concurrent runs, raise `--cpus` in the quadlet.

The total without greenbone is ≈ 3.75 GiB, leaving the rest to the OS and page cache. Swap is off in the containers (`memory-swap` = `memory`). How to measure: `podman stats` in a load test (1,000 devices, 50k IOCs). When a limit is exceeded the container is OOM-killed and `Restart=always` rebuilds it; the event appears on the module health page.

## 3. `vedette-host`

A small root systemd process that replaces the old design's `vedette-updater`. `core` calls it over the Unix socket `/run/vedette/host.sock` (mode 0660 `root:vedette`, no TCP listening). The command list, parameters, error codes and live processes: `specs/host-api.md`. Only the **responsibilities** and **invariants** are stated here.

| Group | Responsibility | Basis |
|---|---|---|
| OS updates | check patches (apt), install security patches / all, unattended-upgrades, reboot needed, release support end date, schedule by maintenance window, reboot now/scheduled; an OS release upgrade is guidance only | S-CORE-7 |
| Network | list of cards and interface counters; the management card (DHCP/static, gateway, DNS) through the host's single netplan file, with a confirmation window; the SPAN card (no IP, promisc); secondary IPs for traps (macvlan in the `vedette-hp` namespace); NTP (chrony). The MAC count seen and the time of the last received packet are measured by `sensor`, not by the host | — |
| Containers | check the index, the manifest (minisign) and the cosign signature in the manifest with the project's code, pull images by digest, render + apply Quadlet units from a constant template, start/stop/restart, health gate, roll back to `previous` (with a DB restore when `rollback.safe=false`) | — |
| Vedette update | fetch the signed `release.json`, check the cohort, replace containers in sequence, health gate, rollback | `UPDATES.md` |
| Backup | store and rotate snapshots that `core` makes, restore, check disk usage | §10 |
| "This box" | read dpkg and return the package list (confidence 1.0) so `inventory` can match vulnerabilities | S-INV-5 |
| Status | the status/health of each container, update log | §11 |

Invariants (checked by contract tests in `modules/core/`):

- Runs only **commands in the fixed list**; parameters are type-checked before use; no shell, no free-form command strings (SYS-1, SYS-2).
- One job at a time (a lock); a running job is not skipped when `core` restarts.
- The DB is backed up before an operation that could damage data (a Vedette update, a large system-package upgrade); health is checked afterwards; every step is audited (SYS-3).
- There is no path for AI to call `vedette-host`; only `core` code, after a user with enough permission performs the operation (or a configured schedule) (ARCHITECTURE §7.2).
- No business logic, and it does not read `core`'s DB.
- Idempotent: repeating the same command does not change a state that has been reached.

### 3.1 The `vedette-host` `.deb` package

`make host-deb VERSION=x.y.z [ARCH=amd64|arm64]` builds `dist/vedette-host_<version>_<arch>.deb` with nfpm (`deploy/deb/nfpm.yaml`, three POSIX scripts `deploy/deb/{postinst,prerm,postrm}`); the installer installs this package with `apt-get install ./…deb` so apt resolves `Depends`.

| | |
|---|---|
| **Installs** | `/usr/lib/vedette/vedette-host` (static binary, 0755), `/usr/lib/vedette/honeypot-containers.conf` (0644, the containers.conf module of the honeypot unit, verbatim `deploy/deb/honeypot-containers.conf`; #486), `/usr/lib/vedette/apparmor-containers.conf` (0644, the module of every unit, `apparmor_profile = "vedette-container"`), `/etc/apparmor.d/vedette-container` (0644, the AppArmor profile of every container, verbatim `deploy/deb/vedette-container.apparmor`; the only conffile, like every shipped Debian profile), the unit `vedette-host.service` into `/usr/lib/systemd/system/` (verbatim `deploy/systemd/vedette-host.service`), `/usr/share/doc/vedette-host/{copyright,NOTICE,third-party-licenses}` (the last file generated by `scripts/hostlicenses` at build time). |
| **Loads the AppArmor profile** (postinst) | only when `aa-enabled --quiet` (like `dh_apparmor`; if AppArmor is off or cannot be managed, for example inside a container, it is skipped and Podman also ignores the profile name): step 1, before creating anything: the file must exist (dpkg does not put a deleted conffile back; the message names the command `dpkg -i --force-confmiss --force-confdef --force-confold /var/lib/vedette-host/selfupdate/packages/vedette-host_$(/usr/lib/vedette/vedette-host -version)_$(dpkg --print-architecture).deb`: reinstall from the package `install.sh` keeps, since no apt source has `vedette-host`), there is no shortcut link `/etc/apparmor.d/disable/vedette-container` (`aa-disable`; if there is, it refuses, because no container could start), and a trial compile with `apparmor_parser --skip-kernel-load --skip-cache` succeeds; then `apparmor_parser --replace --skip-read-cache --write-cache` and an effect check for `vedette-container (<mode>)` (any mode, like the host's and Podman's test) in `/sys/kernel/security/apparmor/profiles`; on failure the package stops. At machine boot `apparmor.service` loads it from `/etc/apparmor.d` before every unit; `vedette-host` at start reloads it if the kernel lacks it (host CONTRACT). `remove` keeps the file (conffile), `purge` deletes it; the loaded profile stays in the kernel until the next boot. |
| **Refuses** (postinst, before creating anything) | an existing `vedette`/`vedette-sensor` account that is not a system account (id outside the `login.defs` range, a group with members, a login shell, a different primary group); a directory that is a symbolic link; an existing `core_data` or `log/` with the wrong owner/mode; another owner's `/etc/subuid` range overlapping podman's range; when AppArmor is on: the profile `/etc/apparmor.d/vedette-container` is missing, disabled by a link in `disable/`, or does not compile |
| **Depends** (minimum) | `podman (>= 4.8)` (Quadlet from 4.4, `ContainersConfModule=` from 4.8: all four units use it, the AppArmor module, with the honeypot adding a sysctl module #486), `systemd (>= 254)`, `nftables`, `iproute2`, `procps`, `chrony`, `netplan.io`, `unattended-upgrades`, `passwd` |
| **Creates** (postinst, re-running changes nothing) | the system group+user `vedette` (`core_uid`, `core_gid` = `socket_gid`) and `vedette-sensor` (`sensor_uid`/`sensor_gid`), ids assigned by the system; `/etc/vedette` 0755 root; `/var/lib/vedette-host` 0700 root; `/etc/containers/systemd` 0755 root; `/var/lib/vedette` (`core_data`) 0700 `vedette`; `/var/lib/vedette-honeypot` 0755 root with `config/` 0755 and `log/` 0750 owned by `vedette`; a line `containers:2147483647:2147483648` in `/etc/subuid` and `/etc/subgid` if there is no `containers:` line yet (for the honeypot's `UserNS=auto`) |
| **Enables, does not start** | `deb-systemd-helper enable` (first install; an upgrade keeps what the administrator turned off) and `daemon-reload`; the unit does not run until the installer writes `/etc/vedette/host.conf` (from `getent`, the package does not write it) and starts it; `ConditionPathExists=/etc/vedette/host.conf` makes the unit skipped at machine boot while the file is absent (no crash loop). A package upgrade (`$2` non-empty) runs `deb-systemd-invoke try-restart vedette-host.service` after `daemon-reload`: a running host is restarted (together with `vedette-honeypot`, `Requires=`), a stopped host stays stopped. |
| **Removes** | `remove`: stops and disables the unit, deletes the binary, the unit and the two containers.conf modules (keeps the AppArmor profile, a conffile); after `remove` (not purge) the `core`/`sensor`/`scan`/`honeypot` units still on disk point at the deleted modules so they **do not start** until the package is reinstalled (Podman reports the missing module). `purge`: additionally forgets the enabled state, deletes `/etc/apparmor.d/vedette-container` (dpkg) and its compiled cache file `/var/cache/apparmor/*/vedette-container` (postrm, like `dh_apparmor`); the loaded profile stays in the kernel until the next boot. **Both keep data**: `/var/lib/vedette` (the database, master key), backups, `/var/lib/vedette-host`, `/var/lib/vedette-honeypot`, `/etc/vedette`, Quadlet units, users/groups, the subuid/subgid lines. To remove everything: `RUNBOOK.md` §1.3. |

Checks: the Go test `deploy/deb` (in `make check`) reads back the built package; `make host-deb-check` (optional, pulls images) installs twice in a Debian 13 and an Ubuntu 24.04 systemd container and compares the state. Still open: the owner of the honeypot `log/` under `UserNS=auto`; self-upgrade must run dpkg through `systemd-run`.

## 4. OS and hardware support matrix

Rule: an OS outside the table makes `install.sh` stop and say so clearly (no half installation). `vedette-host` and `vedette-host -bootstrap` run only on the Debian/Ubuntu in this table (Linux, root): any other OS → refused with `not_appliance` (exit code 3), nothing written.

| Operating system | Architecture | Status | Notes |
|---|---|---|---|
| Ubuntu 24.04 LTS | x86_64, arm64 | **supported** | Podman 4.9 has Quadlet (no drop-in, no `Notify=healthy`); netplan + networkd present; NTP defaults to timesyncd, the installer replaces it with chrony |
| Ubuntu 26.04 LTS | x86_64, arm64 | **supported** | Podman 5.x (re-check the version in the lab); netplan + networkd; chrony is the default (since 25.10) |
| Debian 13 | x86_64, arm64 | **supported** | Podman 5.x; the installer installs `netplan.io` (1.1.2 in trixie) and chrony |
| Debian 12 | — | **not** supported for the Appliance kind | Podman 4.3, no Quadlet yet (from 4.4); use the Container-only kind |
| Others (RHEL, Alpine…) | — | not supported for the Appliance kind | Use the Container-only kind |

**The box's network is netplan with the `networkd` renderer on all three releases.** `vedette-host` owns netplan **exclusively**: there is only `/etc/netplan/90-vedette.yaml` (0600) written by the host, plus the temporary overlay `/run/netplan/90-vedette.yaml` during the confirmation window. `install.sh` (idempotent, verified by effect) must: install `netplan.io` on Debian; write `/etc/cloud/cloud.cfg.d/99-vedette-network.cfg` with `network: {config: disabled}` so cloud-init does not rewrite the network; move every other `*.yaml` in `/etc/netplan` and `/run/netplan` elsewhere (kept for a manual restore); not leave ifupdown or NetworkManager managing a card; then let the host write the first file from the running configuration. If any step is missing, every `net.apply` gets `412 net_backend_unsupported` (the host never reads a netplan file it did not write). Clock: the installer installs chrony and owns `chrony.conf` (only `sourcedir /etc/chrony/sources.d`, not the distro's pool); the host writes `vedette.sources`.

| Item | Minimum (target 1,000 devices) | Notes |
|---|---|---|
| CPU/RAM/disk | 4 cores / 8 GB / 64 GB SSD | + `greenbone`: 16 GB advisable (proposal) |
| NIC | 1 (management) | SPAN needs 1 more card (USB is fine); configure SPAN/TAP on the switch (per-vendor guidance in Box network) |
| Wired network | required for SPAN, macvlan traps | Wi-Fi does not support macvlan/SPAN |
| VM | allowed | the vSwitch must allow promiscuous mode/forged MACs for macvlan and SPAN (VMware: Promiscuous Mode, Hyper-V: MAC spoofing; a Proxmox bridge is usually fine); otherwise decoys are silent: check by effect in Box network and in the lab |
| Clock | NTP required (chrony) | TOTP, mTLS certificates and approval-token expiry depend on the time |
| Install kind | a fresh Ubuntu 24.04/26.04 or Debian 13 by script; ISO/VM image **later** | |

## 5. The two install kinds

| | **Appliance** | **Container-only** |
|---|---|---|
| Installed with | `install.sh` on a clean Ubuntu 24.04/26.04 or Debian 13 (later: ISO/VM image) | Docker Compose v2 on the customer's existing Docker or Podman (`podman compose`): `deploy/compose/container-only/`, guide `INSTALL-CONTAINER.md`; no Quadlet for this kind |
| Runtime | Podman + Quadlet, rootful | Docker or Podman, the customer's choice; rootless can only run `core` (the sensor needs root) |
| `vedette-host` | yes | no |
| OS updates, reboot (S-CORE-7) | in the GUI | **no**; the GUI says there are none and that it is the customer's own job, no button (S-CORE-7) |
| Box network: cards, SPAN, secondary IPs, NTP | configured in the GUI | **no**; the customer prepares the SPAN card (promisc, no IP) beforehand; the card list to choose from is the cards the sensor reports in its heartbeat |
| Vedette self-update | yes, staged, health gate, rollback | **no**; Settings → Updates names the new release and shows the `pull`/`up` commands with its image digests for the customer to run (`INSTALL-CONTAINER.md`); an update is a new `vedette.env` file of the release |
| cosign verification | `vedette-host` checks it itself (minisign for the index/manifest, cosign in the manifest) before pulling by digest | the customer verifies it: minisign for `vedette.env`, `cosign verify --key` for each image (the signature is pushed to ghcr); the commands are in `INSTALL-CONTAINER.md`, the GUI shows them later |
| Backup | DB snapshot + rotation by the host | **no** host backup; the master key and the DB both sit in the `data` volume, the customer backs up the volume |
| SPAN / syslog 514 | available | syslog: add `compose.syslog.yaml` (core listens on 5514, publishes 514 on the address the customer sets); SPAN: add `compose.sensors.yaml` (Linux, root, card already prepared; sensor uid 0 with only `NET_RAW`, scan 65532 with no capability) |
| Traps on secondary IPs | macvlan in the `vedette-hp` namespace created by the host | **not in the first version**: there is no code path for traps without `vedette-host` (the module says why); the old row "traps on the main IP" is dropped |
| "This box" (S-INV-5) | the host's dpkg package list | the device exists, named `vedette`, **with no package list** (answers open question A7) |
| OpenVAS (Greenbone) | optional deep scan of External exposure, started by `vedette-host` | **no**: it needs `vedette-host` |
| In the image/compose | — | `core` and `scan` run `65532:65532`, `sensor` runs uid 0, group 65532 (reads its certificate, 0640), with only `NET_RAW` (Docker grants extra capabilities only to root: measured on Docker 29.1.3 a non-root user gets 0, while Podman 5.7.0 grants them; the fallback is already defined); the data directory is already in the `core` image so a new volume needs no root step |
| Warning | — | Docker `-p` bypasses the UFW firewall (see §12): bind ports to the right IP |

The limits of the Container-only kind must be visible in the GUI (Settings → Updates, Box network): the title "Not available on this install" with the box's sentence, without hiding the item (S-CORE-1: say clearly where something is missing and why; this exists, `web/src/components/common/States.tsx`); the remaining "what the customer does themselves" sentences are in S-CORE-9 and related stories. Minimum Docker/Podman version (B8): record the versions tried (Docker Engine 29.1.3 + Compose 2.40.3; Podman 5.7.0 with compose v2) and then the lab's versions; do not guess a floor.

There is only this one second install kind: Compose, not Quadlet.

## 6. Example units

The files below are **illustrations**. The real `vedette-<service>.container` units (the text here is a template; the constant template in `host/ops/quadlet.go` and the golden files `host/ops/testdata/units/` are the authority) are built **entirely** by `vedette-host` from a constant template in the binary: the only fill-in places are the digest, the `[Install] WantedBy=` line (durable on/off, since a generated unit cannot be `systemctl enable`d/`disable`d), `core_uid`/`core_gid` and `sensor_uid`/`sensor_gid` from `host.conf`; no drop-ins (Podman 4.9 on Ubuntu 24.04 does not document them), no manual edits. Contract tests on the built units: no `--privileged`, capabilities per the §2 table, `Network=host` only for `sensor`/`scan`, honeypot only `ns:/run/netns/vedette-hp`; `sensor`/`scan` have `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, only `NET_RAW`, each mounting only its own role's key volume, read-only.

### 6.1 Quadlet (appliance)

`/etc/containers/systemd/vedette-int.network`

```ini
[Network]
NetworkName=vedette-int
Subnet=172.30.77.0/24
Gateway=172.30.77.1
# A fixed bridge name so vedette-host can bind DOCKER-USER rules to it. PodmanArgs= is a key every supported Podman knows (4.9, 5.x); InterfaceName= exists only from Podman 5.7
PodmanArgs=--interface-name=vedette0
# The subnet is chosen by vedette-host so it does not collide with the LAN range
```

(There is no longer a `vedette-data.volume`: `core`'s data is the `core_data` directory of `host.conf`, mounted straight into the unit.)

`/etc/containers/systemd/vedette-creds-passive.volume` (and `vedette-creds-active.volume` likewise)

```ini
[Unit]
Description=Vedette sensor credentials (passive role)

[Volume]
VolumeName=vedette-creds-passive
# host-side owner: core writes, the sensor's group reads (Quadlet 4.9 has User=/Group= for .volume)
User=<core_uid>
Group=<sensor_gid>
```

The two key `.volume` files are written by `vedette-host` from constant text, with the unit's safe writer, right before it writes the `core`/`sensor`/`scan` units (bootstrap, start, switch, rollback); there are no other keys. The setgid bit of each role directory cannot be set with `.volume`, so nothing relies on it: `core`'s `pki.WriteBundle` (a member of `sensor_gid` thanks to `--group-add`) `fchown`s the key-bundle file to the role directory's group before renaming it (file 0640); confirmed in the lab. The volume is written only at bootstrap and `container.start`, not at rollback; changing `core_uid` later does not re-chown an existing volume.

`/etc/containers/systemd/vedette-core.container`

```ini
[Unit]
Description=Vedette core
After=network-online.target vedette-host.service
Wants=network-online.target

[Container]
ContainerName=vedette-core
Image=ghcr.io/knt048/vedette-core@sha256:<digest>
Pull=never
Network=vedette-int.network
# No IP: changing the management address with net.apply does not restart core
PublishPort=8443:8443
PublishPort=127.0.0.1:8444:8444
# Read-only MCP: the host's loopback only; the runtime forwards to the container's address, not to its loopback, so core (which sees /run/.containerenv) listens on 0.0.0.0:8765 in its own namespace by default; -mcp-listen is not passed so an older image can still run this unit
PublishPort=127.0.0.1:8765:8765
# syslog of the logs module: the box's 514 -> 5514 in the container (an unprivileged port, no capability needed); UDP and TCP, every address like 8443
PublishPort=514:5514/udp
PublishPort=514:5514/tcp
# syslog over TLS: the box's 6514 -> 5515 in the container (-syslog-port + 1), TCP only
PublishPort=6514:5515/tcp
Volume=<core_data>:/var/lib/vedette
Volume=/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config
# the honeypot's log/ is a capped tmpfs volume, see vedette-hp-log.volume below
Volume=vedette-hp-log.volume:/var/lib/vedette/honeypot/log:ro,noexec
# the whole directory, not the socket file: bind-mounting a file keeps the old inode and loses the connection when the host recreates the socket
Volume=/run/vedette:/run/vedette
# OpenVAS's gvmd socket directory: the host creates it at start (0750 root, core's group), with gvmd/ inside it before each time it is turned on; read-only
Volume=/run/vedette-greenbone:/run/vedette-greenbone:ro
# the sensors' key bundles: read-write only in core
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds/passive
Volume=vedette-creds-active.volume:/var/lib/vedette-creds/active
ReadOnly=true
# a 64 MiB-capped tmpfs: a runaway temporary file cannot eat the container's whole 2 GiB of memory
Tmpfs=/tmp:size=64m
NoNewPrivileges=true
# apparmor_profile = "vedette-container": the .deb package's AppArmor profile replaces Podman's containers-default, so processes in the container can signal each other when crun stacks labels (NoNewPrivileges); every unit has this line
ContainersConfModule=/usr/lib/vedette/apparmor-containers.conf
DropCapability=ALL
# core_uid:core_gid from /etc/vedette/host.conf; NOT UserNS=auto (the peer's uid must be fixed)
User=<core_uid>:<core_gid>
LogDriver=journald
# a constant --group-add, core's only supplementary group: Quadlet 4.9 has no GroupAdd=; so core can chown the 0640 key-bundle file to the role directory's sensor_gid group (only a member of the group may)
PodmanArgs=--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 --group-add=<sensor_gid>
# Go's memory limit ~10 % below --memory=2g: the GC cleans up before the cgroup OOM-kills; core's argon2 gate reads this value: min(max(1, GOMAXPROCS/2), 1800 MiB/4/64 MiB = 7); with `--cpus=2` Go sets GOMAXPROCS = 2 so exactly 1 argon2 run at a time (64 MiB) remains, the number 7 is only the memory ceiling
Environment=GOMEMLIMIT=1800MiB
HealthCmd=["/vedette","healthcheck"]
HealthInterval=30s
HealthStartPeriod=60s
HealthRetries=3
# :8444 inside the container; on the host side only PublishPort=127.0.0.1:8444
Exec=-listen :8443 -sensor-listen :8444 -sensor-creds /var/lib/vedette-creds -syslog-port 5514

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

`/etc/containers/systemd/vedette-sensor.container`

```ini
[Unit]
Description=Vedette sensor (passive capture)
After=vedette-core.service
Wants=vedette-core.service

[Container]
ContainerName=vedette-sensor
Image=ghcr.io/knt048/vedette-sensor@sha256:<digest>
Pull=never
Network=host
# sensor_uid:sensor_gid from /etc/vedette/host.conf; NOT UserNS (raw socket on the host network)
User=<sensor_uid>:<sensor_gid>
DropCapability=ALL
# Podman puts the added capability in the ambient set for a non-root uid (checked in the lab; fallback UID 0 + NET_RAW)
AddCapability=NET_RAW
NoNewPrivileges=true
ContainersConfModule=/usr/lib/vedette/apparmor-containers.conf
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds:ro
LogDriver=journald
PodmanArgs=--memory=512m --memory-swap=512m --cpus=1 --pids-limit=256
HealthCmd=["/vedette-sensor","healthcheck"]
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=passive --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

The sensor runs a non-root uid, no `UserNS`, only `NET_RAW` (question A4 in ARCHITECTURE is closed). No `NET_BIND_SERVICE`: syslog 514 is received by `core` (publishing 514 → 5514 in the container, no capability), not by `sensor`. The lab checks: AF_PACKET can be opened and `nmap -sS`/`-O` can run with ambient `NET_RAW` together with `NoNewPrivileges` on Podman 4.9 and 5.x; if not, switch to UID 0 + `NET_RAW` (still no `UserNS`).

There is no `vedette-lan.network` (a Podman macvlan network) and no container per IP: a decoy is a macvlan link that `vedette-host` places in the `vedette-hp` namespace, with one shared container.

`/etc/containers/systemd/vedette-honeypot.container`

```ini
[Unit]
Description=Vedette honeypot (all decoys, namespace vedette-hp)
# vedette-host creates /run/netns/vedette-hp and only then reports READY=1 (Type=notify)
After=vedette-host.service
Requires=vedette-host.service

[Container]
ContainerName=vedette-honeypot
Image=ghcr.io/knt048/vedette-honeypot@sha256:<digest>
Pull=never
Network=ns:/run/netns/vedette-hp
# ip_unprivileged_port_start=0 in the namespace: NET_BIND_SERVICE is not needed
DropCapability=ALL
NoNewPrivileges=true
ContainersConfModule=/usr/lib/vedette/apparmor-containers.conf
ReadOnly=true
Tmpfs=/tmp
UserNS=auto
# default_sysctls = [{append=false}]: crun may not write vedette-hp's sysctls from UserNS=auto (#486); a file of the .deb package
ContainersConfModule=/usr/lib/vedette/honeypot-containers.conf
Volume=/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config:ro
Volume=vedette-hp-log.volume:/var/lib/vedette/honeypot/log:U,noexec
LogDriver=journald
PodmanArgs=--memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=128
HealthCmd=["/vedette","honeypot","healthcheck"]
HealthInterval=30s
HealthRetries=3

[Service]
Restart=always

[Install]
# present while the module is on; container.stop persist=true rebuilds the unit without this section
WantedBy=multi-user.target
```

The directory on the box is the constant `/var/lib/vedette-honeypot`; `core` mounts `config/` read-write and `log/` read-only under `/var/lib/vedette/honeypot`, the default of `-honeypot-dir`; `config/` and `log/` are mounted at the **same absolute path** in the container because `opencanary.conf` records the log path. The permissions of `log/` with `UserNS=auto`: `:U` makes the image's uid 1000 the owner, `init.py` sets mode 0755.

`/etc/containers/systemd/vedette-hp-log.volume`

```ini
[Unit]
Description=Vedette honeypot log (tmpfs, size-capped)

[Volume]
VolumeName=vedette-hp-log
Type=tmpfs
Device=tmpfs
Options=size=64m,nr_inodes=1024,nosuid,nodev,noexec
```

The honeypot's `log/` is **no longer a directory on the box's disk**: it is a tmpfs volume of at most 64 MiB and 1024 files (OpenCanary rotates 10 MiB × 3 copies, about 40 MiB, so there is enough room), so someone who takes over the container cannot fill the filesystem holding `vedette.db` by writing other files into `log/` (at the cap it is `ENOSPC` inside the container, with no effect outside it). `vedette-host` writes the `.volume` file from constant text, with the unit's safe writer, right before it writes the `core` or `honeypot` unit (like the two key volumes, §6.1); no keys, no `User=`/`Group=` (the honeypot's `:U` sets the owner). `noexec` is both in `Options=` and on the `Volume=` line of the two units: Podman's bind into the container has its own flags and does not carry the tmpfs's `noexec` across (`make honeypot-check` catches this), so only the `Volume=` line is effective inside the container. Podman mounts the tmpfs when the first container that uses the volume starts; `core` always runs so the volume survives a honeypot restart. **The log is lost when the box restarts** (tmpfs): acceptable because `core` reads each line into the database and the reader restarts on its own when the file is replaced or truncated (INV-16). Lines `core` has not yet read are lost when `core` and `honeypot` stop together (a reboot, or a honeypot restart while `core` is stopped); while `core` runs normally only the lines not yet read are lost (one poll cycle). **The `core` and `honeypot` units share this volume so they must be changed in the same pass**: if one unit still binds the old directory, `core` reads an empty tmpfs while the honeypot writes to disk, and every hit is lost without an error. An older installation (from before this volume) does not convert by itself (the old unit is "not the host's", INV-17): run `vedette-host -bootstrap -force-units` for **core and honeypot together**; bootstrap refuses (`invalid_args`, before writing anything) when only one of the two is written while the other still has the old bind. The remaining way to disk from a taken-over container is stdout/stderr into journald (`LogDriver=journald`): bounded by journald's `SystemMaxUse` (default 10% of the filesystem, at most 4 GiB), not by this 64 MiB. All 64 MiB is RAM counted against the honeypot's 256 MiB cgroup (`--memory-swap` equals `--memory`, it cannot be pushed to swap). Changing the cap needs `podman volume rm vedette-hp-log` after stopping `core` and `honeypot`: Quadlet's `podman volume create --ignore` does not change the options of an existing volume. The package no longer creates the directory `/var/lib/vedette-honeypot/log`; a box installed with an older version keeps the old unused directory (postinst does not check it or change its owner) until `install.sh --uninstall` removes `/var/lib/vedette-honeypot`.

`/etc/containers/systemd/vedette-scan.container`: like `sensor` (same `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, `DropCapability=ALL`, `AddCapability=NET_RAW`, `NoNewPrivileges`, `ContainersConfModule=/usr/lib/vedette/apparmor-containers.conf`, `ReadOnly`, tmpfs), but with `RunInit=true` and `Image=<64-hex ID>` of the image built on the box `localhost/vedette-scan-nmap:<version>` (pinned by ID), `Volume=vedette-creds-active.volume:/var/lib/vedette-creds:ro`, `Volume=/var/lib/vedette-fence:/var/lib/vedette-fence:ro` (a copy of the host's domain-fence key, owned by the sensor user, `0400`; only the scan unit mounts it, core never does), `PodmanArgs=--memory=1g --memory-swap=1g --cpus=2 --pids-limit=512 --cpu-shares=128`, `Exec=active --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem`.

`/usr/lib/systemd/system/vedette-host.service` (the file `deploy/systemd/vedette-host.service` of the repo, installed verbatim by the `.deb`/installer; the path follows Debian Policy §9.3 for units installed by a package; the block below is a copy, which `deploy/systemd/unit_test.go` compares character by character; the hardening parameters are in §12)

```ini
[Unit]
Description=Vedette host helper
After=network-online.target
Wants=network-online.target
# The package enables the unit but the installer writes host.conf: without the file the unit is skipped at boot (not failed, no crash loop); the installer starts it after writing it
ConditionPathExists=/etc/vedette/host.conf
# Restart=always would hit the default start limit (5 starts in 10 s) in a crash loop and stay down; the helper must come back, so no limit, and RestartSteps below slows the loop
StartLimitIntervalSec=0

[Service]
# READY=1 after Ops.Start finished and the socket is open: namespace vedette-hp, decoys, interrupted runs
Type=notify
ExecStart=/usr/lib/vedette/vedette-host
# No RuntimeDirectory=: systemd would make /run/vedette root:root and re-own it at every start, but the host refuses a directory that is not owned by root and socket_gid (the gid is in host.conf, not in the unit).
# The host creates /run/vedette (0750 root:socket_gid) itself when it is absent, and checks it when it is there. Nothing removes it at a stop or restart: core mounts the directory /run/vedette and reconnects to the new socket
# the host exits 70 when a command ignores its deadline; always restart it
Restart=always
# crash-loop back-off: 2 s growing to 5 min over 8 steps (systemd 254 or newer: Ubuntu 24.04 has 255, Debian 13 has 257)
RestartSec=2s
RestartSteps=8
RestartMaxDelaySec=5min
# control-group is systemd's default, kept to state the intent: a restart kills the apt/podman client processes still in this cgroup.
# Containers are not in it: each lives in its own libpod scope and keeps running
KillMode=control-group
# bounds the Start steps: startHP 120 s (the AppArmor profile load, at most 20 s, runs beside it and is joined after it: max(120, 20)) + startup rollback 180 s + decoy re-apply 120 s + core check 60 s
# + interrupted restore 300 s + core stop/start 120 s + half-written unit reset 60 s = 960 s = 16 minutes
TimeoutStartSec=16min
# Hardening (DEPLOYMENT.md section 12). NO filesystem-namespace option here, ever: `ip netns add vedette-hp` bind-mounts on
# /run/netns/vedette-hp and the honeypot container (podman, outside this unit) must see that mount. Only these, none of which makes a mount namespace
# (systemd.exec(5): each is a seccomp filter or a personality/scheduler limit; they apply to the helper and its children, and a unit running as root
# needs no NoNewPrivileges for a seccomp filter):
# AF_PACKET: ARP probe and gateway check; AF_NETLINK: addresses, routes, nft; AF_UNIX: the host socket, journald, podman
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
# Left out on purpose: NoNewPrivileges and MemoryDenyWriteExecute (inherited by apt/dpkg scripts, netplan, podman and crun; not verifiable without the lab),
# RestrictNamespaces (absent is allowed; the test requires net and mnt if it is ever set)

[Install]
WantedBy=multi-user.target
```

A drop-in under `/etc/systemd/system/vedette-host.service.d/` is **not** covered by the text test: an administrator must not set any filesystem-namespace option there, because doing so makes the `vedette-hp` namespace disappear from podman.

Start order: `vedette-host` (ready at `READY=1`) → `core` → `sensor`/`scan`/`honeypot` → `greenbone`. The whole set comes back after a reboot thanks to `WantedBy=multi-user.target` (a service whose module is off has no such line in its unit).

### 6.2 Docker Compose (dev/CI equivalent)

**The real files for customers (Container-only kind): `deploy/compose/container-only/`** (`compose.yaml` core; `compose.sensors.yaml`; `compose.syslog.yaml`; `vedette.env`), guide `docs/INSTALL-CONTAINER.md`; the illustrative block below is **not** those files (it has no `profile: lab`, uses example addresses, and `honeypot`/`honeypot-lab` do not exist in the Container-only kind) and is kept only as a dev/lab reference.

It uses the **same images**. The difference: host/macvlan networking only makes sense on Linux with a real card (profile `lab`); on a macOS/Windows dev machine use profile `dev` (bridge + high ports + a pcap fixture).

```yaml
# deploy/compose/compose.yaml (illustrative)
services:
  core:
    image: ghcr.io/knt048/vedette-core@sha256:<digest>   # dev: a tag built locally
    command: ["serve"]
    ports: ["127.0.0.1:8443:8443", "127.0.0.1:8444:8444"]   # localhost only
    volumes: ["vedette-data:/var/lib/vedette", "./dev/master.key:/run/secrets/master.key:ro"]
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 2g
    cpus: 2
    pids_limit: 512
    healthcheck: {test: ["CMD", "/vedette", "healthcheck"], interval: 30s, start_period: 60s, retries: 3}
  sensor:
    profiles: ["lab"]            # needs Linux + a real card
    image: ghcr.io/knt048/vedette-sensor@sha256:<digest>
    network_mode: host
    user: "<sensor_uid>:<sensor_gid>"   # no userns
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    read_only: true
    volumes: ["vedette-creds-passive:/var/lib/vedette-creds:ro"]
    command: ["passive", "--core", "https://127.0.0.1:8444", "--creds", "/var/lib/vedette-creds/sensor.pem"]
  sensor-replay:
    profiles: ["dev"]            # replays a sample pcap, does not touch the real network
    image: ghcr.io/knt048/vedette-sensor@sha256:<digest>
    volumes: ["./fixtures:/fixtures:ro", "vedette-creds-passive:/var/lib/vedette-creds:ro"]
    command: ["passive", "--core", "https://core:8444", "--creds", "/var/lib/vedette-creds/sensor.pem", "--replay", "/fixtures"]
  honeypot:
    profiles: ["dev"]
    image: ghcr.io/knt048/vedette-honeypot@sha256:<digest>
    ports: ["127.0.0.1:2222:22", "127.0.0.1:8080:80"]       # high ports, no macvlan
    cap_drop: [ALL]
  honeypot-lab:
    profiles: ["lab"]
    image: ghcr.io/knt048/vedette-honeypot@sha256:<digest>
    networks: {lan: {ipv4_address: 192.168.10.241}, default: {}}
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
  scan:
    profiles: ["lab"]            # image built locally from the base image + nmap from the OS package repository
    image: localhost/vedette-scan-nmap:<version>
    network_mode: host
    user: "<sensor_uid>:<sensor_gid>"
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    volumes: ["vedette-creds-active:/var/lib/vedette-creds:ro"]
    command: ["active", "--core", "https://127.0.0.1:8444", "--creds", "/var/lib/vedette-creds/sensor.pem"]
  # dev: the real file `deploy/compose/compose.yaml` has a `dev` profile with core + sensor (`passive --replay`) + scan (a fake nmap and a fake nuclei,
  # `deploy/compose/fakes/`), one unprivileged uid, only the UI/API port on 127.0.0.1; `make dev-sensors`, `make dev-sensors-smoke`. Differences from this illustration:
  # its own bridge network, `-sensor-listen 0.0.0.0:8444` inside the bridge (not published), one creds volume per role, built locally from the Containerfile.
  # CI does not run the smoke test yet.
networks:
  lan:
    driver: macvlan
    driver_opts: {parent: eth0}
    ipam: {config: [{subnet: 192.168.10.0/24, gateway: 192.168.10.1, ip_range: 192.168.10.240/29}]}
volumes:
  vedette-data:
  vedette-creds-passive:
  vedette-creds-active:
```

There is no `vedette-host` in compose: dev/CI use a **fake host** (`vedette-host --fake`, which returns fixtures over the socket with the same protocol) to test the Updates and Box network screens (proposal). CI runs the sensor↔core contract test through compose (profile `dev`: `core` + `sensor-replay` + `scan` with a fake nmap, checking that one device appears). The key volumes in compose: `core` mounts them read-write at `/var/lib/vedette-creds/{passive,active}`.

## 7. Ports and network

### 7.1 Into the box

| Port | From | To | Purpose | When open |
|---|---|---|---|---|
| 8443/tcp | LAN | `core`, on the management IP (the box's only LAN address; the publish carries no IP) | UI, API, SSE, osquery intake, osquery install script (`/install/*`), the email approval page, the blocklist URL for firewalls to pull | always |
| 8444/tcp | internal | `core` (`:8444` in the container), published **only** as `127.0.0.1:8444` | the mTLS sensor protocol for `sensor`/`scan` | always; **not on the LAN** |
| 514 UDP/TCP | LAN | `core` | receive syslog (`logs` module) | published `514:5514/udp` and `/tcp` in the `core` unit, no capability |
| 6514 TCP | LAN | `core` | receive syslog over TLS (`logs` module) | published `6514:5515/tcp` in the `core` unit, no capability |
| 22, 80, 445, 1433, 3389 | LAN | `honeypot` on the **secondary/decoy IPs** (namespace `vedette-hp`) | traps | `honeypot` on |
| — | Internet | — | **no inbound port** | — |

### 7.2 Out of the box

| Port | To | Purpose | PRIVACY |
|---|---|---|---|
| 443/tcp | feed sources | pull feeds | flow 1 |
| 443/tcp | GitHub Releases (`core` downloads the index/manifest) + `ghcr.io` (`vedette-host` pulls images by digest) | signed releases, images | flow 6 (`ghcr.io` and its blob host, `pkg-containers.githubusercontent.com`, were added with the image-pull code) |
| 443/tcp | the AI provider, Slack (Socket Mode), Telegram (long polling), Zalo, CT logs + the IP probe points | as configured | flows 2, 3, 5, 8, 9 |
| 80,443/tcp | apt mirrors (`archive.ubuntu.com`, `security.ubuntu.com`, `deb.debian.org`, `security.debian.org` or an internal mirror) | OS updates | flow 6 |
| 80,443/tcp | `deb.debian.org` **from inside the `scan` build container** (even on an Ubuntu box; the host's internal apt mirror does not apply) | install nmap into the `scan` image at `container.pull scan` | flow 6 |
| 53 UDP/TCP | DNS | resolution | — |
| 123/udp | NTP: `pool.ntp.org` by default or a server the admin enters (chrony) | clock | flow 10 |
| 25/465/587 | the customer's SMTP | alert email, login codes | flow 5 |
| LAN outbound | devices | SNMP 161/udp, SSH/HTTPS to device APIs (harness/response connections), Wazuh API, nmap within scope, SIEM forwarding | as configured |

### 7.3 Container networking

- `vedette-int`: an internal bridge, with the subnet chosen by `vedette-host` so it does not coincide with the declared LAN/VPN.
- Compose `dev`: compose's own bridge network, `sensor` and `scan` reach `core` through `https://core:8444` (the `core` SAN of the server leaf); `8444` is not published, only `127.0.0.1:18443` (UI/API) goes out to the dev machine. When **building** images (the maintainer's/dev machine, not the box): `github.com` (the nuclei zip, the nuclei-templates tag archive, SHA-256 checked), the Go module repository, `deb.debian.org` (build tools, and nmap on the box), the base image's registry; nothing of this runs during operation.
- `sensor`, `scan`: host network, reach `core` through `127.0.0.1:8444` (`core`'s published port; netavark forwarding to `127.0.0.1` for a process in the host's namespace may need `route_localnet`: check in the lab).
- `honeypot`: only the `vedette-hp` namespace held by the host: each secondary IP/decoy (outside the DHCP range) gets its own macvlan link and MAC; no `vedette-int` leg; nft in the namespace blocks new outbound connections. Macvlan traffic does not pass the host's netfilter, so the rules sit in the namespace itself.
- SPAN card: no IP, promisc, turned on by `vedette-host`; the sensor reads it with AF_PACKET; checked by effect: packets/second > 0 and ≥1 MAC other than the box's own is seen.
- Checked by effect after installation: `ss -ltnup` on the host shows no listening port outside the §7.1 table; from a lab machine (not the real network) ports outside the table are not open.

## 8. First boot

For the Appliance kind, `install.sh` (idempotent; re-running changes nothing when the state has been reached; `--uninstall --yes` returns the box to how it was; the netplan hand-over happens only with `--network-handover` and a DHCP-wired management port; the trial install channel `--test-artifacts` is only for trials, `docs/INSTALL-TEST.md`). The table below is the order of steps; the script merges steps 2 and 3 into "apt packages + `.deb`, then `host.conf`":

| Step | Action | Verified by effect |
|---|---|---|
| 1 | Preflight: OS/version/architecture in §4, Podman ≥ 4.8 (#486), ≥ 1 NIC with an IP, synchronised time, enough RAM/disk | a wrong OS stops and prints the reason; no half installation |
| 2 | Install version-pinned packages (Podman, netavark, UFW if missing; `netplan.io` on Debian, chrony, iproute2, nftables); give netplan exclusively to the host; install `vedette-host` (a package/binary whose signature was verified); keep the checked `.deb` at `/var/lib/vedette-host/selfupdate/packages/vedette-host_<SemVer>_<arch>.deb` (0600 root, directory 0700) **before** apt installs it, on every install, repair or upgrade, so the host picks it up at start and has a way back when a self-upgrade fails (`host-api.md` §6.14) | `vedette-host` active (`Type=notify` has reported ready); the socket exists, mode 0660 `root:vedette`; the kept package file 0600 root has exactly the SHA-256 of the package just installed; `/etc/netplan` has only `90-vedette.yaml`; `chronyc -N -c sources` has sources |
| 3 | Create the system user `vedette` and the directories (`/etc/vedette/host.conf` with `core_data`, `core_uid/gid`, `sensor_uid/gid`; `/etc/containers/systemd`, `vedette-int.network`, the `.volume` files, `/var/lib/vedette-honeypot/config`; the honeypot's `log/` is the volume `vedette-hp-log`, with no directory on disk); `core`'s master key is at **`<core_data>/vedette.key`** (0600, `core` creates it on first run); the minisign and cosign public keys are **embedded in `vedette-host`**, there is no `policy.json` | `vedette-host -bootstrap` refuses a wrong manifest or cosign signature |
| 4 | `vedette-host -bootstrap -index index.json -index-sig index.json.minisig -manifest release-manifest.json -manifest-sig release-manifest.json.minisig` (the daemon is **not** running yet; not through the socket) checks the index, the manifest and the cosign signature in the manifest with exactly the code of `container.pull`, pulls images by digest, creates `core_data` (0700, owned by `core`) if missing, then writes the first Quadlet units and `versions-<service>.json`; it **starts nothing**: the installer runs `systemctl daemon-reload`, `systemctl start` for the units, and checks `core`'s health. Exit codes: 0 done (re-running is a no-op); 1 failed (re-run after fixing); 2 misuse; 3 refused by a check (the code is on the stderr line `vedette-host: bootstrap: <code>: …`); 4 `already_installed`; 5 `unit_foreign` (only `-force-units` overwrites, each file is reported); 6 `daemon_running` | `core` healthy within 300 s; 8443 listening on the management IP (the box's only LAN address) |
| 5 | Print `https://<IP>:8443` and a **one-time setup code** on the console | the `/setup` endpoint refuses without the code |
| 6 | The web wizard (no SSH), four steps: Terms of use (tick to accept the terms of use `TERMS.md`; restoring from an old backup needs it too), Account (the one-time setup code, organisation name, administrator), Network (the LAN range **with prefix**, the scan consent box), Modules (the Small business / Mid-size business / Custom bundles) → Finish setup → Home. Then in Settings: alert channels (Alert channels; Home reminds the administrator until a channel is on), two-step sign-in (My account; Home reminds), AI, Box network | each step writes `core_audit`; a disabled module has no running container |
| 7 | The first device "This box" appears in the inventory (S-INV-5) | the dpkg package list exists, cannot be deleted |
| 8 | First feed pull | `feeds` reports success for the enabled sources; ≤ 5 MB/hour afterwards |

TLS certificate for 8443: self-signed at install, with an option to upload the customer's own certificate (proposal, question B3). A `Secure` cookie should require TLS always on. Already in `cmd/vedette`: `-tls-cert`/`-tls-key` use the customer's pair; if absent and `-listen` is not loopback, a 10-year P-256 pair is generated (`vedette-selfsigned.crt/.key`, mode 0600) beside the DB file at first start, with a SAN containing `-hosts`, the loopback names, `vedette`, the interface addresses and the OS hostname that vedette-host reports (#471; with no host, `core`'s own name); plain HTTP only on loopback; `-hosts` is the list of `Host` values that are answered (421 for other names, against DNS rebinding). Without `-hosts` the list is the self-signed certificate's names **except** names in a public domain: only addresses, one-label names (`vedette`, `office-box`) and names ending `.local`, `.lan`, `.home.arpa`, `.internal` are answered, because a hostname may be set by DHCP (a hostile DHCP setting `rb.attacker.example` would open a DNS-rebinding path). To open the box by a name in a real domain (`box.corp.example`), add it to `-hosts`.

**The box's own CA.** The 825-day leaf certificate above is no longer self-signed: a CA of the box's own (`CA:TRUE`, `pathlen 0`, 20 years; the key and certificate sealed in `vedette.db`, table `core_secret`, with the master key) signs it, and the leaf stays `CA:FALSE` (Firefox rejects a CA used as a server certificate). Renewal and an address change only reissue the leaf, with the same leaf key and the same CA, so a machine that pinned the CA still trusts the box. An old box with a self-signed leaf is reissued a leaf under the CA once at the next start (same key, same SAN); because that is a different certificate, a browser that kept an exception for the old certificate asks to accept once more. The owner's `-tls-cert` pair is not touched. The CA is in the backup along with `vedette.db`: restoring together with `vedette.key` keeps the same CA and enrolled machines keep working; restoring without the master key makes a new CA and machines must re-run the install command. A JSON export never contains the CA. A box upgraded from an older version that kept the CA in two files `vedette-selfsigned-ca.crt/.key`: the first start seals them (same CA) and deletes them, so no plaintext CA key remains on disk; a corrupt file is moved to `vedette-selfsigned-ca.{crt,key}.quarantine-<unix>`. An unusable CA does not stop core from starting: a new CA is made, and an ERROR log says enrolled machines must re-run the install command. Osquery downloads the CA certificate (never the key) at `GET /api/v1/intake/ca.pem`. Trusting this CA in a browser or operating system is optional and should be weighed: the CA has no name constraints (the box's address changes so none can be set) and its key is on the box, so anyone who can read `/var/lib/vedette` (the database and master key) can impersonate **any** site to an administrator who trusts it.

**The certificate follows the management address.** When `vedette-host` exists, `core` keeps the self-signed pair's IP SAN equal to the management card's IPv4 addresses that the host reports (the certificate follows exactly the addresses the host reports), reissues with the same private key within seconds after apply/confirm/revert and every 10 minutes (so a DHCP or console change is also noticed), without a restart; if the host is silent it stays as is. The owner's certificate (`-tls-cert`) is never modified: if it lacks the management address, one warning is logged per change. After an address change, if the browser had pinned an exception for the old certificate, the key is unchanged but the new certificate is a different one (serial number, SAN): accept the exception once more.

## 9. Upgrade and rollback

Replaces the binary A/B slots with **signed images**. Channel overview: `UPDATES.md`.

### 9.1 Vedette software

| Step | Action |
|---|---|
| 1. Discovery | `core` (on a schedule or when the user clicks "Check") fetches `index.json` and the release manifest from GitHub Releases (`update-manifest.md`), checks them with `internal/release` and then hands them to `vedette-host`, which checks again independently. The manifest is **minisign-signed** (verifiable offline): `stable`/`beta` channel, each image's digest, rollout percentage, minimum host version, `revoked[]`, migration notes |
| 2. Cohort | `cohort = SHA-256(install_id ‖ "vedette-cohort")[0:4] mod 100` (`update-manifest.md` §6). A release is offered, by hand or automatically, only when `cohort < rollout`; until then Settings → Updates says the box is not in the rollout yet |
| 3. Pre-flight | enough disk, no other job running, inside the maintenance window (if automatic), Podman at a sufficient version |
| 4. Pull | `container.pull` for each service: the host checks the minisign, the revocation and the cosign signature in the manifest **first**, then `podman pull ghcr.io/knt048/vedette-<service>@sha256:…`; a wrong or missing signature stops it, nothing changes |
| 5. Backup | `core` makes a consistent DB snapshot and passes `snapshot` to `core`'s `container.start`; the host makes a `pre_update` copy within that run |
| 6. Replace | `container.start`: the host rebuilds the unit (new digest), `daemon-reload`, restarts in the order **`core` first** → `sensor`/`scan`/`honeypot` → `greenbone` (`host-api.md` §6.8: a sensor is never newer than `core`; rollback is the reverse). Migrations run when `core` starts, **expand only**: the new version only adds, and the immediately previous version still runs on the new schema (proposal; contract test in CI) |
| 7. Health gate | `core` healthy ≤ 120 s, other containers ≤ 60 s, plus smoke tests: login returns 200, scheduler tick, sensor heartbeat. Windows and thresholds are proposals |
| 8. Finish | write `core_audit` (who/schedule, from/to version, digest, result); keep the previous image for 1 generation, delete older ones |

A failure at steps 6–7: `vedette-host` returns to the previous unit/digest by itself within the same run, re-checks health and reports to the UI (`reverted`, `unit_failed`). The DB is restored (from step 5's `pre_update` copy) only when the manifest declares `rollback.safe=false`, and the GUI states clearly that data is lost.

**Manual rollback** (S-CORE-2): the "Rollback" button on the Updates page (`container.rollback`) switches to the verified `previous` (kept for 1 generation); with `rollback.safe=false` the GUI asks to confirm data loss and the host restores the DB within the same run. Verified by effect: the displayed version is right and the health gate passes.

Offline (air-gapped network): a signed bundle containing the index, the manifest + images as OCI archives; `vedette bundle import` checks minisign and cosign like the online path. The host side (`source: bundle`) is **later** (`412 bundle_unsupported` for now).

### 9.2 Operating system

- Settings → Updates checks the **OS first**: release, kernel, packages with security patches, reboot needed, end of support.
- Executed through `vedette-host`: a fixed apt command list, checked parameters; install security patches / all; unattended-upgrades; schedule by maintenance window; reboot now or scheduled. An OS release upgrade is guidance only, never done automatically.
- DB backup first, health gate afterwards; progress is shown live.
- After a reboot: all containers start by themselves (§6.1); the box is not "done" until the health gate passes.
- If an OS update upgrades Podman/netavark: the host re-checks the minimum version and the containers' health; a violation produces a warning and stops automatic updates.
- Pointing the apt mirror at an internal one is allowed (PRIVACY flow 6).

## 10. Backup and restore

| Item | Design |
|---|---|
| Contents | a consistent SQLite snapshot + uploaded RAG documents + configuration generated from the DB. The RAG index can be rebuilt. Quadlet units need **no** backup (regenerated) |
| Secret key | a backup **downloaded with a password** carries the master key `<core_data>/vedette.key` inside its encryption, so a restore keeps every saved secret and two-step sign-in; a backup downloaded without a password, and the copies the box keeps, never hold it. Restoring without the key means re-entering AI, feed and channel keys |
| Schedule | before each software update, OS update and restore, and on demand (Download backup); scheduled backups are planned ([#1068](https://github.com/KNT048/vedette/issues/1068)); stored at `/var/backups/vedette`, optionally an external directory (USB/NFS) the customer mounts. No cloud (every outbound flow must be in `PRIVACY.md`) |
| Export/delete | Settings → Data: export everything (without secrets), delete everything (S-CORE-6) |
| Restore | a new machine: `install.sh` → upload the backup in the wizard → `vedette-host` puts it into the volume → `core` starts, runs migrations → re-enter secrets if the key is missing |
| Verification | a "restore drill" in CI/lab: back up → build a new machine → restore → compare device count, findings, and that the audit chain is intact |

## 11. Logs and observability

| Source | How collected |
|---|---|
| Container logs | `LogDriver=journald`, one tag per container; JSON application logs with level and request ID; **secrets are never logged** (SYS-4); `journald` limits (`SystemMaxUse`, proposal 1 GiB) |
| Health | the module + container health page (status/health reported by `vedette-host`), job history, feed errors, sensor health (packets seen or not) |
| Audit | `core_audit` (SYS-3), including commands sent to `vedette-host`; the hash-chained AI/response log, kept 1 year by default |
| Download | Settings → Data downloads all the box's logs (audit, AI, response, scan probes, alerts, device logs) as JSON/CSV (S-CORE-6) |
| Forwarding | SIEM syslog/CEF/JSON (S-LOG-3), off by default |
| Error reporting | a filtered diagnostic bundle, which the user previews and sends themselves; the box sends nothing on its own |

There is no Prometheus-style metrics endpoint: there is no story for it, so it is not built; propose it as a story if needed.

## 12. Hardening

**Host.**
- `vedette-host.service`: `Type=notify` (the host reports `READY=1` after creating the `vedette-hp` namespace, re-applying decoys and recovering an interrupted run); restricted as far as possible while still running apt/netplan/podman and still letting the `vedette-hp` namespace appear to podman (**no** filesystem-namespace option at all): `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET` (`AF_PACKET` for the ARP probe and gateway check; root only sends/reads 42-byte ARP frames, it reads no other traffic), `LockPersonality=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native`, **no** `RuntimeDirectory*` (the host creates and checks `/run/vedette` 0750 root:`socket_gid` itself, so the directory survives a restart), `Restart=always`, `RestartSec=2s`, `KillMode=control-group`, `StartLimitIntervalSec=0` (the real file `deploy/systemd/vedette-host.service`). **Deliberately not set**: `NoNewPrivileges` and `MemoryDenyWriteExecute` (seccomp filters/flags inherited by children: `apt`/`dpkg` and package maintainer scripts, `netplan` (Python), `podman`/`crun`; cannot be verified without a lab, so they wait for the lab; the seccomp of the four options above needs no `NoNewPrivileges` because the unit runs as root), `RestrictNamespaces` (absent is fine; if set, the test requires allowing `net` and `mnt`). Limiting damage relies mainly on the **fixed command list**, not on a sandbox. `TimeoutStartSec=16min` (the bound of the `Ops.Start` steps).
- **`vedette-host.service` must not set any filesystem-namespace option.** `ip netns add vedette-hp` bind-mounts onto `/run/netns/vedette-hp` and the `honeypot` container (podman, outside the unit) must see that mount. `systemd.exec(5)`: the filesystem-namespace options set mount propagation to `slave` (the host's mounts appear in the unit, the unit's mounts do not appear on the host), and "Setting this option to `shared` does not reestablish propagation in that case" so `MountFlags=shared` cannot save it. Forbidden: `PrivateTmp=`, `PrivateDevices=`, `ProtectSystem=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectProc=`, `ProcSubset=`, `ReadOnlyPaths=`, `ReadWritePaths=`, `InaccessiblePaths=`, `ExecPaths=`, `NoExecPaths=`, `BindPaths=`, `BindReadOnlyPaths=`, `TemporaryFileSystem=`, `PrivateMounts=`, `MountAPIVFS=`, `MountImages=`, `RootDirectory=`, `RootImage=`. `RestrictNamespaces=` must be left empty or allow `net` and `mnt` (`ip netns` calls `unshare`/`setns`). Keep the options above that do not touch mounts (`RestrictAddressFamilies`, `LockPersonality`, `RestrictRealtime`, `SystemCallArchitectures`).
- UFW/nftables block inbound by default and open ports per enabled module (8443; 514 and 6514/tcp when `logs` is on). `vedette-host` manages the rules; checked by effect (§7.3). **Note:** `core`'s ports 514 and 6514 are published by Podman with DNAT, so ufw's INPUT rules cannot block them; the ports are published even when the `logs` module is off (then no process listens in the container and packets are rejected/dropped). To block them for good, block in FORWARD/nat, not INPUT.
- Never mount `podman.sock`/`docker.sock` into any container; no `--privileged`.
- SSH administration of the host is outside Vedette; it is recommended to allow it only from the management range.

**Containers.**
- `cap_drop=ALL` + the minimum capabilities (§2); `no-new-privileges`; read-only rootfs + tmpfs; Podman's default seccomp; AppArmor: the `vedette-container` profile (Podman's containers-default profile plus signal/ptrace rules for stacked labels) on the appliance, the runtime default on the container-only kind; resource limits (§2.6).
- Secrets through a read-only file mount, not through environment variables.
- Non-root in every container; `core` runs `User=<core_uid>:<core_gid>` fixed, **not** `UserNS=auto` (the host socket's peer check and the ownership check need a stable uid); `sensor`/`scan` run `User=<sensor_uid>:<sensor_gid>` fixed, **no** `UserNS` (a child user namespace's capabilities do not cover the host's network namespace); other containers use `UserNS=auto`. The units are system units, Podman rootful (closes the system/user question).
- Images: digest-pinned, CycloneDX SBOM, `trivy`/`govulncheck` scans in CI, cosign.
- **Building `scan` on the box** is the only place where the host's root runs code supplied by a third-party package repository (the `RUN` step runs as the build container's root, with network, trusting the apt key of the signed base image). Kept: the constant `Containerfile` text in the binary; fixed `podman build` argv (`--pull=never`, no build args from input, the context is a directory of the host's own holding only the `Containerfile`); checked by effect with `podman run --network none --cap-drop ALL --read-only` `nmap --version` ≥ the floor; a bad image is removed and the tag returns to the previous image; the `scan` unit pins the image ID, not a name; the image runs under `User=<sensor_uid>` with only `NET_RAW`.

**Rootless.** The appliance uses **rootful** Podman with the hardening above, because: macvlan, host networking + raw sockets and a shared internal network between containers all need real privileges; trying rootless would force an extra shim layer that increases the surface. Rootless is usable in dev/CI (profile `dev`) and in the Container-only kind for the `core`/`scan` parts that need no raw access. To be confirmed by a PoC at M2 (B4).

**Podman versus Docker and UFW.** Docker inserts `-p` iptables rules into the `DOCKER` chain so published ports **bypass** UFW rules (known behaviour); this is why the appliance chooses Podman. With Podman, still publish only what must be published (only 8443) and do not trust UFW alone: every installation is checked with `ss`/a scan from the lab. The Container-only kind on Docker: bind ports to a specific IP in Compose (`192.168.10.5:8443:8443`), or put rules in the `DOCKER-USER` chain.

**A box that has Docker.** When Docker turns on IP forwarding it sets iptables' `FORWARD` policy to DROP. Netavark (Podman, Ubuntu 26.04) writes rules into its own nftables table, and in nftables an `accept` in this table is not a final decision so packets are still stopped by iptables-nft's DROP policy. The measured consequence: the 8443 interface and syslog 514 cannot be reached from the LAN (only `127.0.0.1`), and containers on `vedette-int` cannot reach the internet (feeds, building the nmap image). The way of Docker, LXD and Fedora is the `DOCKER-USER` chain: `vedette-host` keeps **five fixed rules** in it, bound to the bridge `vedette0` (a fixed name, which `install.sh` sets with `PodmanArgs=--interface-name=vedette0` in the network file) and the range of `vedette-int` (read from `Subnet=` of `/etc/containers/systemd/vedette-int.network`; it accepts only `172.30.x.0/24`, like `install.sh`), and only when the chain exists. The order in the chain: two rules `-i vedette0 -o docker0 -m comment --comment vedette-int -j RETURN` and `-i vedette0 -o br-+ … -j RETURN` (Docker still protects its own network from Vedette's containers: the packet continues into Docker's chain, which decides as before), then `-o vedette0 -d <range> -m conntrack --ctstate DNAT,ESTABLISHED,RELATED -m comment --comment vedette-int -j ACCEPT` (published ports and reply packets) and `-i vedette0 -s <range> -m comment --comment vedette-int -j ACCEPT` (containers going out and reply packets), and at the end of the block `! -i vedette0 -o vedette0 -m comment --comment vedette-int -j DROP`: apart from published ports (through the box's address) and reply packets, nothing can enter Vedette's containers, including the customer's Docker containers (Docker 28 does exactly this for its own networks; to go straight to the `vedette-int` range, put your own ACCEPT rule above the block). Above those rules, each of the box's own uplink bridges named `br-…` (not the Docker bridge form `br-` + 12 hex digits, and having a port that is a network card, bond or VLAN; a Docker bridge, even with a custom name, has only veths), such as `br-lan`, gets a `-s <range> -i vedette0 -o <bridge> -m comment --comment vedette-int -j ACCEPT`, because `br-+` also matches that name and once cut the containers off from the internet; the host reads the names from `/sys/class/net`, a new uplink bridge may lose internet until the next check (at most 30 seconds), and a new Docker network is never opened to Vedette's containers. A Docker network given its own bridge name that does not start with `br-` (`com.docker.network.bridge.name`) is not covered by the RETURN. The ACCEPT rules accept only packets entering or leaving through `vedette0` from or to that range; apart from the RETURN rules, they accept such packets wherever they go. The host checks (`iptables -C`) at start and every 30 seconds, inserting a missing rule at the right place in its own block (`-I … <position>`; it never inserts when a `vedette-int` rule exists in a form the host does not know or another rule sits in the middle of the block, and it logs only once), so it survives Docker starting later or restarting; it logs once whenever the state changes. The network file of an old installation has no bridge name: the host does nothing and logs once that a reinstall is needed (not released, no migration). Stopping the host does not remove the rules (they accept only packets of the Vedette range through `vedette0`; removing them would cut core's connectivity); `install.sh --uninstall` removes them. At the end of installation, `install.sh` checks that the rules are present (warning if not). **The administrator's rules go above Vedette's rules**: to restrict who can reach 8443/514 on a box with Docker, insert your rule above this block (the host only adds missing rules, it never reorders). **ufw (`DEFAULT_FORWARD_POLICY=DROP`), firewalld or a self-written firewall** (FORWARD DROP and no `DOCKER-USER` chain): the host does not touch a firewall that is not Docker's; `install.sh` prints a warning, and the administrator allows forwarding to and from the bridge `vedette0` (that range) (ufw: `ufw route allow in on vedette0` and `ufw route allow out on vedette0`). Docker using the nftables backend has no iptables `DOCKER-USER` chain: nothing is done. **A box without Docker**: Vedette adds no forwarding rules and `vedette-int` does not set netavark's `isolate` (`isolate=true` only blocks between two networks that both enable it); another root Podman container of yours on the box can still reach `core`'s unpublished ports on `vedette-int` (like any root process on the box). From netavark 2.0 isolated networks are `strict` by default: that path closes by itself, but your root Podman container on another network also can no longer reach `core`'s 8443, 514, 6514 through the box's address (a packet DNAT'd out of your bridge into `vedette0`, or a reply leaving `vedette0`, is blocked by netavark's isolation chain); the LAN and the box itself are not affected. To be decided when a supported OS has netavark ≥ 2.0. **The iptables comment `vedette-int` is reserved for Vedette**: every rule carrying that comment and attached to the bridge `vedette0` is considered Vedette's and is removed by `install.sh --uninstall`; do not use it for your own rules. Ruled out: switching netavark to the iptables driver (it changes Podman for every other network, 24.04 and 26.04 differ), `sysctl ip_forward=1` before Docker runs (changes the customer's Docker isolation and does not fix a Docker that is already running), having `install.sh` refuse when Docker is present (Docker is a valid customer choice and the box would still break when Docker is installed later). Sources: [Docker, packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/), [LXD, prevent connectivity issues with LXD and Docker](https://documentation.ubuntu.com/lxd/en/latest/howto/network_bridge_firewalld/#prevent-connectivity-issues-with-lxd-and-docker), [Fedora, Changes/NetavarkNftablesDefault](https://fedoraproject.org/wiki/Changes/NetavarkNftablesDefault).

**The trap's own risk.** The honeypot is a deliberate attack surface from the LAN. Mitigations: its own container, `DropCapability=ALL` (not even `NET_BIND_SERVICE`, thanks to the namespace's `ip_unprivileged_port_start=0`), no DB, **no network port to `core`** (hits go through a file), and `core` treats all data from the trap as untrusted (SYS-6). Blocking lateral movement from the trap into the LAN: macvlan traffic goes straight out the NIC and does not pass the host's netfilter, but it **does** pass the netfilter of the `vedette-hp` namespace itself; the host places there a constant nft ruleset `ct state established,related accept; ct state new drop` at the output hook, so the trap can only answer inbound connections (question B5 is closed). Checked by effect in the lab: `nft list ruleset` in the namespace and trying an outbound connection from the container.

## 13. Development environment

| Task | Command | Notes |
|---|---|---|
| UI + sample data | `make dev` (http://localhost:5173) | mock API (MSW), no containers needed |
| FE check | `make verify` (tsc, lint, vitest, build then clean up) | |
| E2E | `make e2e` (Playwright) | |
| Real KEV/EPSS fixtures | `make fixtures` | |
| Backend | `go test ./...`, `golangci-lint`; `go test ./modules/<id>/... -run Contract` | part of `make verify` (`verify-go`) |
| The whole container set | `make dev-sensors` (compose profile `dev`: `core` + `sensor` replaying a pcap + `scan` with a fake nmap/nuclei); `make dev-sensors-smoke` checks that a device appears through the API and then tears down | the same Containerfile as the appliance; with no `vedette-host`, `/core/network/*` returns `409 not_appliance` |
| Container-only install | `make container-only-smoke` (`SMOKE_RUNTIMES=docker` or `podman` picks one); opt-in, slow, not part of `make check` or CI | builds the images locally, builds `deploy/compose/container-only/*` exactly as `docs/INSTALL-CONTAINER.md` describes, checks by effect: core answers on 8443 at the given address, an unknown Host gets 421, `/core/{updates/os,network,data/backup}` return `409 not_appliance`, the data volume has `vedette.key` 65532:65532 0600 and a 0750 directory, ports are published correctly (8443 on the address, 8444 on 127.0.0.1, `ss` agrees), core uid 65532 with no capability, no-new-privileges, syslog 514 → 5514; the sensor (uid 0 gid 65532 with only `NET_RAW`) and scan (65532, no capability) when the engine runs as root; then removes the containers/volumes/networks/images of that very run (prefix `vedette-smoke-<pid>`). Run on an Ubuntu machine: Docker (rootful) with both sensor and syslog: PASS; Podman rootless 5.7 (turns on the user's `podman.socket` itself and then off): PASS, skipping the sensor part (needs root) and syslog (rootless does not publish port 514). Not yet run: rootful Podman. Finding: rootless Podman creates a new volume with `/data` 0755 (buildah does not carry the image directory's mode) → `tightenDataDir` in core lowers it to 0750 at start |
| Images | `make sensor-image scan-base-image scan-image core-image` (one architecture, for dev); `make images` builds `core`, `sensor`, `scan-base` for `PLATFORMS=linux/amd64,linux/arm64` into one manifest list per image, cross-compiled on the build machine, no qemu, no push; `make images-check` builds each one (the machine's architecture) and checks by effect (`CONTAINER=podman`, the default) | pinned in `deploy/containers/pins.env` |
| Real-network integration | profile `lab` on a Linux VM with a real card | **no scanning/probing of IPs outside the lab**; use pcap/syslog fixtures |
| Connect the GUI to the backend (per module) | `make dev-api` (default `REAL=core`; `make dev-api REAL=core,inventory`) | Go runs at `127.0.0.1:8080` (`.dev/vedette.db`, `.dev/vedette.key`, created on first run), Vite `localhost:5173` proxies `/api` → the backend; modules in `REAL` go to the backend, other modules are still answered by MSW. Ctrl-C stops both |
| Connect the GUI to the backend (everything) | build the SPA with `VITE_API_MOCK=off` (or `VITE_API_REAL=all`) | the contract `api/openapi.json` |
| Release SPA | `make web-release`: builds with `VITE_API_MOCK=off`, does not copy `mockServiceWorker.js`, then `web/scripts/check-release.mjs` fails if `web/dist` still has traces of MSW; leaves `web/dist` for the step that embeds it in core, `make clean` removes it | |
| Clean up | `make clean` (including locally built `vedette-*:dev` images, proposal) | does not delete `node_modules`, the module cache |

**`make dev-api` in detail.** `VITE_API_REAL` (a list of module ids or `all`) decides which MSW handlers are registered: `web/src/lib/apiModules.ts` maps paths → modules exactly as `core/server/modules.go` does, and `api/route-modules.json` (the Go test `core/server/routemodules_test.go` keeps it equal to the Go table, vitest compares it with `apiModules.ts`) prevents drift. Origin: the Vite proxy uses `changeOrigin: false` so `Host` stays `localhost:5173`, exactly equal to the browser's `Origin`, and the backend's `checkOrigin` compares `Origin` with the request's own `Host` so it accepts; POST/PUT/PATCH/DELETE additionally send `X-CSRF-Token` taken from the `__Host-vedette_csrf` cookie. The box's cookies carry the `__Host-`/`__Secure-` prefix and the `Secure` attribute: Chrome and Firefox accept them from `http://localhost` (treating localhost as a secure context) so `make dev-api` works normally through `http://localhost:5173`; Safari does not, so use Chrome or Firefox (or TLS) when trying the real backend. Before the backend has login, `GET /api/v1/modules` returns 401: as expected. **Mock modules when `core` is real (issue #78).** A real login does not fill the mock's session, so the MSW handlers of the mock modules (feeds, inventory…) would return 401. When `core` ∈ `VITE_API_REAL` and mock modules remain, `web/src/mocks/realSession.ts` registers a handler at the front: before a mock module answers, it reads the real backend's `GET /api/v1/me` (through MSW's `bypass()`), keeps the result for 3 seconds and drops it when a write request reaches a real module (login, logout, setup, role change); the mock's `guard()` and `currentUser()` use that user and role, and grant no admin rights. Not logged in for real = 401 as usual. Docker Compose for the whole container set awaits the images.

Convention: development on macOS uses Docker Desktop/Podman machine: no host network, macvlan or real packet capture, so the sensor runs in fixture-replay mode. CI (GitHub Actions): per-module tests, contract tests, multi-architecture builds, `trivy` + SBOM, **cosign signing** in the release job, the restore drill, a "pulling an unsigned image is refused" trial. Git tags are created by hand by the maintainer (#12).

## 14. Open questions

| # | Question |
|---|---|
| B1 | ~~Add a health endpoint to `api/openapi.json`.~~ **Decided: not added; `vedette healthcheck` uses the public route `GET /api/v1/setup`.** |
| B2 | ~~A one-time setup code printed on the console to stop someone inside the LAN from taking `/setup` before the real admin. Is that acceptable?~~ **Decided: yes.** |
| B3 | The 8443 TLS certificate: self-signed + upload (proposal) or an internal ACME? |
| B4 | Accept rootful Podman on the appliance (§12) or require rootless and bear the extra shim? **Settled for units:** system units, rootful; the PoC on a real machine is still in the lab. |
| B5 | ~~Blocking the honeypot's egress (macvlan does not pass the host's netfilter)~~ **Settled:** an nft ruleset in the `vedette-hp` namespace itself blocks every new outbound connection (§12). |
| B6 | ~~Does the cohort block only automatic updates?~~ **Settled:** it blocks the offer itself; a box outside the rollout is offered nothing until the percentage reaches it (§9.1 step 2). |
| B7 | Greenbone management: a GMP socket on a volume or an internal port; pin the digest per `release.json` instead of upstream's cosign? |
| B8 | The minimum Docker/Podman version for the Container-only kind. **Path settled: `deploy/compose/container-only/`.** Version floor: record the versions tried and then the lab's, no guessing (§5). |
