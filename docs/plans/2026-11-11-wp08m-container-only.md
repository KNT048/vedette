# WP-08m: the container-only install (Compose on the customer's Docker or Podman) — plan, phase 1

Status: plan for the lead to approve. Nothing is built. Sources: D-55 §5 table (`docs/DEPLOYMENT.md:187-205`), D-57 (1), D-103, D-146, D-166, the code at `origin/main` 511a9f5. Evidence is `file:line` at that commit. Top-tier links in section 6 were written from memory because this phase has no network: re-open each before the D-xx that cites it.

## 0. What exists and what the three findings are

Exists:
- A dev compose, `deploy/compose/compose.yaml` (profile `dev`, D-146): core + sensor replaying a pcap + scan with fake nmap/nuclei, one uid `65532:65532`, `read_only`, `cap_drop: ALL`, `no-new-privileges`, only core's UI on `127.0.0.1` (`compose.yaml:23-28,50-61`). Smoke: `scripts/dev/sensors-smoke.sh` (`make dev-sensors-smoke`, Makefile:319). It builds from Containerfiles, so it cannot be given to a customer.
- core already runs without a host: `-host-socket ""` or a missing socket gives a container-only install (`cmd/vedette/main.go:87`); every OS and network route answers `409 not_appliance` (`modules/core/oshost.go:42,62`, `handlers_network.go:162`); the setup code is logged at every start while setup is open (`main.go:287-295`, one JSON line, key `setup_code`).
- GUI: `ErrorState` titles `not_appliance` "Not available on this install" and shows the box's sentence (`web/src/components/common/States.tsx:26`, test `core.test.tsx:1342`, e2e on a real bare box `web/e2e-real/bare-box.spec.ts:46-100`).

Findings that change the design (each cost a customer an hour if missed):
1. **421 on first open.** Core's Host allowlist is fixed at start from `-hosts` or the certificate's names, and the "own address" escape needs a host to report addresses (`core/server/hosts.go:30-60`, `cmd/vedette/hostnet.go:232-240`: nil cache = nothing extra accepted). In a bridge container the cert's SANs are the container's names and `172.x` address (`cmd/vedette/tls.go:88-103`). A customer opening `https://192.168.10.5:8443` gets `421 misdirected_request`. The compose must pass `-hosts <address>` from one variable the customer sets. (Appliance does not hit this: the host reports the management address, D-139.)
2. **Card choice cannot work without a host.** `SetInterface` validates the card against `netHost.Interfaces` (D-118, `modules/sensor-passive/CONTRACT.md:48`); with no host that is `osInterfaces()` of core's own container (`cmd/vedette/sensorpassive.go:44-71`), i.e. `eth0` of the bridge, never `enp3s0` that a host-network sensor reports in its heartbeat. Picking the real SPAN card would answer `400 bad_interface`. This is a backend bug of the container-only install, in a screen that exists (S-INV sensors), so no GUI work: slice 4.
3. **"This box" is named by a container id** (`cmd/vedette/inventory.go:45` `os.Hostname()`), and has no packages (no `BoxPackages`, `inventory/box.go:86-89`). The compose sets `hostname: vedette`; the packages gap is a GUI statement (G3).

## 1. What a customer runs

### 1.1 Files (new directory `deploy/compose/container-only/`, the dev compose stays as it is)

| File | What |
|---|---|
| `compose.yaml` | core only. Works on Docker Engine and Podman, rootful or rootless, Linux or Docker Desktop. |
| `compose.sensors.yaml` | override: `sensor` (passive) and `scan` (active) on the host network. Linux, rootful only. |
| `compose.syslog.yaml` | override: publishes syslog 514 to core's 5514. Opt-in, so no UDP port is open while the `logs` module is off. |
| `vedette.env` | the only file the customer edits (3 variables) plus the release-filled image refs (below). |

Image references are never in `compose.yaml` itself: `image: ${VEDETTE_CORE_IMAGE:?not tied to a release}`, and `VEDETTE_CORE_IMAGE`, `VEDETTE_SENSOR_IMAGE`, `VEDETTE_SCAN_IMAGE` live in `vedette.env` as `ghcr.io/knt048/vedette-<service>@sha256:<digest>` (D-57 (3), `DEPLOYMENT.md:53`). In the repo those three values are empty, so a copy from the repo refuses to start, exactly like `install.sh` with empty `VEDETTE_DEB_SHA256_*` (D-166 (2)). The release builder (WP-08f/k) fills them and signs the files (slice 7, blocked on 08k). `scan` is the base image `vedette-scan`: nmap is not in any published image (D-146 (2), D-4), so container-only `scan` has **no nmap**: the module reports it (see 1.3).

### 1.2 `compose.yaml` (core)

- `name: vedette`, `container_name: vedette-core` (same name as the appliance's unit, so one sentence "docker logs vedette-core / podman logs vedette-core" is true on both; today's hint says `docker logs vedette` and `journalctl -u vedette`, `web/src/locales/en/core.json:1123`, wrong on both: G1).
- `hostname: vedette`.
- User: `65532:65532` (the image default, `core/Containerfile`), `read_only: true`, `tmpfs: [/tmp:size=64m]`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `mem_limit: 2g`, `memswap_limit: 2g`, `cpus: 2`, `pids_limit: 512`, `environment: GOMEMLIMIT=1800MiB`: the same numbers as `host/ops/quadlet.go:104-131` (DEPLOYMENT 2.5).
- Command: `-listen :8443 -hosts ${VEDETTE_HOSTS:?} -sensor-listen :8444 -sensor-creds /var/lib/vedette-creds -host-socket ""` (`main.go:87-94`; `-sensor-listen` stays on in the bridge, not published, so a later `-f compose.sensors.yaml` needs no change to core's flags).
- Ports (DEPLOYMENT section 12 / `:623`, Docker `-p` bypasses UFW): `"${VEDETTE_BIND_IP:?}:8443:8443"` and `"127.0.0.1:8444:8444"`. **No default** for `VEDETTE_BIND_IP`: the customer must say which address the UI is on (`127.0.0.1` is a valid answer for a trial). `VEDETTE_HOSTS` is the name(s) or IP(s) the browser will use (feeds both the Host allowlist and the cert SANs, `tls.go:518-537`); for an IP-only setup it equals `VEDETTE_BIND_IP`.
- Volumes (named): `data:/var/lib/vedette` (SQLite, `vedette.key`, the self-signed cert `vedette-selfsigned.crt/.key` made at first start next to the DB, `main.go:166-195`), `creds-passive`, `creds-active` at `/var/lib/vedette-creds/{passive,active}` (core read-write only). The master key is inside `data`, so "back up the volume" is the whole backup (section 5 of the table in DEPLOYMENT: the customer backs up the volume; the DB snapshot is made by core).
- Volume ownership: the dev compose uses a one-shot `volumes-init` running as root from the scan-base image (`compose.yaml:37-46`). For customers prefer **no root step**: bake the three directories into the `core` image owned by `65532:65532` (`COPY --chown` from the build stage, a one-line change in `core/Containerfile`, harmless for the appliance which bind-mounts), so Docker and Podman initialise the empty named volumes with that owner. Slice 2 proves it on both engines; fallback if Podman rootless disagrees: keep `volumes-init` (it already works, smoke-tested), run from the `scan` image.
- Healthcheck: `["CMD","/vedette","healthcheck"]`, `interval 30s`, `start_period 60s`, `retries 3` (DEPLOYMENT 2.1; the dev file uses 5 s for tests).
- `restart: unless-stopped` (appliance has `Restart=always`; a data purge makes core exit 0 and expects the supervisor to restart it, `main.go:204-206` comment, D-154, so a restart policy is **required**, not nice to have: without it "Delete all data" leaves the box stopped; the e2e below checks it).
- No `docker.sock`/`podman.sock`, no `privileged`, no env secrets (DEPLOYMENT section 12).

### 1.3 Compose v2 and Podman

- **One format: Compose Specification v2.** Docker: `docker compose`. Podman: `podman compose` with the docker-compose v2 provider (the provider here is `/usr/libexec/docker/cli-plugins/docker-compose` 2.40.3 on Podman 5.7, verified on this box with `podman compose version`), or `podman-compose` if the customer prefers; the file uses only keys both implement (`cap_drop`, `read_only`, `tmpfs`, `healthcheck`, `restart`, `mem_limit`, no `!reset`, no `include`). The `!reset` tag, needed to swap core's network for a host-network core, is not used (see below).
- **Quadlet / `.kube` are not shipped for container-only.** D-55 says "Compose/Quadlet" (`DEPLOYMENT.md:191`); a customer who wants Quadlet is a customer who can install the appliance, and generating Quadlet files is `vedette-host`'s job (`quadlet.go`, D-123: the Go constants are the source). `podman kube play` would be a second file format to keep in step. Decision D-b below; ask only if kien wants it.
- Minimum versions (B8, `DEPLOYMENT.md:662`): record "tested on" the versions of this box (Docker Engine 29.1.3 + Compose 2.40.3; Podman 5.7.0 + that provider) and of the lab (Ubuntu 24.04: Podman 4.9, Docker from the Ubuntu repo), not a guessed floor. The documented floor is whatever the lab matrix passes.
- **Rootless** (Docker rootless, Podman rootless): core only. Ports below 1024 cannot be bound (syslog 514 needs `net.ipv4.ip_unprivileged_port_start` or rootful), a host-network sensor cannot read a real card (a user namespace's `CAP_NET_RAW` does not cover the host's network namespace, D-114 (3), `DEPLOYMENT.md:77`), and the source IP of syslog may be lost behind slirp4netns (pasta keeps it; lab). `DEPLOYMENT.md:621` already says rootless is for "core/scan without raw".

### 1.4 Modules: what works and what the compose does for each

| Module or feature | Container-only | What the compose does | What the person sees |
|---|---|---|---|
| core, users, audit, AI (BYOK), notify, feeds, findings, inventory (manual and import), reports, response (tiers), exposure (outbound only), mcp-server (loopback `127.0.0.1:8765` inside the container: unreachable, stays off) | works | `compose.yaml` | normal |
| osquery intake and `/install/*` script, approval pages, blocklist URL | works | all on 8443 (DEPLOYMENT 7.1) | normal; the install script embeds the Host the browser used, so `VEDETTE_HOSTS` must be what devices will call |
| logs, syslog | works if opted in | `compose.syslog.yaml`: `"${VEDETTE_BIND_IP:?}:514:5514/udp"` and `/tcp`; core binds 514 else 5514 (`modules/logs/listener.go:23`), a uid 65532 process gets 5514, so no capability is added (consistent with the `-syslog-port` flag, `main.go:94`) | normal; whether the sender's IP survives Docker's NAT (INV-3 matches by sender IP) is checked in the lab, bridge + iptables DNAT keeps it, rootless slirp4netns does not |
| sensor-passive (SPAN, DHCP/ARP/mDNS) | works on Linux, rootful, with a card the customer prepared (promisc, no IP) | `compose.sensors.yaml`: `network_mode: host`, `user: 65532:65532`, `cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `read_only`, `creds-passive:ro`, command `passive --core https://127.0.0.1:8444 --creds ...` (exactly `host/ops/quadlet.go:145-155`) | card picker works after slice 4; Box network says the card must be prepared by the customer (G2) |
| sensor-active (`scan`) | works for nuclei; **no nmap** | same override, `init: true`, `creds-active:ro` (`quadlet.go:202-213`) | the module reports "nmap not available in this install"? Today the worker reports nmap missing as a failed job; wording is checked in slice 4 (needs a code read of `scan` first, not assumed) |
| honeypot | **not in v1** | no service | module card shows why (`notAnAppliance`, `cmd/vedette/honeypot.go:88-99`: "this machine is not an appliance: there is no vedette-host to run the honeypot container"). Reason on the honeypot page: **unverified** that the GUI shows `HostStatus.Reason` (no match for `reason` in `web/src/features/honeypot/*.tsx`): slice 5 checks. DEPLOYMENT 5's "trap on the primary IP, restricted" row is dropped from the table: no code path exists for it (no-imagined-features) |
| Box network (D-56): card, SPAN, secondary IP, NTP | not available | none | 409 text today; G2 adds what to do instead |
| OS updates, reboot (S-CORE-7) | not available | none | 409 text today |
| This box (S-INV-5) | device present, no package list | `hostname: vedette` | G3 |
| Software updates (S-CORE-2) | customer-run | none | 501 today, G4 |
| Backup | customer backs up the `data` volume | none | `409 not_appliance` on the download; G2 |
| greenbone | not in v1 (M7, not built) | none | none |

## 2. First run

1. Customer downloads the release's `compose.yaml` (+ overrides) and `vedette.env`, verifies them (section 4), sets `VEDETTE_BIND_IP`, `VEDETTE_HOSTS`, runs `docker compose up -d` (or `podman compose up -d`).
2. Setup code: `docker logs vedette-core 2>&1 | grep setup_code` (or `docker compose logs core`). It is one JSON line at every start while setup is open (`main.go:293-294`); the setup page asks for it and the 403 text already says "Find it in the box's log" (`setupcode.go:33`). The dev smoke reads it the same way (`sensors-smoke.sh:28`).
3. Address: `https://<VEDETTE_HOSTS first entry>:8443`. TLS: the self-signed pair made at first start, P-256, SAN = `-hosts` + the container's own names (`tls.go:518-537`); the browser warns once; the pair is in the `data` volume, so it survives `down`/`up`, and is kept by "Delete all data" (S-CORE-1 criterion). Customer certificate (`-tls-cert`): not in v1 compose (B3 stays open; one `volumes:` line and two flags when someone asks).
4. Wrong address: 421 with "Open it with the name or address it was set up with" (`hosts.go:62`). The doc line next to the three variables says this in one sentence.

## 3. GUI: what already says "Not available in container-only mode", and every gap

Today (verified in code): Settings → Updates operating-system part and the Box network page show the 409 as an `ErrorState` titled "Not available on this install" with the box's sentence ("This install has no operating system helper (container-only install), so Vedette cannot update or back up the operating system from here." / "... change the box's network from here."). Settings → Data: Download backup toast carries that sentence; Delete all data works and its dialog says the helper's backups are not this box's (`USER_STORIES.md:128`). e2e `bare-box.spec.ts` covers all three on a real bare box. So S-CORE-1's "say why, do not hide" is met for the three screens that exist. Gaps (every one is GUI-first: story criterion, then mock + contract, then screen; none starts before the lead approves; no backend is planned for any of them):

| # | Gap | Where | Story | Notes |
|---|---|---|---|---|
| G1 | First-run hint names a container and a unit that do not exist: `docker logs vedette` / `journalctl -u vedette` (`core.json:1123`) | Setup page | S-CORE first-run criterion (`USER_STORIES.md:144`, D-75, D-76) | text only; becomes "docker logs vedette-core, podman logs vedette-core, or journalctl -u vedette-core" |
| G2 | The 409 says what is missing but not what to do. The matrix promises "customer configures the card, GUI reads status if visible" and "customer backs up the volume" (`DEPLOYMENT.md:195,198`); the Updates and Box network pages give nothing | Updates (OS part), Box network, Data (backup) | S-CORE-7, S-CORE-8, S-CORE-1 | one extra sentence per screen, e.g. Box network: "Prepare the SPAN card on this machine (promiscuous, no address) and start the sensor with compose.sensors.yaml; then choose it in Sensors."; Data: "Back up the Docker volume `vedette_data`." Same `not_appliance` branch of `ErrorState`, so one component change, plus an optional `hint` the backend does not need to send (static text keyed on the code) |
| G3 | "This box" has no packages and the page does not say why | Inventory device page (`DevicePage.tsx:134,150` already special-cases `is_box` for source) | S-INV-5 | one line "The package list of this machine is not available in a container-only install"; needs to know the install kind: **the GUI has no field for it today**. Cheapest honest signal: the existing `not_appliance` from `GET /core/updates/os`. If the lead prefers a field (`install_kind` on `GET /core`), that is a contract change and needs its own story |
| G4 | Software update part: 501 "not available yet" on a real box (`.ai/deferred/feat-core-os-updates.md:3`); for container-only it must show the new version and the two commands, no Apply button | Updates (software part) | S-CORE-2 | blocked on the core software-update check (not built) and 08k, section 4 |
| G5 | Honeypot page reason when the module cannot run | Honeypot | S-HP-1 | unverified, slice 5 reads `HoneypotPage.tsx` first |
| G6 | Sensors page: with no host the card list is the sensor's heartbeat, and the page says nothing about preparing the card | Sensors, Box network | S-INV (sensors), S-CORE-8 | covered by G2's text; no new screen |

No new screen, no new nav item, no new setting. Reading `install_kind` is the only item that could need a contract change; it is deliberately left as a question in section 8.

## 4. Updates and verification

Appliance: `vedette-host` verifies minisign (index, manifest) and the cosign payload inside the manifest, then pulls by digest (D-103). Container-only has no host, so the customer does it.
- Exists today: the verifier code (`internal/release`, D-103), the release builder commands (`scripts/release`, D-164: `cosign-plan`, `manifest`, `sign`, `verify`), the test channel with throwaway keys (`make install-artifacts`, D-166).
- Does not exist, needs WP-08k (keys, registry, a published release): the real digests and the real `cosign.pub` / minisign public key to show; the `ghcr.io/knt048/vedette-*` images; the release assets.
- Needs core work (not 08k): the software-update check on a box (`GET /core/updates` is 501, `feat-core-os-updates.md:3`). Core can do the check without a host (GitHub index/manifest, verified in-process with `internal/release`, D-36, D-103) and for a container-only install answer "new version X, not applied here".
- What the GUI shows (G4), once those two exist: the version, the changelog, and two command blocks the customer copies. Update: `curl -fLO <release>/vedette.env`, `minisign -Vm vedette.env -P <key>`, `docker compose --env-file vedette.env pull && docker compose --env-file vedette.env up -d` (Docker; `podman compose` alike). Verify: `cosign verify --key cosign.pub ghcr.io/knt048/vedette-core@sha256:<digest>` per image. This works because D-103 (3) pushes the legacy cosign signature to ghcr "for whoever wants to check it themselves". Rollback: the previous `vedette.env` (kept by the customer; stated in the same block). Rollout cohort does not apply (host-side only).
- Until then: the doc (`docs/INSTALL-CONTAINER.md`, slice 1) carries the same commands, with the test channel's key for the lab.

## 5. Tests (by effect, no network)

Box: Docker 29 + Compose 2.40 and Podman 5.7 both present; builds use the pinned bases from the local cache.
- **Static (runs in `make check`, no docker)**: a Go test in `deploy/compose` (package beside `deploy/containers`, `go.yaml.in/yaml/v3` is already in `go.mod`) parses the three files and fails on: an image that is not `${VEDETTE_*_IMAGE}`, `latest`, `privileged`, a `docker.sock` or `podman.sock` mount, a published port without an IP, a user of 0 or missing, a service without `cap_drop: [ALL]`, `read_only`, `no-new-privileges`, a missing `restart`, a `network_mode: host` on anything but sensor/scan, a capability other than `NET_RAW`; and that every flag in `command` parses with `newFlags` (the trick of `host/ops` for Exec=, `main.go:44-47`). Also: the three env variables are named in `vedette.env`, empty in the repo (a test, like D-166).
- **Effect (new `scripts/dev/container-only-smoke.sh`, `make container-only-smoke`, opt-in like `dev-sensors-smoke`, not CI)**, per engine (`COMPOSE="docker compose"` or `"podman compose"`; images from `make core-image sensor-image scan-base-image` tagged `localhost/...:dev`, passed through `VEDETTE_*_IMAGE`; rootful sensors part only where allowed):
  1. up core `--wait`; the setup code is in the logs; setup through the API with it.
  2. Host: `curl --resolve` with the right name passes, a wrong `Host` gets 421 (finding 1).
  3. `GET /core/updates/os`, `/core/network`, `/core/data/backup` answer 409 `not_appliance`, never 5xx.
  4. Inspect: uid 65532, read-only rootfs, `CapDrop=ALL`, no-new-privileges, memory limit set; `ss -ltn` shows 8443 only on `VEDETTE_BIND_IP` and 8444 only on `127.0.0.1` (the Docker `-p` point, section 12).
  5. Persistence: `down` then `up`: setup still done, same cert fingerprint, key unchanged.
  6. Purge: "Delete all data" through the API: core exits, the restart policy brings it back, setup is open again with a new code in the logs, the cert is kept (needs `restart:`).
  7. Hostname: "This box" is named `vedette`.
  8. `compose.sensors.yaml` with the dev replay (as `dev-sensors-smoke`, reusing its device assertion); on Podman rootless only part 1-7.
  9. After slice 4: choose a card that exists only on the host (a dummy interface made by `ip link add` in a throwaway netns is not visible to core, so the test uses the card name the replay sensor reports in its heartbeat) and `PATCH /inventory/sensors/{id}` succeeds.
- **Playwright**: nothing new in v1 (no screen). `web/e2e-real/bare-box.spec.ts` is extended in slice 5 for G1-G3 text only.
- **Stays for the lab (WP-31)**: real SPAN card and port mirror (skipped for v1, D-403: SPAN hidden in the GUI), promiscuous on a USB card, syslog source IP through the real NAT, Docker Desktop on macOS/Windows (core only), Docker `-p` against UFW from another machine (`ss` is not proof: scan from the lab host), `podman compose` rootful with a real sensor on Ubuntu 24.04 (Podman 4.9), and a first run by a person who has never seen the product (kien or Mlee's box).

## 6. Top-tier

Phase 2 re-opened all four links; what they really say is in D-168 (the text below was from memory and is wrong in three places: Grafana's compose is not pinned and has no non-root example, Uptime Kuma's README has no Docker socket warning, Wazuh's page does not call itself evaluation-only). Original text:
- **Home Assistant, Container install** (https://www.home-assistant.io/installation/linux/#install-home-assistant-container and the comparison table at https://www.home-assistant.io/installation/): a four-way table of what each install kind has; Container has no Supervisor, no add-ons, no OS management, and says so in the table (our `DEPLOYMENT.md` section 5, the same honesty). Compose given as a snippet with a pinned-or-`stable` tag, `network_mode: host`, `restart: unless-stopped`, config volume, `--privileged` in the `docker run` form. Copy: the explicit limitation table, `restart: unless-stopped`, host network only where the product needs the LAN. Do not copy: `--privileged`, a floating `stable` tag.
- **Grafana, Docker** (https://grafana.com/docs/grafana/latest/setup-grafana/installation/docker/): compose with a named volume, a pinned version, the process as a non-root user, and a section "run as a different user" that spells out volume ownership. Copy: named volume + stated owner, no root step. Do not copy: `ports: "3000:3000"` on all addresses (our section 12).
- **Uptime Kuma** (https://github.com/louislam/uptime-kuma, README "Docker Compose" and `compose.yaml` in the repo): a one-file compose in the repo root, a named volume, `-p 3001:3001`; a warning that the Docker socket mount is optional and dangerous. Copy: one file in the repo plus a copy-paste quick start. Do not copy: the socket mount; unbound ports.
- **Wazuh Docker** (https://documentation.wazuh.com/current/deployment-options/docker/index.html, https://github.com/wazuh/wazuh-docker): a release-tag branch so the compose matches the version, a `generate-indexer-certs.yml` first-run step, a host prerequisite (`vm.max_map_count`) in the docs, and the clear note that it is for evaluation, with real deployments elsewhere. Copy: the compose and the images move together as a release (our `vedette.env` filled by the release), host prerequisites listed first (promisc card, Docker `-p` and UFW, rootful for sensors). Do not copy: a certificate generator service (core makes its own pair).

What we copy overall: a table of limits, one compose file that starts with one command, pinned images that move with the release, named volumes with a stated owner, `restart: unless-stopped`, host prerequisites up front.

## 7. Slices (PR-sized, in order)

| # | Slice | Files | Tests | Risk | Opus review |
|---|---|---|---|---|---|
| 0 | Story and decisions (docs only): new story **S-CORE-9** "Install on my own Docker or Podman" (Trigger, See, Press, Receive; criteria: one command, the three variables, 421 sentence, setup code from logs, the module table, "no host: say why and what to do"); criteria text for G1-G6 added to S-CORE-1/2/7/8, S-INV-5, S-HP-1 (text only, no screen change yet); DEPLOYMENT section 5 table fixed (trap row dropped, "Compose" only, link to the new doc), section 6.2 now points at the real file; ARCHITECTURE A7 answered; D-xx files | `docs/USER_STORIES.md`, `docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md`, `docs/decisions/D-nnn.md` | none (`make check` runs nothing for docs) | low | no |
| 1 | `docs/INSTALL-CONTAINER.md`: the customer's page (prerequisites, the three variables, verify, first run, update, what is not available, Docker `-p` and UFW, rootless limits) written from the files of slice 2; written second but merged with it | `docs/INSTALL-CONTAINER.md`, `THIRD_PARTY_NOTICES.md` unchanged (no new dependency, nothing new leaves the box: PRIVACY unchanged, to be re-read) | link check by eye | low | no |
| 2 | The compose files + `vedette.env` + `core/Containerfile` owned directories + the static Go test | `deploy/compose/container-only/*`, `deploy/containers/core/Containerfile`, `deploy/containers/containers_test.go` (the owner lines), `deploy/compose/compose_test.go` | static test via `heavy go test ./deploy/...`; `make images-check` for the Containerfile change (run by the lead) | medium: volume ownership on Podman rootless; `-hosts` shape | **yes** (security: ports, caps, ownership) |
| 3 | `scripts/dev/container-only-smoke.sh` + Makefile target + `docs/DEPLOYMENT.md` section 13 row; run on this box for Docker and Podman (rootless core, rootful sensors via sudo only if allowed on this box, otherwise Docker only) | `scripts/dev/container-only-smoke.sh`, `Makefile` | the script is the test; `shellcheck` | medium: slow, opt-in, not in CI | no |
| 4 | Backend: card validation without a host uses the sensor's heartbeat cards; scan says "nmap not available" in plain words; both with Contract tests | `cmd/vedette/sensorpassive.go`, `modules/sensor-passive`, maybe `modules/scan`, their `CONTRACT.md`/`IMPACT.md` | `go test ./modules/sensor-passive/... -run Contract`, `./cmd/vedette -run SensorPassive` | medium: touches the validation the appliance also uses (must stay as it is when a host answers) | **yes** (contract change, SYS invariants) |
| 5 | GUI (after story criteria of slice 0 are approved, GUI-first): G1, G2, G3 (text, mock, contract unchanged), G5 check; e2e text | `web/src/locales/en/core.json`, `web/src/components/common/States.tsx` or the three sections, `web/src/features/inventory/DevicePage.tsx`, `web/src/features/core/mocks.ts`, `web/e2e-real/bare-box.spec.ts` | vitest for the changed files, `web/e2e-real` bare-box spec (`make e2e-real`, heavy) | low | no (QA doc row instead, `docs/QA.md`) |
| 6 | Updates for container-only (G4): core check without host + the two command blocks | `modules/core`, `web/src/features/core/UpdatesSection.tsx`, `api/openapi.json` | contract + vitest | high | **yes**; **blocked** on the core software-update work and WP-08k; not started in WP-08m |
| 7 | Release shipping: the release builder copies the three compose files, fills `vedette.env` digests, signs them with minisign as release assets (D-164 builder, D-166 pattern) | `scripts/release/*` | builder tests | medium | **yes**; **blocked** on 08f/08k keys |

Order: 0, 2, 1 (together), 3, 4, 5, then 6 and 7 when 08k lands. Slices 0-5 need no key, no registry and no network. Each slice a branch `feat/container-only-<n>`; heavy commands through `~/vedette-wt/heavy`.

## 8. Decisions to record (own files `docs/decisions/D-nnn.md`, one row each; numbers allocated in slice 0, next free after D-251 on `main`)

1. **Container-only is Compose Specification v2 only**, Docker and Podman (`podman compose`); no Quadlet or `.kube` for it; the appliance owns Quadlet (D-55, D-123). Ref: HA, Grafana, Uptime Kuma, Wazuh all ship Compose. Changes the "Compose/Quadlet" wording of D-55 section 5.
2. **Files and images**: `deploy/compose/container-only/` (compose, two overrides, `vedette.env`); images only by `${VEDETTE_*_IMAGE}` digests filled by the release; repo copy refuses to start (D-166 (2) pattern).
3. **Network and addresses**: core on a bridge; 8443 bound to a required `VEDETTE_BIND_IP`, no default; `-hosts` from `VEDETTE_HOSTS` (Host allowlist and cert SANs; the fix for the 421); 8444 on `127.0.0.1` only; syslog is an override file; sensors only by override on a host network, Linux, rootful.
4. **Modules in container-only v1**: the table in 1.4; honeypot not offered (no code path, D-102 needs host-owned netns); `scan` without nmap; the DEPLOYMENT section 5 row "trap on the main IP" removed.
5. **Identity and ownership**: one uid `65532:65532` for all three containers (as dev, D-146); directories owned in the image so named volumes need no root step; `hostname: vedette`; `container_name: vedette-core` (matches the appliance unit, one log command for both).
6. **Update and verification are customer-run**: GUI shows commands, never an Apply button; minisign for `vedette.env`, cosign for each image (D-103 (3) already pushes the signature to ghcr); needs 08k.
7. **Tested versions, not a guessed floor** (closes B8 with the lab matrix).
8. **Card validation without a host** uses the heartbeat cards of the sensor (slice 4).

## 9. Questions only kien can answer

None blocking: no money, no legal change (no dependency, no new outbound flow: the compose pulls from `ghcr.io`, already PRIVACY flow 6, and the customer runs the pull), no change of product direction. Two worth one line each, with a recommendation:
- **Should the GUI know the install kind (`install_kind` field)?** Recommend no for v1: G3 keys on the existing `not_appliance` answer; add the field only if a screen needs it without a 409.
- **Quadlet for container-only Podman users?** Recommend no (decision 1): they should use the appliance installer. Say so if you want it, as its own story.
