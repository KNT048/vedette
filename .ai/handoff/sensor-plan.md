# Sensor protocol plan: `sensor` and `scan` talk to `core` over mTLS (Opus Plan agent, 2026-11-10; origin/main 54693fe)

I opened every URL cited below while planning. Quick facts:
- D-108 is the last decision.
- There is no CA or mTLS code anywhere yet. The only certificate code is the self-signed pair for port 8443 in `cmd/vedette/tls.go`.
- `cmd/vedette` has no subcommands, so DEPLOYMENT's `serve`, `sensor`, `scan-worker` and `healthcheck` do not exist.
- The spec draft calls the active side "sensor-active". The repo's container for it is `scan` (MANIFEST, ARCH §2). I keep the repo's names: `sensor` runs passive capture, `scan` runs nmap.

## 0. Gaps between the spec and the code
1. **Neither module can work on the appliance today.** `core` runs with `DropCapability=ALL`, so `OpenLive` (AF_PACKET) and `nmap --privileged` both fail with EPERM. sensor-passive INV-2 and sensor-active INV-6 / D-84(5) defer exactly this (`.ai/deferred/feat-sensor-{passive,active}.md`).
2. **Which container runs what.** The spec has one `sensor` doing passive capture, active scans, syslog and the honeypot relay. The sensor-active MANIFEST and ARCH §2 put nmap in `scan`, while DEPLOYMENT §2.2 still has nmap in `sensor`.
3. **`UserNS=auto` breaks raw sockets.** D-105 and DEPLOYMENT §12 give every service except core `UserNS=auto`. With `Network=host`, the container's `NET_RAW` then belongs to a child user namespace and does not cover the host network namespace, so raw sockets fail. Four sources also disagree on the sensor's uid:
   - host CONTRACT: "non-root";
   - DEPLOYMENT §6.1: "UID 0 + 2 caps";
   - D-57(5): "normal user, NET_RAW/NET_ADMIN";
   - ARCH A4: still open.
4. **Where nmap comes from.**
   - update-manifest §4 example: `bundled: scan nmap 7.95`, i.e. nmap shipped inside the image.
   - D-4, D-57(2), LEGAL.md and sensor-active FORBID-4: nmap is never shipped and the `scan` image is built on the box.
   - D-104 and host-api: the host only pulls ghcr digests and has no build command.
5. **Honeypot hits.** Spec §5.4 sends them through the sensor; D-89 uses a file channel instead.
6. **Scan command shape.** Spec §6.2 `scan.now {targets CIDR, profile light|standard}` does not match D-84: three shapes (sweep/normal/gentle), at most 64 IPv4 addresses, a rate, host timeouts, and a deadline of at most 2 h. It also has no "stop when settings change" path (INV-3) and no "probe row written before nmap runs" rule (INV-9).
7. **Observation fields.** Spec §5.3 allows fields `service` and `lldp_neighbor` and sources `nmap`/`snmp`. `core/observe.Field` is a closed set of six values. nmap software results (`ReplaceSoftware`) have no wire type.
8. **Which CA.** Spec §3 uses the osquery-intake CA, which exists only on paper.
9. **Enrollment.** Spec §3.1 has the installer write an enroll token into a shared volume (installer or root handling core secrets). There is no story or GUI for it (D-24, D-57(18)), and `inventory.test.tsx:933` asserts "no remote-sensor endpoints".
10. **Decoding and durability.**
    - Spec §4 says unknown fields are ignored; the repo rule (`internal/jsonstrict`, host-api) refuses them.
    - Spec §5.2 asks for a durable 256 MiB WAL; the sensor-passive queue and `deviceBook` live in memory.
11. **Core sees the wrong interfaces.** Core sits on the `vedette-int` bridge, yet four places read `net.Interfaces`/`net.InterfaceAddrs`: `netHost` (sensorpassive.go), `ProtectedIPs` (sensoractive.go:213), honeypot.go:156 and conn.go:140. On the appliance they see `vedette-int`, not the box's LAN cards. sensor-passive `Status()`/`SpanStats()` also read the in-process engine, which will no longer be in core.
12. **Flood limits move out of core.** The limits (60/200 new MACs per minute/hour, 4 values per MAC per hour) run in the capture process. Once that process is an untrusted container, a compromised sensor skips them; the inventory keeps only its 32-row cap.
13. **Open spec questions.** Port 8444 is "proposed" in ARCH/DEPLOYMENT and open in spec §12 Q2; spec Q1–Q6 are all still open.
14. **Update order.** host-api §6.8 restarts `sensor`/`scan` before `core`, so a newer sensor briefly talks to an older core.
15. **Unneeded capability.** The DEPLOYMENT sensor unit grants `NET_BIND_SERVICE` for syslog 514, but the `logs` receiver is not built.

## 1. Decisions (D-109 to D-116)

**D-109 Transport: HTTPS + JSON on stdlib `net/http`/`crypto/tls`. Sensors only ever call out; commands arrive by long-poll.**
- **Listener:** a second listener in `core`, `:8444` in the container, published only as `127.0.0.1:8444` (already in DEPLOYMENT/host-api §18).
- **TLS:** 1.3 minimum, `RequireAndVerifyClientCert`, `VerifyConnection` checks the role and serial. HTTP/2 when ALPN offers it, never required.
- **Request rules:**
  - every request carries `X-Vedette-Proto: 1`;
  - bodies are decoded with `internal/jsonstrict` (unknown fields refused, depth ≤ 32);
  - `http.MaxBytesReader` before decoding;
  - `ReadHeaderTimeout` 5 s and `WriteTimeout` 35 s.
- **Version skew:** a proto mismatch gets `426` and the sensor waits and keeps its queue. This covers the update-order window (gap 14).
- **Why not something heavier:** the sensor holds `NET_RAW` in the host namespace, so every module linked into it runs with raw-socket privilege. Stdlib keeps the image static and small and leaves govulncheck's surface unchanged.
- **References:**
  - grpc-go go.mod: 23 direct + 11 indirect requirements, including protobuf, genproto, otel and envoy (https://github.com/grpc/grpc-go/blob/master/go.mod).
  - osquery remote API: HTTPS JSON POST, the node polls, `node_invalid` means re-enroll (https://osquery.readthedocs.io/en/stable/deployment/remote/).
  - Elastic Fleet: agents "always initiate the connection … HTTP long polling", "no inbound connection" (https://www.elastic.co/docs/reference/fleet/fleet-server).
  - crypto/tls `VerifyConnection` runs on every connection, including resumed ones (https://pkg.go.dev/crypto/tls).
- **Rejected:**
  - gRPC: dependency weight, protoc toolchain, and streaming is not needed.
  - ogen/OpenAPI: `api/openapi.json` is generated from the GUI's Zod contract (D-18); an internal protocol does not belong in it, and generating code for about 6 routes is overhead.
  - WebSocket: stateful, and long-poll is enough.
  - Unix socket + `SO_PEERCRED` (the `host.sock` pattern): ARCH TB-9 asks for mTLS, and a split sensor must later use the same wire over the LAN.
  - gzip: decompression-bomb surface, and the link is loopback.

**D-110 PKI: `core` is a small internal CA built on `crypto/x509`, for sensors only. Core issues sensor keys and hands them over as files; the host never touches them.**
- **CA:** ECDSA P-256, 10 years. The key is stored with `core/secrets` (AES-256-GCM, `master.key`).
  - It is separate from the 8443 certificate and from the future osquery CA: a CA trusted by LAN agents or browsers must not be able to mint sensor identities (kubeadm also keeps etcd and front-proxy CAs separate).
  - A restore without `master.key` produces a new CA and new sensor certificates; both sensors are local, so nothing breaks.
- **Leaf certificates:**
  - Server: EKU `serverAuth` only; SAN `IP:127.0.0.1` plus `DNS:core` (for compose).
  - Sensors: EKU `clientAuth` only; URI SAN `vedette:sensor:passive` or `vedette:sensor:active`; serial recorded in `core_sensor_cert(role, serial, not_after, retired_at)`.
  - A stolen sensor certificate therefore cannot pose as core (Consul's `verify_server_hostname` idea).
- **Lifetime and rotation:** 7 days. Core checks at start and daily, and renews when ≤ 1/3 of the lifetime is left (step-ca renews at about 2/3).
- **No network enrollment on the appliance.**
  - At start, before it listens, core generates the key and writes one PEM bundle (key, certificate, CA) to `creds/<role>/sensor.pem`.
  - Writing: `os.OpenRoot`, temp file with `O_EXCL|O_NOFOLLOW`, fsync, `Rename`. Core never reads the file back (the D-89 pattern).
  - The sensor re-reads the file in `GetClientCertificate` when its mtime changes and drops idle connections.
  - Core may issue the key because it can already mint any sensor identity; kubeadm likewise issues client certificates for the local controller-manager and scheduler.
- **Revocation:**
  - Each request's leaf serial must be the current or the previous one for its role (rotation retires older serials), and the check repeats per request, not only per handshake.
  - The 7-day lifetime bounds the rest (passive revocation).
- **Host:** does nothing except render the constant units that mount the per-role volumes (D-111/D-114). It never sees keys (D-87).
- **References:**
  - https://developer.hashicorp.com/consul/docs/secure/encryption/tls/enable/new/builtin ("Use a private CA", server vs client names)
  - https://kubernetes.io/docs/setup/best-practices/certificates/ (controller-manager and scheduler client certificates; separate etcd and front-proxy CAs)
  - https://smallstep.com/blog/passive-revocation/ (CRL/OCSP often unchecked; short lifetimes; renew at about 2/3)
- **Rejected:**
  - Reusing the osquery CA.
  - Pinning self-signed leaves: custom verification in both directions, and no EKU or expiry semantics on the stdlib path.
  - Token enrollment on the appliance: an unauthenticated endpoint plus a token passed through a volume, for a component on the same box. It stays for remote sensors (D-115).
  - A CSR written by the sensor: core would have to parse a reverse channel for no trust gain.
  - CRL/OCSP.

**D-111 Authorization by role.**
- **Routes per identity:**
  - `passive`: `GET /sensor/v1/config`, `POST /sensor/v1/observations`, `POST /sensor/v1/heartbeat`.
  - `active`: `GET /sensor/v1/jobs`, `POST /sensor/v1/jobs/{id}/result`, `POST /sensor/v1/heartbeat`.
  - Any other route → `403 forbidden_route`, checked before the body is read.
  - At most one long-poll per role; a second one gets `409`.
- **What a sensor may send:**
  - Observations carry no `source`: core sets `passive` from the role, so a sensor cannot claim `manual`.
  - Fields come from `observe.Field`.
  - Core re-applies the per-sensor flood limits at the endpoint: new MACs ≤ 60/min and 200/h, values ≤ 4 per MAC per field per hour, using an in-memory map keyed by MAC. Excess items are rejected with `budget_exhausted` (fixes gap 12).
- **What core may ask:**
  - The passive sensor gets only `config`: `{interface, span, extract{dns,sni,http,flows}, filters[]}`. If the filters cannot be read, the response is "no capture" (fail-closed, D-80(3)).
  - The active sensor gets only nmap jobs (D-113). There is no generic command, no argv, no path and no URL on the wire.
- **Module off:** the role's routes answer `409 module_off`. The sensor stops at once and drops its queue (SYS-5, D-80(4)).
- **References:**
  - Kubernetes Node authorizer + NodeRestriction: kubelets "limited to reading their own Node objects" (https://kubernetes.io/docs/reference/access-authn-authz/node/).
  - The Consul page above.

**D-112 Observation model and backpressure (OTLP semantics).**
- **Observations:** `POST /observations {epoch, seq, items[1..500]}`.
  - Item: `{mac?, ip?, field, value ≤200 B, confidence 0..1, seen_at}`.
  - `seen_at` must be within 24 h back and 5 min ahead.
  - Body ≤ 1 MiB.
- **Epoch and seq:** a random 16-byte epoch for each sensor process start; `seq` starts at 1. The existing `sp_seq(sensor_id, epoch)` and `SubmitBatch` handle replay (POST-3). Only the last 2 epochs are kept.
- **Reply:** `200 {ack_seq, rejected:[{index, code}]}` is a partial success and is never retried. This maps `observe.ErrRejected` as today.
- **Retries:**
  - `429` (10 req/s, burst 20) and `503 store_busy` carry `Retry-After`; the sensor backs off 1→60 s with jitter (the existing `holdOff` and poison hunt).
  - `413` halves the batch.
  - Any other 4xx drops the batch and is counted.
- **Heartbeat** every 30 s, body ≤ 64 KiB: `{version, interfaces[≤32]{name, mac, link, ipv4[≤8]}, span{pps, other_macs, last_packet_at}, drops{closed keys}, devices_seen}`. `online` means a heartbeat within 90 s. The heartbeat feeds `Status()`, `SpanStats()` and `SetInterface` validation (fixes gap 11 for the sensor).
- **No WAL.**
  - ponytail: observations recur (ARP, DHCP, mDNS), so a sensor restart loses at most one flush (≤ 5 s). The upgrade path is a bounded on-disk queue when sensors go remote.
- **Wire types without a consumer are left out:** SPAN metadata (`logs` not built), `logs.*` and `honeypot.hit` (D-89 stays).
- **Reference:** OTLP: `partial_success` "MUST NOT" be retried, 429/503 with Retry-After, "All other 4xx or 5xx … MUST NOT be retried" (https://opentelemetry.io/docs/specs/otlp/).

**D-113 nmap moves to `scan`; consent stays entirely in core.**
- **Policy stays in core:** `sensoractive` keeps window, scope, `ScanPolicy`, queue, the probe row written first, and the version check. Only `s.runner.Run` is swapped for a `Prober` seam with two implementations: local `core/exec` for tests and dev, and the remote dispatcher.
- **Job:** `{id, shape: sweep|normal|gentle, rate 1..1000, targets 1..64 private IPv4, timeout_s ≤ 7200}`.
- **The worker re-validates:**
  - it rebuilds the argv with the same `buildNmapArgs` and `ValidateNmapArgs` (moved to a leaf package);
  - caps the timeout at 2 h;
  - runs one job at a time;
  - holds no scope. Core is the only consent authority (D-26, D-84). A compromised core can scan private IPv4 within this grammar, which is exactly what it can do today.
- **Dispatcher (in memory, one job in flight = "one nmap on the box"):**
  - **Cancel:** sent through the long-poll (`cancel:[id]`) when the probe context ends; covers INV-3 and the `SettingsChanged` stop.
  - **Lease:** the worker kills the process group if it hears no successful poll for 60 s or the core `instance` nonce changes. A core crash leaves no orphan scan.
- **Result:** `{status: done|failed|stopped|refused, exit_code, truncated, xml ≤ 8 MiB}`, body ≤ 9 MiB. It is parsed by the existing fuzzed `parseNmapXML` and `onlyTargets` in core (INV-7), so nmap observations and software never cross the wire.
- **Health:** `unavailable` with no `scan` heartbeat for 90 s, or when the worker reports nmap missing (INV-6).
- **Image:** the `scan` image is built on the box (D-57(2)) by `vedette-host` from a constant Containerfile:
  - `FROM` the signed `vedette-scan` base digest (Debian slim + `vedette-sensor`), plus `apt-get install --no-install-recommends nmap`;
  - tagged `localhost/vedette-scan:<version>`;
  - effect check: `nmap --version` inside the image.
- **References:**
  - Home Assistant: "Without `image`, the Supervisor builds the app on the device" (https://contributors.home-assistant.io/apps/reference/configuration/).
  - Nmap license: no redistribution "within commercial software or hardware products" (https://nmap.org/book/man-legal.html).
- **Rejected:**
  - nmap inside the ghcr image (D-4, LEGAL).
  - Bind-mounting the host's nmap (libraries differ across Ubuntu 24.04, 26.04 and Debian 13).
  - Parsing XML in the worker (a second schema that core must re-validate; kept as the upgrade path).
  - Durable job tables (one in-flight job; `failInterrupted` already closes orphan rows).

**D-114 Passive capture moves to `sensor`; how the two containers run.**
- **sensor-passive splits in two:**
  - `modules/sensor-passive/capture`: Source, Engine, book, flush/deliver via `Uplink{Config, Submit, Heartbeat}`; no `core/store` imports.
  - The core half: `sp_*`, `SubmitBatch`, `Status`, `SetInterface`; `SpanStats` from the heartbeat. `SetInterface` wakes the config long-poll (ETag), which replaces the `reload` channel.
- **One sensor binary:** new `cmd/vedette-sensor` with `passive`, `active` and `healthcheck` subcommands. Contract test: `go list -deps` contains no `database/sql`, `modernc.org/sqlite` or `ogen` (like host INV-13).
- **Units** (amends D-105, D-57(5), DEPLOYMENT §6.1):
  - `sensor` and `scan` run `User=<sensor_uid>:<sensor_gid>` (new keys in `host.conf`).
  - **No `UserNS`:** man user_namespaces(7) — capabilities only cover resources "governed by that namespace", and the host network namespace belongs to the initial one.
  - `DropCapability=ALL`, `AddCapability=NET_RAW` only. Podman puts added capabilities in the ambient set for non-root users, and ambient caps "populate both the Permitted and Effective sets after execve()". This is a lab gate; the fallback is UID 0 + NET_RAW.
  - `NoNewPrivileges`, `ReadOnly`, tmpfs.
  - `NET_BIND_SERVICE` is dropped until syslog exists. `NET_ADMIN` is never granted (the host sets SPAN promiscuous mode).
- **Credential volumes:** `vedette-creds-{passive,active}.volume` with `User=<core_uid>`, `Group=<sensor_gid>`.
  - Each is mounted read-write only in `core` and read-only only in its own role's container.
  - `core` gets a constant `PodmanArgs=--group-add=<sensor_gid>` (Quadlet 4.9 has no `GroupAdd=`) and writes files `0640 core_uid:sensor_gid`.
- **Box addresses** for `ProtectedIPs`, honeypot and conn come from host `GET /v1/state/net` (host slice 3-3); until that lands, from the passive heartbeat.
- **References:**
  - https://man7.org/linux/man-pages/man7/user_namespaces.7.html
  - https://github.com/containers/podman/issues/13449 (`cap_sys_admin=eip` with `--user 1`)
  - https://gist.github.com/mvazquezc/bf5f129025f9c7f224ed1acb32c95c27 ("Podman supports ambient capabilities")
  - https://developers.redhat.com/articles/2026/10/05/why-your-non-root-container-dropped-its-capabilities-and-how-to-fix-it
  - https://manpages.ubuntu.com/manpages/noble/man5/podman-systemd.unit.5.html (`.volume User=/Group=`, no `GroupAdd`)

**D-115 Remote sensors come later, not in this WP.**
- Not in this WP: no `enroll`/`renew` endpoint, no LAN listener, no GUI. Reasons: D-24, D-57(18), the GUI test, no-imagined-features.
- The wire, role URIs and CA are what a remote sensor will use. The remote path will add kubelet-style bootstrap (bootstrap token → CSR, key generated on the sensor, renewal near expiry; https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/), a LAN bind, a revoke action, and a disk queue. It needs a story first.
- Spec §3.1 moves to a "deferred" appendix.

**D-116 What is testable without root or real networks.**
- **TLS and PKI:** an ephemeral CA in `t.TempDir`, `httptest.NewUnstartedServer` with the real `tls.Config`, and a clock seam for expiry and rotation.
- **Passive:** pcap replay (`FileSource`) → capture → real client → core handlers over loopback mTLS → temp SQLite inventory; the existing sensor-passive contract tests run on the split.
- **Active:** core with a fake `Prober`. The worker runs `exectest` fake-nmap scripts (sleep, emit XML, ignore SIGTERM) to prove kill on cancel, lease loss and deadline.
- **Fuzz:** every decoder and `ValidateNmapArgs`.
- **Lab only:** AF_PACKET and nmap `-sS`/`-O` under non-root ambient `NET_RAW`; `127.0.0.1:8444` from host-network containers; `.volume User=`; the local `scan` build on the three distros.

## 2. Slices (one PR each)

**SP-0 docs-first.**
- DECISIONS D-109…D-116.
- Rewrite `sensor-protocol.md` as the appliance profile: routes, schemas, caps, roles, error table; close Q1–Q6.
- ARCH §2/§6/TB-9/A4; DEPLOYMENT §2.2/§2.4/§6.1/§7 (units, creds volumes, uid, no UserNS).
- host-api §18 unit table + `host.conf` keys; host CONTRACT INV-17 test list.
- sensor-passive and sensor-active CONTRACT/MANIFEST/IMPACT (INV-2, INV-6, INV-8).
- update-manifest `bundled` (nmap is built on the box, not bundled).
- New `.ai/deferred/feat-sensor-protocol.md`.

**SP-1 `core/pki` + `core/sensorlink`** (server and client; no module wiring).
- Files: `core/pki/{ca,issue,creds}.go`, `core/sensorlink/{server,client,limits,errors}.go`, `core_sensor_cert` migration.
- Tests:
  - wrong CA, the 8443 self-signed certificate, expired and not-yet-valid certificates;
  - server certificate used as a client (EKU); wrong role URI;
  - retired serial on a live keep-alive connection;
  - rotation without a restart; a half-written bundle;
  - body caps, unknown field, depth, 426, 429 with Retry-After;
  - a second long-poll gets 409; slowloris timeouts;
  - creds writer refuses symlinks and FIFOs.
- Review must attack: EKU/SAN confusion, TLS 1.3 resumption bypassing the serial check, races on the creds file, CA key handling in `core/secrets`, goroutine exhaustion through long-polls, path escape in the writer.

**SP-2 sensor-active seam, pure refactor** (in parallel with SP-1).
- Move `flagsFor`/`buildNmapArgs`/`ValidateNmapArgs` to `modules/sensor-active/nmapargv`; add `Prober` with the local implementation.
- Tests: every `TestContract_INV*` passes unchanged; `FuzzValidateNmapArgs` stays in the leaf package.
- Review must attack: any behaviour change in the order of checks (INV-1, INV-9).

**SP-3 Remote nmap: dispatcher + `vedette-sensor active`** (needs SP-1 and SP-2).
- Files: `modules/sensor-active/{dispatch.go,worker/}`, `cmd/vedette-sensor/active.go`.
- Tests:
  - the INV-1..5 suite through the dispatcher;
  - cancel during a run kills the process group;
  - lease loss and core instance change kill nmap;
  - the worker refuses public IPs, 65 targets, rate 0 or 1001, unknown shapes, timeout > 2 h;
  - a result for an unknown or foreign job → 404;
  - XML of 8 MiB + 1 → `413`, and the probe row ends `failed`;
  - Health `unavailable` without a heartbeat.
- Review must attack: whether the passive role can fetch or answer jobs; job-id guessing and replayed results; cancel racing start; orphan nmap processes; XML bombs; core trusting the worker's `status`.

**SP-4 Passive split + `vedette-sensor passive`** (needs SP-1).
- Files: `modules/sensor-passive/capture/`, core-half handlers, `cmd/vedette-sensor/passive.go`.
- Tests:
  - replay end-to-end over mTLS;
  - seq/epoch replay;
  - rejected item, 503 retry, poison hunt over the wire;
  - module off stops capture with no final flush;
  - unreadable filters → no capture;
  - SpanStats verdicts from the heartbeat; `/inventory/sensors` from the heartbeat;
  - core-side budgets (`budget_exhausted`).
- Review must attack: a compromised sensor flooding devices or values; spoofed interfaces in the heartbeat (`SetInterface` only picks the sensor's own card); confidence above the protocol scale (core clamps per field).

**SP-5 Packaging + box addresses** (needs SP-3 and SP-4).
- Contents:
  - `deploy/containers/{sensor,scan-base}/Containerfile`;
  - the `go list -deps` boundary test;
  - compose `dev` profile: core + sensor-replay + scan with fake nmap; CI runs it and checks a device appears;
  - core flags `-sensor-listen` and `-sensor-creds`;
  - `ProtectedIPs`/honeypot/conn switch to the box-address provider;
  - remove the capture job and local nmap from production wiring.
- Review must attack: anything left in `core` that still needs a capability; the creds directory reachable from other containers.

**SP-6 Host: units and local `scan` build** (needs host 3-6 and 3-7).
- Contents: templates for `sensor` and `scan` (`User`, no `UserNS`, `NET_RAW`, creds volumes), core's `127.0.0.1:8444` and `--group-add`, `.volume` units, `host.conf` `sensor_uid`/`sensor_gid`, and `container.pull scan` running `podman build` with a fixed argv from the constant Containerfile.
- Tests: golden units; contract test for mounts and capabilities per service; build argv grammar; a failed build keeps the previous image.
- Review must attack: root running `podman build` (RUN steps as container root, network, apt trust); `group-add` widening core; unit injection through `host.conf` values.

## 3. What core and the GUI need
- **GUI-first is met; no new screens.**
  - `SensorsSection` (`GET /inventory/sensors`: status, `last_seen`, version, `devices_seen`, `span_status`) and Box network `SpanCard` (`/core/network/span/status`) already exist. Only their data source changes, to the heartbeat.
  - Enrollment UI is forbidden by the existing test (D-115).
  - sensor-active Health has no screen; that is already deferred.
- **USER_STORIES:** add an S-INV-1 criterion: "the sensor shows offline within 90 s of stopping; capture runs only in the `sensor` container".
- **Core:**
  - the second listener;
  - PKI at start, before listening; a daily rotation job;
  - `module_off` gating;
  - sensoractive `Prober` wired to the dispatcher;
  - sensor-passive core half;
  - the box-address provider;
  - CONTRACT: a core INV for the sensor link (roles, caps, serial check).

## 4. Risks and deferred items
- **Risks (lab-gated):**
  - Podman ambient capabilities for a non-root `User=` on 4.9 and 5.x (fallback UID 0 + `NET_RAW`).
  - nmap `-O` may also want `NET_ADMIN`.
  - netavark forwarding to `127.0.0.1` for host-network clients (needs `route_localnet`).
  - `.volume User=/Group=` on 4.9.
  - `NoNewPrivileges` together with ambient capabilities.
  - The `scan` build needs the apt mirror: a box without it has no active discovery, and Health says so.
  - Core restarting mid-scan drops that batch (by design).
  - A compromised `sensor` can still forge plausible observations (inherent; bounded by the budgets and D-51 approvals).
- **Deferred:**
  - remote sensors (D-115);
  - SPAN metadata and `logs.batch` (with the `logs` module), plus syslog `NET_BIND_SERVICE`;
  - a disk queue;
  - nuclei jobs for the `scan` module (a new job type in the same channel);
  - SNMP;
  - a revoke UI;
  - parsing nmap in the worker.

## 5. Owner questions
None meet the `decide-like-top-tier` bar. D-57(2) already chose the on-box build, so no new data flow or licence question arises (apt mirrors are PRIVACY flow 6). D-114 amends D-105 and D-57(5) in a reversible way.

### Critical files for implementation
- /Users/kien/Desktop/vedette-wt/conn-transport/modules/sensor-active/service.go (on origin/main: `probe()` and the `runner.Run` seam)
- /Users/kien/Desktop/vedette-wt/conn-transport/modules/sensor-passive/service.go (on origin/main: `SubmitBatch`, `SpanStats`, split point; plus `run.go`)
- /Users/kien/Desktop/vedette-wt/conn-transport/cmd/vedette/main.go (on origin/main: `serve()` second listener; with `tls.go` and `sensoractive.go:213`)
- /Users/kien/Desktop/vedette-wt/conn-transport/docs/specs/sensor-protocol.md (on origin/main: rewrite in SP-0)
- /Users/kien/Desktop/vedette-wt/conn-transport/docs/DEPLOYMENT.md (on origin/main: §2.2, §6.1 units, uid, UserNS)