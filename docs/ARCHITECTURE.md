# Technical architecture

This document describes the system as built for v1. Each module's exact rules are in its `CONTRACT.md`; where this overview and a contract differ, the contract and the code win.

Related documents: [`DEPLOYMENT.md`](DEPLOYMENT.md) (containers, installation, upgrades) · [`DATA_MODEL.md`](DATA_MODEL.md) (tables, relations) · [`API_CONVENTIONS.md`](API_CONVENTIONS.md) (REST, errors, pagination, SSE) · [`specs/`](specs/) (`specs/*.md`, including [`specs/host-api.md`](specs/host-api.md)) · `modules/<id>/CONTRACT.md` (per-module contracts, `MODULE_CONTRACTS.md`) · `UPDATES.md` · `DATA_PIPELINE.md` · `AI_ASSISTANT.md` · `../PRIVACY.md` · `../SECURITY.md`.

## 1. Overview

Vedette is an **appliance** placed in a business's LAN (one site): it pulls exploited-vulnerability feeds, matches them against the device inventory, runs confirming scans, honeypots, logs, approved responses and a BYOK AI assistant. It is **not inline and does not block traffic**. Every connection to the Internet is opened by the box itself; no inbound port from the Internet is needed.

```
                         Internet (outbound connections only, HTTPS 443)
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ feed sources (CISA, FIRST, NVD, abuse.ch…)        GitHub Releases + registry │
   │ the customer's AI provider (BYOK)                 (signed software only)     │
   │ channels: the customer's Slack/Telegram/Zalo/SMTP                            │
   └──────────────────────────────▲──────────────────────────────────────────────┘
                                  │ only the box opens connections
┌─────────────────────────────────┴────────────────── customer LAN ───────────────┐
│  VEDETTE BOX (Debian/Ubuntu + vedette-host + Podman)                             │
│                                                                                  │
│   vedette-host (systemd, root, very small)   ◄── internal socket, fixed commands │
│     OS update · netplan · image pull + cosign · start/rollback container · backup│
│        │ manages                                                                 │
│   ┌────▼─────────────────────────────────────────────────────────────────────┐  │
│   │ core   (Go + embedded SPA + SQLite)   ◄── mTLS poll ── sensor  (host net)│  │
│   │  module registry, feeds, inventory,           ◄───── honeypot (macvlan)  │  │
│   │  mitigation, notify, ai, response,            ◄─ mTLS ── scan (host net) │  │
│   │  reports, logs-analysis, mcp-server           ◄───── greenbone (optional)│  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│        ▲ HTTPS 8443        ▲ syslog 514      ▲ SPAN/TAP        ▲ trap (2nd IP)   │
└────────┼───────────────────┼─────────────────┼─────────────────┼─────────────────┘
   browser (3 roles)    firewall/switch/server   mirror port       LAN machine touching a trap
                         (syslog source, osquery, Wazuh API, device API)
```

The box is **not** on the network path: it is a host in the LAN that optionally receives SPAN/TAP (read-only metadata) and syslog. The only write connection to customer devices is the `response` module, off by default, with every action approved by a person.

**Two install kinds**: *Appliance* (full features, `vedette-host` manages the OS) and *Container-only* (the customer's existing Docker/Podman, no OS management). The differences are in `DEPLOYMENT.md` §5.

## 2. Components

| Component | Role | Runs where | Privileges | Basis |
|---|---|---|---|---|
| `vedette-host` | OS update, network configuration (management NIC, SPAN, secondary IPs), pull + verify images, start/stop/rollback containers, backup, read dpkg for "This box" | systemd process on the host | root, very small surface (fixed commands, SYS-1) | — |
| `core` | Go + embedded SPA + SQLite: auth, module registry, jobs, audit, secrets, feeds, inventory, matching, mitigation, notify, ai, response, reports, mcp-server | Container, internal bridge network, publishes 8443 | non-root, cap_drop ALL, read-only rootfs | — |
| `sensor` | passive packet capture: the `capture` half of `sensor-passive` (DHCP/ARP/mDNS/SSDP/LLDP, a SPAN metadata analyzer written in Go), `vedette-sensor passive`, sends observations and heartbeats to `core` over the sensor protocol; syslog is received by `core` (the `logs` module), not by the sensor | Container, **host network** | `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, only `CAP_NET_RAW` (ambient; no `NET_BIND_SERVICE`, no `NET_ADMIN`) | — |
| `honeypot` | One OpenCanary process + honey tokens; configuration read from a file `core` writes, hits written to a file `core` reads | Container in the `vedette-hp` namespace held by the host: each secondary IP/decoy gets its own **macvlan** link and MAC, nft blocks new outbound connections | no capabilities (`ip_unprivileged_port_start=0` in the namespace) | — |
| `scan` | the nmap worker of `sensor-active` (`vedette-sensor active`): receives nmap jobs by long-poll, returns XML; policy and consent live in `core`. Later: the `scan` module's nuclei jobs on the same channel (the `exposure` external-surface scanner runs inside `core`) | Container, host network; image **built on the box** from the signed base image + nmap from the OS package repository | like `sensor`: `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, only `CAP_NET_RAW` | — |
| `greenbone` | OpenVAS (Greenbone Community Edition): the optional deep scan of External exposure, run without logging in on the box's own verified public IP (credentialed scanning, S-SCAN-5, is after v1) | Upstream container group that `vedette-host` starts when an administrator enables it, internal network | GPL/AGPL, unmodified | S-EXP-2 |
| SPA (`web/`) | React, a single `en` locale via i18next | Embedded in `core` | — | — |

One Go codebase, packaged as several images: `core` (`cmd/vedette`) and `sensor`/`scan` (`cmd/vedette-sensor`, subcommands `passive`/`active`/`healthcheck`) are the same Go module with different entrypoints; the sensor binary does not link `database/sql`/SQLite.

## 3. Stack and rationale

| Layer | Choice | Rationale |
|---|---|---|
| Backend | Go (pinned in `go.mod`), `net/http` + a light router, embedded SPA via `embed`, cross-compiled for amd64/arm64 | The external-surface scanner is written with the Go standard library, without httpx/naabu/subfinder (nuclei: a binary in the `scan` container); the sensor I/O is light; one codebase |
| DB | SQLite (`modernc.org/sqlite`, no cgo, WAL), queries through sqlc; FTS5 for the AI knowledge base | Backup = a consistent copy of a file; PostgreSQL is not supported |
| Frontend | React + TypeScript + Vite + Tailwind + Radix + TanStack Query/Table + React Router; English only | Details in `FRONTEND.md` |
| Jobs | In-process (`core/jobs`), with locks + history, no message queue (one process) | Enough for ≤1,000 devices per site |
| Sensor ↔ core communication | HTTPS JSON on the standard library's `net/http`/`crypto/tls`, mTLS with `core`'s own sensor CA, permissions per role, **sensors long-poll core** (core never calls into a sensor) | No inbound port on the sensor; §6, `specs/sensor-protocol.md` |
| Container runtime | **Podman + systemd Quadlet** on the appliance; Docker Compose for dev/CI; the same OCI images | No root daemon; does not open ports through the firewall on its own the way Docker does |
| Supply chain | **cosign**-signed images, CycloneDX SBOM, staged rollout, rollback by the old tag | `UPDATES.md` |
| Discovery/Scan | nmap (separate process, NPSL), Recog, gosnmp, nuclei (binary pinned in the `vedette-scan` image, safe template pack `kev,vkev` signed with the image) | — |
| Honeypot | OpenCanary (BSD-3) as a separate process, configuration generated from the DB | The honeypot is not rewritten |
| AI | Anthropic / OpenAI-compatible / Gemini / custom adapters; harness | BYOK: the customer chooses the provider |

Not used: Zeek, Suricata, a central builder/Cloudflare/CDN, A/B binary slots, fleet/tenant mechanisms.

## 4. Module map

Modules are switched on and off individually (`MODULES.md`): off = no routes, no jobs, no ports, data kept (SYS-5; except jobs that delete by retention period or storage cap). The "Container" column shows which process actually runs.

| Module | Tier | Container | Depends on | Ports/permissions | Story |
|---|---|---|---|---|---|
| `core` | core | core | — | 8443 | S-CORE-1…7 |
| `feeds` | standard | core | core | outbound HTTPS | S-FEED-1…5 |
| `inventory` | standard | core | core, feeds | — | S-INV-1…5 |
| `notify` | standard | core | core | outbound HTTPS/SMTP | S-NOT-1, S-NOT-2, S-ALERT-1, S-ALERT-3 |
| `sensor-passive` | standard | sensor (capture) + core (`sp_*`) | inventory | raw socket; SPAN | S-INV-1, S-INV-3, S-LOG-4 |
| `sensor-active` | standard | core (policy) + scan (nmap) | inventory | raw socket; nmap | S-INV-1, S-SCAN-4 |
| `mitigation` | standard | core | feeds, inventory | — | S-MIT-1, S-MIT-3, S-MIT-4 (S-MIT-2 dropped) |
| `exposure` | optional | core (its scanner runs in `core`; nmap, nuclei and ZAP steps run in containers on the box) | inventory | outbound to the Internet | S-EXP-1, S-EXP-2 |
| `scan` | optional | scan | inventory, feeds | LAN/Internet within scope | S-SCAN-1…4 |
| `scan-credentialed` | optional | greenbone | scan | separate container | S-SCAN-5 |
| `honeypot` | optional | honeypot | inventory | the service ports of each Trap IP (INV-2: 18 TCP/UDP services) | S-HP-1, S-HP-2 |
| `logs` | optional | core (receive, aggregate, baseline, IOC) | feeds, inventory | UDP/TCP 514, TLS 6514 | S-LOG-1…4 |
| `response` | optional | core | notify, inventory (soft: ai) | writes through approved connections | S-RESP-1…4 |
| `agent-intake` | optional | core | inventory | HTTPS (osquery TLS) | S-INV-4 |
| `ai` | optional | core | core | outbound to the provider | S-AI-1…8 |
| `reports` | optional | core | inventory, feeds | — | S-REP-1, S-REP-2 |
| `mcp-server` | optional | core | core | localhost | S-MCP-1 |
| `auth-oidc` | optional | core | core | outbound to the IdP | S-CORE-3 |
| `fleet` | — | — | — | — | S-FLEET-1 dropped |

Conventions still in force: DB tables carry a module prefix, and no module reads another module's tables directly, only through an interface in `core/`. Table details: `DATA_MODEL.md`.

## 5. Main data flows

**5.1 Feed → detection → incident (S-FEED-1, S-ALERT-1)**

```
feed source ─HTTPS(ETag, size/time limits)─► feeds (fail-closed parser)
   ─► normalise ─► deduplicate ─► score ─► feeds_* ─► matching ─► inv_finding
   ─► notify (quiet hours, grouped by product; Critical is sent immediately)
```
A new device (manual entry, CSV, osquery, scan) is matched at once against the entire feed already held. "Confirmed" only when there is safe-scan evidence (S-SCAN-3); everything else is "suspected" (by version) or "product match only". An indicator on a whitelisted domain gets no verdict, and Vedette never blocks traffic itself (`DATA_PIPELINE.md` §3).

**5.2 Device inventory (S-INV-1…5)**: observation sources (manual > agent > snmp > nmap > passive) write to `inv_observation` (append-only), and a device is the merged view. Passive: DHCP/ARP/mDNS/SSDP/LLDP + SPAN metadata (DNS queries, TLS SNI, HTTP Host, IP flows; **payloads are not stored**). Active: nmap only inside a confirmed `inv_scope` (a CIDR must carry its prefix), fragile devices get one light scan and are then only listened to. Agents: osquery (the box is the TLS server) or the read-only Wazuh API. **"This box"** is the first device, with its package list read from dpkg through `vedette-host` (S-INV-5).

**5.3 Confirming scans (S-SCAN-1…4)**: `core` queues the work → `scan` polls and receives it → nuclei (safe tags) / nmap → condensed evidence → `core`. External targets only once verified: a domain by DNS TXT, re-checked right before each scan; an IP only if it is the IP the box itself uses to reach the Internet, which the box probes every 60 minutes and renews on its own, valid for 30 days from the last sighting. Every probe is logged (SYS-7).

**5.4 Log / SPAN → IOC → incident (S-LOG-1…4)**: `core` receives syslog (UDP/TCP 514, TLS 6514) and `sensor` reads SPAN metadata → `core` aggregates by window, 7-day baseline, matches IOCs → incident. Raw logs are not kept long term.

**5.5 Traps (S-HP-1, S-HP-2)**: `honeypot` writes JSON hits to a file and `core` reads it (not through the sensor protocol) → incident + (if any) response rule.

**5.6 One AI call**: task → pre-hook (blocks personal data, out-of-scope security topics) → choose a profile (primary → fallback; logs/devices go only to an internal profile if enabled) → RAG (BM25) + memory + rules → provider → **read-only** tools → post-hook + schema check + "AI-generated" label → the AI log's hash chain.

**5.7 Update**: `core` asks `vedette-host` over the socket → the host pulls the signed manifest → verifies cosign → backs up the DB → swaps images by digest → health check → on failure, goes back to the old tag. Details in `DEPLOYMENT.md` §9 and `UPDATES.md`.

## 6. Separable sensor / server

- Same Go codebase; on the appliance, two sensor containers sit beside `core`: `sensor` (role `passive`: passive packet capture) and `scan` (role `active`: the nmap worker). Both speak the same protocol (`specs/sensor-protocol.md`). Moving a sensor to another machine in the LAN is **later**: it is not exposed in the GUI, and there is no enrolment, LAN listener or disk queue.
- A sensor **only calls out** to `core` over mTLS; `core` never calls into a sensor; commands (capture configuration, nmap jobs, cancel) arrive by long-poll. There is no inbound port on `sensor`/`scan`. The honeypot does not use this protocol: hits travel through a file.
- PKI: `core` is a private internal CA for sensors (key held through `core/secrets`); 7-day leaf certificates, URI SAN `vedette:sensor:passive|active`, separate server/client EKUs, serial checked on every request. `core` hands out keys as files in a per-role volume; the host never sees the keys.
- Permissions by role: `passive` only `config`/`observations`/`heartbeat`, `active` only `jobs`/`result`/`heartbeat`; scan policy, scope and consent live only in `core`; flood-protection limits are applied again in `core`.
- Observations follow OTLP semantics: batches are idempotent by `(epoch, seq)`, partial success is not retried, 429/503 carry `Retry-After`; no write-ahead log on the sensor, because observations repeat themselves. A 30 s heartbeat feeds the sensor and SPAN state.
- On the appliance, port `8444` is published only as `127.0.0.1:8444` and is not opened to the LAN (`DEPLOYMENT.md` §7).

## 7. Security architecture

### 7.1 System invariants (`MODULE_CONTRACTS.md`)

| ID | Invariant | Enforcement in the container architecture |
|---|---|---|
| SYS-1 | External processes only through `core/exec`, binary + argv allowlist, no shell | Also applies to `vedette-host`: a fixed command list, type-checked parameters; lint forbids `os/exec` outside `core/exec` |
| SYS-2 | Input at the boundary is validated against a schema | Handlers are generated from OpenAPI; `vedette-host` re-validates parameters from the socket |
| SYS-3 | Every mutation is written to `core_audit` | Includes commands `core` sends to `vedette-host` (who, command, parameters, result) |
| SYS-4 | Secrets only through `core/secrets` (AES-256-GCM), never logged or exported | Key file 0600 outside the DB, mounted read-only into `core`; not part of the default backup |
| SYS-5 | A disabled module has no routes/jobs/ports, data kept | When every module using a container is off, the container does not start (honeypot, scan, greenbone) |
| SYS-6 | Feeds/logs/web/agents are untrusted | Fail-closed parsers, size/time limits, fuzzing |
| SYS-7 | Network actions outside the LAN only within a verified scope or a declared feed source | `scan` egress is checked against the scope table; egress tests |
| SYS-8 | AI has no write tools | The only exception: `response` (§7.2) |

### 7.2 Exception: executing approved actions

`response` is off by default; turning it on needs an administrator + 2FA + typing a risk-acceptance sentence (audited). Every action passes through the gates, checked **on the server**:

| Gate | Rule |
|---|---|
| G-1 | Execution is on and the emergency stop is not triggered |
| G-2 | The action type is in the allowed list, and the write tool is enabled on an enabled connection |
| G-3 | The request shows the exact before/after change + the undo step |
| G-4 | The approver is a Vedette user with role ≥ operator and a linked channel identity; high risk needs 2 people |
| G-5 | Not expired (15–30 minutes), one approval for exactly one action |
| G-6 | Not over the hourly/per-rule limit; a shared circuit breaker |
| G-7 | Every step is written to the hash-chained audit |
| G-8 | The emergency stop turns execution off and cancels pending requests |

The exception does not extend to `vedette-host`: AI never calls `vedette-host`; only `core` code (the update path, network, backup that an admin clicks) calls it, through the fixed command list.

### 7.3 Trust boundaries

| Boundary | Other side | Main controls |
|---|---|---|
| TB-1 browser ↔ core | LAN users | TLS (own certificate or one self-signed at first start, `-tls-cert`/`-tls-key`; plain HTTP only on loopback), allowed Host list (421, `-hosts`), `__Host-vedette_session` cookie (Secure/HttpOnly/SameSite=Strict) + CSRF + `__Secure-vedette_device` device cookie, 2FA, RBAC, CSP without inline, rate limit |
| TB-2 core ↔ feed sources | Internet data | HTTPS, size/time limits, fail-closed parser, no connection to Vedette itself or to metadata addresses |
| TB-3 box ↔ LAN devices | devices that may be compromised | banners/syslog/agents are untrusted; read-only scans within scope |
| TB-4 harness ↔ AI provider | external service | only when configured; PII masking; internal profile; output by schema |
| TB-5 AI ↔ tools | a model that can be prompt-injected | labelled data blocks; read tools by allowlist; writes only through §7.2 |
| TB-6 chat/email channel ↔ core | approvals from outside | linked identity, signed one-time token, POST to confirm |
| TB-7 box ↔ registry/GitHub | supply chain | minisign for the index/manifest and cosign for images, **verified in `vedette-host` code** before pulling (embedded key, offline); pull references built from constants + digest; revocation, anti-downgrade; staged rollout |
| TB-8 core ↔ `vedette-host` | root process | tightly permissioned internal socket, fixed commands, type-checked parameters, one job at a time, audit; see `specs/host-api.md` |
| TB-9 sensor/honeypot/scan ↔ core | containers with an attack surface from the LAN (packets, scan responses, traps) | `sensor`/`scan`: mTLS with `core`'s own sensor CA, 7-day per-role leaf, serial checked on every request, per-role routes, strict decoding with caps, limits and confidence clamping in `core`, nmap XML parsed in `core`; non-root, no `UserNS`, only `NET_RAW`, no DB; the honeypot has no network port to `core`, only a one-way file, and cannot open a new connection out of its namespace; a compromised honeypot has no path to the DB |

### 7.4 Container isolation layer

| Layer | Applied |
|---|---|
| Privileges | No `--privileged`; `cap_drop ALL` + exactly the capabilities needed (table in `DEPLOYMENT.md` §2); `no-new-privileges`; read-only rootfs + tmpfs |
| User | No root in the container. `core` and `sensor`/`scan` run fixed uids from `host.conf` (`core_uid`, `sensor_uid`), not `UserNS=auto` (a child user namespace's capabilities do not cover the host's network namespace); `sensor`/`scan` receive `NET_RAW` through the ambient set (checked in the lab, fallback UID 0 + `NET_RAW`); other services use `UserNS=auto` |
| Network | Internal bridge by default; host/macvlan only for `sensor`, `scan`, `honeypot` where needed |
| Image | Pinned digest; cosign mandatory; only the minimal runtime; SBOM for every release; `govulncheck`, `trivy` in CI |
| Host | `vedette-host` is systemd-hardened; no SSH into containers |

### 7.5 Authentication, authorisation, API

- REST JSON `/api/v1`, OpenAPI 3.1 **spec-first**: the contract `api/openapi.json` is generated from the Zod schemas in `web/src/features/*/contract.ts` (the file name is fixed in `API_CONVENTIONS.md`). Go generates types/handlers; CI checks they match. SSE `/api/v1/events`. Standard error `{"error": {"code","message"}}`.
- 3 roles: viewer / operator / admin; real permissions are always checked on the server (the GUI only hides buttons). Enabling response execution: admin + 2FA only.
- Passwords argon2id (minimum 12 characters); 2FA TOTP or email code; OIDC optional (`auth-oidc`); API tokens read-only, scoped; MCP read-only, localhost by default.
- Secrets: `core/secrets` AES-256-GCM, the UI shows only the last 4 characters. Headers: strict CSP, no external CDN resources, only three login cookies (session, CSRF, device), no analytics.

## 8. AI harness

The box does **not** embed an external agent; Vedette's own harness wraps every call (`AI_ASSISTANT.md`):

| Component | Role |
|---|---|
| Profiles + task assignment | Several providers, one primary + one fallback profile per task, the rule "logs/devices go only to an internal profile" |
| Rules / Memory / Skills / RAG | Rules injected into every call; memory can be viewed/edited/deleted/disabled; product skills (listed in code, each can be switched off); FTS5 knowledge base (+ optional vectors) |
| Connections (MCP/SSH/HTTP) | Host/command allowlist per connection; each tool is read or write; writes only through §7.2 |
| Hooks | Block PII, block out-of-scope-for-security work, write tools need approval (lock always on); hooks the customer adds |
| Log | one entry per call with hashes of what was sent and received, hash chain, kept 365 days by default (at least 90), downloadable (S-AI-8, S-CORE-6) |
| Label | Every output is marked "AI-generated, needs human review", cannot be removed |

Mitigation recommendations have two sources that are not mixed: the pack the maintainers confirm (shipped with the release) and the customer's own AI answer when there is no pack.

## 9. Response

```
trigger (trap touched, malicious connection, new finding, unknown device, log over threshold,
         new port on a public IP, schedule, manual run)
   ─► WHEN/IF/THEN (user rule) or an AI proposal (with guard rails)
   ─► safety envelope: never-touch list, deduplication, limits, circuit breaker, maintenance window
   ─► grouped approval request (channels: Slack, Telegram, email/Zalo via link, in-app)
   ─► execute through a connection (pull preferred: an internal URL blocklist with a token; push: API/SSH from a template)
   ─► re-check after the run · undo + TTL · hash-chained audit
```

Parameters controlled by an attacker (IPs, domains in logs) are type-checked and escaped for the transport (SYS-1). Every action needs approval; rule-based "pre-approved" is an option that is OFF by default. A new rule runs as a dry run first. Devices with no API/SSH: alert only.

## 10. Component licences

| Component | Licence | How it is used in the container architecture |
|---|---|---|
| Vedette code | Apache-2.0 | |
| nuclei, nuclei-templates | MIT | separate process in the `scan` container (pinned binary + template pack signed with the image) |
| httpx, naabu, subfinder, dnsx | MIT | not used: the external-surface scanner (`modules/scan/surface`) is the Go standard library |
| recog / recog-go | BSD-2 | embedded |
| nmap | NPSL 0.95 | **separate process** in `scan`; installed from the OS package repository into the `scan` image that `vedette-host` builds on the box; the project does not distribute it |
| OpenCanary | BSD-3 | separate process in the `honeypot` image |
| Greenbone CE | GPL-2/AGPL-3 | its own upstream container group, unmodified, not embedded |
| Podman, Quadlet, cosign, netavark | Apache-2.0 | host tools, not redistributed in images |
| Zeek, Suricata | — | **not installed**; a customer's Suricata logs still arrive through syslog like any source, and IPS events in them become alerts of the `ids` module |
| Wazuh, osquery | GPL-2 / Apache-2.0+GPL-2 | not shipped; osquery reports to the box, Wazuh is read through its API |
| Feed data | per source | the box pulls directly; IOCs with restrictive licences are still pulled by the box |
| OpenCVE | BSL 1.1 | not used in the core |

A new dependency/feed → update `../THIRD_PARTY_NOTICES.md` in the same commit.

## 11. Target performance (targets, to be measured on a real box)

- A 4-core/8 GB box: 1,000 devices, 50k IOCs, 7 days of aggregated logs ≤ 2 GB of SQLite; UI < 300 ms p95 for the main pages.
- Passive sensor ≤ 5% of one core at 100 Mbps SPAN.
- Feed pulls ≤ 5 MB/hour thanks to ETag/If-Modified-Since.
- Per-container resource limits and the measurement method: `DEPLOYMENT.md` §2.6.
- Upgrade: roll back to the previous version in ≤ 5 minutes (proposal: measured by an effect test).

## 12. Settled design questions

- **Operating systems**: the appliance runs on Ubuntu 24.04, Ubuntu 26.04 and Debian 13, all with netplan (`networkd` renderer) and
  chrony (`DEPLOYMENT.md` §4).
- **nmap**: not redistributed; `vedette-host` builds the `scan` image on the box from the signed base image, with nmap from the
  distribution's package repository.
- **Images**: `ghcr.io/knt048/vedette-<service>`, signed with a cosign key; the signature travels in the signed manifest and is
  verified offline in `vedette-host`'s code.
- **Sensor privileges**: `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, `DropCapability=ALL` + `AddCapability=NET_RAW` (ambient).
- **Honeypot**: one container, one OpenCanary process in the `vedette-hp` namespace with every decoy; nft blocks new outbound
  connections from it.
- **Container-only "This box"**: the device exists without a package list (the interface says why); the customer runs the image update
  with the commands the Updates page shows.
- **Backup and the secret key**: a backup downloaded with a password carries the decryption key inside its encryption; one without a
  password never holds it (`DEPLOYMENT.md` §10).
