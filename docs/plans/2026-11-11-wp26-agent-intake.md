# WP-26 `agent-intake` plan (osquery TLS server, enrolment tokens, Wazuh pull)

Status: PLAN ONLY (phase 1), 2026-11-11. Story S-INV-4. Decisions D-33, D-34, D-190 (owner AI-Trưởng). Decisions of this WP go in `docs/decisions/D-169.md` (list in section 8).
Rules in force: gui-first (the approved GUI, its mock and `contract.ts` are the contract), no-imagined-features, modules (on/off), contracts, security (untrusted input, secrets), legal (PRIVACY/NOTICES), ships-as-code, ponytail, decide-like-top-tier.

## 0. Lead decisions on this plan (c9c9a8c APPROVED, 2026-11-11). They supersede the text below where they differ.

- **Q1 (supersedes option A in 2.6 and slice 1):** NOT `CA:TRUE` on the 8443 leaf (Firefox refuses a CA certificate used as the server's end-entity certificate: `MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY`). Use the former fallback B: a separate box CA (own key, `CA:TRUE`, `pathlen 0`, long-lived) signs the self-made 8443 leaf; D-139 renewal reissues only the leaf under the same CA; osquery pins the CA through `/intake/ca.pem`. Reference: Proxmox VE (`pve-root-ca` signs the node's `pve-ssl.pem`). An owner-supplied `-tls-cert` is never touched: `ca.pem` is then the chain the owner supplied. What the agent pins in that case: a leaf-only file pins that leaf (the owner re-runs the install command when they change their certificate); a private-CA chain pins the chain; a public-CA chain is tested in slice 1 and, if a pinned intermediate does not verify, the script drops the embedded file and uses osquery's bundled roots. Slice 1 = core TLS, Opus mandatory.
- **Q2:** YES, bake the pinned official osquery packages into the release image (no runtime download, no new outbound flow); the `THIRD_PARTY_NOTICES.md` row (osquery, Apache-2.0 / GPL-2.0 dual, shipped as unmodified files for the endpoint, not linked into Vedette) goes in the same commit as the build step (slice 3). The lead tells kien, who may veto.
- **Q3:** the lead asks kien for a Windows Server test machine; until then the PowerShell script has static tests only and a dated deferred line for the real run.
- **Q4:** YES, add the `interfaces` query and drop `cpu_brand`, `physical_memory` and `patches` from the schedule; the GUI text change is a story criterion + mock change in slice 0.
- Every [verify] item is a dated line in `.ai/deferred/feat-agent-intake.md` or a named test in its slice.
- **Correction made while doing slice 0:** the two `sample-data` operations are NOT removed from the contract or the route table (they are generated from `api/openapi.json` and `core/server/modules_test.go` lists them). In the real build their handlers answer 404 (CONTRACT INV-10). Slice 0 is recorded in D-169 (14).

Research limits: WebFetch re-opened osquery remote docs, Elastic Fleet enrolment tokens, Wazuh API getting-started, Wazuh RBAC reference, Wazuh authd password page, Fleet server configuration. Not reachable or truncated: Fleet "enroll hosts" (404), Wazuh API reference (ReDoc page empty; the OpenAPI spec is 696 KB and only the first 100 KB was read), Wazuh syscollector field names. Each unverified item is tagged **[verify]** and has a named test in section 7.

## 1. What the approved GUI does, and what the mock implies

Everything is in `web/src/features/inventory/` (no new GUI is planned except the two small items marked GUI in section 7, slice 0).

| Piece | Evidence | Behaviour the backend must reproduce |
|---|---|---|
| Section "Agents" in Inventory, hidden behind `RequireModule agent-intake` with "module off" fallback | `AgentsSection.tsx:231-275` (`RequireModule`, `ModuleOff`), `modules/agent-intake/MANIFEST.yaml` `gui_under: inventory` | Off module: `GET /inventory/agents` is 404 (server gate), the SPA already shows the fallback (`web/src/lib/apiModules.ts:11-13`). |
| Token table: name, `last4` mask, expiry (relative, "Expired" chip when past, "No expiry"), last received (or "never" in warn colour), hosts, buttons Config / Send sample (mock only) / Revoke | `AgentsSection.tsx:240-258`; `AgentToken` `contract.ts:95-98` | `last_received` = last time a node of this token delivered a result log; `hosts` = number of enrolled nodes of the token. |
| Create-token dialog: name (max 64), expiry select 1/7/30/90/0 days (default 7), then the result view: full token once, one-liner install, platform switch Linux / Windows Server, SHA-256 of the script, "read the script" disclosure, uninstall one-liner, Advanced (manual steps, the schedule JSON, CA fingerprint note) | `AgentsSection.tsx:39-132`, `agentConfig.ts:21-58`, `installScripts.ts` | Server returns `CreateTokenResult {token, secret}`; the install data come from `GET /inventory/agents` (`install.{linux,windows}.{url,sha256,script}`, `osquery_version`) so the real build must serve scripts whose SHA-256 equals the one in that response. |
| Wazuh card: connect / edit / disconnect, status chip never/connected/error, last sync + `agents` + `packages`, dialog with read-only-user steps, URL, user, password (blank keeps the saved one), interval 5/15/60/360/1440, Test and Save | `AgentsSection.tsx:134-229`, `WazuhConnection/WazuhInput/WazuhTestResult` `contract.ts:102-110`, steps `agentConfig.ts:60-70` | Test runs login without saving and returns `{ok, version, agents}`; Save verifies first (PRE-2) then stores; password only `password_last4` back. |
| "Send sample data" buttons | `AgentsSection.tsx:22,208,253` guarded by `MOCK_BUILD` | Not implemented in the real build (CONTRACT INV-10): the 2 `sample-data` operations stay mock-only and out of the Go route table (`api/route-modules.json:204-205` lists them for the mock; see slice 0 for how they are excluded). |

Endpoints the mock implies (`contract.ts:138-148`, `mocks.ts:600-700`):

| Operation | Role | Type | Mock behaviour to copy |
|---|---|---|---|
| GET `/inventory/agents` | admin | `AgentsResponse` | tokens, wazuh (no password), install block, `server_url` (`mocks.ts:22`, `https://<ip>:8443` or placeholder) |
| POST `/inventory/agents/tokens` (201) | admin | body `{name<=64, kind?='osquery', expires_in_days 0..365}` -> `CreateTokenResult` | `mocks.ts:620-634`: name regex, `bad_name`, `bad_kind`, secret `vdt_osquery_` + 32 chars of `abcdefghijkmnpqrstuvwxyz23456789` (160 bits), audit `inventory.agent_token_create` |
| DELETE `/inventory/agents/tokens/{id}` (204) | admin | - | `mocks.ts:635-642`, audit `inventory.agent_token_revoke`, 404 `not_found` |
| GET `/install/osquery.sh`, `/install/osquery.ps1` | public | file | `mocks.ts:608-609`: text of the template with box URL, version, CA filled in |
| POST `/intake/osquery/status` | public (Bearer) | `OsqueryStatus {enrolled, hosts}` | `mocks.ts:612-618`: regex `^Bearer vdt_osquery_[a-z0-9]{32}$`; 403 `invalid_token`, 403 `token_expired`; `enrolled = last_received != null` |
| PUT `/inventory/agents/wazuh` | admin | `WazuhInput` -> `WazuhConnection` | `mocks.ts:294-306,665-678` (`bad_url` 400, `wazuh_unreachable` 502, `wazuh_auth` 422), audit `inventory.wazuh_connect` |
| POST `/inventory/agents/wazuh/test` | admin | `WazuhInput` -> `WazuhTestResult` | same checks, nothing stored |
| DELETE `/inventory/agents/wazuh` (204) | admin | - | `mocks.ts:681-686`, audit `inventory.wazuh_disconnect`, deletes the password |

Endpoints the GUI text already assumes but `contract.ts` does not have (found in `scripts/osquery.sh:55-67`, `agentConfig.ts:35,44,52`): `POST /intake/osquery/{enroll,config,log}`, `GET /intake/ca.pem`, and `GET /install/osquery/{SHA256SUMS,<package file>}` (the mirror). CONTRACT open question 2 says the same. They are public machine-to-machine operations: slice 0 adds them to `contract.ts` (schemas + minimal mock handlers) so `api/openapi.json`, the route table and the module gate (`core/server/server.go:250-262`) cover them. Alternative (rejected): a hand-written mux outside ogen. It would need its own module gate, body caps and envelope, i.e. a second copy of SYS-5 logic.

Two gaps in the approved GUI that the backend cannot paper over:

1. **Device identity.** The schedule shown to the user (`agentConfig.ts:24-33`) has no query that returns a MAC or IP. `observe.AssetHint` needs a MAC or an IPv4 (`core/observe/observe.go:79`, `modules/inventory/observe.go:62-79`), and enrolment `host_details` carries no network data. Fix: add ONE query `interfaces` (section 2.5) to `OSQUERY_SCHEDULE` and to the Go config. This changes text the user sees ("what we collect"), so it is a GUI-visible change needing story criteria (slice 0).
2. **Windows script.** The approved Windows script depends on `curl.exe --cacert`. Windows Server 2019 ships curl 7.55.1 **[verify]**; curl added `--cacert` support to the Schannel backend only in 7.60. If that is right, the script fails on Server 2019 (works on 2022). Needs a real Windows Server test (question Q3).

## 2. osquery TLS remote API (v1)

Source: https://osquery.readthedocs.io/en/stable/deployment/remote/ (re-opened today). All calls are `POST` with a JSON body.

### 2.1 Endpoints needed for S-INV-4

| Endpoint (flag) | Request | Response | v1 |
|---|---|---|---|
| enroll `/api/v1/intake/osquery/enroll` | `{"enroll_secret": "<token>", "host_identifier": "...", "host_details": {os_version, osquery_info, system_info, platform_info}}` | `{"node_key": "...", "node_invalid": false}`; failure = `{"node_invalid": true}` | yes |
| config `/api/v1/intake/osquery/config` | `{"node_key": "..."}` | config JSON (`{"schedule": {name: {query, interval, snapshot, platform}}}`) plus `node_invalid` | yes |
| logger `/api/v1/intake/osquery/log` | `{"node_key", "log_type": "result"\|"status", "data": [events]}` | `{"node_invalid": false}` (or true to force re-enrol) | yes |
| distributed read/write | `{"node_key"}` / `{"node_key","queries","statuses"}` | `{"queries":{...}}` | **no** (FORBID: no remote query execution; osquery keeps distributed off unless a flag turns it on and the script never does; the route does not exist, so a hostile admin-less caller gets 404) |
| status (Vedette's own, in the contract) | `Authorization: Bearer <token>`, empty body | `{"enrolled": bool, "hosts": n}` | yes, as mocked |

Statuses: osquery "does not handle HTTP errors" and retries failed requests 3 times, exits if config cannot be fetched, buffers logs in RocksDB when the logger endpoint is down (same page). So:

- Unknown/revoked/expired credential, bad key, malformed body that parses as JSON: HTTP 200 + `{"node_invalid": true}` (never a distinguishing error; no oracle between "unknown" and "revoked"). Server-side log line with a reason code and the source IP, never the secret or key.
- Oversized body, non-JSON, wrong content type, rate limit: 413 / 400 / 429 with the standard `apierr` envelope and `Retry-After`. osquery treats them as failures and retries; correct for a sick client.
- Module off: 404 (gate).

### 2.2 Credentials and node_key lifecycle

- **Token = enrol secret.** Format as mocked: `vdt_osquery_` + 32 chars of a 32-letter alphabet = 160 bits, from `crypto/rand`. Stored as SHA-256 hex in `intake_agent_tokens.token_hash` (UQ), plus `last4`. SHA-256 (not a slow hash) is right for 160-bit random secrets and matches DATA_MODEL §secrets (`docs/DATA_MODEL.md:465`). Lookup by hash through the unique index; compare equality in SQL (the hash of a random secret leaks nothing useful through timing).
- **Expiry** (`expires_at`, default 7 days, 0 = never, `expires_in_days` 0..365, D-34): an expired token cannot **enrol** new nodes. Already-enrolled nodes keep reporting (CONTRACT POST-4, open question 3; Elastic Fleet behaves the same: "Agents that are already enrolled continue to function", expiry/revocation only stop new enrolment). Revoke is stronger (POST-3): it deletes the token's nodes, so the next report gets `node_invalid`, data already received stays. `GET /inventory/agents` marks past `expires_at` as Expired (GUI already does).
- **node_key**: 32 bytes from `crypto/rand`, base64url (43 chars), returned once in the enrol response, stored only as SHA-256 in a new table `intake_osquery_nodes` (`id, token_id FK CASCADE, node_key_hash UQ, host_identifier, hostname, platform, osquery_version, enrolled_at, last_seen, last_result_at, bound_ip, bound_mac`). Sent in the body by osquery on every call (also accepted as `Authorization: NodeKey` is NOT needed; osquery does not send it). No expiry of the key itself; it dies with the token (revoke) or after 90 days without any call (Housekeeping job, see section 5). MANIFEST `tables` and DATA_MODEL get the third table (backend-only doc change).
- **Re-enrol**: the same `(token, host_identifier)` enrolling again replaces the older node row (a reinstall must not double `hosts`). Device identity in the inventory is NOT host_identifier (hostnames collide, clones share uuid); it is the MAC/IP binding from the `interfaces` query (2.5). The script keeps `--host_identifier=hostname` as approved; it is only a label.
- **Cap**: 50 active tokens, 500 nodes per token, 5,000 nodes total (DATA_MODEL assumes ~100 osquery servers, `docs/DATA_MODEL.md:542`). Beyond: enrol answers 429 `daily_cap`-style code `too_many_nodes` (new code, listed in API_CONVENTIONS).
- **Audit** (SYS-3): `inventory.agent_token_create`, `inventory.agent_token_revoke` (names as in the mock) with name only; node enrol is audited as `inventory.agent_enroll` with token name and hostname (rate-limited: one audit row per node per day, not per call). Token and node_key never reach log, audit or export (SYS-4, INV-4).

### 2.3 Size limits, rate limits, fail-closed parsing

Body caps through `Config.BodyLimits` by operationId (`core/server/server.go:41-45,229-248`): enrol 64 KiB, config 4 KiB, log 4 MiB, status 1 KiB. Declared lengths over the cap are refused before reading (`limitBody`, `opLimit`).

Rate limits (public endpoints, in-module token bucket keyed by source address with `/64` aggregation for IPv6, same shape as `core/auth/ratelimit.go`; reuse it if its API allows, else a 40-line limiter in the module, ponytail):
- failed enrol/status (bad token): 10 per minute per source, then 429 + `Retry-After` doubling to 10 minutes. A 160-bit token cannot be guessed; the limit protects the box's writer and log.
- valid node: config 6/min, log 12/min per node; excess 429.
- global: at most 4 concurrent mirror downloads (the packages are 20-30 MB each), excess 429 with `Retry-After: 5`.
- All writes use the request writer wait limit already applied to every request (`limitWrites`, D-246); 503 `server_busy` surfaces to osquery as a retry.

Parsing (SYS-6, INV-7):
- One strict decoder per endpoint on top of the ogen-decoded `jx.Raw` or `[]byte`: `encoding/json` into typed structs, `Decoder.UseNumber`, depth and size bounded by the body cap, trailing data refused, `host_identifier` and `hostname` through the same cleaning as inventory (`cleanText`, invisible characters via `core/observe.Ignorable`).
- Unknown envelope keys (osquery adds `decorations`, `epoch`, `counter`, `numerics`, `action`) are ignored and never stored; only allow-listed columns of allow-listed queries are read. This amends CONTRACT INV-7 ("reject unknown fields"): rejecting unknown envelope keys would break on every osquery upgrade. Rows with unexpected types or invalid text are dropped one by one (as `inventory.checkItems` does for invisible characters, `modules/inventory/software.go:36-47`), the rest of the batch is kept, a counter is logged.
- Only `log_type=result` with a `snapshot` of a **known query name** (`os_version`, `system_info`, `deb_packages`, `rpm_packages`, `programs`, `patches`, `interfaces`) feeds anything; `status` lines are read for size only and discarded; differential results are ignored (the schedule is snapshot-only).
- Item caps: <=5,000 software items per device (`modules/inventory/software.go:19`), <=8 interface rows, version <=100 chars, name <=200 chars. Over-cap lists keep the first 5,000 and log `truncated`.
- Fuzz targets (Go native, seeds from real osquery 5.x output): `FuzzParseEnroll`, `FuzzParseLog`, `FuzzMapPackages`, `FuzzDebVersion`; each asserts no panic, outputs within caps, no control characters, and that accepted output is exactly the allow-listed shape (pattern: `modules/honeypot/fuzz_test.go`).

### 2.4 Binding a node to a device (anti-spoofing)

A node holding a valid key could claim another device's MAC and replace that device's software list (`ReplaceSoftware` replaces by hint, `modules/inventory/software.go:265-307`, MAC first). Rule: the IP hint is the **TCP peer address** of the request (cannot be forged by the client; no proxy sits in front: `core/server` serves 8443 directly, `X-Forwarded-For` is never read); the node's `interfaces` result must contain that IPv4, and the MAC used is the one of that very interface. If the peer address is not among the reported IPv4 addresses (NAT, IPv6-only, multi-homed odd path) the software list is NOT written; the node is recorded `unmatched` and shown nowhere new in the GUI (only the log line and the `hosts` count). Fail closed. The binding is stored (`bound_ip`, `bound_mac`) and re-checked on every result. IPv4 only because the inventory is IPv4-only today (`modules/inventory/observe.go:75-77`).

### 2.5 Queries and what each feeds in the inventory

Config returned to every valid node (same JSON as the GUI shows, plus one query), snapshot-only, no writes, no `exec`-type tables, no `file`/`hash` tables, no `curl`:

| Query (interval) | Platform | Columns used | Feeds |
|---|---|---|---|
| `os_version` (3600) | all | name, version, major, minor, patch, build, platform, arch | observation `os` = `"<name> <version>"` (+ build on Windows), source `agent`, conf 0.95 via `core/observe.Sink.Record` |
| `system_info` (86400) | all | hostname, hardware_vendor, hardware_model | observations `hostname`, `vendor`, `model` (conf 0.95); cpu_brand and physical_memory are NOT stored (no field exists; GUI list shows them, trimmed in slice 0 only if lead wants parity, else dropped silently from the Go config and the GUI text is kept; see D-169 (7)) |
| `deb_packages` (3600) | linux | name, version, arch, source | software via `SoftwareSink.ReplaceSoftware(hint, Agent, items)`; version normalised to upstream (strip epoch `N:` and Debian revision `-x`, keep original in display) |
| `rpm_packages` (3600) | linux | name, version, release, arch, epoch | same; upstream version = `version` |
| `programs` (3600) | windows | name, version, publisher, install_date | software, Vendor = publisher, Product = name |
| `patches` (3600) | windows | hotfix_id, description, installed_on | not stored in v1 (no inventory field; ponytail: stored when findings can use hotfixes); the query is dropped from the Go config unless lead asks to keep GUI parity. Open item D-169 (7). |
| `interfaces` (3600) **NEW** | all | `SELECT d.mac, a.address FROM interface_details d JOIN interface_addresses a USING (interface) WHERE a.address NOT LIKE '%:%' AND a.address NOT LIKE '127.%' AND a.address NOT LIKE '169.254.%' AND d.mac != '00:00:00:00:00:00'` | the device hint only (2.4); not stored as an observation except `mac` (conf 0.9, `hintConfidence`, `modules/inventory/software.go:15`). **[verify]** the join works on Windows (`interface` naming) and on Linux bridges/VLANs with a real Windows Server and the Ubuntu box |

Package-name to KEV key mapping (the real value of S-INV-4: fewer "suspected"). osquery gives package names, not vendors; `ReplaceSoftware` defaults the key to `lower(vendor)|lower(product)` (`software.go:90-93`), which only matches when the pair equals a KEV pair. So:
- `modules/agentintake/pkgmap.json` (embedded): explicit map from deb/rpm source names and Windows display names to `{vendor, product}` for the products the catalog already knows as server software (`content/catalog/curated.json`, e.g. OpenSSH at line 112, `kev_match: ["openbsd|openssh"]`): OpenSSH, Apache httpd, nginx, OpenSSL, Exim, Postfix, Samba, Sudo, polkit, Exchange, 7-Zip, WinRAR, Chrome, Edge, Office, Veeam, etc. (first cut about 60 entries, grown by test, never from a heuristic).
- A Go test checks that every mapped pair exists in `content/catalog/kev-products.json` or `curated.json` (no dead keys) and a golden test pins 20 real package names.
- Unmapped packages: Vendor = deb `maintainer`/rpm `vendor`/Windows `publisher` if present else the name, Product = name, no KEV key (same ponytail already used by sensor-active, `modules/sensor-active/results.go:142-144`, with the same stated upgrade path: a bigger table).
- Not planned: touching `inventory.checkItems` to guess keys by search (`Catalog.find` can match any alias-containing text and would create false positives).

### 2.6 One-line install, CA and pinning (D-34, D-139)

What the box serves (all public, no secret, INV-5): `/install/osquery.sh`, `/install/osquery.ps1` (templates `web/src/features/inventory/scripts/*` copied to `modules/agentintake/scripts/`; a Go test fails if the web copy and the Go copy differ after placeholder fill, the same drift idea as the `openapi.json` check), `/install/osquery/SHA256SUMS`, `/install/osquery/<file>` (exact allow-list of three names + SHA256SUMS, map lookup, no path joining of input), `/intake/ca.pem`.

Script content must be byte-stable (no timestamps) because the GUI shows its SHA-256 from `GET /inventory/agents`, computed on the same bytes. `@@BOX@@` = `https://<host>:8443` where host is the request Host if it is one of the names/IPs in the current certificate, else the management IPv4 from `vedette-host` (D-139 SAN logic, `cmd/vedette/tls.go:529`), else `<VEDETTE_BOX_IP>` (CONTRACT PRE-3, never guessed).

**Trust anchor problem (found, blocking).** The script embeds "the CA" and osquery gets it as `--tls_server_certs` (a PEM of trusted roots; osquery has no SPKI pin option). But the 8443 certificate the box makes is a **self-signed leaf, CA:FALSE, no certSign** (`cmd/vedette/tls.go:523-527`), and D-139 re-issues it with the same key whenever the address set changes and every ~795 days. A new leaf B (same key, new serial and SAN) does not verify against the old leaf A as an anchor, because OpenSSL requires an issuer to be CA:TRUE **[verify]**. So pinning the current leaf would silently break every enrolled osquery at the next renewal or address change (D-139 (3) keeps the key precisely so an admin's SPKI pin survives; osquery cannot pin an SPKI). Options:

| Option | What | Verdict |
|---|---|---|
| A | Self-made certificate gets `IsCA: true` + `KeyUsageCertSign` (still self-signed, same key kept); the script embeds that certificate; B (same key, same subject, AKI/SKI equal) chains to A. One line in `selfSignedPEM`; existing boxes pick it up at the next reissue (force one reissue at upgrade). | **Recommended.** Same key = same trust as today (whoever holds the key can already impersonate the box). Browsers accept it. Must be proven with real osqueryd and with a renewed cert (slice 1 test). |
| B | Two tier: a long-lived "Vedette box CA" signs the leaf; scripts embed only the CA | Cleaner PKI, bigger change (CA storage in `core/secrets`, owner-cert mode, migration). Fall back to it only if A fails the real test. |
| C | Pin the leaf, GUI banner "re-run the install command after a certificate renewal" | Silent breakage of a security tool; rejected. |

Owner-supplied `-tls-cert` (never modified, D-139 (1)): the script embeds the whole chain the box serves; for a private CA this is the anchor, for a public CA it is harmless. Documented in the story criteria; to be tested in slice 5.

First download trust: the one-liner in the GUI uses `curl -k` once and checks the SHA-256 that the admin read in the authenticated GUI (`installScripts.ts:26-32`); every later download uses the embedded CA. That stays as approved.

**Package mirror source (CONTRACT question 4).** Recommended: bake `osquery_<v>-1.linux_amd64.deb`, `osquery-<v>-1.linux.x86_64.rpm`, `osquery-<v>.msi` and `SHA256SUMS` into the release image at build time (`deploy/osquery/PINS` holds the version and the three SHA-256 values; the build downloads from the official GitHub release, verifies the pinned hashes, and fails otherwise; ships-as-code). Reasons: no new outbound flow (nothing in PRIVACY changes for osquery), no runtime dependency, works offline, one atomic update with the box (managed version: `AgentsResponse.install.osquery_version`). Cost: about 60-90 MB more in the image **[verify sizes]**. `THIRD_PARTY_NOTICES.md:87` already lists osquery mirrored unmodified; slice 5 adds the license files and states we distribute under Apache-2.0 (dual Apache-2.0/GPL-2.0), pinned version, source link. The GUI constant `OSQUERY_VERSION='5.12.1'` (`installScripts.ts:23`) and the pin must be the same number; whichever is newest at build time wins and both files change together (a Go test reads the GUI constant).

## 3. Wazuh pull

### 3.1 API usage (read-only, D-33)

Source: Wazuh docs, re-opened: API getting started (`POST /security/user/authenticate?raw=true` with basic auth returns the plain JWT; port 55000; token appears to last 900 s; default certificate self-signed), RBAC reference (`agent:read` on `agent:id:*`, `syscollector:read`).

Per pull (one client, strictly sequential, total budget 10 minutes, per-call 15 s):
1. `POST /security/user/authenticate?raw=true` (basic auth). The only non-GET call; the client wrapper allows exactly this path with POST and nothing but GET elsewhere (FORBID-4; unit test with a recording server asserts no other method or path).
2. `GET /` for the API version shown in the Test result **[verify]** whether it needs an RBAC action the read-only role lacks; fallback: version taken from the `GET /agents` response or shown as "unknown".
3. `GET /agents?select=id,name,ip,registerIP,status,os.name,os.version,os.platform&status=active,disconnected&limit=250&offset=N` paged until `total_affected_items` is read (limit maximum **[verify]**). Agent `000` (the manager) is included.
4. For each agent: `GET /syscollector/{id}/os`, `/netaddr`, `/netiface`, then `/packages?select=name,version,vendor,architecture,format&limit=250&offset=N`. Syscollector field names **[verify]** against the OpenAPI spec (`wazuh/api/api/spec/spec.yaml`, tag v4.9.x) in slice 4.
5. Never any other endpoint. Resources of the documented read-only policy: `agent:read` + `syscollector:read` on `agent:id:*` (`agentConfig.ts:60-70`); if the role also allows more, the client still cannot call it.

Mapping into the inventory (same path as osquery, one shared mapper):
- Device hint: agent `ip` if a valid IPv4 (not `any`), MAC from `/netiface` of the interface whose `/netaddr` equals that IP; neither -> skip the agent (counted in the log, not an error).
- Software via `ReplaceSoftware(hint, Agent, items)`; Vendor from `vendor`, Product from `name`, upstream version as in 2.5, pkgmap applied; confidence 0.95 (mock) - mapped KEV key or not.
- OS observation `os` = `os.name + " " + os.version`; `hostname` = agent name; conf 0.95.
- An agent with zero packages and a non-empty previous list: no replace (syscollector disabled on the agent must not wipe data); counted.
- If osquery and Wazuh both report one device they overwrite each other (both are `source=agent`, DATA_MODEL enum fixed, `docs/DATA_MODEL.md:197`); last writer wins. Stated in CONTRACT as a known limit (ponytail, upgrade path: a `wazuh` source value), question D-169 (6).
- `intake_wazuh.agents` = agents read, `packages` = total package rows mapped; written at the end of each pull with `status`, `last_sync`, `error`.

### 3.2 Auth, TLS verification, secrets, network policy

- Password: `core/secrets` (`purpose intake_wazuh.password`, already named in `docs/DATA_MODEL.md:456`; call `secrets.Reserve` in an `init` like `core/pki/ca.go:42` so only the module opens it). `secret_id` FK in `intake_wazuh`; `DELETE` removes the row and the secret in one transaction. Only `password_last4` leaves. It is decrypted only inside the pull and test code, passed as `secrets.Value`, redacted from every error line (`core/conn/internal/transport/clean.go` `Redact`/`CleanLine` pattern).
- TLS: Wazuh ships a self-signed certificate by default, and the GUI form has no CA or pin field. Plan: reuse the D-94 behaviour of `core/conn` instead of writing a second TLS client: public CA chain valid -> system roots required afterwards; otherwise **trust on first use**: the first successful Test or Save pins the SPKI SHA-256 of the leaf (`intake_wazuh.tls_pin`, new column, plus `tls_pin_first_seen`); a later mismatch stops the pull with `status=error` and the message "The Wazuh certificate changed. Open Edit and press Save to trust the new one." Pressing Save re-runs the first-use decision (an authenticated admin act, audited as `inventory.wazuh_connect` with the new fingerprint). Mismatch never sends the password. No redirect, no proxy, TLS >= 1.2 (`core/conn/internal/transport/https.go:85-110`).
- Network policy: the same `Dialer` refusal (loopback, link-local incl. cloud metadata, unspecified, multicast, the box's own subnets; private LAN addresses allowed since Wazuh lives on the LAN; `core/conn/validate.go:361`, `internal/transport/dial.go:47-60`). `url` must be `https`, host + port only, no user-info, no path (mock `bad_url`).
- `core/conn/internal/...` is not importable from a module. Slice 3 adds a small exported facade in `core/conn` (for example `conn.NewPinnedHTTPS(Refuse, Pin, TOFU)` returning the existing client behind a narrow `Do(ctx, method, path, ...)`), updates core CONTRACT/IMPACT and gets Opus review. Rejected alternatives: storing Wazuh as a `core_connection` of kind http (the approved GUI, `intake_wazuh` table and `/inventory/agents/wazuh` API are a separate model, and the connection has tools/allow-lists the Wazuh card does not use); a copy of the transport inside agent-intake (a second TLS/SSRF implementation to keep in sync).
- Limits: response <= 1 MiB (`transport.MaxResponse`), request <= 64 KiB, page size 250.

### 3.3 Scheduling, intervals, states

- One job `agent-intake/wazuh-pull`, `Every: 1 minute`, `Run` does nothing unless `now >= last_sync_attempt + interval_minutes` (the job runner has one fixed `Every` per job, `core/jobs/jobs.go:34-40`; intervals 5, 15, 60, 360, 1440 from the GUI). Save sets the next attempt to now, so the first pull happens within a minute of connecting. No "pull now" button (not in the GUI).
- States: `never` (saved, not pulled yet), `connected`, `error` (`error` text set; old inventory data untouched, POST-2). Error codes shown in dialogs or the card (all with the standard envelope, messages in plain words like the mock): `bad_url` 400, `wazuh_unreachable` 502, `wazuh_auth` 422, `wazuh_tls` 502 (untrusted or changed certificate, new), `wazuh_forbidden` 422 (the user lacks `agent:read` or `syscollector:read`, new), `wazuh_bad_reply` 502 (not the documented shape, new), `module_off` is the 404 gate. New codes are added to `docs/API_CONVENTIONS.md` error table in the slice that adds them.
- Failure policy: three consecutive failures keep `status=error` and the pull continues at its interval (no exponential growth of calls on the customer's Wazuh); a success clears the error.

### 3.4 PRIVACY and legal (rules/legal.md)

The Wazuh pull is a **new outbound flow** (the box opens HTTPS to an address the admin typed, sends the read-only account's user name and password, and receives agent and package inventory). `PRIVACY.md` lists 13 flows and has no Wazuh row (checked `PRIVACY.md:7-19`); the closest is flow 12 "Connections you add". Same commit as the code (slice 4): new row 14 "Wazuh pull (only if you connect it, D-33)" with what is sent (credentials, GET requests above), where to (only the typed address), how to turn off (disconnect, or turn the module off), the TOFU pin sentence; matching entry in the Settings -> Privacy data (`modules/core/handlers_privacy.go`, mock `web/src/features/core/mocks.ts:720-721`, locale text) and the contract test of the privacy flows. The osquery path is inbound only: no PRIVACY change. `THIRD_PARTY_NOTICES.md`: osquery line exists (`:87`); add the pinned version and the licence files; Wazuh: "not shipped, API client only" (ARCHITECTURE:239 already says so). No new Go dependency is planned (stdlib `net/http`, `crypto/tls`, `encoding/json`).

## 4. Module on/off (rules/modules.md, SYS-5)

| Item | On | Off |
|---|---|---|
| Routes `/install/*`, `/intake/*`, `/inventory/agents*` | served | 404 for everything, the same body as unknown routes (`core/server/modules.go:19-21` already maps all three prefixes to `agent-intake`; public ones are gated first, `server.go:262-267`) |
| Port | no new port: osquery uses the 8443 HTTPS listener | no route; the listener belongs to core |
| Job `wazuh-pull` | runs | cancelled at once, idle (`core/jobs`) |
| Job `node-prune` (delete nodes silent 90 days) and token tidy-up | runs | `Housekeeping: true` (D-160): deletes only data past the stated retention; opens nothing |
| Enrolled osqueryd on customer servers | reports | gets 404 on config; osquery exits and the systemd unit restarts it, so a retry loop hits the box (cheap 404 through the gate); documented in IMPACT, checked on the real box in slice 5 |
| Data | - | tokens, nodes, `intake_wazuh`, secrets, received software all kept; inventory shows the age of agent data (existing behaviour) |
| Turn on without `inventory` | - | ask first, never enable silently (modules.md); `depends: [core, inventory]` already in MANIFEST |

Retention note: DATA_MODEL says expired tokens are deleted 30 days after expiry [ĐX]. With node keys outliving expiry (2.2), deleting a token would orphan live nodes. Plan: delete an expired token only when it has no nodes; a token with nodes stays (listed as Expired) until revoked. Recorded as D-169 (4).

## 5. Top-tier comparison (links re-opened today unless marked)

| Product | Enrolment secret | Node/agent credential after enrol | What we take |
|---|---|---|---|
| osquery TLS reference (https://osquery.readthedocs.io/en/stable/deployment/remote/) | `enroll_secret` read from file/env, posted once at enroll (`--tls_secret_always` would resend it on every request); server may approve each enrol | server-issued `node_key` stored by osquery, sent on every config/log call, server decides validity, `node_invalid` forces re-enrol | exact protocol shapes and the 200 + `node_invalid` convention; we do NOT use `--tls_secret_always` (would put the token into every request) |
| FleetDM (https://fleetdm.com/docs/configuration/fleet-server-configuration, read; the "enroll hosts" page returned 404, so secrets/rotation detail is [not verified] and taken from the config page only) | secrets are server-side; `osquery_enroll_cooldown` rejects a host (by `osquery_host_identifier`) enrolling again within a window; `osquery_node_key_size` default 24; option to require the `Authorization: NodeKey` header and ignore the body field; host identifier choices provided/uuid/hostname/instance | per-host node key | node key size >= 32 bytes; re-enrol replaces the old row; a cooldown of 60 s per `(token, host_identifier)`; keep body-field `node_key` because osquery sends no header |
| Elastic Fleet (https://www.elastic.co/guide/en/fleet/current/fleet-enrollment-tokens.html) | a token is tied to one agent policy, reusable for many agents, optional expiry (blank = never), revoke = API key invalidated | after enrol the agent gets its own communication API key; revoking or expiring the token does NOT stop enrolled agents | expiry and revoke affect **enrolment** only for expiry, and revoke additionally removes the token's nodes (POST-3 is stricter than Elastic: the CONTRACT wants revoke to cut machines off at the next report); our choice written in D-169 (3) |
| Wazuh enrolment (https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html, read) | shared `authd.pass` password on manager and endpoint; random password regenerated at manager restart if none set; page does not say whether it is single-use or what the agent keeps | client key issued at enrol | confirms the shared-secret model is normal and that a leaked enrol secret should be rotatable by revoke; we keep one token per group of machines, shown as `last4` only |
| Wazuh API client side (https://documentation.wazuh.com/current/user-manual/api/getting-started.html, `.../api/rbac/reference.html`, read) | n/a | JWT from `/security/user/authenticate`, about 900 s | login per pull, no token reuse or storage; RBAC read-only role as already written in the GUI |

## 6. Tests per layer

- **Contract (Go, `modules/agentintake/contract_test.go`)**: one test per INV/POST of CONTRACT (INV-1..10, POST-1..4, FORBID-1..4), including: token shown once, only hash stored; expired token cannot enrol but enrolled node still reports; revoke -> `node_invalid` and data kept; module off -> 404 on every route; mutations audited; no secret in log or audit (capture handler); Wazuh client never sends a method/path outside the allow-list.
- **Fuzz**: parsers (2.3). Seeds: real osquery 5.12 enroll/config/log captured from a local osqueryd run, saved under `testdata/`.
- **Server-level (httptest with the production `tls.Config` and a real self-signed cert chain)**: enrol -> config -> log -> device and software visible through `inventory`; peer-address binding (2.4) with a client on 127.0.0.1 claiming another IP; oversized bodies; rate limits; status endpoint shapes equal the mock (`OsqueryStatus`).
- **Inventory integration**: through the real `inventory.Service` as `observe.SoftwareSink`/`Sink` (no table access), including "manual rows untouched" (INV-8).
- **Drift**: Go script templates == web templates after fill; `OSQUERY_VERSION` == `deploy/osquery/PINS`; `api/openapi.json` regenerated.
- **Real-client test (local, not CI, like the live AI tests)**: on the Ubuntu test box (`ssh vedette-dev`, `192.168.18.181`) run real `osqueryd` installed from the mirrored deb through the install script against a `make dev`-style backend build; assert POST-1 end to end, then renew the self-signed certificate (same key) and assert osqueryd still connects (the trust-anchor test), then revoke and assert it is cut off. Wazuh: a pinned `wazuh/wazuh-manager` container with the read-only role from the GUI steps, local only (no CI minutes). Windows Server script: needs a real Windows Server 2019 and 2022 (question Q3).
- **e2e (Playwright, module only)**: the existing Agents specs run on the mock; add a spec `agents-real.e2e` under `web/e2e-real/` (per `make e2e-real`, outside CI): create token in the GUI, run the Linux one-liner in a container, see the device with software and the `last_received` turn from "never" to a time.

## 7. Slices (PR-sized, in order)

Opus review (D-255: at most 2 rounds, round 1 in parallel with the checks) is mandatory on slices 1-5 (untrusted input, auth, TLS, secrets, outbound). Heavy runs only through `~/vedette-wt/heavy`. LOW findings go to dated `.ai/deferred` lines.

| # | Slice | Files (main) | Tests | Risk | Opus |
|---|---|---|---|---|---|
| 0 | **Contract and story.** Add to `contract.ts`: `POST /intake/osquery/{enroll,config,log}`, `GET /intake/ca.pem`, `GET /install/osquery/{file}` (public, schemas, minimal MSW handlers); (the two `sample-data` ops stay in the contract; the real handler answers 404, see section 0); add the `interfaces` query to `OSQUERY_SCHEDULE` (+ trim or keep `system_info`/`patches` columns per D-169 (7)); new acceptance lines under S-INV-4 (node key, identity through interfaces, TOFU pin, no wipe on empty); regenerate `api/openapi.json`, `api/route-modules.json`; `docs/decisions/D-169.md` skeleton | `web/src/features/inventory/{contract,mocks,agentConfig}.ts`, `docs/USER_STORIES.md`, `api/*`, `modules/agent-intake/CONTRACT.md` (open questions 2-5 answered) | vitest of inventory, openapi drift, `make check` web part | Touches the approved GUI-contract: additive only, lead approves first (gui-first). No untrusted-input code. | no (lead reviews the diff) |
| 1 | **Stable trust anchor for 8443** (option A, B on failure): `selfSignedPEM` gets `IsCA` + `KeyUsageCertSign`; one forced reissue for old self-made leaves, owner certs untouched; `core` CONTRACT/IMPACT and D-139 note | `cmd/vedette/tls.go`, its tests | reissue-with-same-key chain test using Go `x509.Verify` AND a real `openssl verify -CAfile old.pem new.pem` run in the test; browsers' acceptance noted; SPKI pin unchanged | security/TLS change in the always-on listener; a mistake locks admins out of the GUI. Mitigation: keep the key, keep SANs, test both fresh and upgraded boxes | yes |
| 2 | **osquery intake core**: migrations (`intake_agent_tokens`, `intake_osquery_nodes`), token service (issue/revoke/list, hashing, expiry, caps), the four public handlers (enroll, config, log, status), parsers, rate limiter, binding rule, mapper and `pkgmap.json`, wiring in `cmd/vedette/modules.go` (`BodyLimits`, jobs `node-prune`), audit, MANIFEST `tables`, DATA_MODEL | `modules/agentintake/*`, `modules/agentintake/migrations/sqlite/*`, `cmd/vedette/*`, `docs/DATA_MODEL.md` | contract, fuzz x4, server-level, inventory integration, mapper golden | the main untrusted-input surface; unauthenticated write path to the inventory; spoofing (2.4); DoS through large logs | yes |
| 3 | **Admin API of the module**: `GET /inventory/agents`, `POST/DELETE tokens`, script and CA serving, SHA-256, mirror files with allow-list and download concurrency cap, `server_url`/Host handling, `deploy/osquery/PINS` and build step (download, verify, embed), drift tests | `modules/agentintake/{handlers,install}.go`, `deploy/osquery/*`, `Makefile`/image build, `THIRD_PARTY_NOTICES.md` | contract (admin role, audit, secret shown once), byte-stable script test, traversal tests on the mirror route, SHA-256 equals the GUI value | public file serving; path handling; image size; supply chain (pin check) | yes |
| 4 | **Wazuh**: `core/conn` exported pinned client facade (+ core CONTRACT/IMPACT); `intake_wazuh` migration, secrets, test/save/delete, pull job, mapper reuse, error codes, API_CONVENTIONS rows, **PRIVACY row 14 + Settings->Privacy data + mock + contract test in the same commit** | `core/conn/*`, `modules/agentintake/wazuh*.go`, `PRIVACY.md`, `modules/core/handlers_privacy.go`, `web/src/features/core/mocks.ts`, locales | fake Wazuh server in httptest (shapes from the official docs); allow-list test; TOFU pin and mismatch; no wipe on empty; secret redaction; local-only live test against a real manager | outbound credentials + new flow; core change | yes |
| 5 | **Real-client proof and docs**: local real-osqueryd run (Ubuntu box), certificate-renewal test, revoke test, module-off retry-loop observation, `web/e2e-real` spec, `install.sh` check that the mirrored files are present, CONTRACT/IMPACT final (Last verified), ROADMAP/completion-log, Windows script verification result | `web/e2e-real/*`, `modules/agent-intake/{CONTRACT,IMPACT}.md`, docs | the real-client runs above | Windows path unverified until a Windows Server is available | yes (final read of the whole diff, round 2 only on fixes) |

Order rationale: 0 first (the contract the others implement), 1 before 2 (the CA the scripts embed must be stable before any script ships), 2 before 3 (nodes exist before scripts point at them), 4 is independent of 1-3 after slice 0 and may run in parallel with 3 (max 2 heavy jobs). Estimated size M per TEAM_PLAN, in practice about 5 PRs of S/M.

## 8. Decisions to record in `docs/decisions/D-169.md` (one row, sub-points)

1. Two sources only, osquery TLS v1 = enroll + config + log (+ Vedette status); distributed (remote queries) not implemented; config is snapshot-only, read-only tables.
2. Token = enrol secret, 160-bit, SHA-256 at rest, `last4`, expiry blocks enrolment only; node_key 256-bit, SHA-256 at rest, no expiry of its own, dies with revoke or 90 days silent; caps (50 tokens, 500 nodes/token, 5,000 nodes); re-enrol replaces; 60 s cooldown.
3. Revoke cuts enrolled nodes (POST-3) while expiry does not (POST-4); Elastic Fleet and Fleet references (links above).
4. Retention: an expired token is deleted only when it has no nodes (supersedes the DATA_MODEL [ĐX] "delete 30 days after expiry"); idle nodes pruned at 90 days (Housekeeping).
5. Identity and anti-spoofing: peer address + `interfaces` query, fail closed, IPv4 only; new query shown in the GUI.
6. Source overlap: osquery and Wazuh both write `source=agent`; last writer wins (known limit).
7. Schedule parity: `cpu_brand`/`physical_memory` (`system_info`) and `patches` have no inventory field; decide whether to remove them from the GUI text (recommended: remove, honest "what we collect") or keep collecting unused data (not recommended, no-imagined-features).
8. Wire format: 200 + `node_invalid` for every credential failure; non-JSON/oversize/rate = 4xx with envelope; unknown envelope keys ignored, allow-listed columns only (amends INV-7 wording).
9. Trust anchor: self-made certificate becomes CA:TRUE with the same key (option A), B as fallback; owner-supplied certificate embeds the served chain; first download pinned by SHA-256 as already approved (D-34).
10. Package mirror baked into the image from pinned official release files (hash-checked at build); no runtime download; no PRIVACY row for osquery.
11. Package-name mapping: explicit `pkgmap.json` validated against the KEV catalog; unmapped = vendor/product from package metadata or name, no KEV key.
12. Wazuh: read-only client (one POST for login, GET for the rest, allow-listed paths), TLS = system roots or trust-on-first-use pin of the SPKI, re-Save re-pins, SSRF dialer policy of `core/conn`, facade exported from `core/conn`; PRIVACY row 14 same commit.
13. Wazuh pull scheduling: 1-minute tick job, interval from the GUI, no pull-now, no wipe on an empty package list, failure does not accelerate.
14. Routes are in the ogen contract (public ops) instead of a side mux, so SYS-5 gating, body caps and envelope come free.

## 9. Questions only kien can answer (with a recommendation)

- **Q1 (security/product):** may the box's self-made 8443 certificate become CA:TRUE (same key, same trust, option A) so enrolled osquery agents survive a certificate renewal or address change? Recommend yes. Without it every renewal silently disconnects every enrolled server until the install command is run again. Option B (separate CA) is the fallback if the real osqueryd test fails.
- **Q2 (cost/size):** bake the osquery packages (about 60-90 MB, **[verify]**) into the release image so servers need no Internet and the box adds no outbound flow? Recommend yes. The alternative (box downloads from GitHub at runtime) adds an outbound flow (PRIVACY + UI) and breaks the "works offline" promise of D-34.
- **Q3 (resource):** is a Windows Server 2019 and a 2022 test machine available for the real run of the PowerShell script? Recommend yes before slice 5 merges; otherwise the Windows path ships marked "not yet verified on a real server" and the `curl.exe --cacert` issue on 2019 (if confirmed) is handled by switching the script to a .NET certificate callback (changes the script text and its SHA-256 in both web and Go).
- **Q4 (GUI text, not money):** may the schedule text shown in the GUI add the `interfaces` query and drop the unused `cpu_brand`, `physical_memory` and `patches` (slice 0)? Recommend yes; both are needed for an honest "what we collect" and for identity. If kien prefers not to touch the approved text, the only safe fallback is to refuse software from any node whose peer address cannot be mapped, which means no MAC, and makes every device `unmatched` behind NAT.

No legal or money question remains: the licence position (osquery Apache-2.0/GPL-2.0 dual, Wazuh not shipped) is already in `THIRD_PARTY_NOTICES.md` and ARCHITECTURE.
