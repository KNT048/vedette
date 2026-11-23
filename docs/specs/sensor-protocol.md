# Sensor protocol: `sensor`/`scan` ↔ `core` (appliance profile)

Status: **settled on paper** (2026-11-10); the first code (`core/pki`, `core/sensorlink`; not yet wired to modules) clarified a few points, marked "Clarified in code" below; replaces the earlier draft (2026-11-09). Field names, error codes and paths are in English.
Traceability: `ARCHITECTURE.md` §2, §6, TB-9; `DEPLOYMENT.md` §2.2, §2.4, §6.1; stories S-INV-1, S-INV-3, S-SCAN-4.

## 1. Purpose and scope

The **appliance** profile: two containers on the same box talk to `core` over `127.0.0.1:8444`:

- `sensor`: passive packet capture (the `capture` half of the `sensor-passive` module), host network, `NET_RAW`;
- `scan`: the nmap worker of the `sensor-active` module, host network, `NET_RAW`.

Both run the same `vedette-sensor` binary (subcommands `passive`, `active`, `healthcheck`). There is **only one** direction of initiation: the sensor calls out, `core` never calls into the sensor; commands from `core` arrive by long-poll.

Out of scope for this profile:
- sensors on other machines, enrolment, renewal over the network, manual revocation (the old design is in appendix A);
- syslog (SPAN metadata travels on the wire from §6.7, matched in `core` by `logs`), honeypot (goes through files), osquery (`osquery-intake.md`). (The nuclei job of the `scan` module is the second job type from version 2; SNMP reads are the third type from version 5, see the "SNMP reads" block in §6.5.)

## 2. Actors and roles

| Actor | Role | Notes |
|---|---|---|
| `core` | protocol server; the sensors' CA; holds the DB, policy, scan consent | the `core` container, a second listener `:8444`, published on `127.0.0.1:8444` |
| `sensor` | role **`passive`**: receives `config`, sends observations and heartbeats | `User=<sensor_uid>:<sensor_gid>`, no `UserNS`, only `NET_RAW` |
| `scan` | role **`active`**: receives nmap jobs, sends results and heartbeats | like `sensor`; image built on the box |
| `vedette-host` | builds constant units that mount the key volume per role | never sees the keys |

Trust model: the sensor is **an attackable machine** (it sits on the LAN, reads packets and responses an attacker controls). `core` trusts the **role identity** after mTLS, not the **content** (SYS-6): everything the sensor sends is checked for size, type and quota, and its confidence is clamped in `core`.

## 3. Transport

- HTTPS, JSON (`Content-Type: application/json`), no compression (any `Content-Encoding` → `400 invalid_request`). TLS **1.3** minimum; HTTP/2 when ALPN offers it, not required.
- A separate `core` listener, turned on with `-sensor-listen :8444` (inside the container) together with `-sensor-creds <directory>` (empty = no listening), separate from the UI listener 8443; `core` opens the PKI, writes the two key bundles, **and only then** listens, and the daily `sensor-cert-renew` job calls `Authority.Renew`; on the appliance only `127.0.0.1:8444` is published (`DEPLOYMENT.md` §6.1). `ClientAuth = RequireAndVerifyClientCert`, the pool contains only the sensor CA.
- Prefix `/sensor/v1/`. Every request carries `X-Vedette-Proto: 5` (version 5: the `snmp` job type, `snmp` in the `active` heartbeat and in results, `running` up to 3 ids; version 4: `capture_error` in the passive heartbeat; version 3: `host_errors` in nuclei results; version 2: the `nuclei` job type). `core` accepts its own version and **the one right before it** (`4`), never a newer one. Version 5 adds a job type to the `jobs` **response**, but `core` only sends `snmp` jobs to a worker whose heartbeat has `"snmp": true` (a version 5 field), so a version 4 worker gets a response in version 4 shape.
- `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s (long-poll held for at most 30 s).
- Body: `http.MaxBytesReader` at the route's cap (§9) **before** decoding; decoded with `internal/jsonstrict` (unknown fields, duplicate keys, keys duplicated after case folding, depth > 32 → `400 invalid_request`). Unknown query parameters → `400 invalid_request`.
- Clarified in code: a POST body must have `Content-Type: application/json` (missing or different → `400 invalid_request`); the body is read for at most **10 s** (a socket clock, not a seam; whole-request `ReadTimeout` 15 s; 10 s for 11 MiB is ~9 Mbit/s, only right for a local sensor, to be recomputed when remote sensors are built) and the connection is closed when the body stalls midway or exceeds the cap (net/http has no body read deadline that does not break long-poll); `IdleTimeout` 2 minutes; `MaxHeaderBytes` 16 KiB. `If-None-Match` must have the form `"<1…64 characters [A-Za-z0-9._:-]>"`, otherwise `400`. `wait` is an integer 0…30 (one value, not repeated); `running` is 32 hex or empty.
- The listener accepts at most **64 connections** at once (`PendingListener`, written with the standard library): **16 in handshake** (not yet authenticated; when full, a new connection replaces the longest-waiting one if it has waited ≥ 250 ms, otherwise the new connection is closed at once; each waiting connection is closed after 3 s of handshake), then by role at the TLS handshake: `passive` ≤ 32, `active` ≤ 16; the `http.Server`'s `ErrorLog` goes through slog like the 8443 server (refused handshake errors go to the log, not to stderr). The client **does not follow redirects**: a 3xx is a request error, and `Location` is not called (the client certificate is never presented to another machine).
- The sensor's reading of `core`'s responses is also capped (config ≤ 64 KiB, jobs ≤ 64 KiB, other responses ≤ 16 KiB) and decoded strictly like `core` does.

## 4. Certificates and identity

| Item | Rule |
|---|---|
| CA | ECDSA P-256, 10 years, created by `core` the first time; the key is stored through `core/secrets` (AES-256-GCM, `master.key`). Signs leaves **only** for the 8444 listener and for sensors; separate from the 8443 certificate and the future osquery CA (`osquery-intake.md` §4). A restore without `master.key` → a new CA, new leaves |
| Server leaf | EKU **only** `serverAuth`; SAN `IP:127.0.0.1` and `DNS:core` (compose profile); 7 days |
| Sensor leaf | EKU **only** `clientAuth`; **exactly one** URI SAN: `vedette:sensor:passive` or `vedette:sensor:active`; the CN decides nothing; 7 days; the serial is recorded in `core_sensor_cert(role, serial, not_after, retired_at)` |
| Rotation | `core` checks at start and daily; a leaf with ≤ 1/3 of its lifetime left gets a new one; serials older than "the one right before" get `retired_at` set |
| Key delivery | at start, **before listening**, and at every rotation: `core` generates the key and writes **one** PEM bundle (key, leaf, CA) to `<creds>/<role>/sensor.pem` through `os.OpenRoot`, temporary file `O_EXCL\|O_NOFOLLOW`, fsync, `Rename`; mode `0640`, owner `core_uid:sensor_gid`. `core` **never reads** the file back |
| Sensor side | mounts the key volume of its own role **read-only**; reloads the bundle in `GetClientCertificate` when the mtime changes; after a change, closes idle connections. A broken or half-written bundle → keeps the old bundle in memory, retries after 5 s |
| Sensor side checks the server | chain to the CA in the bundle, EKU `serverAuth`, name `127.0.0.1` (or `core` in compose) |

**Clarified in code.** `core` always issues new leaves for the server and both roles at start (`Authority.Start`), because it never reads the bundles back and so does not have the keys of the previous leaves; the previous serial stays alive (it is "the one right before"). The daily job (`Authority.Renew`) only replaces leaves with ≤ 1/3 of their lifetime left. A bundle that was issued but could not be written (volume error, the role directory replaced by a symlink) is kept in memory and written again at the next `Renew`, not reissued. `NotBefore` is set 1 minute before `core`'s clock. The handshake and every request check that the EKU is **exactly** `[clientAuth]`, exactly one URI SAN, the leaf is not a CA; every request also checks `NotBefore ≤ now ≤ NotAfter` of the leaf (a keep-alive connection can outlive the certificate) → `403 cert_retired`.

**`core`'s checks** (in order):
1. Handshake: chain to the sensor CA (validity, signature), EKU `clientAuth`, exactly one URI SAN belonging to the two roles, the serial is the **current or the one right before** for that role. Any failure → the handshake fails (no HTTP response). `VerifyConnection` also runs on resumed connections (TLS 1.3 resumption).
2. **Every request**: checks the serial again (a keep-alive connection can outlive the serial's retirement) → `403 cert_retired`.

**An unusable CA is replaced (review finding).** A CA row that cannot be decrypted with the current `master.key` (key lost, or a backup without a key restored onto the box's key: `host-api.md` §16), is broken, expired or not yet at `NotBefore` → `pki.Open` creates a new CA **in the same write transaction** that detected it (overwriting the `core_secret` row), revokes every live serial of the old CA, writes the audit `sensor-ca.replace` (reason: `cannot_decrypt`, `damaged`, `expired`, `not_yet_valid`) and logs the warning `sensor_ca_replaced`; `Start` reissues and rewrites every bundle. A DB error is not a reason to drop the CA.

**Audit.** Every PKI change is a `core_audit` row (actor `system`) in the same transaction: `sensor-ca.create`, `sensor-ca.replace`, `sensor-cert.issue` (role, serial, `not_after`), `sensor-cert.retire` (role, serial). Group names use hyphens because `audit` does not accept underscores in groups. There is never a key or PEM in the audit or the log.

**Cleaning up and writing bundles.** `Start` deletes the temporary files `.sensor.pem.*` (regular files; directories, symlinks and other names are left alone) left over after a crash in the middle of a write. The root directory and the role directories are checked not to be symlinks **and**, after opening, must be exactly the checked directory (`os.SameFile`): swapped in between → refused (`ErrCredsPath`). `ParseBundle` checks that the leaf chains to the CA in the bundle itself (the CA is the only root, EKU `clientAuth`).

**A long-poll opened before a rotation.** A request held open when its serial is retired runs to the end (the serial was checked when it started); the next request on that connection is refused with `403 cert_retired` (the server closes the connection), the client reloads the bundle and reconnects with the new certificate. That is enough: no operation is lost, because the sensor resends the same batch and the long-poll repeats by itself.

There is no interface for active revocation; revocation = rotation (the old serial retires) plus the 7-day lifetime (passive revocation).

## 5. Common conventions

- Times: RFC 3339 UTC. Job id: 32 lowercase hex (128 random bits). `epoch`: 32 lowercase hex.
- Errors: `{ "error": { "code": "snake_case", "message": "English text" } }`; `code` is the contract, `message` is for reading only. 429 and 503 carry a `Retry-After` header (seconds).
- `version`: SemVer 2.0, ≤ 64 bytes.
- Card name: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`; MAC: `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`; IPs through `netip` (IPv4/IPv6 unicast); a card's address in prefix form (`192.168.10.5/24`) through `netip.ParsePrefix`.
- Free-text strings: valid UTF-8, no C0/C1 control characters, bidi, line/paragraph separators, Unicode Cf (as in sensor-passive INV-3); invalid → the item is refused, `core` does not truncate.

## 6. Routes by role

| Role | Route | Request body (cap) | Returns |
|---|---|---|---|
| `passive` | `GET /sensor/v1/config?wait=<0..30>` | — | `200` configuration + `ETag`, or `304` |
| `passive` | `POST /sensor/v1/observations` | ≤ 1 MiB | `200 {ack_seq, rejected[]}` |
| `passive` | `POST /sensor/v1/metadata` (§6.7) | ≤ 512 KiB | `204` |
| `passive`, `active` | `POST /sensor/v1/heartbeat` | ≤ 64 KiB | `200 {instance}` |
| `active` | `GET /sensor/v1/jobs?wait=<0..30>&running=<id[,id]>` (`running` empty or omitted when idle; ≤ 2 ids, version 2) | — | `200 {instance, jobs[], cancel[]}` |
| `active` | `POST /sensor/v1/jobs/{id}/result` | ≤ 11 MiB | `204` |

Every other (method, path) pair, including the other role's routes → `403 forbidden_route`, checked **before reading the body**. Each role has at most **one** long-poll open; a second one → `409 poll_in_progress`. The role's module turned off (`sensor-passive` for `passive`, `sensor-active` for `active`) → every route of the role gives `409 module_off`.

### 6.1 `GET /sensor/v1/config` (passive)

A conditional long-poll: the sensor sends `If-None-Match: "<etag>"` of the version in use (none the first time). `core` answers `200` at once when the ETag differs; otherwise it holds for up to `wait` seconds (default 25), then answers `304` with no body. `SetInterface` (changing the card/SPAN in Box network) and filter changes wake the open long-poll (replacing the in-process `reload` channel).

```json
{ "interface": "enp2s0", "span": true,
  "extract": { "dns": true, "sni": true, "http": false, "flows": true },
  "filters": [ { "type": "cidr", "value": "10.0.5.0/24" }, { "type": "port", "value": "443" } ] }
```

| Field | Rule |
|---|---|
| `interface` | card name, or `""` = **no capture** (module not configured yet, or fail-closed) |
| `span` | the card is a SPAN/TAP port (no IP) |
| `extract` | four switches for extracting SPAN metadata. The sensor extracts according to the switches, then sends what needs matching through `POST /metadata` (§6.7) |
| `filters[]` | exclusion rules `{type: cidr\|host\|port, value}` (sensor-passive INV-7) |

Fail-closed: `core` cannot read the filters → `interface: ""`. The sensor receives an `interface` different from the one running → closes the old card, opens the new card; `""` → stops capturing at once, without flushing the last batch.

### 6.2 `POST /sensor/v1/observations` (passive)

```json
{ "epoch": "3f9c…(32 hex)", "seq": 41,
  "items": [ { "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.23", "field": "hostname", "value": "printer-3f",
               "confidence": 0.6, "seen_at": "2026-11-10T08:00:01Z" } ] }
```

| Field | Rule |
|---|---|
| `epoch` | 32 random hex, generated every time the sensor process starts |
| `seq` | integer 1 … 2^53−1, increasing within an epoch |
| `items` | 1 … 500 items |
| `items[].mac`, `.ip` | optional, at least one of the two; the IP must be unicast |
| `items[].field` | ∈ `observe.Field`: `hostname`, `mac`, `vendor`, `model`, `os`, `kind` |
| `items[].value` | 1 … 200 bytes, clean text (§5) |
| `items[].confidence` | 0 … 1; `core` clamps it to the cap of the passive scale for each field (sensor-passive CONTRACT, "Confidence scale") |
| `items[].seen_at` | RFC 3339 (a wrong format or type → `400` for the whole batch, clarified in code); within 24 hours before to 5 minutes after `core`'s clock (outside → `out_of_window` per item) |
| (absent) `source` | `core` sets `passive` by role; a `source` field in the body → `400 invalid_request` (unknown field) |

**Epoch and seq**. `core` keeps `sp_seq(sensor_id, epoch, last_seq)` with `sensor_id = sn-local` (the box's own sensor) and only **the 2 newest epochs** (a third epoch deletes the oldest). A batch with `seq ≤ last_seq` of that epoch → `200`, `ack_seq = seq`, `rejected: []`, not written again (POST-3). There is no `seq_gap`: seq only guards against replay, and gaps are normal (dropped batches).

**Processing** (one batch): (1) check each item (§5, the table above) → invalid items go into `rejected[]`; (2) flood quotas in `core`: never-seen MACs ≤ 60 per minute and ≤ 200 per hour, new values ≤ 4 per (MAC, field) per hour, an in-memory map by MAC (repeating a value already let through does not count as new); exceeded → `budget_exhausted`; (3) `SubmitBatch` with the remaining items; an `observe.ErrRejected{Index}` from inventory → that item goes into `rejected[]` with `refused`, and the rest is resent within the same request; (4) store `seq`.

Returns `200 { "ack_seq": 41, "rejected": [ { "index": 3, "code": "budget_exhausted" } ] }`: **partial success, never retried**. Item codes (closed set):

| `code` | Meaning |
|---|---|
| `invalid_item` | wrong type/regex/cap, unknown `field`, missing both `mac` and `ip`, dirty text |
| `out_of_window` | `seen_at` outside the time window |
| `budget_exhausted` | exceeds `core`'s flood quota |
| `refused` | inventory refuses at its boundary (`observe.ErrRejected`) |

Store busy (SQLite busy, `Write` timed out, or the write connection held for more than 5 s: `store.ErrBusy`) → `503 store_busy` for the whole batch, no item is written or counted toward the quota.

### 6.3 `POST /sensor/v1/heartbeat` (both roles)

Every 30 s. The body depends on the role (strict decoding: the other role's fields are unknown fields):

```json
{ "version": "1.4.0",
  "interfaces": [ { "name": "enp1s0", "mac": "aa:bb:cc:00:00:01", "link": true, "ipv4": ["192.168.10.5/24"] },
                  { "name": "enp2s0", "mac": "aa:bb:cc:00:00:02", "link": true, "ipv4": [] } ],
  "span": { "pps": 1200, "other_macs": 37, "last_packet_at": "2026-11-10T08:00:29Z" },
  "drops": { "malformed_dhcp": 2, "new_macs_dropped": 0 },
  "devices_seen": 214, "capture_error": "no_permission" }
```

```json
{ "version": "1.4.0", "nmap": { "present": true, "version": "7.94SVN" },
  "nuclei": { "present": true, "version": "v3.3.7", "pack": { "version": "2026.11.10", "sha256": "9f…(64 hex)" } } }
```

| Field | Rule |
|---|---|
| `interfaces` (passive) | ≤ 32 cards; `ipv4` ≤ 8 prefixes per card |
| `span` (passive) | `pps` ≥ 0; `other_macs` = number of MACs other than the box's seen in 5 minutes (only unicast frames between two machines that are not the box, sensor-passive INV-9); `last_packet_at` or `null` |
| `drops` (passive) | ≤ 64 keys from the **closed set** of drop counters in `capture` (`malformed_*`, `excluded`, `value_empty`, `fragment_skipped`, `new_macs_unconfirmed`, `new_macs_dropped`, `values_dropped`, `observation_failed`…; 35 keys, listed in the "Passive capture" block of §6 and `sensorlink.DropKeys`); values ≥ 0 |
| `devices_seen` (passive) | ≥ 0 |
| `capture_error` (passive, version 4) | why capture on the selected card is not running right now: the closed set `sensorlink.CaptureErrors` = `no_permission` (opening the socket got EPERM/EACCES: no `CAP_NET_RAW`, as in a rootless container), `no_interface` (the card is not on the machine), `filters_invalid` (the filters cannot be read), `capture_failed` (every other error); absent or `""` while capturing or when no card is selected. The sensor sets it when opening the card or when a session fails, and clears it when the card opens or capture stops. Never the error text (that text is in the sensor's log). Form: lowercase `[a-z][a-z0-9_]{0,47}`, another form → `400`; a well-formed value `core` does not know → `core` shows `capture_failed` and logs once (keeping at most 64 unknown names) |
| `nmap` (active) | `present` = `/usr/bin/nmap` exists and `--version` runs; `version` ≤ 32 bytes; `full` (version 5) = `true` when the worker's nmap is exactly `nmapargv.ReviewedNmapVersion` (7.95) and the worker runs the two shapes `external_full` and `external_disruptive` (behind the box's own IP fence), absent = `false` (an older worker): `core` never hands those shapes to a worker that has not said `full` (`ErrFullUnsupported` before queueing the job; a waiting job is also held back if a later heartbeat stops saying `full`) |
| `nuclei` (active, version 2) | `present` = `/usr/local/bin/nuclei` exists and `-version -duc` runs (nuclei prints its version to stderr); `version` ≤ 32 bytes; `pack` = the `version` (`YYYY.M.D`) and `sha256` (64 hex) of the template pack index shipped in the image, **both empty** when there is no usable index (unreadable or does not pass `pack.Parse`); one empty and one not → `400`; `own_ip` (version 5) = `true` when the worker runs nuclei jobs with `own_ip` scope (with the box's own IP fence), absent = `false` (an older worker): `core` never hands an `own_ip` job to a worker that has not said `own_ip`; `full` (version 5, added before the first release like `own_ip`) = `true` when the worker runs nuclei jobs with `depth` `full`, absent = `false`: `core` never hands a full job to a worker that has not said `full` |
| `domain_ip` (active, version 5) | `true` when the worker holds the box's domain fence key (vedette-host mounts it read-only into the scan container, `/var/lib/vedette-fence/fence.key`) and checks the domain fence itself; absent = `false` (a remote sensor, a container-only install, an old worker): `core` never sends it a `domain_ip` job |

Returns `200 { "instance": "<32 hex>" }`: a nonce generated every time the `core` process starts (the lease of §6.4).

`core` uses heartbeats for:
- `Sensor.status`: `online` when there is a heartbeat within **90 s**; the `last_seen`, `version`, `devices_seen`, `interfaces` (card names) of `GET /inventory/sensors` come from the latest passive heartbeat; `capture_error` too, but **only when `online`** (an old heartbeat says nothing about now; kept in memory, not in the DB; GUI: "Reporting, not capturing" with the reason);
- `SpanStats()` / `span_status`: `off` (configuration `span=false`), `no_link` (SPAN card `link=false`), `no_traffic` (`last_packet_at` older than 30 s, `null`, or sensor `offline`), `own_only` (`other_macs = 0`), `ok`;
- `SetInterface`: `interface` must be one of the host's cards; only when core runs without a host is it a card from the latest passive heartbeat; `400 bad_interface` (sensor-passive INV-9); no host and no heartbeat yet → `bad_interface`;
- the box's addresses (the `ProtectedIPs` of sensor-active, the honeypot's decoy IP check, `conn`) **until** the host's `GET /v1/state/net` existed;
- `sensor-active` health: `unavailable` when there has been no `active` heartbeat for 90 s or `nmap.present=false` (INV-6);
- health of the nuclei scanner (`scan`): `scanner_unavailable` (503 in the API) when there has been no `active` heartbeat for 90 s, `nuclei.present=false`, `nuclei.pack.sha256` is empty, or a nuclei job ran past its deadline and the worker could not stop it yet; nmap and nuclei are independent: a missing one does not make the other `unavailable`.

No heartbeat within 90 s deletes no data; it only changes the displayed state.

### 6.4 `GET /sensor/v1/jobs` (active): jobs, cancellation, lease

`core` holds the request for up to `wait` seconds (default 25) and answers **at once** when there is a new job or a cancel command; on timeout it returns empty arrays (always `200`, so the worker always gets `instance`).

```json
{ "instance": "9b1d…(32 hex)",
  "jobs": [ { "id": "c0ffee…(32 hex)", "kind": "nmap", "shape": "normal", "rate": 100,
              "targets": ["192.168.10.20", "192.168.10.21"], "timeout_s": 5400 },
            { "id": "badc0de…(32 hex)", "kind": "nuclei", "timeout_s": 600,
              "pack": { "version": "2026.11.10", "sha256": "9f…(64 hex)" },
              "templates": ["CVE-2024-1234", "CVE-2023-9999"],
              "targets": [ { "host": "192.168.10.20", "port": 8080, "scheme": "http" },
                           { "host": "192.168.10.21", "port": 22, "scheme": "" } ],
              "rate": 5, "max_host_errors": 3 } ],
  "cancel": [] }
```

| Field | Rule |
|---|---|
| query `running` | ids of the jobs the worker is running, comma-separated: empty, one id, two or (version 5) three ids (one nmap, one nuclei, version 2; one snmp, version 5), each id 32 hex, no duplicates; otherwise → `400` |
| `jobs` | 0 … 3 elements, **at most one job per kind** |
| `jobs[].kind` | `nmap` \| `nuclei` (version 2) \| `snmp` (version 5, its fields are in the "SNMP reads" block of §6.5). Missing `kind` = `nmap`. An unknown kind: decoding only takes `id` and `kind`, and the worker returns `refused` (`invalid_job`) without failing the whole poll |
| `jobs[].shape` | (nmap) `sweep` \| `normal` \| `gentle` (the three original shapes) \| `versions` (`-sV` without `-O`: a hand-picked pass over devices of unknown type; an old worker that does not know this shape refuses the job with `invalid_job`, and identification reports `unavailable`) \| `gentle_titles` (the gentle scan of a non-fragile device of unknown type, plus `--script http-title,ssl-cert,http-hp-ilo-info,vmware-version --script-timeout 20s`; like `versions`, an old worker refuses with `invalid_job` during an update, and that gentle scan runs again in the next window; no proto bump) \| `external` (the default scan of exactly the box's own public IP for exposure, two jobs with the same name: **port discovery** `--privileged -sS -Pn -n --max-rate 100 --max-retries 2 --host-timeout 2m --top-ports 1000` (the job carries no `ports`; nmap picks the 1000 ports from its own `nmap-services`, and core reads the probed ports back from `<scaninfo services>`), then **`-sV`** `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 --host-timeout 3m -p <ports>` (the job carries `ports`: every port of `nmapargv.ExtraPortNumbers` (commonports and the reviewed management ports) plus at most 40 ports the discovery found open outside those, ascending; the worker builds `-p` from that and the grammar refuses any other list); no `-O`, no `--script`; the worker **checks by itself** right before nmap that the box goes out to the Internet through that address (three public services, 2/3, at most 5 rounds, remembered for 5 minutes; `core/egressip`; IPv4 only: `tcp4`), a service reporting a different address → `refused`/`not_own_ip`, no round with an answer (unreachable, TLS, no agreement) → `refused`/`egress_unverified`, nmap does not run; an old worker that does not know this shape → `invalid_job`; an old worker that knows the shape runs its old line (`-sV` on 99 ports) for the discovery job, core recognizes that `<scaninfo>` and reports an old worker, and does not send the `-sV` job; exposure reports "may be older"; no proto bump) \| `external_full`, `external_disruptive` (version 5, before the first release: a deep scan of the box's own public IP once the target's testing terms have been accepted; `--privileged -sS -sV -Pn -n -p- --script "<list>" --script-timeout 5m --max-rate 300 --max-retries 2 --host-timeout 60m`, the list being **exactly one** of the two fixed reviewed script lists: `nmapargv.FullScripts` for `external_full`, `nmapargv.DisruptiveScripts` for `external_disruptive`; no `--script-args`; the same target rule and the same worker own-IP fence as `external`, and the worker **asks that fence again every 3 minutes** while nmap runs: the first answer that is not "yes" kills nmap, drops the whole result and returns `stopped`/`not_own_ip` or `stopped`/`egress_unverified` (`stopped` because nmap already ran, `refused` only when nmap has not run yet); the worker only runs the deep shapes when its nmap is exactly `nmapargv.ReviewedNmapVersion` (otherwise → `invalid_job`); only handed to a worker whose heartbeat has `nmap.full=true`). \| `extra_ports` (follows every `normal`/`versions` scan of a device, at the same rate: `--privileged -sS -sV --script <nmapargv.Scripts> -n --max-rate R --max-retries 3 -p <nmapargv.ExtraPorts: the 98 commonports ports plus the reviewed management port list> --host-timeout 30m`, private IP targets like the LAN shapes) \| `all_ports` (only probes every TCP port once a week for a non-fragile device, `--privileged -sS -n --max-rate R --max-retries 1 -p- --host-timeout 90m`, `R` ≤ 100, no `-sV`, no scripts; private IP targets) \| `port_versions` (`-sV` after `all_ports` on exactly the ports the job carries: `--privileged -sS -sV --script <nmapargv.Scripts> -n --max-rate R --max-retries 3 -p <ports> --host-timeout 30m`, exactly one private IP target; the nmap job also carries `ports` (1..20 ascending integers in this shape; also in the `external` `-sV` job as above; `omitempty` on every other job) and is only handed to a worker whose heartbeat has `nmap.ports=true`, like `nmap.full`). Like `gentle_titles`, `extra_ports` and `all_ports` do not bump the proto: an old worker refuses with `invalid_job` during an update (that `extra_ports` pass is dropped, the top-1000 result is kept; the device of that `all_ports` pass waits for the next window); an old worker does not say `nmap.ports`, so it never gets `port_versions` (ports are recorded without versions). `normal` and `versions` carry exactly `--script rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert,http-hp-ilo-info,vmware-version` (`nmapargv.Scripts`: two NTLM type 1 scripts, no credentials; the page title and the TLS certificate subject); the shape names do not change, so no proto bump: an old-release worker builds those two shapes without scripts (only during an update; `sa_probe.flags` then records scripts that did not run, never fewer) |
| `jobs[].rate` | (nmap) 1 … 1000; `gentle` always `1`; `external` always `100`; `external_full` and `external_disruptive` always `300` |
| `jobs[].targets` | (nmap) 1 … 64 private IPv4 addresses (RFC 1918 or the RFC 6598 shared range 100.64/10, `core/localnet.Addr`), canonical, no duplicates (the `ValidateNmapArgs` grammar); `external` (and `external_full`, `external_disruptive`): **exactly one** canonical public IPv4 (`egressip.IsPublicIPv4`: not private, CGNAT, loopback, link-local, documentation, multicast, reserved), and only these three shapes accept public addresses |
| `jobs[].timeout_s` | nmap: 1 … 7200 = min(end of window, 2 hours); nuclei: 1 … 3600 = min(the probe context's deadline, 1 hour); computed by `core` when handing out the job |
| `jobs[].pack` (nuclei) | `{version, sha256}` of the template pack `core` chose the templates from; the worker refuses when the index in the image differs (`pack_mismatch`). `sha256` is a **label** written into the index by the pack builder (`pack.Index.SHA256`), not a hash the worker computes; what is hashed again is each selected template file, compared with the `sha256` of the matching index entry. `core` also compares this label with the heartbeat **before handing out the job** (`ErrPackMismatch`, no retry); `pack_invalid` (hash mismatch, a link in the pack) is an integrity signal: `ErrPackInvalid`, log ERROR, no retry |
| `jobs[].templates` (nuclei) | 1 … 32 template **ids** (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`), no duplicates; no paths, no URLs, no YAML. The worker turns ids into paths with the checked index; an id not in the index → `invalid_job` |
| `jobs[].targets` (nuclei) | (scope `lan`; `own_ip`: see `scope`) 1 … 16 `{host, port, scheme}`: `host` is a private RFC 1918 or RFC 6598 IPv4 address (100.64/10; except 100.100.100.200, Alibaba Cloud metadata) in canonical form, not `.0`/`.255` (**no domain names**, no public IPs, the part of 100/8 outside 100.64/10, loopback, link-local, benchmark, 240/4), `port` 1..65535, `scheme` `"http"` \| `"https"` \| `""` (network templates, `host:port`); no duplicates |
| `jobs[].rate` / `max_host_errors` (nuclei) | `rate` 1 … 20 (`-rl`), `max_host_errors` 2 … 20 (`-mhe`) |
| `jobs[].scope` (nuclei, version 5) | absent or `"lan"` = the rules above (`scan`); `"own_ip"` = `exposure`'s safe vulnerability check on the box's own public IP: **exactly one** target, `host` is a canonical public IPv4 (`localnet.Public`, the same rule as `egressip.IsPublicIPv4`), `port` is the job's port, `rate` always `5`, 1 … 32 templates from the checked pack (each one the template of a CVE `core` has matched, not chosen by tag), **each template must be marked `own_ip: true` in the image's index** (decided when the pack is built from the template file itself: read-only requests only, GET or HEAD without a body, no credentials, no commands) and the template file must pass `pack.OwnIPText`, which the worker reads itself; the argv's `-etags` adds `default-login,brute-force,sqli,time-based-sqli,xss,injection,code-injection,argument-injection,ssti,file-upload,rce,authenticated,login` (not yet checked in the lab with `-t`, not relied on); any other value → `invalid_job`. `core` **leaves `scope` empty** on LAN jobs, so an older worker gets exactly the shape it knows; `own_ip` jobs are only handed to a worker whose heartbeat has `nuclei.own_ip=true`, and are not queued behind another nuclei job (slot busy → `ErrNucleiBusy`, nothing is sent). An older worker that receives a job with `scope` fails strict decoding: nothing runs |
| `jobs[].depth`, `jobs[].disruptive` (nuclei `own_ip`, version 5) | absent = the `own_ip` job above; `depth` `"full"` = a deep scan of a target whose testing terms have been accepted (exposure): the same **single** public IPv4 and the same own-IP fence, `rate` always `20`, 1 … 200 templates, each template must belong to the `deep` set of **the image's** index (plus `disruptive` when `disruptive: true`; templates only in `kev`, such as KEV PUT/PATCH templates, never), the template file (hashed) must pass `pack.FullText` (no write methods, no out-of-band); argv: fixed flags as for LAN except `-c 10`, `-etags dos,intrusive,fuzz,brute-force,default-login,authenticated` (with `disruptive`: `intrusive,fuzz`), plus `-or -ot`; `disruptive` without `depth`, or `depth` outside `own_ip` → `invalid_job`. `core` leaves both empty on every other job and only hands full jobs to a worker whose heartbeat has `nuclei.full=true`; an older worker that receives one fails strict decoding: nothing runs |
| `jobs[].scope`, `jobs[].domain` (nmap full and nuclei `depth` `full`, version 5) | `scope` `"domain_ip"` + `domain` `{domain, name, token, proof_at?}` = a deep scan of **one** public IPv4 that is **not** the box's outgoing Internet IP, because a name under a verified domain resolves to it: nmap only in the `external_full`/`external_disruptive` shapes, nuclei only with `depth` `"full"` (the argv is the full form of `own_ip`); `domain` follows exposure's domain regex, `name` is the domain or a name under it, `token` 16 hex; `proof_at` (optional) is a parent name of `domain` (the zone apex) where the record of `domain` itself lives. A worker that does not know this field refuses the job; the worker checks that `proof_at` lies between `domain` and its registered domain (`proofat.Within`, PSL on both parts) before the fence, otherwise `invalid_job`. No other job carries the nmap `scope`/`domain` or the nuclei `domain`; `core` only sends them to a worker whose heartbeat has `domain_ip` |
| `cancel` | ≤ 8 ids of jobs that must stop |

**External -sV batches** (this supersedes what the `jobs[].shape` row says about the `external` -sV job): the default scan's -sV runs in batches, each its own nmap job (`nmapargv.BatchFlags`: `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 --host-timeout <N>s -p <ports>`, 1 to 40 ascending ports, N whole seconds from 60 to 120, never `--version-light`), because nmap's `--host-timeout` drops every result of a host that times out. An `external` job with `ports` is one batch and also carries `host_timeout_s` (60..120; only on this job, `omitempty` on every other); the worker builds the argv from both (`nmapargv.BuildBatch`) and refuses other values as `invalid_job`. A worker built before `host_timeout_s` decodes jobs strictly and fails its poll on it, so the batch job expires unread (`worker_lost`); only while the box updates.

There are **no** argv, flags, paths, URLs or ranges on the wire: the worker builds the argv with the same `buildNmapArgs` + `ValidateNmapArgs` (leaf package `modules/sensor-active/nmapargv`); for nuclei jobs with `nucleiargv.Build` + `Validate` (leaf package `modules/scan/nucleiargv`).

**The dispatcher** (`core`, in memory):
- `sensoractive` calls `Prober` **after** writing the `sa_probe` row (INV-9 keeps the order); no `active` heartbeat within 90 s → `ErrUnavailable` at once, no job is created.
- Two separate **slots**, nmap and nuclei (version 2): each slot has one running job = one process on the box; one nmap job and one nuclei job run at the same time, so "Scan now" and KEV rescans do not wait behind a 2-hour discovery scan. A slot's new job is only handed out when that slot is free and the poll no longer names the slot's just-finished job or an id `core` does not know (an unknown id holds both slots until the worker stops reporting it); a second job of the same kind waits (still bound by its deadline). Every rule below (lease, pickup wait, 30 s, cancellation) applies per slot.
- A job not picked up within 60 s → probe `failed` (`worker_unavailable`). A job handed out where a later poll reports a `running` other than that id with no result yet → probe `failed` (`worker_lost`: the sensor restarted midway or the response was lost).
- The probe context ends (end of window, `SettingsChanged`, `rate` lowered, the device changes, module off; INV-3) → a job not yet handed out is dropped; one already handed out gets `cancel:[id]` at the next long-poll (an open long-poll is woken). `core` treats the probe as `stopped` after at most 30 s even if the worker has not confirmed; a new job still waits for an empty `running`.

**The worker** (`vedette-sensor active`):
- Checks the job again (the grammar of the table above, `ValidateNmapArgs` on the built argv, deadline ≤ 2 hours); invalid → result `refused` (`invalid_job`), nothing runs. Receiving a job while the slot of the same kind is running another job → `refused` (`busy`); the other slot is not touched.
- Runs `/usr/bin/nmap` through `core/exec` (binary + argv allow list, no shell), its own process group, deadline `timeout_s`, stdout capped at 8 MiB (`Truncated`).
- `nuclei` jobs (version 2): checks again with `nucleiargv` (counts, private IPv4 targets, `rate`, `max_host_errors`), `timeout_s` 1..3600, the **pack** (`pack.version` and `pack.sha256` must equal the index in the image, otherwise `refused`/`pack_mismatch`), each template id must be in the index (otherwise `invalid_job`); then walks **the whole pack tree** with `Lstat`: only directories and regular files, a symlink, fifo, socket or device anywhere → `refused`/`pack_invalid`; hashes each selected template file with SHA-256 (opened through `os.Root`) and compares with the index (mismatch → `pack_invalid`). Runs `/usr/local/bin/nuclei` through `core/exec` with the argv from `nucleiargv.Build` (one `-t <TemplatesDir>/<path>` per template, never the whole directory), a **clean environment** (only `PATH`, `LANG=C` and `HOME` set by `core/exec`; no `*_PROXY`, `ENABLE_CLOUD_UPLOAD`, `PDCP_API_KEY`, nothing from the parent process), `HOME` is a new empty directory on tmpfs (deleted and recreated before every run; no `~/.config/nuclei`), its own process group, deadline `timeout_s`, stdout capped at 4 MiB (`Truncated`); **stderr is never sent** (it holds the `-elog` error log; the worker only counts per-target timeouts into `host_errors`). Missing binary → `failed`/`nuclei_missing`. The result is raw JSONL in `jsonl_b64`; `core` parses it fail-closed (`nucleiout`).
- `nuclei` `own_ip` `depth` `full` jobs (version 5): the full grammar of `nucleiargv`; a template outside the set the depth allows in the image's index, or a file that does not pass `pack.FullText` → `invalid_job`; then exactly the own-IP fence of the `own_ip` job below. A non-full job only accepts templates from the `kev` set.
- `nuclei` jobs of every scope: a template file (hashed) that does not pass `pack.NoChangeText` (write methods, `@Host:`, method override, `INTO OUTFILE`, `xp_cmdshell`, `file_put_contents`, multipart file upload, `gopher://`/`dict://`) → `invalid_job`; nuclei does not run (no proto bump: only the worker refuses more).
- `nuclei` jobs with scope `own_ip` (version 5): the `own_ip` grammar of `nucleiargv` (one public IPv4, `rate` 5, fixed flags as for LAN except `-etags`), a template without `own_ip: true` in the image's index or a template file (hashed) that does not pass `pack.OwnIPText` → `invalid_job`; then, **right before nuclei**, the worker checks by itself that the box goes out to the Internet through that address (the same fence as the nmap `external` shape: three public services, 2/3, at most 5 rounds, remembered for 5 minutes, `core/egressip`): a different address → `refused`/`not_own_ip`, no round answers → `refused`/`egress_unverified`; nuclei does not run.
- `domain_ip` jobs (nmap full or nuclei full, version 5): the own-IP fence is **not** asked; right before the tool runs, the worker checks the domain fence itself (`core/domainfence`): grammar (invalid → `invalid_job`), `token` must equal the first 16 hex characters of HMAC-SHA256(the worker's key, `"vedette-verify\x00"+domain`) (different, or `domain` not in the host's copy of the list `/var/lib/vedette-fence/domains`, read again at every check; an unreadable copy is read once more after 1 s before refusing → `token_foreign`), the TXT of `domain` (or of `proof_at` when present; the `domainfence.Owned` rule: also `_vedette-verify.<name>`, not through CNAME, no wildcard, the query name in its original form) contains `vedette-verify=<token>` (otherwise → `target_not_owned`), `name` resolves A (system resolver, 10 s) to a set containing the target (otherwise → `name_moved`), a CNAME lookup (a disruptive job and a canonical name outside the domain → `cname_outside`); DNS error → `ownership_unchecked`; a "yes" is cached for 5 minutes per `(domain, name, ip)`. A worker without the key → `invalid_job`. Deep nmap jobs and nuclei `domain_ip` jobs check again (no cache) every 3 minutes while the tool runs; an answer other than "yes" → kills the tool, `stopped` with that code, drops the output. Each refusal/stop is one worker log line with the CNAME chain.
- **Cancellation**: an id in `cancel` → kills the process group, result `stopped` (`cancelled`).
- **Lease**: 60 s without a single `200` poll, or an `instance` different from the `instance` at job pickup → kills the process group and **drops** the result (the side that handed out the job is gone). A `core` crash leaves no orphan nmap.
- While running, it keeps long-polling continuously with `running=<id>` (version 2: `running=<id>,<id>` when both slots are busy).
- While a result is being sent, the poll loop waits (`waitPost`, at most as long as the lease): the other slot is not polled during that time, so a new job for it waits until the result has been sent (accepted: results ≤ 11 MiB, 60 s).

### 6.5 `POST /sensor/v1/jobs/{id}/result` (active)

```json
{ "status": "done", "reason": "", "exit_code": 0, "truncated": false, "xml_b64": "PD94bWwg…" }
{ "status": "done", "reason": "", "exit_code": 0, "truncated": false, "xml_b64": "", "jsonl_b64": "eyJ0ZW1w…" }
```

| Field | Rule |
|---|---|
| `status` | `done` \| `failed` \| `stopped` \| `refused` |
| `reason` | `""` or one of `invalid_job`, `busy`, `nmap_missing`, `exec_failed`, `deadline`, `cancelled`; version 2 adds `nuclei_missing`, `pack_mismatch`, `pack_invalid`; later `not_own_ip` and `egress_unverified` were added (only for `external` jobs, only a `core` of the same release sends those jobs: no proto bump); nuclei `own_ip` jobs use those two codes; deep nmap jobs use them with `status` `stopped` when the worker re-checks a deep nmap job midway and stops it (nmap already ran, the output is dropped), and with `refused` when it has not run yet; `token_foreign`, `target_not_owned`, `name_moved`, `ownership_unchecked`, `cname_outside` belong to `domain_ip` jobs (`refused` when not run yet, `stopped` when a midway re-check stops nmap) |
| `exit_code` | −1 … 255 (−1 = did not run or was killed) |
| `truncated` | stdout hit the cap (nmap 8 MiB, nuclei 4 MiB) |
| `xml_b64` | standard base64 of the nmap stdout; ≤ 8 MiB after decoding; empty when not `done` (otherwise → `400`); always present, empty in nuclei results |
| `jsonl_b64` (version 2) | standard base64 of the nuclei stdout (`-jsonl`); ≤ 4 MiB after decoding; only when `done`, and **not together with `xml_b64`** (both → `400`); over 4 MiB → `413` |
| `host_errors` (version 3, nuclei) | optional, left empty when no target had a timeout: an array of ≤ 16 entries `{target "host:port", errors 1..1048576, unreachable bool}`, one entry per target, only when `done` (otherwise → `400`). The worker counts the `kind` = `network-temporary-error` lines per target from nuclei's error log (`-elog /dev/stderr`); `unreachable` = `errors` ≥ the job's `max_host_errors`. `core` refuses (`ErrResultRejected`) targets outside the job, or an `unreachable` inconsistent with `errors`; an nmap result carrying `host_errors` is also refused |

`{id}` must be a **running** job handed by this same `core` to the `active` role; anything else (an unknown id, a finished job, a second resend) → `404 unknown_job`. A body > 11 MiB, decoded XML > 8 MiB or decoded JSONL > 4 MiB → `413 payload_too_large` and the probe `failed`. Returns `204`.

`core` **does not trust** the worker's `status`: `done` with `exit_code ≠ 0` or `truncated` → probe `failed`, the whole batch is dropped (INV-7); the XML is parsed with `parseNmapXML` (fuzzed) and `onlyTargets` inside `core`, so observations and software from nmap never travel on the wire. `refused` → probe `failed` and log ERROR (worker and `core` disagreeing about the grammar is a bug or a compromise); `nmap_missing` → health `unavailable` (INV-6).

**Nuclei jobs (version 2; code `modules/sensor-active/{dispatch.go,nuclei.go,worker/}`, `core/sensorlink`).**
- `Job` carries `kind`; two slots in `Dispatcher` (nmap, nuclei) and two `cur` in the worker; the poll's `running` is a list of ≤ 2 ids (`Backend.Jobs(ctx, wait, running []string)`, `Client.Jobs(ctx, running []string, wait)`). A poll in which the worker names a slot's id, a slot's just-finished id, or an unknown id is handled as in the dispatcher block below, but per slot; an unknown id gets `cancel` on the first poll and holds both slots.
- Deadline handed out: nuclei `timeout_s` = min(remaining ctx deadline, 3600); the `core`-side cap is `timeout_s` + 30 s as for nmap, and nuclei's `Health` reports "overdue" separately.
- Seam for `scan`: `sensoractive.Scanner` (`Ready(ctx) error`, `RunNuclei(ctx, NucleiRequest) (nucleiout.Outcome, error)`), satisfied by `*Dispatcher`. `RunNuclei` checks the grammar (like `nucleiargv.Build`) before handing out; returns `ErrScannerUnavailable` (and the errors that wrap it: `ErrScanWorkerUnavailable`, `ErrNucleiMissing`, `ErrPackMismatch`) when the scanner is not ready (503 `scanner_unavailable`); `ErrWorkerLost`, `ErrWorkerRefused`, `ErrResultRejected` (including JSONL refused by `nucleiout`), `ErrOutputTruncated`, `*exec.ExitError` make the run `failed`.
- `core` only trusts the exit code, `truncated` and the JSONL bytes; any line outside the job's templates or targets (host:port) drops the whole run ((7)). A nuclei result with `xml_b64` (or the reverse) is refused.

**SNMP reads (version 5; code `core/sensorlink/wire.go`, `modules/sensor-active/{snmp_dispatch.go,snmp.go,worker/snmp.go}`).**
- The `active` heartbeat adds `"snmp": true` (a version 5 worker always sends it: gosnmp is in the binary). Missing = a version 4 worker: `SNMPHealth` says the worker is older than `core`, and no `snmp` job is created.
- Job (changed before the first release of version 5): `{ "id", "kind": "snmp", "timeout_s" 1..3600, "rate" 1..1000, "targets": [ 1..64 × {"ip", "credential": {"version": "v2c", "community"} | {"version": "v3", "user", "auth": "sha"|"sha256", "auth_pass", "priv": "aes128"|"", "priv_pass"} (plus an optional `"port"` 1..65535: the agent's UDP port; absent = 161)} ] }`. **Each credential sits inside exactly one target**: there is no shared credential list and no index; the worker only sends a target's credential to that target's own address (one device's secret only goes to its read address; `core` refuses to build a job for an address other than the device's stored read address, sensor-active INV-10 (d)). Community 1..64, user 1..64, v3 passwords 8..64 printable ASCII characters; no v1, MD5, DES, noAuthNoPriv. IP: canonical IPv4, no duplicates, local (`core/localnet`). `sensorlink.CheckSNMPJob` is the shared grammar; `core` checks before handing out, the worker checks again (`refused`/`invalid_job`, no packet sent). **No OIDs on the wire**: the worker always GETs exactly its own list (sysDescr, sysObjectID, sysName, entPhysicalClass/ModelName/SoftwareRev/SerialNum.1, MIKROTIK-MIB mtxrLicVersion.0). Secrets travel on the wire only inside this mTLS link; `SNMPCredential` prints itself as `[redacted]`.
- Worker: one target at a time, sends the target's credential to its UDP port (`port`, absent = 161); timeout 2 s, 1 retry; after each target it pauses `2/rate` seconds (one v3 read is two packets). A third slot (`slotSNMP`); a second `snmp` job while the slot is busy → `busy`. `timeout_s` runs out → `done` with `reason: "deadline"` and the targets already finished.
- Result: `{"status": "done", …, "xml_b64": "", "snmp": [ ≤ 64 × {"target", "status": "ok"|"no_answer"|"auth_failed"|"unknown_user"|"error", "values": {"sys_descr", "sys_object_id", "sys_name", "ent_class", "ent_model", "ent_software", "ent_serial", "os_version" (MIKROTIK-MIB mtxrLicVersion.0; absent when empty)}} ]}`; each value ≤ 512 bytes (the worker cuts at 255, valid UTF-8), values only when `ok`; `snmp` only when `done`, not together with `xml_b64`/`jsonl_b64`/`host_errors` (otherwise → `400`). `core` refuses answers for targets the job did not name (`ErrResultRejected`) and parses the values itself (untrusted, sensor-active INV-10).
- `core`: `sensoractive.Service` writes the `sa_probe` row (`shape` `snmp`) **before** opening the secrets and handing out the job; one snmp job at a time (`snmpMu`).

**The dispatcher (clarified in code, `modules/sensor-active/{dispatch.go,worker/}`).**
- `timeout_s` is computed when the job is **handed out** (`min(remaining probe context deadline, 7200)`, rounded up), not when it is queued, so a job that waits long to be picked up does not run past the probe's deadline.
- The worker's `wait` is at least 1 s: the wire only carries whole seconds, and `wait=0` is a poll that returns at once and would loop.
- The `jobs` reply carries `cancel:[id]` **every time** until the worker reports it done, but only the first one wakes an open long-poll. A poll that still names a **just-finished** job is answered at once, once (so the worker polls again with an empty `running`; the next job does not have to wait out `wait`).
- A result body refused by the server (`413` or `400`) while `{id}` is running: the `Backend` is told through the optional interface `sensorlink.ResultRejector` and the probe is `failed` at once (the worker does not resend the result); `404` reports nothing (no job is affected).
- `cancel` arriving in the same reply as the job: the worker does not run nmap and sends `stopped`/`cancelled`. A second job arriving while another job runs: `refused`/`busy`, sent at once, the running job is not touched. `refused` also keeps `running=<id>` in the polls until the result has been sent, so `core` does not wrongly report `worker_lost`.
- The worker sends no result when it was killed because of the lease, a changed `instance`, `409 module_off` or a process shutdown; it sends `stopped`/`deadline` when `timeout_s` runs out.
- Whether a running job is alive is decided by **the last poll that names it** (90 s without a poll → `worker_lost`), plus the `core`-side cap of `timeout_s` + 30 s. A poll naming a `running` job `core` does not hold (a dropped job, or `core` just restarted) gets `cancel:[id]` at once.
- The worker resends the result on 429, 503 or a connection error (after `Retry-After`/backoff, within 60 s), and does not resend on 400, 403, 404, 409, 413; the poll loop waits until the result has been sent. A job id that does not match `^[0-9a-f]{32}$` is dropped and never used in a URL or log.
- The key bundle must be a regular file, in a directory that is not a symlink, with a mode within `0640` (core writes `0640`; any bit outside that, such as group write or other read, is refused); the client opens it through an `os.OpenRoot` of the containing directory.
- Consequences of the result in `core`: exit code `> 0` → probe `failed` (nmap exited with that code); `< 0` or `status ≠ done` → `failed`; `refused` → `failed`, log ERROR; `reason=nmap_missing` → `unavailable` until the next heartbeat. The `sa_probe.result` row records the code: `worker_unavailable`, `worker_lost`, `nmap_missing`.

**Passive capture (clarified in code, `modules/sensor-passive/{capture,backend.go}`).**
- Every `observations` send uses a new `seq` within the same `epoch`, even when resending items that failed: a resent batch may be a different set of items (split in half, a poisonous item dropped), and `core` drops a `seq` it has already seen. The sensor retries **after** `core`'s `Retry-After` but no later than 60 s; a connection error, `426`, `429`, `503` and `403 cert_retired` mean "retry" (only a `503 store_busy` together with a heartbeat that just succeeded leads to splitting the batch; `503 not_ready` never does); `413` splits in half (a single item still `413` is dropped); every other code drops the batch and counts `batch_dropped`. A batch that fails 3 times in a row is split in half until an item stands alone; that item is dropped (counted as `observation_failed`) only when a heartbeat has just succeeded.
- Item checks in `core`: a `mac` row must have `mac` and `value == mac`; `kind` only accepts `ap`, `switch`, `router`, `printer`, `iot` (clamped to 0.6, 0.6, 0.6, 0.5, 0.3); an item with the box's own MAC or IP (by the host's cards) is `refused`; `mac` well formed (lowercase) and not a group or all-zero address; `ip` unicast IPv4 (IPv6 is `invalid_item`, because assets only have IPv4 addresses); `confidence` outside [0,1] is `invalid_item`, inside the range it is clamped to the field's cap: `mac` 0.9, `hostname` 0.7, `kind` 0.6, `model` 0.5, `vendor` 0.4, `os` 0.3; a missing `seen_at` is `out_of_window`.
- Repeat filter: the same (MAC, IP, field, value) within 15 minutes is acknowledged without being written (not in `rejected[]`); a cap of 6000 items per minute for the `passive` role (the excess: `budget_exhausted`, not read). Plus a quota of 4 new IP addresses per MAC per hour.
- The flood quota is computed **before** writing and charged **after** inventory accepts: a store error (`503`) costs no quota. Items without a MAC count by IP address. "Quota exhausted" is logged once per minute.
- `drops` carries **35 known keys**: `arp_mac_mismatch`, `batch_dropped`, `capture_failed`, `dhcp_mac_mismatch`, `dns_name_rejected`, `excluded`, `filters_invalid`, `flows_dropped`, `fragment_skipped`, `malformed_{arp,dhcp,dns,ethernet,http,ipv4,lldp,mdns,ssdp,tcp,tls,udp}`, `metadata_dropped`, `metadata_failed`, `new_macs_dropped`, `new_macs_unconfirmed`, `non_unicast_ip`, `observation_failed`, `observation_rejected`, `observations_dropped`, `unusable_record`, `value_empty`, `value_meaningless`, `value_truncated`, `values_dropped`, `vendor_rejected`; an unknown but well-formed key (`^[a-z][a-z0-9_]{0,47}$`) is **ignored by `core` and logged once per key** (forward compatibility); a negative value, a wrong type or a malformed key is `400`; a duplicate card name in `interfaces` is also `400`. Values are counters accumulated since the sensor process started. `filters_invalid` increases every time the sensor receives a filter it cannot compile; it does not capture while that is the case.
- The sensor sends a heartbeat right at start and every 30 s, even when `config` says `interface ""`; during `module_off` it does not send. The `interfaces` list is filtered to the wire's shape (card names by regex, lowercase MACs, ≤ 32 cards, ≤ 8 IPv4 prefixes per card).
- The `config` long-poll: `core` re-reads the settings (the network page's filters) every 5 s while holding the request, and `SetInterface` wakes it at once. Filters `core` cannot read give `interface ""` (the same ETag as the normal "no capture" configuration).
- `Client.PostObservations` is a single attempt, no backoff, no sleep, and is the only path that sends observations (`SendObservations` no longer exists).

### 6.6 `POST /sensor/v1/jobs/{id}/progress` (active, #830)

How far a running nmap or nuclei job is, so the scan page shows a phase, a bar and an estimate instead of "0/1 devices done" until the device ends. Added to protocol 5 before its first release, like the nuclei `own_ip` fields (no new number: the latest release speaks 4); optional on both sides.

- Body (`JobProgress`, ≤ 1 KiB, strict decoding): `{phase, percent, done, total, remaining_s}`. `phase` ∈ `discovery`, `ports`, `services`, `scripts`, `vulns`; `percent` is `-1` (none) or 0 … 100; `0 ≤ done ≤ total ≤ 2^20` (nuclei's template × target checks; `0`/`0` = no count); `remaining_s` 0 … 86400 (the tool's own estimate, 0 = none). Anything else is `400`.
- Source, no extra work asked of the tools: nmap gets `--stats-every 5s` (part of every shape in `nmapargv`, before `-oX -`), which writes `<taskprogress task percent remaining etc/>` into the XML on stdout; the worker reads those lines while nmap runs (task names map to phases; an unknown task, a malformed line or one over 512 bytes is ignored) and `core`'s XML parser skips them. nuclei: no new flag. Its `-ms` lines (one per template and target that ran) are counted while it runs, through the same `nucleiout` reader `core` uses; a line over 64 KiB is not counted. nuclei's own `-stats` is not used: it starts a `/metrics` HTTP listener (clistats) inside the scan container.
- nmap runs on a terminal of its own (`core/exec` `Binary.TTY`: a new pseudo-terminal is its stdin and controlling terminal, in a new session; stdout and stderr stay the pipes). nmap 7.95 prints `--stats-every` only when `/dev/tty` opens and its process group is the terminal's foreground one (`nmap_tty.cc`; nmap lifted that in 2026-06, nmap#3175, after 7.95): without a terminal, a test box got no `<taskprogress>` at all (#830). Where no terminal can be opened nmap runs as before, and the worker still names the phase: the one its command line starts with (`discovery`, or `ports` with `-Pn`) as nmap starts, then `ports` at nmap's first `<hosthint>` (written and flushed when discovery finds a host up); these only move forward, a `<taskprogress>` is taken as it is.
- Throttle: the worker keeps only the latest state of a job and posts it as the job starts, then at most every `ProgressEvery` (5 s), one attempt, never retried, never after the job's result (the reporter is joined before the result is posted). `core` enforces it too: a report of a job sooner than `ProgressEvery` − 1 s after the last one it took is answered `204` and dropped. A report takes a body slot like any body, without waiting: none free → `503 store_busy`, unread and dropped (the worker does not retry it).
- `core`: answered before the body is read like a result (`404 unknown_job` for a job that is not running; a `core` without the receiver answers `404` too, and an older build of protocol 5 without the route `403 forbidden_route`; the worker logs both at debug). The `Dispatcher` passes the report to the `progress.Sink` the probe's context carried (the scan run or the exposure scan waiting for that job), under its lock so no report lands after the job's result, and stores nothing (the first report of a job opens a new pass of its phase); a report of a job being cancelled is dropped. Advisory only: nothing is decided from it.

### 6.7 `POST /sensor/v1/metadata` (passive)

The mirror-port metadata the capture extracted (DNS query names, TLS server names, HTTP hosts, IPv4 flows), reduced to what core's bad-address matching needs. Added to protocol 5 before its first release, like §6.6 (no new number); optional on both sides.

- Body (`MetadataRequest`, ≤ 512 KiB, strict decoding): `{items: [{kind, at, src, dest}]}`, 1 … 1000 items. `kind` ∈ `dns`, `sni`, `http`, `flow`; `at` is when it was seen; `src` is the LAN device's IPv4 address in canonical form; `dest` is the name (lower case, no trailing dot, ≤ 253 bytes of `a-z 0-9 - _` in non-empty labels of ≤ 63 bytes) or, for `flow`, the destination IPv4 address in canonical form. One item that is not of this shape refuses the whole body (`400`): the sensor checks its items with the same rule (`sensorlink.ValidMetadataItem`) before it sends them. No epoch, no seq: a batch sent twice makes the same matches, which core keeps once.
- Nothing else of a packet is on the wire: no port, no counter, no resolver address, no payload. A flow is sent only in the direction that started the conversation (a TCP SYN without ACK; a SYN-ACK or RST is an answer; mid-connection, and for a UDP datagram from a port below 1024 to one above, the side with the higher port is the client; otherwise the first packet seen) and only to an address a feed could list (not private, shared, loopback, link-local, multicast or broadcast): a LAN server answering a scan is never a flow to the scanner. Each (kind, src, dest) is sent once per 10 minutes.
- Pacing: the capture loop only queues (at most 10,000 items; more are dropped); a goroutine of its own posts batches of at most 1000 items, at least 2.5 s apart (2 per 5 s), waiting as long as a `429`/`503` `Retry-After` asks (capped at 60 s) and doubling up to 60 s while core does not answer. `503 store_busy` is offered 5 times, then dropped; `400`, `403` and `413` drop the batch; `409 module_off` drops the queue. Every loss is counted as `metadata_failed`.
- `core`: a Backend without the receiver answers `403 forbidden_route` before the body is read. `sensor-passive` hands the batch to the logs module's matching (`logs.MatchMirror`), which looks up each destination in the threat feeds as it does for a firewall line and stores only the matches (`logs_ioc_hits`, `seen_via` `span_dns`, `span_sni`, `span_http`, `span_flow`). With the logs module off the batch is answered `204` and dropped; a matching that cannot store its hits, or could not look at the whole batch (a feed lookup failed, or the batch reached the 50 new hits one batch stores), is `503 store_busy`: the sensor sends the batch again, and the pairs already stored are skipped as repeats.

## 7. Error table

| HTTP | `code` | When | What the sensor does |
|---|---|---|---|
| — | (handshake failed) | wrong CA, expired/not yet valid, wrong EKU, wrong/missing URI SAN, retired serial, TLS < 1.3 | reload the key bundle; back off 1 → 60 s with jitter, retry |
| 200 | `rejected[].code` | partial success (§6.2) | **no retry** |
| 304 | — | `config` unchanged | poll again at once |
| 400 | `invalid_request` | not JSON, unknown fields, duplicate keys, too deep, missing/wrong type, unknown query, a `Content-Encoding` present | drop the batch, count, no retry |
| 403 | `forbidden_route` | the route does not belong to the role (before reading the body) | programming error: log ERROR, never retry that route |
| 403 | `cert_retired` | the leaf's serial is no longer the current/previous one (checked on every request) | reload the bundle, close idle connections, back off, then retry |
| 404 | `unknown_job` | a result for a job that is not running or was not handed out by this `core` | drop the result |
| 409 | `module_off` | the role's module is off | **stop at once**, drop the queue, do not flush the last batch (SYS-5); ask `config`/`jobs` again every 60 s (usually the host has already stopped the container entirely) |
| 409 | `poll_in_progress` | a second long-poll of the same role | programming error: wait for the open poll to finish |
| 413 | `payload_too_large` | the body exceeds the route's cap; XML > 8 MiB | observations: split the batch in half (a one-item batch still 413 → drop, count); job results: do not resend (the probe is already `failed`) |
| 426 | `proto_unsupported` | `X-Vedette-Proto` missing, or neither `core`'s version nor the one right before (newer than `core`, or more than two versions older) | keep the queue, back off up to 60 s, retry (§10) |
| 429 | `rate_limited` | more than 10 requests/second, burst 20, per role | wait for `Retry-After` |
| 503 | `store_busy` | `core`'s store is busy | wait for `Retry-After`, resend **the same** batch |
| 503 | `not_ready` | `core` does not yet have enough facts to judge the batch: the `passive` role does not know the box's own cards yet (the host is configured but has not provided the list; no host and no heartbeat within 90 s) | wait for `Retry-After` (5 s), resend the whole batch; do **not** split the batch, do not blame any item |
| 500 | `internal` | any other `core` error | drop the batch, count (OTLP: no retry) |
| — | (no response) | connection error, `core` restarting | resend the same batch after a 1 → 60 s backoff with jitter (`holdOff`); beyond the in-memory queue cap, drop the oldest and count |

Clarified in code: only requests that pass steps 1 to 3 (including `module_off`) spend a rate token; the `Retry-After` of a `429` is the number of seconds until the next token (rounded up, at least 1). Every code in the table is defined by `core/sensorlink/errors.go` (`codes`); error bodies have a fixed message per code. This table does **not** go into `API_CONVENTIONS` §3.3 (that is the GUI's public API; the sensor wire is internal).

Check order in `core` for every request: serial (`cert_retired`) → `X-Vedette-Proto` (`426`) → route by role (`403`) → module (`409 module_off`) → rate (`429`) → single long-poll (`409 poll_in_progress`) → (job results only) a well-formed id (`400`), then a running job (`404 unknown_job`), **without reading the body** → the role's body slot (`503 store_busy`, **without reading the body**) → body cap (`413`) → strict decoding (`400`) → handler.

**In-memory bodies are capped per role (review finding; SYS-6).** A rate of 10/s does not limit how many bodies `core` holds at once: a compromised certificate could hold dozens of 11 MiB bodies open for 10 s. So before reading **any** body, a request takes a slot: at most **2 bodies being read at once per role** (`MaxBodiesPerRole`), and **1** for `POST /jobs/{id}/result` (`MaxResultBodies`; the worker runs one job at a time). No slot → `503 store_busy` with `Retry-After: 1`, the body is not read, the connection is closed; the slot is returned when the request ends (including when the connection drops or the body times out). Job results: before reading the body, `core` asks `Backend.JobRunning(id)`; a malformed id → `400`, a job not running → `404 unknown_job`, neither reads the body and both close the connection. The sensor handles `503` as before: waits for `Retry-After`, resends the same batch.

**One sensor cannot hold all the connection slots.** `MaxConns` = 64 = 16 slots for connections in handshake (`MaxPending`) + each role's share **at the TLS handshake** (the role is read from the verified certificate): `passive` at most 32, `active` at most 16 (`MaxConnsPassive`, `MaxConnsActive`); a connection beyond its role's share fails the handshake, even if it sends no byte, on HTTP/1 and h2. On HTTP/1 every refusal before reading the body returns `Connection: close` with a 1 s read deadline (`DrainGrace`) when the request may carry a body (h2: the whole connection is not closed); a `GET` with a body = `400 invalid_request`. The whole-request `ReadTimeout` = `ReadHeaderTimeout + BodyTimeout` (15 s); a long poll lifts that deadline for itself. Known limit: unauthenticated TCP/TLS streams before the handshake cannot be counted per role yet.

## 8. Sequence

```mermaid
sequenceDiagram
    participant H as vedette-host
    participant C as core
    participant S as sensor (passive)
    participant W as scan (active)
    H->>H: build constant units (key volume per role)
    C->>C: CA + leaves; write creds/passive/sensor.pem, creds/active/sensor.pem; only then listen on 127.0.0.1:8444
    S->>C: GET /config?wait=25 (mTLS, passive role)
    C-->>S: 200 {interface, span, extract, filters} ETag "e1"
    loop every 30 s
        S->>C: POST /heartbeat {interfaces, span, drops}
        W->>C: POST /heartbeat {nmap}
    end
    S->>C: POST /observations {epoch, seq 41, items}
    C-->>S: 200 {ack_seq 41, rejected [{3, budget_exhausted}]}
    W->>C: GET /jobs?wait=25&running=
    Note over C: sensoractive writes sa_probe, Prober hands out the job
    C-->>W: 200 {instance, jobs [j1], cancel []}
    W->>C: GET /jobs?wait=25&running=j1
    Note over C: window closes (INV-3)
    C-->>W: 200 {instance, jobs [], cancel [j1]}
    W->>W: kill the nmap process group
    W->>C: POST /jobs/j1/result {stopped, cancelled}
    C-->>W: 204
```

## 9. Limits

| Item | Limit |
|---|---|
| `observations` body | 1 MiB; 1 … 500 items; `value` ≤ 200 bytes |
| `seen_at` window | 24 hours before … 5 minutes after `core`'s clock |
| `heartbeat` body | 64 KiB; ≤ 32 cards, ≤ 8 IPv4 prefixes per card, ≤ 64 `drops` keys |
| Job result body | 11 MiB; XML ≤ 8 MiB, JSONL ≤ 4 MiB after base64 decoding |
| `metadata` body (§6.7) | 512 KiB; 1 … 1000 items; `dest` ≤ 253 bytes; at most one request per 2.5 s, longer when core asks |
| `progress` body (§6.6) | 1 KiB; at most one per job every 5 s (core drops one within 4 s of the last); a body slot taken without waiting, none free → `503`, dropped |
| nmap job | 1 … 64 targets, `rate` 1 … 1000, `timeout_s` 1 … 7200 |
| nuclei job (version 2) | 1 … 32 template ids, 1 … 16 private IPv4 targets, `rate` 1 … 20, `max_host_errors` 2 … 20, `timeout_s` 1 … 3600; JSONL ≤ 1024 lines |
| Concurrent jobs | one nmap and one nuclei (`running` ≤ 2 ids); one job per kind in a reply |
| `cancel` per response | 8 |
| `core` responses (read by the sensor) | `config`, `jobs` 64 KiB; others 16 KiB |
| `wait` | 0 … 30 s (default 25) |
| Request rate | 10/second, burst 20, per role (long-polls count too) |
| Open long-polls | 1 per role |
| Bodies read at once | 2 per role, 1 for job results; no slot → `503 store_busy`, `Retry-After: 1` |
| Concurrent connections | 64 for the whole listener (`PendingListener`: 16 in handshake + 32 passive + 16 active) |
| Flood quota (`core`) | new MACs 60/minute and 200/hour; new values and new IP addresses 4 per (MAC, field) per hour; 6000 items/minute for the `passive` role; repeats within 15 minutes are not written |
| Heartbeat | every 30 s; `online` when ≤ 90 s |
| Worker lease | 60 s without a successful poll |
| Job pickup wait | 60 s |
| Certificates | 7 days; renewed when ≤ 1/3 is left |
| Epochs kept | 2 per sensor |
| Server timeouts | `ReadHeaderTimeout` 5 s, `WriteTimeout` 35 s |

The numbers are starting points to be measured again once there is code (ARCHITECTURE §11), not measured results.

## 10. Versioning

- Path `/sensor/v1`; `X-Vedette-Proto` is an integer, currently `5` (version 5: the `snmp` job, and, before the first release of version 5, the nuclei job's `scope` and `nuclei.own_ip` in the heartbeat, then `nmap.full` in the heartbeat and the two shapes `external_full`, `external_disruptive`, in the same way: only handed to a worker that has said `full`; then the SNMP credential's `port`: `core` drops it when it is 161, so a version 5 worker built earlier gets exactly the shape it knows for every default-port credential; a credential with another port sent to that worker gets `refused`/`invalid_job` (strict decoding, no packet sent), only within the update window because `core` and `scan` come from the same release; version 4: `capture_error` in the passive heartbeat; version 3: `host_errors` on nuclei results; version 2: `Job.kind`, nuclei jobs and results, the `nuclei` heartbeat, `running` with several ids). Because decoding is strict, every wire change (even adding a field or a `shape`) bumps the proto, **unless** that number has never been released (the nuclei `own_ip` job was added to version 5 before its first release, see the next bullet).
- **Version skew (like Kubernetes version skew: the kubelet is never newer than kube-apiserver, but may be older):** `core` accepts its own proto (`sensorlink.ProtoVersion`) **and the one right before it** (`sensorlink.ProtoPrevious`, currently `4`; `TestProtoPreviousIsOneBelow` keeps it at exactly the version minus one); a sensor or worker **newer** than `core`, or more than two versions older → `426`. A proto bump must keep `core` able to serve the older side: new request fields are optional (absent = the old meaning; proto 3 without `capture_error` = no capture error); changing what `core` **returns** (the reply) first requires adding what does not exist yet: passing the request's proto to the handler and returning the old shape to the `ProtoPrevious` side, with a test. Version 4 compared with version 3 only adds `capture_error` to the request, so the reply does not differ. The nuclei `own_ip` job was added to version 5 **before its first release** (not bumped to 6: the latest release `v0.1.0-beta.1` speaks 4, and a version 6 would have no update path from it): `own_ip` in the heartbeat is optional (absent = `false`); `scope` only exists on `own_ip` jobs, and `core` only hands that job to a worker with `own_ip=true`, so a version 4 worker (and a version 5 worker built before `own_ip`) gets exactly the reply it knows (`sensoractive` `TestOwnIPNucleiNeverGoesToAWorkerWithoutOwnIP`).
- **Update order:** Apply switches `core` **first** and only then `sensor`/`scan`/`honeypot` (`modules/core/updates_run.go` `planApply`, core CONTRACT INV-35): the sensor/worker health check is a heartbeat received by `core` (`cmd/vedette-sensor/health.go`), so it can only be judged once `core` is on the new release; during that window the old sensor (N-1) is still accepted. Rollback goes the other way: `sensor`/`scan` first (back to a proto the running `core` still accepts), `core` last, so a sensor is never newer than `core`. A sensor that rolls itself back after a failed switch stays at N-1 and is still accepted. A release that bumps the proto to N must set `min_upgrade_from` (`update-manifest.md`) no lower than the first release with proto N-1, so no box jumps two proto versions at once; `release-manifest` checks this rule from git (the proto at this release's tag and at every earlier one) and refuses when `min_upgrade_from` would still let through a release with a proto below N-1.
- Limit: the update plan is made by the **running** release, so only an update **from** a release that already has this order follows this order; a box running an older release (such as `0.0.1-test.16`) still switches the sensor first and gets reset when the proto increases: reinstall with the new release's `install.sh`.
- A sensor that meets an unknown `shape` or field: `refused` (`invalid_job`) / `400` when decoding, no crash.
- Widening the grammar's target set without changing the wire (adding 100.64/10) does not bump the proto: the wire stays the same; during the update window (core first), an old worker returns `refused`/`invalid_job` for a job with a new target like any job that breaks the grammar (no process runs), and never scans anything outside its grammar. Because `nextBatch` (`modules/sensor-active/service.go`) walks the merged ranges in address order, a discovery batch mixing RFC 1918 and 100.64/10 addresses is refused **as a whole**: during that window some RFC 1918 machines wait until the next turn for discovery, and each refused job leaves an Error log line and a failed probe row; nothing outside the grammar runs.

## 11. Security considerations (SYS mapping)

| SYS | Applied here |
|---|---|
| SYS-1 | No general commands; the worker only runs `/usr/bin/nmap` through `core/exec` with an argv built from a checked job and `ValidateNmapArgs` |
| SYS-2 | Body cap before decoding, `jsonstrict`, `netip`, regexes at `core`'s boundary; the worker checks the job again |
| SYS-3 | Issuing, rotating and retiring sensor certificates writes `core_audit` (actor `system`); every nmap run has an `sa_probe` row **before** the job is handed out (INV-9) |
| SYS-4 | The CA key through `core/secrets`; sensor keys only in the role's volume (0640, read-only in the container), not logged, not exported, not shown in the GUI |
| SYS-5 | Module off → `409 module_off` and the host stops the container; data is kept |
| SYS-6 | Everything from the sensor is untrusted: caps, strict decoding, quotas, confidence clamping, XML parsed in `core` |
| SYS-7 | `core` is the only consenting side; the worker only accepts private IPv4 addresses within the grammar of the three shapes |
| SYS-8 | Not applicable (AI is not part of the protocol) |

Remaining risks:
- A compromised `sensor` can still fake **plausible** observations (inherent): limited by `core`'s quotas, inventory's cap of 32 rows per (device, field, source), new devices being `approved=false` (S-INV-3), and every action needing approval.
- A compromised `scan`/`sensor` holds `NET_RAW` in the host's network namespace: it can send and read frames on the LAN (inherent to that capability); no `NET_ADMIN`, no root, a read-only rootfs, no DB, no key of the other role.
- A stolen certificate: only opens that role's routes, expires within ≤ 7 days, retires at the next rotation.
- `core` restarting mid-scan: an unfinished batch is dropped (the lease kills nmap), finished batches are kept (as in INV-3).

## 12. Questions from the draft (closed)

1. ~~No story for enrolling separate sensors~~ **Closed:** not built; the old §3.1 moved to appendix A; on the appliance there is no enrolment over the network, `core` delivers keys by file.
2. ~~Shared or separate listener port and CA~~ **Closed:** a separate listener `:8444`, only `127.0.0.1:8444` on the appliance; one CA **dedicated to sensors** signs both the 8444 server leaf and the sensor leaves, with EKUs separating the roles; separate from the 8443 certificate and the osquery CA.
3. ~~Does the honeypot get its own mTLS identity or go through the sensor~~ **Closed:** neither; hits go through a one-way JSON-lines file, and the honeypot has no network path to `core`.
4. ~~IOC matching in the sensor or in `core`~~ **Closed:** matched in `core` (the `logs` module, like syslog lines); the sensor only sends (kind, src, dest) through §6.7, and no IOCs are sent down to the sensor.
5. ~~Syslog parsing in `core` or in the sensor~~ **Closed for this profile:** no syslog intake, no `NET_BIND_SERVICE` until `logs` is built.
6. ~~90-day certificate lifetime, caps/WAL not measured~~ **Closed:** 7 days, renewed in the last third; no WAL; the caps in §9 are starting points to measure.

## 13. Implementation order

The code landed in small PRs after this document, in this order: `core/pki` + `core/sensorlink` (server, client, not yet wired to modules); the `Prober` seam and the `nmapargv` package (a pure refactor, in parallel with the first step); the dispatcher + `vedette-sensor active` (needs the first two); splitting sensor-passive + `vedette-sensor passive` (needs the first step); packaging, the `dev` compose profile, the box's address source (needs the dispatcher and the passive split); the `sensor`/`scan` units and the local `scan` build in `vedette-host` (needs the host's Quadlet unit and container pull work).

## Appendix A. Later: sensors on other machines

Not built. There is no story; the GUI test `inventory.test.tsx` asserts there is no remote sensor endpoint. When there is a story, the remote path keeps this document's wire, role URIs and sensor CA, and adds: kubelet-style bootstrap (bootstrap token → a CSR created by the sensor, the key stays on the sensor, renewal near expiry), binding on the LAN, a revocation action with an interface, a capped disk queue (replacing today's "no WAL"), and per-sensor identities instead of the two per-role URIs.

The §3.1 text of the earlier draft (2026-11-09), kept for reference; where it differs from the current decision is noted in square brackets:

> **Enroll.** Sensor enrolment token: single use, default expiry 1 hour, revocable, **only in the `Authorization: Bearer` header**, never in a URL. On the appliance, the installer generates a local token into a shared volume; the user does not see it. [The appliance no longer enrols.]
>
> `POST /sensor/v1/enroll` (one-way TLS, no client certificate yet)
>
> | Field (request) | Type | Required | Rule |
> |---|---|---|---|
> | `csr` | string (PEM PKCS#10) | yes | ECDSA P-256 key; core drops any subject/SAN set by the sensor and writes its own |
> | `name` | string | yes | regex `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$` |
> | `version` | string | yes | semver |
> | `interfaces` | string[] | no | card names (`^[a-z0-9._-]{1,15}$`), at most 16 |
> | `capabilities` | string[] | no | a subset of `passive`, `span`, `active_scan`, `syslog` |
>
> Response `201`: `{ "sensor_id": "sn_…", "certificate": "<PEM>", "ca": "<PEM>", "not_after": "<RFC3339>", "poll": { "commands_wait_s": 25 } }`.
>
> Errors: `401 invalid_token`, `403 token_expired | token_used`, `400 invalid_csr`, `409 name_taken`.
>
> Renewal: `POST /sensor/v1/renew` (mTLS, body `{ "csr": "…" }`) when ≤ 1/3 of the lifetime is left; returns a new certificate with the same `sensor_id`. An expired certificate → must enrol again with a new token.
>
> **Certificates (draft §3).** The sensor pins the CA by the SHA-256 fingerprint passed at enrolment (`--ca-sha256`); without a fingerprint, enrolment is refused (no silent TOFU). Client certificate `CN=sensor:<sensor_id>`, SAN URI `vedette:sensor:<sensor_id>`, 90 days. Revocation: core keeps `sensor_id → active|revoked`, checked on every request, `403 sensor_revoked`. [The CA is a dedicated sensor CA, not the osquery CA; lifetime 7 days; on the appliance identity is per role.]

#### Public IP scope typed by the user (`domain_ip` with `typed`)

`jobs[].domain.typed` `{method, ptr_name?, cover_domain?, cover_token?, cover_proof_at?}` turns a `domain_ip` job into a job for a public IPv4 address the user typed into exposure: `domain` and `name` are the IP itself, `token` is that IP's box-bound token (the `HMAC` of the fence key over the IP, the same function as the domain token) and the worker checks the IP's proof itself right before the tool and at every `domainfence.Recheck` while running: `method` `"file"` is the file `/.well-known/vedette-verify.txt` served on the IP itself (http or https, redirects only to the same IP and web port, body at most 512 bytes) containing the token; `"ptr"` is forward-confirmed reverse DNS: the IP's PTR is `ptr_name`, and `ptr_name` is proven by the box's domain `cover_domain` (the same rule as a domain job, with `cover_token` and `cover_proof_at`). An unknown token, or an IP not in the host's list → `token_foreign`; no proof found → `target_not_owned`; a lookup error → `ownership_unchecked`; bad grammar → `invalid_job`. The heartbeat's `typed_ip` is `true` when the worker holds the fence key (and knows this field); core only sends `typed` jobs to a worker with `typed_ip`, and older workers get no such job.
