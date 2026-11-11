# Deferred / plan: feat/logs-module (WP-24, `logs`)

Status: PLAN ONLY (step 1). No code. Read: TEAM_PLAN WP-24, MODULES, `modules/logs/{MANIFEST,CONTRACT,IMPACT}`, S-LOG-1..4, `web/src/features/logs/{contract,mocks,types,kinds}`, DATA_PIPELINE, ARCHITECTURE 5.4, sensor-protocol 12/13, D-30, D-43, D-52, D-55, D-56, D-86, D-112 (7), D-114, D-132, `.ai/deferred` lines on logs (feat-logs-export, feat-sensor-protocol, feat-response-13b, feat-notify-module), rules/security.md.

## Facts that shape the plan

- The mock `web/src/features/logs/{contract,mocks}.ts` is the contract (GUI-first): 10 operations, `/logs/*`, already in `api/openapi.json` and `core/api/routes`; the GUI is done, so no GUI redesign. Every slice ends with the mock-vs-real check the feeds and findings modules went through.
- `modules/logs/` has only MANIFEST, CONTRACT, IMPACT: no Go. Tables `logs_sources|events|retention|siem|ioc_hits`, `container: sensor`, ports udp/514 tcp/514 tcp/6514.
- Nothing on the sensor wire carries logs (D-112 (7), D-114 (3): no syslog, no `NET_BIND_SERVICE` on `sensor` until `logs` is built; sensor-protocol 12 q4 and q5 say the IOC matching place and the syslog place are decided together with `logs`). Precedent for "runs in core now, moves to the sensor later": `modules/sensor-passive/local.go` (`localLink`, SP-5).
- Consumers that wait for logs: `response` (trigger `ioc_connection`, `Evidence.IocHit` is nil in the real build, 13b-10), `notify` (`logs.anomaly.detected`, `logs.bad_address.detected`, payload fixed in CONTRACT), `core/logexport` (`device_logs`, `known_bad` categories are unregistered, D-132), `ai` (`/ai/logs/digest`, `log-digest`), `inventory`/`feeds` (read ports).
- `feeds` already exposes `Store.IOCLookup(ctx, kind, value)` and a verdict (`block|alert`); `findings` and `notify` already show the port/adapter pattern in `cmd/vedette/wiring.go`.

## Slices (one PR each; each useful on its own, in this order)

Common to every slice: module code in `modules/logs/` only; cmd additive lines in their own commit (`wiredModules` entry, handler embed in `handler.go`, jobs, `registerLogSources`); CONTRACT/IMPACT updated in a docs commit; tests red first; `heavy make check`; fuzz one target at a time; no real network; stdlib only (no new dependency, so no THIRD_PARTY_NOTICES change).

### L1: sources, events, retention (core side, no network yet)
- Stories: S-LOG-1 (declare sources, see lines, retention).
- Does: migrations `logs_sources`, `logs_events`, `logs_retention`; `Service` (sources CRUD with the mock's validation and error codes, duplicate sender IP 409, `asset_id`/`asset_name` resolved from inventory at read time through a `logs.Inventory` port, `state` receiving/silent/never from `last_received`); `Ingest(ctx, Batch)` port (idempotent by `(listener, epoch, seq)`, clips line to 2 KiB, assigns receive time as `ts`, bumps `last_received` and `lines_per_hour`); `GET /logs/events` (window <= retention, `source`, `q` <= 200, 200 newest, exact `total`); `PUT /logs/retention`; hourly purge job in batches of 10k rows (never holds the writer); `logexport` source `device_logs` (+ registration line in `registerLogSources`); handlers for 7 of the 10 operations (sources x4, events, retention, and `GET /logs/sources` box block from the host).
- INV/POST: INV-3, INV-4, INV-5 (CONTRACT), POST-3; SYS-3 audit on every mutation; module off = no routes, no job, data kept (SYS-5).
- Tests: contract tests per INV; roles + gate through real HTTP (`servertest`); retention purge in batches with a held writer; deleting a source keeps its events (INV-4); export source writes JSON lines with no secret; mock-vs-real script like `findings/conformance.test.ts`.
- Touches shared/Kiên: `cmd/vedette` additive lines (D-65 exception), `registerLogSources` line. Reads inventory through a port (adapter in cmd, like `findingsInventory`; likely `DeviceRefs`-style lookup by IP: if inventory has no by-IP read, that is an issue for Kiên, fallback `Devices` is capped at 2,000).
- Useful alone: yes (sources and search work on lines injected through `Ingest`; the GUI real-box pass can already run).

### L2: syslog listeners (in-process, the shared `listen` package)
- [x] 2026-11-11 — DONE in feat/logs-l2-syslog except TLS 6514 (needs a core seam; see `.ai/deferred/feat-logs-l2-syslog.md`). Everything else below is built; the limits chosen are in CONTRACT.md "Listener syslog".
- Stories: S-LOG-1 (point syslog at the box).
- Does: package `modules/logs/listen` (no `database/sql`, no `core/store`, like `sensor-passive/capture`, so it moves to `vedette-sensor` unchanged): UDP, TCP (RFC 6587 octet-counting and newline framing), TLS 6514 (server cert only); envelope parser RFC 3164 + RFC 5424 + CEF/LEEF header, fail-closed (a line that does not parse is kept raw, counted, never drops the batch); sender identity = remote IP, matched to a declared source; unknown senders dropped and counted (bounded LRU of 256); limits (see Quyết định cần ghi); batching (<= 500 lines or 1 MiB or 2 s) into `Ingest`. Runs as a `core/jobs` job inside core (`localLink`-style) on a configurable port (default 514 when the process may bind it, else 5514), listeners opened/closed when sources change, no listener while the module is off.
- INV/POST: INV-1, INV-2 (syslog only), FORBID-5, POST-1.
- Tests: table tests for each envelope; hostile input (NUL, huge line, bad octet count, slow-loris TCP, 10k connections); rate limit; fuzz targets `FuzzParseSyslog`, `FuzzOctetFraming`, `FuzzCEF` (20 s each, one at a time, through heavy); loopback sockets only, no external network.
- Touches Kiên: binding 514 needs `NET_BIND_SERVICE` or `net.ipv4.ip_unprivileged_port_start` on the `core` container: the Quadlet/installer is his. Until then default 5514 and a status line. No change to `core/` code.
- Useful alone: yes (real syslog from a lab firewall shows up in Logs).

### L3: signatures, baseline, digest, anomaly events
- [x] 2026-11-11 — DONE in feat/logs-l3-signatures (decisions in D-206; open lines in `.ai/deferred/feat-logs-l3-signatures.md`). Built: profiles as data (FortiGate, MikroTik, Windows) + generic miner, daily and 5-minute counters, baseline digest, `anomaly` job and `logs.anomaly.detected`, `Counts`, retention.
- Stories: S-LOG-1 (new / spike, not raw logs).
- Does: kind profiles as DATA (`modules/logs/data/profiles/*.json`: signature rule, normalised sample, optional src/dst fields): ship FortiGate, MikroTik, Windows Security (event ids), and a generic template miner (mask IPs/numbers/hex) for all other kinds, honest in the GUI catalog; per-day counters `logs_signature_daily(day, signature, source, dest) count` (no extra raw storage); baseline 7 days, "new" = not in baseline, "spike" = >= max(20, 5x `baseline_per_day`) in 24 h; per-source warm-up of 24 h with no "new" and no events (the D-78 lesson); `GET /logs/digest`; events `logs.anomaly.detected` (payload fixed in CONTRACT, grouped by source+target, max 20 per hour per source); `Counts(ctx, source, signature, window)` read port for `response` `log_threshold`.
- INV/POST: INV-6, INV-1 (profiles are untrusted-input parsers too).
- Tests: baseline math with a fake clock (`synctest`); warm-up silent; clean install gives empty digest; profile loader rejects unknown fields; fuzz `FuzzSignature` per profile; flood test: 1M identical lines make one signature row.
- Touches: `notify` already subscribes (Emily's); nothing of Kiên's. `ai` digest later reads `Digest` through a port (WP-25).

### L4: IOC matching (syslog first) and bad connections — DONE in feat/logs-l4-ioc (D-213; the SPAN half comes with L6; the open parts are in `.ai/deferred/feat-logs-l4-ioc.md`)
- Stories: S-LOG-2, S-LOG-4 (syslog half).
- Does: extract public destination IPs/domains from parsed events (firewall traffic, DNS logs), skip private/special; look up through a `logs.Feeds` port (adapter on `feeds.Store.IOCLookup`; feeds off = no hits and the digest says so, PRE-3); `logs_ioc_hits` (dedupe by (src,dest) per 24 h, cap rows); `bad_connections` in the digest with device resolved at read time; events `logs.ioc_hit` and `logs.bad_address.detected` (notify incident); `IocHits(ctx, since, minConf)` read port for `response` (`Evidence.IocHit`) and the `known_bad` export source. Feed lookups are cached per run; a feed pull does not block ingest.
- INV/POST: INV-7, POST-2, PRE-3, INV-11 (raw lines never go to AI).
- Tests: a known-bad IP in a FortiGate line makes one hit and one event; private/special never match; verdict `alert` vs `block` maps to confidence; dedupe; feeds off; hit flood bounded; response port returns what the GUI shows.
- Touches: `cmd/vedette` ports (feeds adapter), `registerLogSources` (`known_bad`); response (Kiên) reads `IocHits` later: issue text for him at the end of the slice.

### L5: SIEM forwarding
- Stories: S-LOG-3.
- Does: `logs_siem` config with the signing key sealed in `core/secrets` (`secret_last4` only); `PUT/GET /logs/siem`, `POST /logs/siem/test` (all admin); forwarder job: syslog (UDP/TCP/TLS), CEF, JSON webhook with an HMAC signature; subscribes to `findings.finding.created|status_changed`, notify incidents, `honeypot.hit`, `logs.ioc_hit`; an on-disk or in-memory bounded queue with drop-oldest and a counter; destination is the one the customer typed (SYS-7) but never loopback, link-local, unspecified or the box itself (the D-86 (2) rule, rechecked after resolution, no redirects, no proxy); disabled = nothing sent (FORBID-3).
- INV/POST: INV-8, INV-9, INV-10, POST-4, FORBID-2, FORBID-3.
- Tests: golden bytes per format; key never in any response, log or export; SSRF table; disabled sends nothing; retry/backoff with `synctest`; a slow SIEM does not slow ingest.
- Touches: `PRIVACY.md` flow 7 (ours; edit only if the table text changes) and the Settings -> Privacy UI line; `core/secrets` use only. Event names consumed from other modules are read-only.

### L6: sensor transport and SPAN metadata (Kiên-heavy; our side is thin) — post-v1, D-297, issue #363
- Stories: S-LOG-4 (SPAN half), S-LOG-1 on boxes where the listener must keep the sender IP.
- Does (ours): move `listen` into `vedette-sensor syslog`; core accepts `POST /sensor/v1/logs {epoch, seq, items[1..500]}` through the existing `Ingest`; SPAN-derived DNS/SNI/HTTP/flow observations arrive as `seen_via span_*` items and take the same IOC path as L4.
- Needs from Kiên (issue text written at the start of L6): route and limits in `core/sensorlink` and `sensor-protocol.md` (new section, `capabilities` gains `syslog`), `cmd/vedette-sensor` subcommand, `NET_BIND_SERVICE` in the sensor Quadlet (D-114 (3) dropped it), the SPAN extractor output on the wire (D-112 (7) removed it), the Quadlet port publishing. Not started before his decision; L1..L5 do not depend on it.

### L7: GUI on the real backend and QA
- Does: `make dev-api REAL=core,inventory,feeds,logs`; conformance script (mock vs real, like findings), Playwright spec for Logs (sources form matrix over the 48 kinds x allowed protocols, retention, events filters, digest, SIEM formats, roles, phone), seed helper for a box (inject syslog over loopback UDP), QA.md form-matrix rows (agent built, not independently checked), independent QA agent walk.
- Touches: `docs/QA.md` (shared, minimal), nothing in `web/src/lib` or `web/src/mocks`.

Order and size: L1 (M), L2 (L), L3 (L), L4 (M), L5 (M), L7 (M) are ours and need no Kiên decision; L6 waits for him. Each PR needs about two heavy runs for tests plus one `make check` (about 30 min of lock including the queue); L2 adds three fuzz runs, L7 adds Playwright.

## Open questions (answered the top-tier way) — Quyết định cần ghi

1. **Where the listener lives.** Decision: one `listen` package, two hosts: in-process in `core` now (like `sensor-passive/local.go`), in `vedette-sensor` from L6 (host network keeps the sender IP, which rootless port publishing can hide; MANIFEST says `sensor`). Reference: Graylog and Wazuh run inputs on 1514/5514 with 514 redirected; Splunk/Elastic Agent keep syslog in a separate collector.
2. **Syslog from an undeclared IP (CONTRACT q2, FORBID-5).** Decision: drop and count in a bounded per-IP table; no new GUI. Reference: Wazuh `allowed-ips`, rsyslog `AllowedSender`. A "who is sending?" hint on the Sources page would be a new story; propose it later, do not build it.
3. **`log_threshold` (CONTRACT q3).** Decision: `response` evaluates rules (it owns the rule engine); `logs` only offers the read port `Counts(source, signature, window)` (L3). Reference: Wazuh frequency rules live in the manager's rule engine, not in the decoder.
4. **`SiemEvent 'alerts'` after D-52 (q4).** Decision: keep the enum value `alerts` (API and approved GUI), document that it means Incidents.
5. **Limits (q5, SYS-6).** Decision (starting points to measure, ponytail): line 8 KiB on the wire (rsyslog default) stored clipped to 2 KiB; UDP datagram <= 64 KiB; TCP frame <= 64 KiB, idle 5 min, 256 connections per source and 1,000 total; 2,000 lines/s per source (burst 10,000), excess dropped and counted; batch <= 500 lines or 1 MiB (as D-112); stored lines capped at 1M per source (oldest out) on top of retention; hits table capped at 100k rows.
6. **Storage.** Decision: the same SQLite file, batch inserts (<= 500 rows per transaction every 2 s), purge in 10k-row batches; digest from daily counters, not by scanning lines. Ceiling and upgrade path: if the lab shows the writer is starved, move `logs_events` to its own file opened with `store.Open` (the code only touches `logs_*`). `q` uses `instr(lower(line), ?)` inside the window; `total` is exact up to the cap and the GUI contract is kept; measure with 5M rows before L1 merges.
7. **Timestamps.** Decision: `ts` = receive time (RFC 3164 has no year or zone and device clocks drift); the device time stays inside the line. Reference: Graylog `timestamp` vs `gl2_receive_timestamp`.
8. **Parsers per kind (INV-1 says "per SourceKind").** Decision: one envelope parser for all 48 kinds, plus small data profiles for the kinds that have a story-level need (FortiGate, MikroTik, Windows first); every other kind uses the generic template miner and says so in its catalog entry. More profiles are data-only additions, each with a fuzz seed. Reference: Wazuh decoders, Drain template mining.
9. **First-pull silence.** Decision: 24 h per-source warm-up with no "new" items and no `logs.anomaly.detected` (D-78 applied to logs).
10. **TLS 6514.** Decision: server certificate only (the box's TLS cert), no client certificates (FortiGate, MikroTik and Windows forwarders rarely do mutual TLS; sender IP is the identity, as for UDP).
11. **Core purge.** To check in L1: `POST /core/data/purge` must clear `logs_*` (IMPACT says so); verify how core purges by prefix and add a test, no decision needed.
12. **Special cases for Kiên (really special):** none to ask now. L6 needs his schedule (sensor route, Quadlet capability, SPAN extractor output); the issue text is written when L6 starts.

## Deferred lines (one per open item, per rules/deferred-work.md)

- [ ] 2026-11-10 — measure the writer load and `q` search cost with 5M rows before L1 merges; decide whether `logs_events` needs its own SQLite file — ở đâu: L1, `modules/logs/store.go`.
- [ ] 2026-11-10 — a "who is sending?" hint for dropped unknown senders needs a story (S-LOG-1 criterion) — ở đâu: Quyết định 2.
- [x] 2026-11-12 — L6 sensor transport and SPAN metadata: deferred past v1 (D-297); the owner:kien issue is [#363](https://github.com/KNT048/vedette/issues/363) "L6 (post-v1)" — ở đâu: sensor-protocol 12 q4/q5, D-112 (7), D-114 (3).
- [x] 2026-11-10 — `response` reads `IocHits` and `Counts` (13b-10 `Evidence.IocHit`, `log_threshold`): issue text at the end of L3 and L4 — Kiên. — Done: L3 part earlier (Counts wired in #341); L4 part: issue [#376](https://github.com/KNT048/vedette/issues/376) (wire `Evidence.IocHit`, subscribe to `logs.ioc_hit.detected`), owner:kien.
- [x] 2026-11-10 — check by-IP device lookup in inventory for `asset_id`: Done in L1: there is none; `cmd/vedette/logs.go` `logsInventory` lists every device with `DevicesOfKind(inventory.Kinds)` (uncapped) and picks the addresses. Issue text for Kiên below.

## L1 outcome (WP-24, branch feat/logs-module)

Quyết định cần ghi (L1):
- **Storage: logs.db, a second SQLite file with its own writer, from L1** (the lead's decision after #159/#160). `core/store.Open(path)` and `store.Migrate(db, module, fs)` are per database, so no change in `core/store` was needed. Config (`logs_sources`, `logs_retention`; `logs_siem` in L5) stays in the main database so it is audited in the same transaction (SYS-3) and backed up; the volume (`logs_events`, `logs_source_buckets`, `logs_source_seen`; `logs_ioc_hits` and `logs_signature_daily` later) is in `logs.db`. Reference: Graylog/Wazuh/Elastic keep the log store apart from the configuration store.
- Ingest writes one transaction per batch (<= 500 lines) on logs.db only; `TestIngestNeverWaitsForTheCoreWriter` holds the core writer and ingests anyway. No latency budget test was needed because the writers are separate.
- `ts` is the receive time; the newest-first search walks the ts index backwards (ids are not a time order when more than one listener feeds the table).
- Limits (starting points to measure): line stored <= 2,048 bytes, 500 lines per batch, 20M stored lines at most, count of a search capped at 100,000.
- The digest in L1 has only `lines_24h`; `new`, `spikes`, `bad_connections` are empty until L3/L4 (the GUI says nothing is new even when something is: acceptable while the module is off by default and L3 follows). Closed: L3 made `new` and `spikes` real, L4 made `bad_connections` real.
- The SIEM operations answer 501 from `server.Fallback` until L5.

Issue texts for Kiên (open when the PR is opened; label owner:kien):
1. **core purge and backup: `logs.db`**: answered by #187 / D-151 (not in the backup; purge from a list of module data file names; logs registers nothing). Our part: the volume migrations must be add-only, guarded by `TestVolumeMigrationsAreAddOnly`.
2. **inventory: a read by IP** (optional): `DeviceRefsByIP(ctx, ips []string) (map[string]DeviceRef, error)`. `cmd/vedette/logs.go` lists every device with `DevicesOfKind(inventory.Kinds)` and filters; it works to a few thousand devices and misses a device whose kind is outside `inventory.Kinds`.
3. **core/store** (only if the lab shows trouble): `Open` is enough today; if more modules want a second file, a shared helper that opens `<core_data>/<name>.db` and migrates it would replace the 10 lines in `cmd/vedette/main.go` and in the two test helpers.

## Review of #186: deferred, all to be done before L2 opens a listener

- [x] 2026-11-11 — **M2** the 20M-line cap must become a byte or disk-space bound, and `Ingest` must trigger a purge when over (today only the hourly job enforces it; at 2,000 lines/s a source adds 7M an hour) — ở đâu: `modules/logs/purge.go`, `ingest.go`. — Done in fix/logs-production-safety
- [x] 2026-11-11 — **L1** `device_logs` can make the whole `GET /core/logs/export` answer 413 (core's 128 MiB total cap, D-132): give it its own cap or leave it out of the default export — ở đâu: `modules/logs/export.go`, `core/logexport` (Kiên's) — ask when L2 starts. — Done in fix/logs-production-safety
- [x] 2026-11-11 — **L2** clamp `Line.At` to [now - retention, now] (today only the future is clamped, so a listener bug can write lines that the next purge deletes at once), and cut a line to 4x `MaxLineBytes` before sanitizing (the sanitizer walks the whole string) — ở đâu: `modules/logs/ingest.go`. — Done in fix/logs-production-safety (clamped to the oldest time at first: review of fe9b026 found the boundary line is purged, so it is now clamped to now)
- [x] 2026-11-11 — **L4** source attribution over UDP/TCP is best-effort (the sender IP can be spoofed on UDP, and any host on the LAN can claim an IP); plan TLS client-certificate pinning per source for the L2 TLS listener (6514) — ở đâu: `modules/logs/CONTRACT.md` FORBID-5. — Done in fix/logs-production-safety
- [x] Done in fix/logs-purge-lifecycle (`Housekeeping: true`, D-160, #225) — 2026-11-11 — **L5** the purge job does not run while the module is off (SYS-5), so a box with logs switched off keeps its lines past the retention: run the purge anyway or say so on the page — ở đâu: `modules/logs/purge.go` `Jobs`, `web/src/features/logs` (GUI text needs a story). — Not done: needs a way in core/jobs to run a job while the module is off (none today); see .ai/deferred/fix-logs-production-safety.md

## Handoff (2026-11-11): where #186 stands and how to continue

- **L1 is #186** (fix round pushed on top of the first push; the independent review said OK to merge, no High). **L2 to L7 are NOT started**: the plan for each is above ("Slices"), with stories, INV/POST, tests and the Kien-owned parts. Next slice is **L2** (syslog listeners, the `listen` package, in-process in core); do the deferred review lines of the section above (M2, L1, L2, L4, L5) before it opens a listener.
- Decisions taken in L1 are in the "L1 outcome" section above and in the PR body (second SQLite file logs.db; purge started row plus end row; searches 2 at once and 5 s with 503 server_busy; ASCII-only keyword folding; every Cc/Cf/Zl/Zp character except tab becomes a space; AUTOINCREMENT ids).
- D-151 (#187): logs.db is not in the backup; its migrations must be **add-only** (TestVolumeMigrationsAreAddOnly); an incompatible change means a new file logs-v2.db and a new decision.
- Real-box check of the API: `web/src/features/logs/conformance.test.ts` with VITE_LOGS_REAL_URL and VITE_LOGS_QA_PASSWORD (box prepared with `web/e2e/qa/real-box.mjs`, BOX_MODULES=inventory,feeds,logs BOX_SKIP_DATA=1). Last result: one difference in 30 steps (a name with spaces: D-73 400 invalid).

## Mutation evidence for L1 (re-run: `heavy bash .ai/deferred/feat-logs-module.mutate.sh` after pointing D= at a log folder; ONLY=regex runs some; the working tree must be clean)

One behaviour broken at a time in the committed source, the package tests run, the file is restored. **40 source mutations: 39 killed, 1 equivalent survivor** (events-window-clamp: retention >= 7 days and window <= 7 days, so the clamp cannot change an answer). Plus 4 temporary non-add-only migrations (red) and 1 add-only (accepted).

```
baseline: green
sanitize-no-Cc KILLED by 4 test(s) [FuzzSanitizeLine TestIngestMakesDeviceTextSafe TestIngestStripsBidiAndLineSeparators TestIngestStripsInvisibleCharacters ]: controls (C0, DEL 0x7f, C1 incl. NEL) no longer stripped
sanitize-no-Cf KILLED by 3 test(s) [FuzzSanitizeLine TestIngestStripsBidiAndLineSeparators TestIngestStripsInvisibleCharacters ]: format characters (bidi, zero-width, BOM, soft hyphen) no longer stripped
sanitize-no-Zl-Zp KILLED by 2 test(s) [FuzzSanitizeLine TestIngestStripsBidiAndLineSeparators ]: U+2028 and U+2029 line separators no longer stripped
sanitize-tab-too KILLED by 1 test(s) [TestIngestMakesDeviceTextSafe ]: tab no longer allowed (control check without the tab exception)
sanitize-length KILLED by 2 test(s) [FuzzSanitizeLine TestIngestMakesDeviceTextSafe ]: length cap raised from 2048 to 8192 bytes
sanitize-utf8 KILLED by 2 test(s) [FuzzSanitizeLine TestIngestMakesDeviceTextSafe ]: invalid UTF-8 is kept
events-like-wildcards KILLED by 1 test(s) [TestEventsInputsAreDataNotSQL ]: keyword matched with LIKE: % and _ become wildcards
events-source-concat KILLED by 1 test(s) [TestEventsInputsAreDataNotSQL ]: the source filter is concatenated into the SQL, not bound
events-case-ascii-vs-unicode KILLED by 1 test(s) [TestEventsKeywordIsCaseInsensitiveForASCIIOnly ]: keyword folded with Go's Unicode lowercasing (M5: SQLite folds ASCII only)
events-case-none KILLED by 4 test(s) [TestContract_INV5_EventsWindowKeywordSourceAndPage TestEventsInputsAreDataNotSQL TestEventsKeywordIsCaseInsensitiveForASCIIOnly TestEventsRetentionAndDigestOverHTTP ]: keyword search no longer
events-or-parentheses KILLED by 1 test(s) [TestEventsNameMatchRespectsTheWindowAndTheSourceFilter ]: no parentheses around the keyword OR: a source-name match ignores the window and the source filter
events-source-filter KILLED by 3 test(s) [TestContract_INV5_EventsWindowKeywordSourceAndPage TestEventsInputsAreDataNotSQL TestEventsNameMatchRespectsTheWindowAndTheSourceFilter ]: source filter ignored
events-window KILLED by 1 test(s) [TestContract_INV5_EventsWindowKeywordSourceAndPage ]: time window four times too wide
events-window-clamp SURVIVED (no test red): window clamp to the retention changed (equivalent: retention >= 7 d and window <= 7 d)
events-no-concurrency-cap KILLED by 1 test(s) [TestEventsSearchIsBoundedInTimeAndInNumber ]: any number of searches at once
ingest-batch-limit KILLED by 1 test(s) [TestIngestDropsUnknownSourcesAndBoundsABatch ]: batch limit raised tenfold
ingest-future-clamp KILLED by 1 test(s) [TestIngestDropsUnknownSourcesAndBoundsABatch ]: a timestamp in the future is kept
ingest-writes-core-db KILLED by 21 test(s) [TestContract_INV3_SourceStateAndDeviceName TestContract_INV4_DeletingASourceKeepsItsLines TestContract_INV4_PurgeBoundaryIsStrict TestContract_INV4_RetentionChoicesAndPurge TestContract_
ids-reused KILLED by 1 test(s) [TestEventIDsAreNeverReused ]: the line id is not AUTOINCREMENT: ids are reused after a purge
purge-boundary KILLED by 1 test(s) [TestContract_INV4_PurgeBoundaryIsStrict ]: a line exactly at the retention boundary is purged
purge-retention-days KILLED by 1 test(s) [TestContract_INV4_PurgeBoundaryIsStrict ]: retention counted as 23 hours a day
purge-cap-off KILLED by 2 test(s) [TestPurgeChunksCapAndContext TestPurgeKeepsLiveMarksAndAuditsTheCapAlone ]: the cap on stored lines is not enforced
purge-cap-off-by-one KILLED by 2 test(s) [TestPurgeChunksCapAndContext TestPurgeKeepsLiveMarksAndAuditsTheCapAlone ]: the cap keeps one line too many
purge-chunk-size KILLED by 2 test(s) [TestPurgeAuditsEveryWayOut TestPurgeRunsInChunksAndStopsWhenCancelled ]: one transaction deletes everything instead of 10,000 rows
purge-stops-after-first-chunk KILLED by 2 test(s) [TestPurgeAuditsEveryWayOut TestPurgeRunsInChunksAndStopsWhenCancelled ]: deleteChunks returns after the first chunk
purge-ctx-ignored KILLED by 2 test(s) [TestPurgeAuditsEveryWayOut TestPurgeRunsInChunksAndStopsWhenCancelled ]: purge ignores a cancelled context
purge-ctx-check-removed KILLED by 2 test(s) [TestPurgeAuditsEveryWayOut TestPurgeRunsInChunksAndStopsWhenCancelled ]: the ctx.Err check of deleteChunks removed (Write still honours ctx, but the context error is then wrapped)
purge-dropstale-all KILLED by 1 test(s) [TestPurgeKeepsLiveMarksAndAuditsTheCapAlone ]: dropStale deletes every last-received mark, also those of sources that exist
purge-audit-only-expired KILLED by 1 test(s) [TestPurgeKeepsLiveMarksAndAuditsTheCapAlone ]: no end audit row when only the cap removed lines
purge-audit-started-always KILLED by 1 test(s) [TestContract_INV4_RetentionChoicesAndPurge ]: a purge with nothing to delete still writes audit rows
purge-audit-never KILLED by 3 test(s) [TestContract_INV4_RetentionChoicesAndPurge TestPurgeAuditsEveryWayOut TestPurgeKeepsLiveMarksAndAuditsTheCapAlone ]: a purge that deletes lines writes no audit row
purge-audit-needs-live-ctx KILLED by 2 test(s) [TestPurgeAuditsEveryWayOut TestPurgeRunsInChunksAndStopsWhenCancelled ]: the end audit row uses the purge's own context: lost when the purge is cancelled
guard-two-databases KILLED by 1 test(s) [TestNewServiceRefusesTheMainDatabaseAsTheVolume ]: NewService accepts the main database as the volume
export-inclusive KILLED by 1 test(s) [TestExportDeviceLogsWritesJSONLinesInRange ]: export range excludes both ends
export-open-end KILLED by 1 test(s) [TestExportDeviceLogsWritesJSONLinesInRange ]: an open upper end of the export range stops in 2000
export-order KILLED by 1 test(s) [TestExportDeviceLogsWritesJSONLinesInRange ]: export newest first instead of oldest first
d151-drop-table KILLED by 27 test(s) [TestContract_INV3_EditAndDeleteSourceAreAudited TestContract_INV3_SourceStateAndDeviceName TestContract_INV3_SourceValidationFollowsTheMock TestContract_INV4_DeletingASourceKeepsItsLines TestC
d151-rename-column KILLED by 24 test(s) [TestContract_INV3_SourceStateAndDeviceName TestContract_INV4_DeletingASourceKeepsItsLines TestContract_INV4_PurgeBoundaryIsStrict TestContract_INV4_RetentionChoicesAndPurge TestContract_INV
d151-drop-column KILLED by 24 test(s) [TestContract_INV3_SourceStateAndDeviceName TestContract_INV4_DeletingASourceKeepsItsLines TestContract_INV4_PurgeBoundaryIsStrict TestContract_INV4_RetentionChoicesAndPurge TestContract_INV5_
d151-delete-rows KILLED by 1 test(s) [TestVolumeMigrationsAreAddOnly ]: D-151 guard works
d151-add-column PASSES as it should (add-only migration accepted)
--- done
--- redone after a first attempt that did not build, or that hung (the first script counted only '--- FAIL'):
sanitize-boundary KILLED by 1 test(s) [FuzzSanitizeLine ]: a long line is cut in the middle of a character
events-no-timeout KILLED by 1 test(s) []: a search has no 5 s deadline
events-busy-not-mapped KILLED by 1 test(s) [TestEventsSearchIsBoundedInTimeAndInNumber ]: a search that hits its deadline answers a raw error, not 503 server_busy
ingest-unknown-sender KILLED by 2 test(s) [TestContract_INV4_DeletingASourceKeepsItsLines TestIngestDropsUnknownSourcesAndBoundsABatch ]: lines of an undeclared source are stored
```

## Rà lần 2 của #186 (2026-11-11, sau merge 38d81ec) — không chặn merge
- [x] 2026-11-11 — `TestVolumeMigrationsAreAddOnly` lách được: bỏ comment trước khi bỏ chuỗi, nên `'--'` trong chuỗi xoá phần còn lại của dòng, cặp chuỗi `'/*'` … `'*/'` giấu được một DROP; còn sót `REPLACE INTO`/`INSERT OR REPLACE`, `CREATE TRIGGER`, `CREATE UNIQUE INDEX`. Sửa: bỏ chuỗi và comment trong một lượt trái→phải, thêm các mẫu đó và 2 ca lách làm test — vì sao để sau: wind-down, không chặn — ở đâu: modules/logs/migrations_test.go:35-36 — Done in fix/logs-production-safety
- [x] 2026-11-11 — Purge bị huỷ trước chunk đầu để lại dòng `logs.purge_started` không có dòng kết thúc (trông như crash): luôn ghi dòng kết thúc khi đã ghi dòng bắt đầu, kể cả số đếm 0. Khi không có gì hết hạn và không vượt trần thì vẫn chạy lệnh xoá mà không có audit: bỏ qua lệnh xoá — vì sao để sau: không chặn — ở đâu: modules/logs/purge.go:59, :73 — Done in fix/logs-production-safety
- [x] 2026-11-11 — Tìm kiếm hết giờ giữa chừng có thể trả 500 thay vì 503 (modernc báo "interrupted" chứ không phải deadline); test ở service_test.go:700 dùng deadline đã qua nên không ngắt giữa lần quét — vì sao để sau: giới hạn 5 s / 2 lượt vẫn giữ — ở đâu: modules/logs/events.go:61 — Done in fix/logs-production-safety
