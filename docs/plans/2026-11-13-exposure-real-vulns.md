# External exposure: real vulnerabilities on verified public targets (kien beta item 24)

Owner: AI-Mlee (exposure, findings, feeds). Touch points owned by AI-Trưởng (image, host, sensor, core) are marked **[T]**; agree them with him first.
Status: plan only, nothing built yet. Decision numbers come from Mlee's range D-480…D-499 (the next free one is D-493).

**Done (kien):** on the N100 (8 GB, Ubuntu 26.04, Podman), a verified public target shows its identified services, matched CVEs and "what was checked", within the legal limits.

**The constraint that sets the order:** both argv validators, `nmapargv` and `nucleiargv`, are the worker's last fence (D-113 (3)), and both accept only private IPv4 by design. Nothing on a public address can run in the scan container until that fence gets a safe public exception. So that fence is the first decision, and the image work comes after it.

## 1. Today

### 1.1 The surface scan (D-229, exposure INV-12, scan INV-12)
- **Request path:** `POST /exposure/targets/{id}/scan` calls `exposure.Service.Scan` (`modules/exposure/scan.go`), which runs these steps in order:
  1. The gate checks: verified, committed, TXT re-check for domains, and INV-13 "box still goes out through this IP" (2-of-3).
  2. One scan at a time (409), and one per target every 10 minutes (429).
  3. `Runner.Scan`, then `sanitize`.
  4. One snapshot a day (`exp_snapshot`), then `exposure.snapshot.created`.

  Every attempt writes an `exposure.scan` audit row.
- **The runner** is `cmd/vedette/scan.go` `exposureRunner` over `modules/scan/surface`. It is Go stdlib, runs in core, and uses no container.
  - **IP target:** a TCP connect to the fixed 98 `commonPorts`, 300 new connections a second. Each open web port gets one `GET /`, and each TLS port gets a TLS handshake.
  - **Domain target:** names come from crt.sh, and each name gets an HTTP check by name on 80 and 443 only (D-57 (7)). An address is port-scanned only if `ScannableIP` says it is itself a verified, committed, current IP target.
  - **Probe log:** every probe is written to `scan_probe` before and after it is sent, and kept 90 days. The whole scan is capped at 5 minutes. The HTTP request waits for the snapshot.
- **Missing today:** service versions (beyond the web `Server` header), CVE matching, and a "what was checked" list. These are the W1-23 deferred lines.

### 1.2 How a job reaches the scan container
- **The container:** `vedette-scan` runs `vedette-sensor active` with `Network=host`, `NET_RAW` only, read-only, `--memory=1g`. It long-polls core's sensor link (mTLS on :8444).
- **The dispatcher:** `sensoractive.Dispatcher` has two slots, nmap and nuclei (D-125 (3)). No argv goes over the wire (D-111 (3)). The worker rebuilds the argv and checks it again: `worker.go argvOf`, `worker/nuclei.go nucleiArgv`.
- **The nmap fence:** `nmapargv` has 4 fixed shapes. `validTarget` is `localnet.Addr`: RFC 1918 plus 100.64/10, at most 64 targets.
- **The nuclei fence:** `nucleiargv`'s `validHost` accepts private IPv4 only (D-126 (4)). Its flags are fixed: `-duc -ni -dr -nh -pt http,tcp,ssl -etags dos,intrusive,fuzz -c 1 -bs 1`.
- **The images:** `scan-base` is Debian slim plus `vedette-sensor`, nuclei 3.11.1 (D-319) and the KEV pack (988 templates). `scan/Containerfile.onbox` adds trixie `nmap` on the box (D-4, D-146 (2)).

### 1.3 Reuse the scan container, with a fence that keeps its property
nmap and nuclei stay out of core (D-113, D-125), so exposure reuses the scan container. The worker grammar must not simply accept public addresses: a compromised core could then port-scan anyone from the customer's IP.

**Worker-side own-IP check:** a public target is accepted only if the worker itself sees that the box goes out through that IP. It uses the same 2-of-3 rule as exposure INV-2, with the result cached for at most 5 minutes. D-25 already says a public IP target is only ever the box's own egress IP, so a compromised core gains nothing beyond what exposure already allows.

This needs `PublicServiceProber`/`parseAnswer` and `IsPublicIPv4` to move into a leaf package the sensor binary may link (for example `core/egressip`). **[T]**

| File | Change |
|---|---|
| `modules/sensor-active/nmapargv/argv.go` **[T]** | A 5th shape, `external`: `--privileged -sS -sV -Pn -n --max-rate 100 --max-retries 2 -p <the 98 commonPorts, fixed> --host-timeout 10m -oX - <1 public IPv4>`, with no `-O` and no `--script`. A public target is valid only in this shape, and only one. A test keeps the ports equal to `surface.commonPorts`. |
| `modules/sensor-active/migrations/sqlite/0003_*.sql` **[T]** | `sa_probe.shape` CHECK adds `external`. |
| `modules/sensor-active/service.go` **[T]** | `ScanExternal(ctx, actor, ip)`: takes `runMu` within `busyWait`, writes the `sa_probe` row first, parses the XML into services and software. It never writes inventory. |
| `modules/sensor-active/worker` **[T]** | Shape `external`: the own-IP check runs before nmap. Otherwise the job is refused with `not_own_ip`. |
| `core/sensorlink/wire.go`, `docs/specs/sensor-protocol.md` **[T]** | Slice b adds nuclei `Scope "lan"\|"own_ip"`. An old worker refuses the job, so it fails closed. The protocol version is bumped. |
| `modules/scan/nucleiargv/argv.go` **[T]** | `validHost` scope `own_ip`: one public IPv4, re-checked by the worker. |
| `cmd/vedette/scan.go` `exposureRunner` **[T/scan]** | New phases after the surface scan. |
| `modules/inventory/catalog.go` **[T]** | Export `KevKeysForCPE(ctx, cpe)` (today it is the unexported `keysForCPE`, D-501). |
| `deploy/containers/*` | Slice a: none (nmap is already on the box). Slices b2, c and d: see below. |

## 2. Matching
- **The matcher:** `findings.MatchAsset(Asset, []Vuln, have, now)` is a pure function. nmap `-sV` gives a CPE per service, and the inventory catalog maps a CPE to KEV keys. Together they let an external port be matched without an inventory device: `Asset{ID: "ext:<target_id>", Name: "<ip>"}`, with the vulns from the cached `findingsFeeds.Vulns`.
- **Limit, stated on the page:** NVD ranges are held only for CISA KEV CVEs (D-500 (1)). So "matched CVEs" means *exploited* CVEs, and non-exploited CVEs are not checked; that needs a new feed, which is kien's call.
- **Data model:** option C, exposure computes and shows the matches.
  - The snapshot stores `services` (what nmap saw).
  - Vulns are computed on read against the current KEV list, so a new KEV entry shows without a rescan. They are also stored as of the scan, for history and diff.
  - **Rejected:** a virtual inventory asset breaks inventory's scope invariants. Findings rows on `ext:` assets come later, as S-EXP-2b (notify on a new exploited CVE on a public port). Attaching the CVEs to the gateway device is wrong, because a forwarded port belongs to a LAN server.
- **New story S-EXP-2** `[chưa]`: for the box's verified public IP, Vedette identifies the service and version on each open port (nmap `-sV`), compares them with exploited CVEs (CISA KEV plus NVD ranges), confirms with safe nuclei templates where it can, and scans the web pages passively (ZAP baseline). Every scan says what was checked, what was not, and why.

  Acceptance:
  1. Each open port shows service, product, version and source, or "no version sent".
  2. Exploited CVEs are listed per port with their basis (version in range, product only, or confirmed by template), the NVD range, the KEV date and ransomware use. A version that can't be read shows "N exploited CVEs of X could not be checked".
  3. "What was checked" lists every probe kind with counts and times. "Not checked" lists UDP, ports outside the list, non-exploited CVEs, and skipped phases with the reason.
  4. Nothing is sent to an address the gate did not pass, and every probe is in the probe log.

## 3. Legal limits
- **Authorization:** D-5 and D-26 as amended by D-473 (an admin with two-step sign-in records the confirmation on the first Scan now). Ownership is verified: DNS TXT is re-read before every scan, and an IP must be the box's own egress, current at scan time.
  - **Decided: D-559** (kien 2026-11-14): the sentence names service identification, safe checks for known exploited vulnerabilities and a passive web scan; existing commitments are asked for again once.
- **D-57 (7):** names under a verified domain get HTTP checks by name only. nmap and nuclei network templates go only to `ScannableIP` addresses.
  - **Decided: D-559** (K-5): by-name checks may run nuclei safe http templates and ZAP passive (spider + passive rules, no form posting, no AJAX spider).
- **LEGAL §3:** active scans only on verified assets. Every probe is logged with target, time and template, at least 90 days, before it is sent. No exploit templates.
- **Templates (D-125 safe set):** the pack is `kev,vkev` minus {dos, intrusive, fuzz, oast}, with only http/tcp/ssl protocols and `-ni -duc -dr -nh`.
  - The non-KEV pack (b2) also excludes `default-login`, `brute-force`, `sqli`, `xss`, `injection`, `file-upload` and anything that sends a credential. It allows `ssl`, `tech`, and `exposure`/`misconfig` at severity medium or above. **Decided: D-559** (K-6).
- **ZAP baseline:** passive only: the spider plus passive rules, never the active scan. Form posting is off (`spider.processform=false`, `spider.postform=false`), and there is no AJAX spider.
- **Rate limits:**
  - nmap: `--max-rate 100`, `--max-retries 2`.
  - nuclei: 5 rps, `-c 1 -bs 1`.
  - ZAP: `-m 1 -T 5`.
  - Overall: one scan at a time, and one per target every 10 minutes.

## 4. Tools, licences, RAM, disk

| Tool | Licence | How it ships | RAM (estimate; measure on the N100) | Disk |
|---|---|---|---|---|
| nmap `-sV` | NPSL 0.95 | already installed from trixie into the on-box image (D-4); not distributed by Vedette | 30–80 MB per host, inside scan's 1 GiB | 0 |
| nuclei 3.11.1 + templates | MIT / MIT | already in the signed scan-base; b2 adds a second pack directory | 150–300 MB with ≤ 300 templates | +5–20 MB |
| ZAP (`ghcr.io/zaproxy/zaproxy:stable`) | Apache-2.0 (image: OpenJDK GPL-2+CE, Debian) | separate one-shot container, unmodified, pulled by digest, never linked | 0.6–1 GB while it runs, capped `--memory=1g` | ~1.5–2 GB image |
| Greenbone CE | gvmd/gsa AGPL-3.0, openvas GPL-2.0, feed with its own terms | separate unmodified containers (THIRD_PARTY_NOTICES already lists it, scan-credentialed INV-6) | upstream minimum 4 GB, recommended 8 GB; measured on the N100 next to Vedette: peak ~4 GB used + ~2 GB swap during the feed import, ~2 GB while scanning (D-494) | measured ≈ 50 GB (images 9 GB + feeds 41 GB) |

**N100 budget:** the limits are core 2 GiB + sensor 512 MiB + honeypot 256 MiB + scan 1 GiB, about 3.75 GiB, plus the OS. nmap and nuclei fit in scan's 1 GiB; measure the peak with both slots busy. ZAP adds about 1 GB only while it runs. Greenbone ran on the 7 GB N100 alongside the rest (2026-11-13 trial, D-494), but swapped during its ~2 h first feed import.

**How to measure:**
- `cat /sys/fs/cgroup/system.slice/vedette-scan.service/memory.peak` after a restart and one test scan.
- `podman stats --no-stream` every second during ZAP.
- `podman image inspect --format '{{.Size}}'`.
- Record the numbers in `docs/project-map/`.

## 5. Slices (one PR each, each with an N100 acceptance)

### Slice 0: the scan runs asynchronously (prerequisite; Mlee)
Today the request waits up to 5 minutes, and nmap, nuclei and ZAP add minutes more.
- **API, gui-first** (contract.ts and mocks first):
  - `POST …/scan` passes the same gate, then returns 202 with `ScanRun {id, target_id, phase, started_at, by}`.
  - `GET /exposure/scan` returns the current run, or the last one with `status` and `error`.
  - `POST /exposure/scan/stop` (operator).
- **Files:** `modules/exposure/{scan,handlers,types,errors}.go`, CONTRACT INV-12, a progress row in the web page that polls every 2 s, `api/route-modules.json`, `core/server/modules_test.go`. The response `new_port` bridge is unchanged.
- **Flows and dependencies:** none new.
- **N100:** Scan now returns at once, the phase moves on, and the snapshot appears.

### Slice a: nmap `-sV` on verified IPs + exploited-CVE match + "what was checked" (Mlee; [T] for sensor-active, the core leaf and the inventory export)
- **[T] parts:** §1.3. `exposureRunner` calls `ScanExternal` after `surface.IP`, with a `scan_probe` row before each probe. If sensor-active is off, missing, or busy after 2 minutes, the phase is skipped with a "Not checked" line.
- **Mlee parts:**
  - `Content.Services`, `Checks`, `NotChecked`.
  - Migration `0003_services.sql` (new JSON columns, default `'[]'`).
  - `sanitize` limits.
  - A `Matcher` seam wired to `findings.MatchAsset` + `findingsFeeds` + `KevKeysForCPE`.
  - Vulns computed on read, `Diff` kinds `service` and `vuln`.
  - Page sections "Exploited vulnerabilities" and "What was checked".
  - CONTRACT INV-16 and INV-17, story S-EXP-2.
- **Privacy:** PRIVACY flow 9 and Settings → Privacy, in the same commit, gain "SYN and service-version probes (nmap -sV) to the 98 ports of this box's own verified IPs" and "the scan container checks the box's own public IP with the same three services right before it".
- **THIRD_PARTY_NOTICES:** the nmap row's "how used" line changes.
- **Decision:** the external nmap shape plus the worker own-IP fence (amends D-113 (3)), and "matched CVEs = KEV only". **Opus review is mandatory** (nmapargv is the security fence).
- **Tests, with no network:**
  - nmap XML fixtures: Apache 2.4.49 gives CVE-2021-41773/-42013 by version; nginx without a version gives the NeedVersion line; tcpwrapped.
  - nmapargv table tests.
  - The worker own-IP check against httptest servers.
  - Match tests on `modules/findings/testdata/kev-nvd-golden.json`.
  - A fake Dispatcher.
- **N100:** forward a router port (for example 18443) to `httpd:2.4.49` on the LAN for at most 30 minutes, then Scan now on the box's public IP.
  - The port shows "Apache httpd 2.4.49 (nmap -sV)" and CVE-2021-41773 "version in range".
  - "What was checked" and "Not checked" are listed.
  - The probe log has the rows, and `memory.peak` is recorded.
  - Remove the forward afterwards.

### Slice b: KEV templates per detected service (confirms a); b2: a non-KEV safe pack
- **b (no image change):** per port, the KEV pack's templates for the CVEs matched in a, plus templates tagged with the product, at most 32 a job, scope `own_ip`, 5 rps.
  - A match turns the basis into "confirmed". No match reads "No match reported", never "not vulnerable".
  - **[T]:** nucleiargv scope, the sensorlink `Scope` field and spec, the worker re-check.
  - **Privacy:** PRIVACY flow 9.
  - **Decision:** amends D-126 (4) and D-125 (1).
- **b2 [T image]:** an "exposure-safe" pack built with `scripts/scanpack` from the §3 allow-list.
  - Changes: `pins.env` `EXPOSURE_PACK_VERSION`, scan-base copies a second directory, the worker reads two indexes, the THIRD_PARTY_NOTICES pack row.
  - **kien decides** the template classes.
  - At most 300 templates; measure nuclei RSS.
- **N100:** on the same httpd 2.4.49 forward, CVE-2021-41773 becomes "confirmed by template", and the probe log lists each template id.

### Slice c: ZAP baseline one-shot container for web ports ([T] host + image pin)
- **Host op:** a new vedette-host operation `zap.baseline` with fixed argv: `podman run --rm --pull=never --network vedette-zap --add-host <name>:<ip> --cap-drop ALL --read-only --tmpfs /zap/wrk --memory=1g --pids-limit=256 <digest> zap-baseline.py -t <url> -m 1 -T 5 -J out.json -z "-silent -config spider.processform=false -config spider.postform=false"`.
  - **Network:** nft egress on `vedette-zap` allows only `<ip>:<port>`, with no DNS.
  - **Host checks:** the host re-checks own-IP or the TXT token itself.
  - **Results:** the report is read back, at most 4 MiB.
  - **Uninstall:** `--uninstall` removes the image and the network.
- **Pin:** `ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:<2.x>@sha256:…` in `pins.env`. Upstream is not signed with our key, so integrity is by digest; agree this with Trưởng against D-57 (3).
- **Mlee parts:** a fail-closed parser of the ZAP JSON (alert, risk, confidence, CWE, 3 sample URLs) with a fuzz test, and the page section "Web findings (passive)".
- **Privacy:** PRIVACY flow 6 (the image from `ghcr.io/zaproxy`) and flow 9. Check with `tcpdump` that nothing goes to zaproxy.org.
- **THIRD_PARTY_NOTICES:** a ZAP row.
- **Decision:** one D for the ZAP host op and image pin.
- **Risks:** fitting the JVM heap inside 1 GiB (measure in the lab), and spider load on a fragile site.
- **N100:** passive alerts listed for the forwarded test site; `memory.peak` at most 1 GiB.

### Slice d: Greenbone, optional, off by default ([T] host; Mlee scan-credentialed)
- An unauthenticated scan of the box's own public IP with `safe_checks=yes`, and without the brute-force, default-account and DoS families.
- Preflight refuses to enable below 8 GiB RAM or 60 GB free disk (Greenbone's recommended sizing, confirmed by the trial: D-494), and shows the reason.
- Runs as Greenbone's own unmodified compose project next to Vedette (separate processes, GPL/AGPL not embedded); Vedette talks GMP over the gvmd socket. The ~2 h first feed import is a visible phase ("Greenbone is loading its feed"), not a hang.
- Results come in as findings marked "scanner: Greenbone" with their QoD (≥ 70 only); they never close or hide Vedette's version-based findings ("Greenbone found nothing" is not "not affected": on Ubuntu .181 it reported 0 CVEs where Vedette had 4 real exploited ones, because distributions backport fixes).
- Uninstall never touches the Greenbone project or its volumes (true since #686/#689; keep a test).
- **Privacy:** a new PRIVACY row for the feed sync.
- **N100:** enabling is refused with the RAM reason (7 GB). The 2026-11-13 trial on the N100 itself is the RAM and disk record.
- **Value, measured:** on a Linux host with an agent it adds hardening notes, not CVEs; it is for hosts without an agent (appliances, Windows without osquery, web apps). Next trial: Windows .49 and a web app.
- **Not part of item 24's Done:** it comes after a–c.

## 6. Order and what to ask first
The order is 0 → a → b → c, then b2 and d.
- **Before a:**
  - the worker fence decision, agreed with Trưởng and Opus-reviewed;
  - kien on the commitment sentence (§3).
- **Before b2 and c:** kien on the template classes, and on widening D-57 (7) beyond one `GET /` by name.
