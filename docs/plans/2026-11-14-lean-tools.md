# LEAN-1/2/3, Mlee's side: each tool runs only what Vedette uses

Owner: AI-Mlee (what exposure asks of Greenbone, ZAP and nuclei; Mlee's own modules). **[T]** = AI-Trưởng (host, containers, scan/sensor images, the Greenbone compose project). Status: plan only, no code.
**kien (2026-11-14 17:1x):** every integrated tool runs only what Vedette uses; switch off what is never used (e.g. the OpenVAS web GUI: Vedette talks GMP).
**Done:** each change below is on the N100 with a before/after number in the LEAN-3 table (§6), and the customer journeys it touches still work (Greenbone deep scan of a lab host, passive ZAP of a page, the own-IP nuclei run, findings on an Ubuntu host).

## 1. OpenVAS / Greenbone CE: the GMP-only path (LEAN-1)

**What Vedette uses** (`modules/exposure/gmp.go`, `greenbone.go`): over the gvmd unix socket only, `authenticate`, `get_feeds` (readiness: any `currently_syncing`, or no feed at all), `get_configs`/`create_config`/`modify_config`/`get_preferences` (a copy of "Full and fast" per level, families, `safe_checks`, two Settings NVT checkboxes), `get_port_lists` ("All IANA assigned TCP"), `create_target` (one IP, `Consider Alive`, **no credentials**), `create_task` (scanner "OpenVAS Default"), `start_task`, `get_tasks`, `get_reports` (`details=1`, **no `format_id`**, `min_qod=70 levels=hml`), `stop_task`, `delete_task`/`delete_target`, `get_targets`. From a result it reads host, port, severity, QoD, NVT OID/name/solution and `refs` of type `cve`. Plus `SyncFeed` [T]: `compose pull` + `up -d` of the feed data images, weekly (D-564 G6).

**Facts checked in gvmd's source** (github.com/greenbone/gvmd, `main`, fetched 2026-11-14):
- CVE refs of a result come from the NVT's own refs (`xml_append_nvt_refs`, VT feed). CERT-Bund/DFN-CERT refs are added only `if (cert_loaded)` (`results_xml_append_cert`); Vedette ignores them anyway.
- SCAP and CERT data are required only by `get_info` and `get_resource_names` ("The SCAP database is required", `gmp.c`), and by EPSS/CPE extras; Vedette sends neither command and has its own EPSS feed.
- `get_reports` without `format_id` sets `no_report_format` and never looks a report format up (`gmp.c` ~l.15747): Vedette's report read does not need the report-formats data.
- `get_feeds` omits a feed whose `feed.xml` is missing (`get_feed_info` returns -1), and `currently_syncing` comes from **one shared feed lock** for every feed type (`get_feed_lock_status`): today the SCAP/CERT import holds the lock, so it also holds back Vedette's first scan and every weekly update window.
- Risk to test: with no SCAP/CERT tables gvmd's sync check reports status 2 and logs "No SCAP db present, rebuilding SCAP db from scratch" (`manage_sql_secinfo.c`). It must not loop holding the lock (gate A2 below).
- Notus (local security checks) compares the package list an **authenticated** scan gathers ("Determine OS and list of installed packages via SSH login", OID 1.3.6.1.4.1.25623.1.0.50282; https://github.com/greenbone/notus-scanner). Vedette's targets carry no credentials, so notus has nothing to compare. Credentialed scanning (S-SCAN-5) is post-v1 (D-417); it brings notus back.
- The current compose has **no mosquitto and no notus-scanner**: openvasd in `OPENVASD_MODE: service_notus` replaced both (https://greenbone.github.io/docs/latest/_static/compose.yaml).

**Services of the official compose** (https://greenbone.github.io/docs/latest/22.4/container/index.html, compose fetched 2026-11-14):

| Service | Role | Needed for GMP socket / scans / report read / weekly feed? | Plan |
|---|---|---|---|
| gvmd, pg-gvm, pg-gvm-migrator | manager, its database, one-shot PG major upgrade | yes (all) | keep |
| redis-server, ospd-openvas | scanner and its VT/KB store | scans | keep |
| configure-openvas | writes `openvas.conf` (one-shot) | scans | keep; stage B changes its two lines |
| gpg-data | Greenbone's keyring, VT signature check | scans | keep |
| vulnerability-tests | the NVTs (VT feed) | scans, CVE refs | keep (SyncFeed) |
| data-objects | "Full and fast", port lists | configs, port list | keep (SyncFeed) |
| report-formats | report formats into `data_objects_vol` | not for `get_reports` without `format_id` | **stage B: drop** |
| notus-data, openvasd | notus advisories + the notus engine | only authenticated LSC | **stage B: drop** |
| scap-data | CVE/CPE/EPSS (GSA SecInfo pages, CVE scanner) | no | **stage A: drop** |
| cert-bund-data, dfn-cert-data | CERT advisories (GSA SecInfo, CERT refs) | no | **stage A: drop** |
| gsa, gsad, gvm-config, nginx | web GUI files, HTTP→GMP API, its nginx config/certs, nginx on 127.0.0.1:443/9392 | no (Vedette speaks GMP itself) | **stage A: drop** |
| openvas | only `cat openvas.conf; tail -f openvas.log` (log viewer) | no | **stage A: drop** |
| gvm-tools | gvm-cli container (used by the trial's `gmp.sh`) | no | **stage A: drop** |

**Compose changes for [T]** (Vedette's pinned copy of the upstream file; a test diffs it against the pinned upstream and allows only these edits, so a bump shows any new service):
- **Stage A** (sourced above): delete services `gsa`, `gsad`, `gvm-config`, `nginx`, `gvm-tools`, `openvas`, `scap-data`, `cert-bund-data`, `dfn-cert-data`; delete volumes `gsa_data_vol`, `nginx_config_vol`, `nginx_certificates_vol`, `scap_data_vol`, `cert_data_vol`; in `gvmd` delete the volume lines `scap_data_vol:/var/lib/gvm/scap-data/` and `cert_data_vol:/var/lib/gvm/cert-data` and the `depends_on` entries `scap-data`, `cert-bund-data`, `dfn-cert-data`. `SyncFeed` pulls 4 images (`vulnerability-tests`, `notus-data`, `data-objects`, `report-formats`), not 7. An upgraded box also runs `podman volume rm` of the two data volumes and drops the `scap`/`cert` schemas only if gate A2 shows gvmd does not rebuild them (else leave them).
- **Stage B** (trial on the N100, keep only if its gates pass): delete `notus-data`, `openvasd`, `report-formats`, volume `notus_data_vol`; in `ospd-openvas` delete `--notus-feed-dir /var/lib/notus/advisories`, the `notus_data_vol` mount and the `notus-data` dependency; in `gvmd` delete the `report-formats` dependency; `configure-openvas` writes `table_driven_lsc = no` and no `openvasd_server` line. `SyncFeed` pulls 2 images.
- Not changed: `KEEP_ALIVE: 1` of the data containers (the `service_healthy` conditions need them running); `GVMD_ARGS` (`--disable-scheduling` exists, but `manage_schedule` still runs and the saving is not measurable).
- **Gates on the N100** (each before and after): A1 Vedette's Greenbone scan of lab .181 gives the trial's results (3 Low at QoD ≥ 70, CVE refs where the NVT names one); A2 for 30 min after the feed load, `get_feeds` shows no `currently_syncing` and `podman logs gvmd` has no repeated "rebuilding SCAP"; A3 nothing listens on 443/9392 (`ss -ltnp`). B1 = A1 again; B2 `get_reports` answers with the results (no "Failed to find report format"); B3 ospd-openvas and gvmd logs show no notus/openvasd error loop.
- **Mlee's half:** update the `GreenboneHost.SyncFeed` comment in `greenbone.go` and exposure CONTRACT INV-25 to the kept image list, and add a test that the GMP client never sends `get_info`, `get_resource_names` or a `format_id` (the lean compose depends on that). No other exposure change.

## 2. ZAP (LEAN-2; host argv `host/ops/zap.go` [T], rules `content/zap` and `modules/exposure/zap.go` Mlee)

- **Used:** `zap-baseline.py --autooff` (traditional runner, D-525), spider 1 min, passive rules 5 min, JSON report (`-J`); later the active scan (FULL-3).
- **Already lean, no change:** `-silent` "ensures ZAP does not make any unsolicited requests, including check for updates" (https://www.zaproxy.org/docs/desktop/cmdline/), and with `-silent` `zap-baseline.py` drops its own `-addonupdate -addoninstall pscanrulesBeta` (`install_options`, https://raw.githubusercontent.com/zaproxy/zaproxy/main/docker/zap-baseline.py). `check_zap_client_version` (PyPI) is skipped in a container (`zap_common.py`). The HUD is off in daemon mode by default ("This defaults to false", https://www.zaproxy.org/docs/desktop/addons/hud/options/). The fence blocks any call home anyway.
- **Add-ons:** the stable image copies its add-ons into `/zap/plugin`, the install dir (`Dockerfile-stable`); our root is `--read-only`, so `-addonuninstall` cannot remove them, and removing them means a derived image (against D-521's upstream digest). Not done. **Check (correctness, not size):** with `-silent` pscanrulesBeta is not added at start; run `podman run --rm --pull=never <zapImage> zap.sh -cmd -silent -addonlist` once and confirm every rule id of `content/zap/vedette-baseline.conf` (e.g. 10062, 10097, 10052, 10056, 10105) is in an installed add-on; a rule that is not is a FAIL row that can never fire.
- **IGNORE rules still run:** `-c` only filters the report (`print_rules`, `zap_common.py`; no `disable_scanners` call) and Vedette does not even pass `-c` (exposure drops IGNORE alerts when it reads the report). The AF `passiveScan-config` route is closed by `--autooff`. The working route is a hook (`--hook=/zap/wrk/hooks.py` with `zap_started(zap, target)` calling `zap.pscan.disable_scanners(<IGNORE ids>)`, https://www.zaproxy.org/docs/docker/scan-hooks/), ids generated from `content/zap`. **Recommendation: measure first, do not build now** (ponytail: 10 regex rules over at most a minute of spidered pages); build it only if the passive phase on a real site (zap.out, spider end → passive done) is over 30 s.
- **JVM heap:** `-Xmx512m` in a 1 GiB container (tmpfs 256 MiB counts too). Measure `memory.peak` on two real pages; lower `-Xmx`/`--memory` only if the peak stays under half the cap; raise nothing.

## 3. nuclei (LEAN-2; argv `modules/scan/nucleiargv` Mlee, image [T])

- **Already lean, no change:** `-duc` ("disable automatic nuclei/templates update check"; in v3.11.1 `internal/runner/runner.go` the version check, `FreshInstallIfNotExists` and `UpdateIfOutdated` all sit behind it), `-ni` (no interactsh), `-nh` (no httpx probe), `-silent -jsonl -nc`, `-pt http,tcp,ssl`, `-c 1 -bs 1`, each template named by `-t` from the signed pack (never a directory). No `-stats`: the clistats metrics server (127.0.0.1:63636/`-mp`) starts only when the progress ticker is active (`pkg/progress/progress.go` `Init` → `stats.Start()` under `if p.active`), so nothing listens. No `-dashboard`/`-cloud-upload`, `ENABLE_CLOUD_UPLOAD` unset (and `core/exec` passes no such env). Docs: https://docs.projectdiscovery.io/opensource/nuclei/running.
- **Check on the N100:** during an own-IP run, `podman exec vedette-scan ss -ltnp` lists no nuclei listener and nuclei's stderr has no "failed to install nuclei templates".

## 4. Mlee's own modules (feeds, mitigation, findings, notify, exposure, scan, logs, ai, reports, mcp-server; `docs/TEAM_PLAN.md` §2)

All run inside `core`; none starts an outside process. Listeners and long-lived connections exist only while needed: logs syslog sockets (514/6514, module on), mcp-server on 127.0.0.1:8765 (module on), Telegram long poll / Slack Socket Mode / Zalo personal listener (only while that channel is configured, enabled and takes approvals: `tglisten.go`, `slacklisten.go`). Nothing to switch off there.
- **One real waste: the distribution feeds (D-516).** `RunPull` pulls every enabled due feed; nothing asks whether a device needs it. `ubuntu-osv`, `ubuntu-vex` and `debian-tracker` download 63 + 79 + 90 MB a day and the two xz archives unpack to 12.6 + 29.9 GB that are parsed in `core` every time Canonical changes them (numbers from `distro.go`, 2026-11-14). **Change (Mlee):** pull the Ubuntu pair only while the inventory (the box included) has an Ubuntu device with deb packages, and the Debian tracker only while it has a Debian one; the first pull runs on the next tick after one appears; the Feeds page says "Not pulled: no Ubuntu device yet". Needs an acceptance line on the D-516 story criterion (`docs/USER_STORIES.md`) and a D-xx with top-tier sources, written with the slice (no claim made here: Trivy and Grype ship one DB for every distribution, so they are not the model). Saving: on an Ubuntu box with no Debian device, 90 MB/day and the Debian parse; on a box with neither, all three.
- Kept as is: IOC feeds (MBs, read by logs, ai, response, core), CISA/EPSS/NVD/CVE.org (the product itself).

## 5. Split table

| Item | Owner | Exact change | Why safe (source) | Expected saving | Measure on the N100 (before and after) |
|---|---|---|---|---|---|
| L1-A GUI | [T] | drop gsa, gsad, gvm-config, nginx + 3 volumes | Vedette speaks GMP itself (`gmp.go`); gsad only translates HTTP→GMP (Greenbone docs) | 4 containers, their images; ports 443/9392 closed | `podman stats --no-stream`; `podman system df -v`; `ss -ltnp` |
| L1-A tools/log | [T] | drop gvm-tools, openvas (log tail) | trial helper only; `tail -f` only (compose) | 2 containers + gvm-tools image | same |
| L1-A SCAP/CERT | [T] | drop scap-data, cert-bund-data, dfn-cert-data, 2 volumes, gvmd mounts/deps | only `get_info`/`get_resource_names` need them; CVE refs come from NVTs (`gmp.c`) | most of the trial's ~2 h first load, its 4 GB RAM peak and swap, GBs of disk | time `compose up` → Vedette readiness; `memory.peak`; `du -sh` volumes; PG size |
| L1-A Mlee | Mlee | SyncFeed list + INV-25 text; test: no `get_info`/`get_resource_names`/`format_id` | keeps the lean compose valid | — | CI |
| L1-B notus, report formats | [T] | drop notus-data, openvasd, report-formats; `table_driven_lsc = no` | targets have no credentials (notus needs the SSH package list); no `format_id` (`gmp.c`) | 3 containers, redis/PG VT rows, feed time | gates B1–B3; `redis-cli info memory`; NVT count |
| L2 ZAP flags | — | none | `-silent`, HUD daemon default off (ZAP docs) | — | — |
| L2 ZAP rules | Mlee | check rule ids vs `-addonlist`; hook only if passive > 30 s | correctness first; hook is documented | small CPU | zap.out phase times; `memory.peak` |
| L2 nuclei | — | none | `-duc -ni -nh`, no `-stats` (source) | — | `ss -ltnp` in the scan container |
| L2 distro feeds | Mlee | pull per distro present in inventory (built: D-570, feeds INV-22) | data unused without such a device (D-516 story) | up to 232 MB/day download, 42 GB/day unpack+parse | core `cpu.stat` around "Fetch now"; feed pull duration |
| L2 sensor/scan/honeypot (nmap/NSE, OpenCanary, Zeek, osquery, Wazuh, containers) | [T] | Trưởng's own plan | — | — | same commands |

**Commands** (rootful podman on the N100; the Greenbone project name is `greenbone-community-edition`):
- RAM now: `podman stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}'`.
- RAM peak since start: `cat /sys/fs/cgroup$(podman inspect -f '{{.State.CgroupPath}}' <ctr>)/memory.peak` (box: `free -m` + `vmstat 60` during the feed load, as in the trial). A `--rm` ZAP run: read it in a 5 s loop while `podman container exists vedette-zap`.
- CPU of a job: `cpu.stat` `usage_usec` of the same cgroup before and after (core around a feed "Fetch now"; ospd-openvas around a scan).
- Disk: `podman system df -v`; `du -sh $(podman volume inspect -f '{{.Mountpoint}}' <vol>)`; `podman exec <pg-gvm> psql -U gvmd -d gvmd -c "select nspname, pg_size_pretty(sum(pg_total_relation_size(c.oid))) from pg_class c join pg_namespace n on n.oid=c.relnamespace group by 1 order by sum(pg_total_relation_size(c.oid)) desc limit 5"`.
- Time: `compose up -d` on empty volumes → Vedette's Greenbone readiness "ready" (trial: ~2 h); Greenbone scan of .181 start → done (trial: 3 min 22 s); ZAP run start → report (host audit rows).

## 6. LEAN-3 table template (for `docs/DEPLOYMENT.md`, a new §2.5 "Lean tools"; numbers only from the N100)

The rule for a new tool: list what Vedette asks of it, switch off the rest, add a row here with the measurement.

| Tool | Switched off | Why it is safe (source) | RAM idle / peak before → after | Disk before → after | Time/CPU before → after | Measured (date, build, by) | Owner |
|---|---|---|---|---|---|---|---|
| Greenbone CE | web GUI (gsa, gsad, gvm-config, nginx), gvm-tools, log tail | GMP over the gvmd socket only | … | … | — | … | [T] |
| Greenbone CE | SCAP + CERT data | Vedette reads only NVT refs | … | … | first load …; weekly sync … | … | [T] |
| Greenbone CE | notus, report formats (if stage B passes) | no credentials; no `format_id` | … | … | … | … | [T] |
| ZAP | update check, add-on download, HUD (already) | `-silent`; daemon default | — | — | — | … | [T]/Mlee |
| nuclei | update check, template download, interactsh, metrics server (already) | `-duc -ni`, no `-stats` | — | — | — | … | Mlee |
| feeds | distro feeds without such a device | D-516 story | … | … | CPU per day … | … | Mlee |
