# feat/scan-module: WP-23 part 2 (`scan`, S-SCAN-1..4): design note, step 1 (2026-11-10)

## 1. Where nuclei runs
In the `scan` container, as a **second job kind on the sensor protocol `jobs` channel** (proto 2). The docs already say so: ARCHITECTURE §2 and §5.3, `sensor-protocol.md` §1, MANIFEST `container: scan`, and the deferred line "job nuclei cho module scan" in feat-sensor-protocol.md.
The docs do not settle library vs. binary: ARCHITECTURE §10 and D-8 say "Go library", while D-109 (6), D-113 and D-114 (2) push the other way. I applied D-74 and chose a **separate process**:
- `/usr/local/bin/nuclei` (MIT, so we may distribute it) is pinned by version and sha256 in the signed `vedette-scan` base image.
- The worker runs it through `core/exec` with an argv it builds and re-validates itself (`modules/scan/nucleiargv`, a leaf package like `nmapargv`).
- `-jsonl` is parsed **in core**, fail-closed and fuzzed, the same way core parses nmap XML (D-113 (5)).
Why not the library:
- nuclei's library pulls in a very large module graph into `go.mod`, which is Kiên's file.
- That graph probably includes `database/sql` (through its JS protocol libraries), which would break the D-114 (2) test `go list -deps`.
- `govulncheck` would then run over that whole graph.
- We could no longer kill the scanner as a process group.
Templates:
- They are the safe `kev,vkev` subset, built at release time (D-36: content packs ship inside the signed image).
- They are baked into the scan image, and their index (`id → cve, tags, sha256, first request line`) is embedded in core.
- A job names only template ids plus the pack hash. There are no paths, URLs or YAML on the wire (D-111 (3)).
- Fixed flags: no interactsh, no update check, no template download, no cloud upload, `-etags dos,intrusive,fuzz,…`, and no headless, code or file templates. These are verified in the lab against the pinned version.

## 2. Consent and scope, all in core (D-113 (1), SYS-7)
`scan` is the only party that decides. The worker keeps only grammar caps.
- **Checks before each device job, not only at POST** (INV-1, INV-2):
  - the commitment (`scope_confirmed_at`);
  - internal targets: `InScope` ∖ `scan.config.exclusions`, `approved`, not the box;
  - external targets: `exposure.CheckScannable(ctx, actor, "ext:<id>")`, which runs the TXT check and the INV-13 IP check;
  - a TOCTOU test for each of these checks.
- **Rate, schedule and exclusions:**
  - Rate is `-rl <rate>` with `-c 1 -bs 1`.
  - Fragile devices run at `max(1, rate/4)`, as the GUI says.
  - Scheduled runs only start inside the window, and "Scan now" ignores it (GUI text in `scan.json`).
- **Probe log (INV-7):**
  - One `scan_probe` row per (device, template) is written in the same transaction that queues the job, **before** the job leaves.
  - The `request` text comes from the pack index, not from the device.
  - The result is filled in afterwards, and a startup pass closes rows that a crash left open.
- **Unresponsive devices (INV-6):**
  - nuclei gets `-mhe <unresponsive_after>`, so a dead host stops getting requests inside the job.
  - Core counts host errors from the `-ms` lines, sets `auto_stopped` and dispatches nothing more.
- **Stop now:**
  - Stop sets `stopping` and cancels through the long-poll, which wakes at once; the worker then kills the process group.
  - The run becomes `stopped` within 5 s.
  - If the worker never confirms, the 60 s lease still kills nuclei.

## 3. Rescan after a new KEV (S-SCAN-2, INV-9)
- **Recording the event:**
  - A subscriber to `feeds.vuln.new_kev` only inserts a pending `scan_event` row.
  - A reconcile job every 5 min adds any KEV CVE first seen in the last 7 days that has a template in the **installed pack** and no row yet (events are not persisted).
- **Acting on it (job every 1 min):**
  - With `auto_rescan=false` the row becomes `skipped_off`.
  - Otherwise the devices are the open findings for that CVE that the automatic policy allows. None means `no_match`.
  - Otherwise one `trigger=new_kev` run starts with that single template, then the row gets `matched`/`clear`, `latency_min` and `run_id`.
- The ≤ 60 min latency is tested with a fake clock.
- Upstream `has_template` alone is not enough: the template must be in the pack.

## 4. Results → findings (S-SCAN-3, INV-8, INV-10)
- **Template choice:** templates come from the device's open findings (`findings.List`) intersected with the pack. A CVE without a template gives `no_template` with no packet sent; a device with none gives `not_applicable`.
- **On `matched`:**
  - core calls `findings.ConfirmFromScan` **directly**, through an interface wired in `cmd/vedette`, and gets the `finding_id` back.
  - The evidence:
    - request and response from the JSONL, valid UTF-8, control characters stripped, capped at 2 KiB and 4 KiB;
    - a summary that includes the recheck line (`nuclei -id <CVE> -u <url>`);
    - `CheckedAt`.
  - `scan.finding.confirmed` is still published, for information only.
- **On not matched:** `RescanClear`.
- With `findings` off, rows keep their note and nothing is confirmed.

## 5. Slice plan (one PR each, red-first, `heavy make check`, no push)
- **S0:** GUI/mock changes only, and only if go (open questions 2–4).
- **S1:** migrations `scan_*`, store, `GET`/`PUT /scans/config` (INV-5, dangerous_locked, next_run in the organization time zone, audit).
- **S2:** leaf packages `nucleiargv`, `nucleiout` (JSONL) and `pack`, with fuzzing and recorded fixtures.
- **S3:** targets, runs, stop, probes and CSV (formula-guarded), all on an `Engine` seam with a fake in tests and a dev-only `core/exec` engine; findings and exposure calls.
- **S4:** jobs (schedule, 90-day retention, KEV rescan) and `GET /scans/events`.
- **S5:** remote engine over Kiên's dispatcher plus Health (needs SP-3 and proto 2); docs commit for CONTRACT/IMPACT.

Supervisor go 2026-11-10 for S0–S4; Kiên answered #115 with D-125 (nuclei binary, proto 2, nuclei slot, `scanner_unavailable`) and D-126 (VulnScanPolicy(explicit), box and `regular_scan=never` absolute, fragile/unclassified/hand-declared only on an explicit pick, KEV rescan not windowed) in PR #116; the remote dispatcher/worker is PR #117 (S5 base).

## Open items
- [x] 2026-11-10 — S5: remote nuclei engine over the dispatcher, proto 2 job/result/heartbeat, worker exec, scan-base Containerfile + release pack builder (D-125) — vì sao để sau: Kiên's PR #117 and SP-5 first — ở đâu: modules/scan, core/sensorlink, cmd/vedette-sensor — Moved → #115
- [x] 2026-11-10 — `inventory.VulnScanPolicy(ctx, assetID, explicit)` (D-126 (1)) merged — Done (#119)
- [ ] 2026-11-10 — `VulnScanPolicy` (merged in #119): its `Rate` is sensor-active's packets/s (1..1000), not scan's requests/s (1..20): scan needs only "quarter speed or not"; ask Kiên for a `Careful bool` (or `Quarter`) on `ScanDecision` instead of inferring it from `Rate < Active.Rate` (wrong when Active.Rate ≤ 3) — vì sao để sau: inventory is Kiên's (D-65) — ở đâu: modules/inventory/scanpolicy.go, cmd/vedette adapter
- [x] 2026-11-10 — External targets (exposure) are listed but not scanned (`not_supported`); decide template choice (no findings) and how a match becomes a finding without an asset — vì sao để sau: D-126 (4), supervisor Q5 — ở đâu: modules/scan, web/src/features/scan — Moved → #115
- [x] 2026-11-10 — `exposure.Runner` (hosts/ports/admin panels/certs snapshot) is a separate small WP — vì sao để sau: not S-SCAN-1..4, D-126 (4) — ở đâu: modules/exposure/ports.go — Moved → #115
- [ ] 2026-11-10 — The mock's `vedette/fingerprint` banner probe (`result: banner`) has no story criterion and no backend counterpart; the backend never writes `banner` — vì sao để sau: no-imagined-features, ask whether to drop it from the mock — ở đâu: web/src/features/scan/mocks.ts
- [ ] 2026-11-10 — GUI preselects devices with findings, fragile ones included (NAS-PHOTOS); D-126 says a fragile device needs an explicit pick: is a preselected row that the user leaves ticked and confirms with Scan now an explicit pick? Kept as approved GUI for now — vì sao để sau: product question for kien — ở đâu: web/src/features/scan/RunsTab.tsx StartPanel
- [ ] 2026-11-10 — H1 (review of S2): when exposure targets are scanned, the worker resolves a domain once, refuses loopback, link-local, multicast and the box's own addresses, and pins the IP it scans; until then `nucleiargv` accepts private IPv4 literals only — vì sao để sau: external targets are not scanned yet (D-126 (4)) — ở đâu: modules/scan/nucleiargv, worker (Kiên)
- [ ] 2026-11-10 — M1 lab checks on the pinned nuclei: does `-etags` still exclude a template that `-t` names directly; do goflags list options read a file when a value names one (run nuclei from an empty read-only cwd); does `-duc` plus a tmpfs HOME stop every template download, or is `DISABLE_NUCLEI_TEMPLATES_*` also needed; do `-pt`, `-dr`, `-nh` exist under these names — vì sao để sau: no real nuclei here (agent-safety) — ở đâu: lab, SP-5/S5
- [ ] 2026-11-10 — M2: the release builder and the worker check that the template directory holds exactly the index's files and that each file's `id:` equals its index id (nuclei reports the file's own id) — vì sao để sau: builder and worker are SP-5/S5 (Kiên) — ở đâu: release make, worker
- [ ] 2026-11-10 — Needs for Kiên's worker (add to #115): build the argv with `nucleiargv.Build` from template paths of its verified index (the wire still names ids, D-111 (3)); run nuclei with a clean environment (no ENABLE_CLOUD_UPLOAD, PDCP_API_KEY, *_PROXY; HOME on tmpfs, no ~/.config/nuclei; empty read-only cwd) — vì sao để sau: worker is Kiên's — ở đâu: issue #115
- [ ] 2026-11-10 — `modules/scan/nucleiout/testdata/matched.jsonl` is hand-written in the shape nuclei v3 prints (`-jsonl -ms`); replace it with a recording of the pinned nuclei against the lab target, and check the flags of `nucleiargv.fixedFlags` (`-duc -ni -ms -etags -ept -c -bs -timeout -retries`) against that version's `nuclei -h` — vì sao để sau: no real scan here (agent-safety), lab is SP-5/S5 — ở đâu: modules/scan/nucleiout, modules/scan/nucleiargv
- [ ] 2026-11-10 — `scan.Decision.Careful` comes from the device row in the cmd adapter (fragile or kind unknown), so a fragile device allowed regular scans is still slowed to a quarter (safe side); D-126 says normal rate for it. Ask Kiên for a flag on `inventory.ScanDecision` — vì sao để sau: inventory is Kiên's (D-65) — ở đâu: cmd/vedette/scan.go `VulnScanPolicy`
- [ ] 2026-11-10 — S3 review L6 (efficiency): GET /scans/targets makes two or three inventory reads per device (VulnScanPolicy as a pick and without, plus Device in the adapter); one batch read of the policy for all devices would do — vì sao để sau: inventory is Kiên's, a batch read is his API; fine at hundreds of devices — ở đâu: modules/inventory/scanpolicy.go, modules/scan/targets.go
- [ ] 2026-11-10 — S3 review L1: inventory could return the address VulnScanPolicy decided on (`ScanDecision.Addr`) instead of the adapter reading the device right after; and the 15-minute job is not checked again while it runs (CONTRACT) — vì sao để sau: inventory is Kiên's — ở đâu: modules/inventory/scanpolicy.go, cmd/vedette/scan.go
- [ ] 2026-11-10 — S3 review M3: the recheck command could be a structured field of the evidence (findings `Evidence.Recheck` + the findings GUI contract) instead of a sentence in the summary built from validated parts — vì sao để sau: a findings and GUI contract change (GUI-first) — ở đâu: modules/findings, web/src/features/findings
