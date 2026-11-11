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
- [x] (Done: ScanDecision.Careful, feat/inventory-scan-decision) 2026-11-10 — `VulnScanPolicy` (merged in #119): its `Rate` is sensor-active's packets/s (1..1000), not scan's requests/s (1..20): scan needs only "quarter speed or not"; ask Kiên for a `Careful bool` (or `Quarter`) on `ScanDecision` instead of inferring it from `Rate < Active.Rate` (wrong when Active.Rate ≤ 3) — vì sao để sau: inventory is Kiên's (D-65) — ở đâu: modules/inventory/scanpolicy.go, cmd/vedette adapter
- [x] 2026-11-10 — External targets (exposure) are listed but not scanned (`not_supported`); decide template choice (no findings) and how a match becomes a finding without an asset — vì sao để sau: D-126 (4), supervisor Q5 — ở đâu: modules/scan, web/src/features/scan — Moved → #115
- [x] 2026-11-10 — `exposure.Runner` (hosts/ports/admin panels/certs snapshot) is a separate small WP — vì sao để sau: not S-SCAN-1..4, D-126 (4) — ở đâu: modules/exposure/ports.go — Moved → #115
- [ ] 2026-11-10 — The mock's `vedette/fingerprint` banner probe (`result: banner`) has no story criterion and no backend counterpart; the backend never writes `banner` — vì sao để sau: no-imagined-features, ask whether to drop it from the mock — ở đâu: web/src/features/scan/mocks.ts
- [x] (Done: S3 #154, ScanTarget.pick_only, the GUI never ticks such a device) 2026-11-10 — GUI preselects devices with findings, fragile ones included (NAS-PHOTOS); D-126 says a fragile device needs an explicit pick: is a preselected row that the user leaves ticked and confirms with Scan now an explicit pick? Kept as approved GUI for now — vì sao để sau: product question for kien — ở đâu: web/src/features/scan/RunsTab.tsx StartPanel
- [ ] 2026-11-10 — H1 (review of S2): when exposure targets are scanned, the worker resolves a domain once, refuses loopback, link-local, multicast and the box's own addresses, and pins the IP it scans; until then `nucleiargv` accepts private IPv4 literals only — vì sao để sau: external targets are not scanned yet (D-126 (4)) — ở đâu: modules/scan/nucleiargv, worker (Kiên)
- [ ] 2026-11-10 — M1 lab checks on the pinned nuclei: does `-etags` still exclude a template that `-t` names directly; do goflags list options read a file when a value names one (run nuclei from an empty read-only cwd); does `-duc` plus a tmpfs HOME stop every template download, or is `DISABLE_NUCLEI_TEMPLATES_*` also needed; do `-pt`, `-dr`, `-nh` exist under these names — vì sao để sau: no real nuclei here (agent-safety) — ở đâu: lab, SP-5/S5
- [ ] 2026-11-10 — M2: the release builder and the worker check that the template directory holds exactly the index's files and that each file's `id:` equals its index id (nuclei reports the file's own id) — vì sao để sau: builder and worker are SP-5/S5 (Kiên) — ở đâu: release make, worker
- [ ] 2026-11-10 — Needs for Kiên's worker (add to #115): build the argv with `nucleiargv.Build` from template paths of its verified index (the wire still names ids, D-111 (3)); run nuclei with a clean environment (no ENABLE_CLOUD_UPLOAD, PDCP_API_KEY, *_PROXY; HOME on tmpfs, no ~/.config/nuclei; empty read-only cwd) — vì sao để sau: worker is Kiên's — ở đâu: issue #115
- [ ] 2026-11-10 — `modules/scan/nucleiout/testdata/matched.jsonl` is hand-written in the shape nuclei v3 prints (`-jsonl -ms`); replace it with a recording of the pinned nuclei against the lab target, and check the flags of `nucleiargv.fixedFlags` (`-duc -ni -ms -etags -ept -c -bs -timeout -retries`) against that version's `nuclei -h` — vì sao để sau: no real scan here (agent-safety), lab is SP-5/S5 — ở đâu: modules/scan/nucleiout, modules/scan/nucleiargv
- [x] (Done: ScanDecision.Careful, feat/inventory-scan-decision) 2026-11-10 — `scan.Decision.Careful` comes from the device row in the cmd adapter (fragile or kind unknown), so a fragile device allowed regular scans is still slowed to a quarter (safe side); D-126 says normal rate for it. Ask Kiên for a flag on `inventory.ScanDecision` — vì sao để sau: inventory is Kiên's (D-65) — ở đâu: cmd/vedette/scan.go `VulnScanPolicy`
- [ ] 2026-11-10 — S3 review L6 (efficiency, optional): since #162 the adapter reads the device once and `inventory.VulnScanPolicies` gives the policy of all devices in one read; GET /scans/targets still asks per device (as a pick and without). Add a batch method to `scan.Inventory` and use it in `Targets()` — vì sao để sau: optional, fine at hundreds of devices — ở đâu: modules/scan/targets.go, ports in service.go, cmd/vedette/scan.go
- [x] (Done: #162 cd57dc5, ScanDecision.IP; the adapter reads the device once) 2026-11-10 — S3 review L1 (also the #154 reviewer's note 1): the address compared is now the one the policy decided on. The 15-minute job is not checked again while it runs: a documented limit in CONTRACT, not a deferred item — ở đâu: modules/inventory/scanpolicy.go, cmd/vedette/scan.go
- [ ] 2026-11-10 — #154 reviewer, note 2: while the engine is still busy after a stop (M2), the GUI still offers Scan now and the click gets 409 `already_running`. Show it as busy (e.g. `ScanView.engine_busy` with the button disabled and a hint) — vì sao để sau: a GUI and contract change (GUI-first), non-blocking — ở đâu: web/src/features/scan/RunsTab.tsx, contract.ts, modules/scan/service.go view
- [ ] 2026-11-10 — #154 reviewer, note 3: `scan_probe.label` and the run results JSON store the device label raw (it comes from the network: hostname/DHCP). It is escaped on display and CSV has the formula guard, but it is stored unbounded and unfiltered; cap its length and strip control/bidi characters when writing, as the evidence does — vì sao để sau: non-blocking; S4 or a small follow-up — ở đâu: modules/scan/run.go writeProbes, conclude
- [ ] 2026-11-10 — S3 review M3: the recheck command could be a structured field of the evidence (findings `Evidence.Recheck` + the findings GUI contract) instead of a sentence in the summary built from validated parts — vì sao để sau: a findings and GUI contract change (GUI-first) — ở đâu: modules/findings, web/src/features/findings
- [ ] 2026-11-10 — SP-5 lab (S2 reviewer, final pass): record a real `-jsonl` line from the pinned nuclei. If nuclei ≥ 3.2 writes `host` as a bare hostname with `port`/`url` separate, `nucleiout.hostOf` refuses every real result and nothing is ever confirmed; fix the target matching once the line exists (AI-Trưởng's fake nuclei in SP-3b emits both shapes) — vì sao để sau: needs the pinned binary in the lab — ở đâu: modules/scan/nucleiout/parse.go hostOf
- [ ] 2026-11-10 — For Kiên's worker (SP-3b, #115): Lstat each pack file before hashing it and accept regular files only (no symlink out of the pack directory) — vì sao để sau: worker is Kiên's; AI-Trưởng told — ở đâu: cmd/vedette-sensor, worker
- [ ] 2026-11-10 — S5 blocker (lab, D-133 (5)): how nuclei reports a template that `-etags` or `-pt` dropped (a line, a log message, nothing). With JSONL for matches only, a dropped template looks like "no match reported"; the probe row must say it did not run — vì sao để sau: needs the pinned binary in the lab — ở đâu: modules/scan/run.go templateResult, worker
- [x] (Done: S5, cmd/vedette/scan_engine_test.go over the real Dispatcher, link and worker with a fake nuclei) 2026-11-10 — S5 blocker (test): an adapter test over the real seam `sensoractive.Scanner{Ready, RunNuclei}` (*Dispatcher already satisfies Engine.Ready) proving scope, consent and the probe row come first, before any job reaches the dispatcher; S5 adds the run call, the cmd wiring comes with SP-5 — vì sao để sau: S5 — ở đâu: modules/scan engine adapter, cmd/vedette/scan.go
- [ ] 2026-11-10 — INV-6 with matches-only output (D-133 (5)): an empty output is now "no match reported", so a dead device is seen as unresponsive only when nuclei prints error lines. nuclei's -mhe still stops sending to it; for the auto-stop of the run the worker should report host errors (e.g. a count per target in the job result) — vì sao để sau: a wire change in the SP-3b job result (Kiên's) — ở đâu: core/sensorlink job result, modules/scan/run.go unresponsive
- [ ] 2026-11-10 — findings CONTRACT still says scan calls RescanClear; scan no longer does (a no-match never touches a finding, D-133 (5)). Decide whether `findings.RescanClear` and the history action `rescan_clear` stay (unused) or go — vì sao để sau: findings is Emily's, a separate small change — ở đâu: modules/findings/CONTRACT.md, service.go
- [x] (Done: feat/scan-s4b) 2026-11-10 — S4b (approved by the lead 2026-11-10, after S4 is gated): `feeds.vuln.new_kev` is not persisted, so an entry announced while the scan module was off or the process was down is never rescanned. Catch-up: a feeds read "KEV entries first seen since T that have a template" (feeds is Emily's) and a scan job that queues the missing `scan_event` rows. Design so far (branch feat/scan-s4b, paused for the #164 fixes): feeds writes `feeds_vuln.kev_announced_at` on exactly the rows it publishes new_kev for (never the D-78 baseline, never a custom feed) and reads them with `Store.NewKEVSince(at, cve, limit)` ordered by (kev_announced_at, cve); scan keeps that cursor in `scan_setting`, each rescan pass reads one page (≤ 100) and records the rows like OnNewKEV (ts = when feeds announced it, so latency is honest); a long backlog is rescanned in one run per batch of CVEs (templates ≤ nucleiargv.MaxTemplates, targets ≤ 200), not one run per CVE — vì sao để sau: its own slice after S4 — ở đâu: modules/feeds/store.go, modules/scan/jobs.go
- [ ] 2026-11-11 — S4b catch-up order: feeds stamps kev_announced_at with the pull's finish time, computed before its write transaction commits. Two cisa-kev pulls that overlap (the job and "Fetch now") could commit out of stamp order, and a catch-up pass between the two commits would move its read point past entries the later commit adds with an earlier stamp. They are still announced on the bus, so they are missed only if that event is lost too. Fix if it shows: serialize cisa-kev pulls in feeds, or stamp from a sequence (e.g. rowid order) instead of time — vì sao để sau: two rare events at once; ponytail — ở đâu: modules/feeds/pull.go markAnnounced, modules/scan/catchup.go
- [x] (Done: 357da5b) 2026-11-11 — #189 review L1: matchedCVE closed an event as matched by template path, so two CVEs sharing a template both read as matched when only one did; match by the row's finding id (a finding id belongs to one CVE) — vì sao để sau: fixed in S5 (feat/scan-s5), red first — ở đâu: modules/scan/jobs.go matchedCVE
- [x] (Done: 7404bd8) 2026-11-11 — #189 review L2: a backlog run (onlyCVEs) could probe a CVE on a device the event did not list (the device's finding for that CVE mitigated: plan keeps mitigated, affected() counts only suspected/confirmed); keep the (device, CVE) pairs of the events — vì sao để sau: fixed in S5 (feat/scan-s5), red first — ở đâu: modules/scan/run.go plan, jobs.go startRescan
- [ ] 2026-11-11 — #189 review L3: if the wall clock moves back (an NTP correction), kev_announced_at of a later pull can be earlier than the read point, and the catch-up skips those entries; the bus still delivers them while scan is on, so they are lost only if that event is lost too. Same fix as the line above (a sequence instead of time) — vì sao để sau: rare, ponytail — ở đâu: modules/feeds/pull.go markAnnounced, modules/scan/catchup.go
- [ ] 2026-11-10 — From D-146 (#176), still open after S5: (a) the pinned nuclei is v3.11.1, so the flags of `nucleiargv.fixedFlags` and the hand-written `nucleiout/testdata/matched.jsonl` are checked against that binary in the lab (`nuclei -h`, one recorded `-jsonl` line). Done in S5: (b) core holds the same index (content/nucleipack, written by `make scan-pack`, held to pins.env by a test) and every job names the pack; (c) the adapter test runs the real worker with a fake nuclei (workertest, the same shape as the dev compose fake) — vì sao để sau: needs the lab and the pinned binary — ở đâu: modules/scan/nucleiargv, modules/scan/nucleiout/testdata
- [ ] 2026-11-10 — A dropped KEV rescan event (dropEvent after 7 days: no template in the pack, the scanner not ready, or the organization zone unreadable) leaves no row the user can see; only the log says why. Keep it in the rescan log with a result of its own (e.g. `expired`, with the reason), a GUI-first contract change — vì sao để sau: a new RescanEvent value is a product decision like D-145 (7) (#164 coordinator, 2026-11-10) — ở đâu: modules/scan/jobs.go dropEvent, web/src/features/scan/contract.ts RescanEvent
- [ ] 2026-11-10 — While the organization zone cannot be read, scan starts nothing automated and next_run is null, so the Schedule tab says "The schedule is off." although it is on; there is no field for the reason, so it is only logged (#164 coordinator: no new GUI in this PR). A reason field (e.g. `schedule_blocked`) with its text is a GUI-first change — vì sao để sau: new GUI — ở đâu: web/src/features/scan/SafetyTab.tsx, contract.ts ScanConfigView, modules/scan/service.go view
- [x] (Done: 84e80cc, with run-seed-1 and the seeded rescan matches) 2026-11-10 — The mock seeds run-seed-2, a new_kev run on the fragile NAS only (web/src/features/scan/mocks.ts seedRuns), which D-126 (2) forbids for a KEV rescan; seed it on a device that may be scanned without a pick, and check the run-history vitest that counts the seeded runs — vì sao để sau: found while adding D-145 (7), outside the review fixes — ở đâu: web/src/features/scan/mocks.ts
- [x] (Done: D-145 (7), 25f81fd GUI, c23c6d8 job) 2026-11-10 — RescanEvent.result has no value for "the affected devices may only be scanned by a pick" (fragile, unclassified, hand-declared: D-126 (2)) nor for "the rescan run was stopped"; S4 writes no_match (devices []) and clear. Proposed in the S4 PR under "Quyết định cần ghi" (two new values, @kiennt048 asked); `no_match`/`clear` stay until he answers, then a GUI-first change — vì sao để sau: product question — ở đâu: web/src/features/scan/contract.ts RescanEvent, modules/scan/jobs.go

## Rà độc lập #208 (S5, 2026-11-11, sau merge 153ac45) — không chặn merge
- [ ] 2026-11-11 — Kẽ hở lệch chỉ mục: sửa tay `pins.env` và `index.source` sang nguồn template mới mà giữ nguyên pack version thì test vẫn qua với `index.json` cũ (an toàn vì worker từ chối mọi job); ghi version và sha256 của nguồn vào chính index rồi assert — vì sao để sau: fail safe — ở đâu: content/nucleipack
- [ ] 2026-11-11 — `make scan-base-image` chạy `scan-pack`, nên sau khi đổi `pins.env` nó ghi lại các file đang được git theo dõi trong `content/nucleipack` và để cây làm việc bẩn — vì sao để sau: Makefile dùng chung (@sysjrvn) — ở đâu: Makefile scan-base-image
- [ ] 2026-11-11 — Lý do dừng `ErrEngineDown` nhúng nguyên chữ lỗi của Dispatcher (cắt 400 ký tự, một phần đến từ worker; GUI có escape); nên dùng thông điệp cố định cho từng lỗi — vì sao để sau: GUI đã escape — ở đâu: cmd/vedette/scan.go, modules/scan
- [ ] 2026-11-11 — `matchedCVE` đọc mọi finding mỗi khi một sự kiện quét lại có liên kết đóng; ổn với cỡ dữ liệu hiện nay — vì sao để sau: ponytail — ở đâu: modules/scan
