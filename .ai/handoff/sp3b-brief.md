You implement slice **SP-3b** of the Vedette sensor protocol (KNT048/vedette): **nuclei as a job kind** (D-125, issue #115). Core's dispatcher hands a nuclei job to the worker in `vedette-sensor active`. The worker runs the pinned `/usr/local/bin/nuclei` through `core/exec`, with argv from Emily's leaf package `modules/scan/nucleiargv` (Build + Validate), and returns JSONL. Core parses it fail-closed. This is the "S5 needs from Kiên" part of #115.

- **Worktree:** `/Users/kien/Desktop/vedette-wt/sp-nuclei`
- **Branch:** `feat/sensor-nuclei`, cut from origin/main. Main has SP-3 (#117), SP-4 (#130), D-125/D-126 (#116), D-131 (#129) and Emily's scan S0 (#127).
  - **Check first:** does `modules/scan/nucleiargv` exist on main? It is Emily's.
  - If it does not, stop and report. Do not write it yourself. The lead will ask Emily for it or decide otherwise.
- **Shell:** use `/bin/ls`, never plain `ls`; the shell alias hangs.
- **Git:** commit on the branch. Do NOT push, tag or create branches.

## Read first (binding)
- `CLAUDE.md` and `.claude/rules/*`, especially security (untrusted output, fail-closed parsers, size caps, fuzz), legal (active scans only in confirmed scope, every probe logged) and ponytail.
- `docs/DECISIONS.md` (**D-136 (4)-(7)** narrow the grammar after #138's review; they win over older text in D-125/#115):
  - **D-125**, all of it: the job and result shape, the heartbeat `nuclei{present, version, pack}`, a nuclei slot separate from nmap, cancel waking the long-poll so Stop lands within 5 s, and the worker rules;
  - D-113 (SP-3);
  - D-114;
  - D-122;
  - **D-126**;
  - D-131.
- `gh issue view 115 --repo KNT048/vedette`: Emily's design note, including the needs list 1–3.
- The sensor protocol spec under `docs/specs/`, §9 caps. Bump the protocol to **v2**: `Job.kind` (`nmap`|`nuclei`). An old worker that gets a nuclei job must refuse it cleanly. Old jobs without `kind` mean `nmap`.
- The code:
  - `modules/sensor-active/dispatch.go` and `worker/worker.go` (SP-3, review-fixed);
  - `core/sensorlink` (wire types and limits);
  - `cmd/vedette-sensor` (flags, and the quadlet `Exec` gate tests from #125/#130);
  - `modules/scan` (Emily's: `CONTRACT.md`, the `nucleiargv`/`nucleiout` leaf packages, and the scanner seam she wrote for S0–S4);
  - `.ai/deferred/feat-scan-module.md`.

## Build
1. **Wire (`core/sensorlink`):**
   - `Job.kind`.
   - The nuclei job: `{id, kind, pack{version, sha256}, templates[1..32] (ids), targets[1..16]{host (canonical private RFC 1918 IPv4 only; no domain, no public, CGNAT, benchmark or 240/4 address — D-136 (4)), port, scheme}, rate 1..20, max_host_errors 2..20, timeout_s ≤ 3600}`. Core checks the same grammar before dispatch; `nucleiargv.Validate` stays the last fence in the worker.
   - The result: `{status, reason, exit_code, truncated, jsonl_b64}`, with JSONL ≤ 4 MiB.
   - Heartbeat `nuclei{present, version, pack}`.
   - Strict decoding and caps.
2. **Dispatcher:**
   - A nuclei slot separate from the nmap one: one nuclei job and one nmap job may run at once. Same lease, pickup, heartbeat and grace rules as SP-3, including its review fixes (cancel of unknown running ids, the core-side cap).
   - Cancel wakes the open long-poll, so Stop lands within 5 s.
   - Expose a `Prober`-like seam that Emily's `scan` module calls. Implement the interface Emily defined if it exists; otherwise define the smallest one and say so.
3. **Worker:**
   - Re-validate the job with `nucleiargv.Validate`.
   - Map template ids to paths from the verified pack index (D-136 (6)); one `-t <TemplatesDir>/<path>` per template, never the whole directory. An id missing from the index refuses the job.
   - Run nuclei with a clean environment (D-136 (5), scan CONTRACT INV-4): only what the builder sets; no `ENABLE_CLOUD_UPLOAD`, `PDCP_API_KEY`, `*_PROXY`, and a fresh tmpfs `HOME` so no `~/.config/nuclei` is read.
   - Check that the pack's sha256 matches the baked index inside the image (`/usr/local/share/vedette/nuclei-pack/index.json` or wherever D-125 says). Refuse on a mismatch.
   - Run nuclei through `core/exec`, with argv from `nucleiargv.Build`, in its own process group, with `HOME` on a tmpfs path (a flag or env from the unit).
   - Kill the group on cancel, lost lease, deadline or shutdown.
   - Cap stdout at 4 MiB with `truncated`. Never post stderr.
4. **Core result parsing:** use Emily's `nucleiout` parser if it exists. Otherwise parse JSONL fail-closed with per-line caps and fuzz it, as a leaf, and note it. The result goes to Emily's `scan` module through the seam.
5. **Health:** `scanner_unavailable` when there is no worker heartbeat or the heartbeat says nuclei is missing (D-125 (5)).
6. **`vedette-sensor active`:** add whatever flags the nuclei path needs (the nuclei binary path, the pack dir). Keep the quadlet `Exec` gate test of the scan unit green, and update the scan template in `host/ops/quadlet.go` and its golden file if the flags change.

## Tests (red first; fake nuclei through `exectest.WriteScript`; never the real nuclei; never the network)
- The worker refuses what the grammar forbids:
  - domains, public, loopback, link-local, CGNAT and 240/4 targets (D-136 (4));
  - a template id not in the pack index;
  - a proxy or cloud-upload variable in the parent environment does not reach nuclei (fake nuclei prints its env);
  - more than 16 targets or more than 32 templates;
  - a rate outside the bounds;
  - a pack hash that does not match;
  - an unknown kind;
  - a flag-like target.
- Separate slots: an nmap job and a nuclei job run at once, and a second nuclei job waits.
- Stop within 5 s of a cancel. The process group is killed, with no orphans (use SP-3's zombie-safe check).
- Oversize output is truncated. Hostile JSONL is refused per line; fuzz it.
- Old kind-less jobs still run as nmap.
- `scanner_unavailable` when there is no heartbeat, or nuclei is missing.
- The scan unit's `Exec` gate still passes.

## Docs
- The spec (v2), sensor-active CONTRACT and IMPACT, scan CONTRACT (only the seam line, since it is Emily's module).
- The deferred file: SP-5 must pin nuclei by version and sha256 in scan-base, build the pack with `make` (Emily's filter), add `bundled[]` to the manifest, and run the lab check that nuclei reaches only its targets.

## Rules
- Every Bash command has a timeout: quick 15 s, targeted tests 3 min (use 10 min for heavy packages), fuzz 60 s, build 5 min.
- At most 2 heavy jobs machine-wide, and other agents are running. Wait in a bounded loop (every 60 s, 30 min max) while load5 > 15. If load never drops, run only the targeted packages. Before `make check`, wait until `pgrep -f scripts/check.sh` is empty.
- Tests: `TZ=UTC go test -race -count=1 ./modules/sensor-active/... ./core/sensorlink/... ./cmd/vedette-sensor/... ./modules/scan/...`.
- Linux lint: 0 issues.
- Run `make check` once at the end.
- No new dependency.
- Never `go build ./cmd/vedette` at the repo root.
- Do not modify Emily's `modules/scan` beyond implementing the seam it declares. If you need a change there, report it instead.
- New D-xx: use **D-133**.

## Report
- Each requirement → code (file:line) → test → pass.
- The seam and what Emily calls.
- Test counts, Linux lint, and the tail of `make check`.
