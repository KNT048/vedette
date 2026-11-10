You implement the **`healthcheck` subcommands** that the Quadlet units' `HealthCmd=` lines call. This is the gate the deferred file names before 3-8 and WP-08: without these subcommands, every `container.start` reverts. The project is Vedette (KNT048/vedette).

- **Worktree:** `/Users/kien/Desktop/vedette-wt/healthcmd`. **Branch:** `feat/healthcmd`, from origin/main.
- **Check first:** origin/main must contain both #130 (`vedette-sensor passive`) and #137 (logs export). Run `git log origin/main --oneline | grep -E "#130|#137"`. If either is missing, stop and report.
- **Shell:** use `/bin/ls`, never plain `ls`; the alias hangs.
- **Git:** commit on the branch. Do NOT push, tag or create branches.

## Read first (binding)
- `CLAUDE.md` and `.claude/rules/*` (security, ponytail, ships-as-code).
- `host/ops/quadlet.go`, the templates. The `HealthCmd=` lines are:
  - `/vedette healthcheck` for core;
  - `/vedette honeypot healthcheck` for the honeypot;
  - `/vedette-sensor healthcheck` for sensor and scan.

  Also read `HealthInterval`, `HealthStartPeriod` and `HealthRetries` there, and the gate tests `cmd/vedette/quadlet_exec_test.go` and `cmd/vedette-sensor/quadlet_exec_test.go`.
- `docs/DEPLOYMENT.md` §2.1–§2.4 (what each container is and what "healthy" means) and §12.
- `docs/DECISIONS.md`: D-105 (3) (the health effect check), D-121 L8 (honeypot `lo` up and `oif lo accept`, so a local health check works inside `vedette-hp`), D-123 and its amendments, D-113, D-114 and D-122.
- `.ai/deferred/feat-host-net-containers.md`, the "Cổng trước 3-8/WP-08" line.
- `cmd/vedette/main.go` (flags, `newFlags`, subcommand handling: today it rejects positional args) and `cmd/vedette-sensor/main.go` (`active`/`passive` subcommands and their flag sets).
- **The honeypot container:** what binary and image it runs (OpenCanary, D-89/D-90). Is `/vedette` even present in that image? If the template's `HealthCmd` can't work in that image, report it and propose the fix: a different `HealthCmd`, such as a tiny check OpenCanary's image can run, or the honeypot image built FROM something that has the binary. Do not invent an image.

## Build
1. **`vedette healthcheck` (core):**
   - Exit 0 only if core answers its own health endpoint on loopback within 3 s. Find the existing liveness route, for example `/api/v1/health` or `/core/health`; if none exists, use the cheapest unauthenticated readiness probe the server has.
   - Use TLS to 127.0.0.1:8443 with the right ServerName, and pin the box's own certificate from the data volume if it is readable. Otherwise skip verification **only** for loopback, and write in the code why that is safe.
   - No proxy env. Exit 1 with one short stderr line otherwise.
   - It must not need the master key or the DB.
2. **`vedette-sensor healthcheck`:**
   - Exit 0 if the sensor process is alive and its link to core is healthy. The sensor writes a small heartbeat file (an mtime touch on `/tmp`, which is tmpfs in the unit) after each successful heartbeat, and the healthcheck checks it is younger than 2 × the heartbeat interval.
   - Same for `active` and `passive`.
   - The healthcheck needs no creds or network.
3. **`vedette honeypot healthcheck`:** if the binary exists in that image (see above), a TCP connect to one configured OpenCanary port on 127.0.0.1 within 2 s. Read the config file the honeypot uses; never hard-code a port. If the binary does not exist in that image, change the template's `HealthCmd` to something the image has, and keep the gate test true.
4. **Gate tests:** extend the quadlet `Exec` gate tests, or add new ones, so each template's `HealthCmd` parses with the real binary's subcommand and flag set. A typo in a template must fail the test. No subcommand may need arguments the template doesn't pass.

## Tests (red first; loopback only; no real containers)
- core healthcheck: a test server on 127.0.0.1 answers healthy → 0; not listening → 1; slow → 1 within the deadline.
- sensor healthcheck: a fresh heartbeat file → 0; stale → 1; missing → 1. Test the sensor's heartbeat-file writer too.
- honeypot healthcheck, per whatever you decide.
- The gate tests.

## Docs
- DEPLOYMENT §2.x: what each health check checks.
- The deferred file: tick off the gate line, and add lab lines for the real image health checks.
- host CONTRACT/IMPACT if the template changed.

## Rules
- Every Bash command has a timeout: quick 15 s, targeted tests 3 min, `cmd/vedette` up to 6 min.
- Wait in a bounded loop while load5 > 15 (every 60 s, 30 min max). Before `make check`, wait until `pgrep -f scripts/check.sh` is empty.
- Tests: `TZ=UTC go test -race -count=1 ./cmd/vedette/... ./cmd/vedette-sensor/... ./host/ops/... ./modules/sensor-passive/... ./modules/sensor-active/...`.
- Linux lint: 0 issues. Run `make check` once at the end.
- No new dependency. Never `go build ./cmd/vedette` at the repo root.
- New D-xx: **D-137**.

## Report
Each item → file:line → test → pass; the honeypot finding; test counts, lint, and the tail of `make check`.
