# `host.self_update`: plan

Status: design for the lead and the Opus reviewer. No code is written yet. Sources: D-316 (`docs/decisions/D-316.md`), the
spec `docs/specs/host-api.md` §6.14, the story S-CORE-2 criterion D-316 in `docs/USER_STORIES.md`, D-57 (21), D-155 (8),
D-340. It closes `.ai/deferred/feat-host-deb.md` line 2, `.ai/deferred/feat-host-framework.md` line 2 and
`.ai/deferred/feat-host-net-containers.md` line 7 once slices 1 to 6 are merged.

## 0. The design in one paragraph

Core downloads the `.deb` named in the signed manifest from the GitHub Release (no new host leaves the box) into
`<core_data>/host-packages/<hex32>.deb`. It then calls `host.self_update {version, index+sig, manifest+sig, package}`.
The host re-verifies the documents with `verifyPull`, copies the file into a root-only folder while it hashes it, and
compares the hash with `host.files[]`. It simulates the apt install, writes `selfupdate/journal.json` and starts
`vedette-host-upgrade.service` with `systemd-run`. That unit runs a copy of the old binary
(`<state>/selfupdate/applier`, copied from `/proc/self/exe`) in `-self-update-apply` mode (the "applier"), outside the
host unit's cgroup. `Run` then returns a parked result (`server.Parked`), so the run stays `running` with the write lock
through the SIGTERM that postinst sends. The applier runs `apt-get install <file>` with a dpkg lock timeout, or
`dpkg -i <file>` when an interrupted dpkg left the package half done. The package's postinst restarts the host, the new
host sends READY and then writes `started.json`, and the applier checks that the new host is healthy (right version,
`MainPID`, stable for 30 s). If it is not, the applier checks the effect first and otherwise reinstalls `from`, the
running version kept as a `.deb`. Whichever host is running reads the journal and settles the run (`Settle`). Only
upgrades are allowed, and there is no rollback by hand. In core's software run, the host step comes first: a host step
that fails, or a host too old to have the command, stops the run before any image changes.

## 1. Slices

GUI-first order (`rules/gui-first.md`): the host command is below core's API, so it comes first, as `container.*` did.
The core API and the GUI follow: mock and GUI before the core backend. Each slice is one PR, has its own branch and gets an
Opus review (host code, D-255).

### Slice 1: a parked run survives the host's own restart (`host/server`)

Why this slice exists (review H1): today a SIGTERM makes `Server.Shutdown` cancel `baseCtx`
(`host/server/server.go` `Shutdown`), the handler's run ends `failed` through `outcome`/`finish`
(`host/server/handlers.go`) and the lock is released, and `recover()` only offers `awaiting_confirm` runs to
`Options.Resume`. A run that merely "keeps running" cannot survive the restart that postinst causes.

- `server.Parked{Deadline, Result}`: a value `Run` returns for a command that declares `Spec.Parks`, modelled on
  `server.Awaiting` (`enterAwaiting`). The run is stored `running` with `parked_deadline`, keeps the write lock, gets one
  `parked` audit line and a `log` event, and its goroutine returns, so `Spec.Timeout` no longer applies to it.
- `Shutdown` leaves a parked run as it is on disk, as it does an awaiting run. `recover()` offers `awaiting_confirm`
  runs **and parked runs** (`running` with `parked_deadline`) to `Options.Resume` and keeps a parked one, with its lock,
  when the answer is yes. Built: other non-terminal runs are not offered, because `(*Ops).Resume`
  (`host/ops/netpending.go`) would mark a `net.apply` cut short mid-run as kept and skip `recoverOrphan`.
- `SettleParked` (a name of its own: `Settle` of awaiting runs already exists) ends a parked run exactly once
  (compare-and-swap; the loser gets `ErrNotParked`). The order is the one of an awaiting run (`liveRun.finish`): audit
  line, then the run file together with the lock release, then the final event. Events go on from the stored ones
  (`seq` continues; `Last-Event-ID` still works).
- Files: `host/server/{server,awaiting,handlers,registry}.go` (or a new `parked.go`), `host/server/*_test.go`, and
  `modules/host/contract_test.go` for the INV-3 rows.
- Tests (a test-only parking command): **SIGTERM lands while the run is parked** (`Shutdown` with the run on disk), then
  `New` with Resume brings it back `running` with `409 busy` for other writes; SIGTERM lands **before** it parks, so the
  run ends `failed shutting_down` as today and the lock is released; `Settle` ends it once and a racing second `Settle`
  gets `not_parked`; a Resume that panics counts as "no" (`failed host_restarted`); `Settle` after `Shutdown` began is
  refused and changes nothing; an invalid `Parked` (deadline in the past, command without `Spec.Parks`) gives
  `failed command_failed` and releases the lock. Review r2: the command's **first** side effect outside its state dir
  happens after parking. The test command's "dispatch" runs in the settle goroutine, so a SIGTERM before parking leaves
  nothing running. A dispatch failure is a `Settle(failed)` that releases the lock.

### Slice 2: the host command, the applier, the reader (`host/ops`, `cmd/vedette-host`)

- `host/ops/selfupdate.go`: `Check` (order of host-api §6.14; step 5 compares `versions.json.current`, the binary's own
  version and `dpkg-query`), `Run` (stage, `dpkg-deb --field`, `apt-get update` when stale, `apt-get -s`, journal with
  `deadline`, copy `/proc/self/exe` to `selfupdate/applier`, journal `staged` with `attempt: 0`, then return
  `server.Parked`; **park first, dispatch after**: the settle goroutine's first round writes `attempt: 1` and runs
  `systemd-run`, and a failed dispatch settles `failed applier_failed`).
  `selfupdatestate.go`: `versions.json`, `journal.json`, `started.json` with strict readers and atomic writes, adoption
  at `Start`, keeping `packages/` at two files with one SemVer file-name validator. `selfupdateapply.go`: the applier,
  with phases, the install-method choice (apt when `installed` and `dpkg --audit` is clean, `dpkg -i` otherwise), effect
  checks before any reinstall, and rollback to `from`. `selfupdateargv.go`: builders and validators for `systemd-run`,
  `dpkg-deb`, `dpkg-query`, `dpkg --audit|-i`, the `apt-get` forms (with `DPkg::Lock::Timeout=600`) and
  `systemctl show|restart|is-active`. There are two runners: the host runner never accepts `install <file>`, `dpkg -i`
  or a restart of its own unit. `core/exec` `Binary.Env` allows the two constant `NEEDRESTART_*` keys.
- `Ops.Start`/`AfterReady`: read the journal before Listen, answer `Options.Resume`, send READY before waiting on
  anything of the applier, write `started.json`, then start the settle goroutine. Each 2 s round reads the journal **and**
  `systemctl is-active vedette-host-upgrade.service`. When the run is not ended and the applier is dead, it dispatches
  the applier copy again (`attempt` 2) only if now + 60 min ≤ `journal.deadline`; otherwise it ends the run
  `self_update_interrupted`. It ends the run at `journal.deadline` once the unit has stopped. Orphan journals at
  `Start` (the run is not `running`): `attempt: 0` → clean up and audit `self_update_abandoned`; `attempt` ≥ 1 → raise
  the write gate (`409 transition_pending`), follow the journal to its end without a run, then lower the gate.
- Applier lock wait before every `dpkg -i` (review r2): the `F_GETLK` probe of `host/ops/lock.go` (four lock files)
  every 5 s, up to 10 min in total per install. If `dpkg -i` fails while the probe sees the lock again, the applier waits
  within the same budget and retries once.
- State formats (review M6): no host state file is rewritten into a form the previous release cannot read while a
  self-update journal is not `installed`; any real format change runs after `Settle(succeeded)`. Keep a `testdata`
  state folder per release (taken at `checking`) and test that the previous release's `Start` accepts it.
- `os.install` drops `vedette-host` from its upgrade list as a second layer (no apt repository carries it, D-81).
- `host/api/selfupdate.go`: args, result and codes. `host/client`: `SelfUpdate`, `StateHost`. `GET /v1/state/host`
  goes through `server.Readers`.
- `cmd/vedette-host`: the `-self-update-apply rn_<16 hex>` flag. It refuses when it is not root, and it opens no socket,
  no `host.lock` and no audit file.
- `host/ops/opstest`: a `SelfUpdate` fake world. The fake `systemd-run` runs the applier in a goroutine. The fake
  `apt-get` changes the "installed version" and calls a hook that simulates postinst `try-restart`: it **shuts the
  `Server` down as a SIGTERM would** and starts a new `Server` + `Ops` from the same state dir. The fake also swaps the
  file at the `/usr/lib/vedette/vedette-host` seam at unpack, so a test can prove the second dispatch runs the copy. Fakes
  for `dpkg-query`, `dpkg --audit|-i` and `systemctl show`. Markers: "new host never writes started.json",
  "crash-loops (NRestarts grows)", "apt fails", "rollback apt fails", "policy-rc.d (no restart)", "applier dies at
  phase X", **"dpkg interrupted"** (status `half-installed`, `--audit` not clean, apt refuses "dpkg was interrupted":
  only `dpkg -i` of this package succeeds), **"lock taken after Check"** (the first apt waits on
  `DPkg::Lock::Timeout`; when the lock outlives it, apt exits 100 and nothing changed, so the rollback sees `from`
  installed and healthy and does not reinstall), **"lock taken right after the probe"** (`dpkg -i` exits on the lock
  once; the applier waits and retries within the 10 min budget), **"SIGTERM before parking"** (no `systemd-run` call,
  journal `staged` cleaned at the next `Start`), **"dispatch fails"** (`applier_failed`, lock released), **"run file
  lost after dispatch"** (orphan journal, write gate), **"applier dies at minute 75"** (no second applier, because it
  would pass the deadline).
- Tests, all in `modules/host/contract_selfupdate_test.go` and `host/ops/selfupdate*_test.go`: the contract tests named in
  host-api §6.14 "Đề xuất cho CONTRACT.md" (INV-26 … INV-30, POST-5, FORBID-7). Also
  `TestTimeLimitsAreConsistent`: the pre-park `Spec.Timeout` of 10 min covers update + simulation; one applier run's
  `RuntimeMaxSec` of 60 min covers lock wait (≤ 10 min in total, also for `dpkg -i` with its one retry) + install with
  `TimeoutStartSec` + health + rollback lock wait (≤ 10 min) + rollback install + health (57 min); `journal.deadline` =
  start + 130 min covers pre-park + two applier runs + slack; a second applier is only started when now + 60 min ≤
  deadline, so no applier outlives the deadline; core waits until deadline + 5 min. Also fuzz for every new validator and for the journal
  and started readers, and the real `internal/release` vectors under `-tags releasetestkeys` (a manifest with a `host`
  part).
- Docs in the same PR: add INV-26 … INV-30, POST-5 and FORBID-7 to `modules/host/CONTRACT.md` and the allowlist row, update
  `modules/host/IMPACT.md`, and turn host-api §6.14 "Trạng thái: thiết kế" into "Đã xây". Add a RUNBOOK section
  "vedette-host self-update stopped half way" (what is in `selfupdate/`, `dpkg -i` of the kept `from` `.deb`, deleting
  `journal.json` and `applier`).
- Timing in tests: `testing/synctest` or waiting on state, never wall-clock deadlines (D-373 (3)). The 120 s health and
  30 s stability windows are `Deps` seams.

Split of slice 2 (2026-11-12, two PRs, each with its Opus review):
- **2a** (branch `feat/host-self-update-cmd`): `host/api/selfupdate.go`, `host/client` `SelfUpdate`/`StateHost`,
  `GET /v1/state/host` (`server.Readers.Host`), `selfupdateargv.go` (both runners' builders and validators;
  `core/exec` `NEEDRESTART_*` with their one value each), `selfupdatestate.go` (the file-name validator, the
  strict readers and atomic writers, adoption at `Start` with the trim to two files), `Check` and `Run` up to
  `server.Parked` (with `rc.RequestID` in the journal; a run that does not park cleans its staged journal in
  `AfterFinish`), the `os.install` second layer of FORBID-7, the `opstest` helpers for Check and Run, and the rows
  INV-26, INV-27, INV-29 and FORBID-7. The command is **not** in the registry yet: nothing settles a parked run
  before 2b, and a production command that parks without its settle goroutine would hold the write lock.
- **2b**: the settle goroutine (dispatch, re-dispatch, deadline, orphan journals, write gate, and the merge gate of
  `.ai/deferred/feat-host-parked-run.md`: recover a panic into `SettleParked(failed)` and a tested safety net past
  `parked_deadline` + margin), `Start`/`AfterReady`/`Resume`, `started.json`, the applier, the `-self-update-apply`
  flag, the fake world of the applier and of the host restart, the registry entry, INV-28, INV-30, POST-5, the
  `testdata` state folder (M6), RUNBOOK.

Built in 2b (branch `feat/host-self-update-apply`): everything listed above for 2b. The fake world is
`opstest.SUWorld` (hosts restart on the postinst marker, the applier runs through `Deps.StartUnit` after the real
systemd-run validator, markers per scenario); the "/usr/lib/vedette/vedette-host seam at unpack" was not needed:
the tests check that every dispatch runs `<state>/selfupdate/applier` holding the old binary's bytes. The safety
net of the merge gate is 15 min past the journal's deadline, in the loop and in `Resume`. Settled in 2b: the
applier's state directory comes from its own path; no `log` event at dispatch (the framework cannot add events to
a parked run; the audit line stays); `rollback_failed`, interrupted and a panic raise the write gate, and every later start
raises it again from the kept journal until a person removes it (RUNBOOK 5.6).

Settled while building 2a:
- The verification shared by `container.pull`, `-bootstrap` and `host.self_update` is `verifyRelease(command,
  version, index, index_sig, manifest, manifest_sig)` in `host/ops/pull.go` (index, manifest, version, channel hash,
  appliance install mode); `verifyPull` adds the platform, the image and cosign (review r1 LOW).
- The simulation refuses (`dependencies_unavailable`) when apt would **upgrade** another installed package, not only
  remove or purge one: a new `Depends` may add packages, never move one that `os.install` owns ("Install the
  pending OS updates first"). `SelfUpdateSimOK`, fuzzed (review r1 LOW).
- The one file-name validator refuses a prerelease with a `-` inside and build metadata, so the Debian version is
  always the SemVer one with its first `-` turned into `~` (review r1 LOW, host side; the builder side is slice 3).
- Adoption trims `packages/` to the two versions of `versions.json` at once (review r1 LOW).
- Parked-run deferred line 4 (`afterReadyGiveUp` while a parked self-update holds the lock): no change. `Check`
  refuses `transition_pending` while any unit journal or `restore.json` exists, so `AfterReady` has nothing to
  restore whenever a self-update is parked (test: the case "an open unit change" of
  `TestSelfUpdate_RefusalsAreAllDecidedInCheckWithNoWrite`).
- The run window is exactly 10 + 2 × 60 = 130 min (spec 6.14 said "+ 10 slack", which is 140): a retry after a
  full-length first run is not guaranteed (a second applier starts only when now + 60 min ≤ deadline, so none
  outlives it); core's 5 min past the deadline stay.

### Slice 3: ship the first kept package (`install.sh`, release builder)

- `install.sh` `install_deb`: after the install is verified, put the `.deb` at
  `/var/lib/vedette-host/selfupdate/packages/vedette-host_${RELEASE}_${ARCH}.deb` (the SemVer form, the same name as the
  release asset and as `host.files[].name`, never the Debian `~` form; 0600 root, `install -d -m 0700` for the folders). This runs on every install and every repair or upgrade by `install.sh`. The host adopts the file at its next
  start. `--uninstall` removes the folder with the rest of `/var/lib/vedette-host` (it already does for purge; check the
  `--keep-data` path).
- `scripts/release`: refuse a `host` part whose version has `-test.`, whose file names are not
  `vedette-host_<host.version>_<amd64|arm64>.deb`, or that has no file for an architecture of the images.
- Tests: the install.sh test harness (`scripts/dev/install-check` or what exists for D-166) checks the file and its hash.
  `scripts/release` unit tests cover the new refusals.

### Slice 4: contract, mock and GUI (S-CORE-2 criterion D-316)

- `web/src/features/core/contract.ts`: `UpdateStep` gets `'host'`, and a component `id: 'host'` (kind `software`,
  `previous: null`). Regenerate `api/openapi.json`.
- `web/src/features/core/mocks.ts`: scenarios for the release with a new helper, success, reverted
  (`self_update_unhealthy`, `install_failed`), the refusals (signature, checksum, older, test build, dependencies, dpkg
  busy), `host_too_old` (criterion (h)) and `rollback_failed`. Each has the exact sentence of the story.
- `UpdatesSection.tsx`: the System helper row (no Rollback), "Includes system helper <v>." on the available release, the
  `host` step label and its in-progress sentence, run errors. `locales/en/core.json`: the strings.
- Tests: vitest for each scenario (row, step, end sentence, buttons disabled while running, no Rollback on the host row),
  and the e2e spec of the Updates page (desktop) for success, reverted and one refusal. QA per `docs/QA.md`: an
  independent reviewer, the persona walkthrough, light and dark themes, and phone width.
- `PRIVACY.md` flow 6 and the Settings → Privacy text (`core.json`): add "and the package of the system helper
  `vedette-host`" to the GitHub releases item. There is no new destination, but the text must stay exact (rules/legal.md).

### Slice 5: core backend

- `modules/core/updates_run.go`: the plan gets a first call `host.self_update` when `manifest.host.version` is above
  `/v1/info.host_version`. When `commands[]` does not have the command, the run stops before any host call (`failed`,
  `host_too_old`, story criterion (h): "Run install.sh of release <v>…"). It never skips the step, because the new images
  may need the new host (review M7). The download goes to `<core_data>/host-packages/<hex32>.deb` (`O_EXCL` 0600). The
  size is capped at the manifest `size` and the SHA-256 is checked before the call. The redirects use `releaseHosts`, as
  in the check. The call uses its own idempotency key stored before sending, and core waits until the run's `deadline`
  (130 min from the host's start of the run) plus 5 min. A step that is not `succeeded` stops the run with the mapped
  error. On success the plan goes on to the image pulls.
- Reconnect: the host socket drops while the host restarts. Use the same lookup-by-key path that core's own restart uses.
- `updates_check.go`: the `host` component (version from `/v1/info`), and "Includes system helper" on the offered release.
  History rows with `component: host`. Sweep `host-packages/` at start (files older than 1 hour), as with snapshots.
- Map the host codes to the API error sentences of the story (core CONTRACT INV-21 table).
- Tests: `updates_run_test.go` with a fake host for success, reverted (run stops, no `container.pull` call), refusal, a
  host restart in the middle (`ErrUnreachable` then the run found by key), a download that does not match the hash (no
  host call), a host without the command while the manifest has a newer host (`host_too_old`, no host call, no image
  touched), and a release without a newer host (no step). `modules/core/CONTRACT.md` / `IMPACT.md`.

### Slice 6: lab (LAB-VM.md, default passt network, no cable needed)

On `ubuntu2404` and `debian13` (and Ubuntu 26.04 on Mlee's box, D-198), using test-channel artifacts built with
`releasetestkeys` (`install.sh --test-artifacts`):
1. Install N, then run self_update to N+1 from the GUI. Check: `dpkg-query` shows N+1, `systemctl show vedette-host`
   shows a new `MainPID`, the run is `succeeded`, `packages/` holds N and N+1, and core reconnects. Check that the
   applier was in its own cgroup (`systemctl status vedette-host-upgrade` while it runs; `/proc/<pid>/cgroup`). Check
   that the honeypot (`Requires=` the host) came back.
2. N+1 built to exit 1 at start (a test build flag): the run is `reverted self_update_unhealthy`, N runs again, and the
   journal is gone.
3. N+1 that adds a `Depends` the mirror has: the dependency is installed. A `Depends` the mirror lacks gives
   `dependencies_unavailable` with nothing changed.
4. Reboot the VM while the applier is in `installing`, once during apt's dependency step and once during the unpack of
   `vedette-host` (`/var/lib/dpkg/updates/` not empty after the boot). The next boot finishes or rolls back with the
   applier copy (not the new `/usr/lib/vedette/vedette-host`), using `dpkg -i` for the half-done package. `attempt` is
   2 and nothing loops.
5. `policy-rc.d` that forbids starts (exit 101): the applier restarts the host itself.
6. unattended-upgrades holding the dpkg lock: `409 dpkg_locked` at Check. Taken between Check and the install, apt waits
   (`DPkg::Lock::Timeout=600`) and goes on. Held longer than that, the run ends `reverted install_failed` without a
   reinstall (the effect check sees `from`).
6b. `systemctl kill -s TERM vedette-host` from outside while the run is parked: the run comes back `running` with the
   lock and ends normally.
7. A leftover `vedette-host-upgrade.service` (failed, not collected) on the second run: `--collect` prevents it; confirm
   what `systemd-run` says when the name is taken.
8. `postinst try-restart` with the new host's `TimeoutStartSec` (Type=notify): no deadlock, because the new host
   sends READY before it waits for the journal.

## 2. Risks

| Risk | What guards it |
|---|---|
| Deadlock: postinst `try-restart` waits for READY, and a new host that waits for the applier before READY | The host reads the journal before Listen but waits for it only after READY (same lesson as UNIT-2/D-123 H1); lab check 8 |
| The new host crash-loops and the box reboots during the applier window, so nobody restarts the applier | Accepted limit (D-316); RUNBOOK; the GUI shows the host unreachable with its last known version |
| The run ends `failed` on the SIGTERM that postinst sends (review H1) | `server.Parked` + Resume for parked runs (slice 1), test with SIGTERM while parked |
| A SIGTERM between dispatch and parking leaves an applier running with no run and no lock (review r2) | Park first, dispatch after (the settle goroutine dispatches); orphan journals handled at `Start` |
| A second applier outlives core's wait (review r2) | Attempt 2 only when now + 60 min ≤ deadline; core waits until deadline + 5 min |
| `dpkg -i` hits the lock just after a reboot, when the apt timers fire (review r2) | `F_GETLK` wait (10 min in total) before every `dpkg -i` and one retry |
| A dpkg cut mid-unpack blocks every apt install (review H2) | The applier picks `dpkg -i` of this package when its status is not `installed` or `dpkg --audit` is not clean; the "dpkg interrupted" marker; lab check 4 |
| unattended-upgrades takes the lock between Check and the install (review M1) | `DPkg::Lock::Timeout=600`; the rollback checks the effect before reinstalling |
| The second dispatch runs the new, broken binary (review M2) | The applier is a copy of the old binary in `selfupdate/`, with its hash in the journal |
| The new host rewrites state that the reinstalled old host cannot read (review M6) | No format change before `Settle(succeeded)`; N+1 → N `testdata` test |
| A compromised core forces a downgrade of the root helper | Only upgrades; no manual rollback command; the automatic rollback goes only to `from` (the running version, checked against the binary and `dpkg-query`) with its hash checked again (INV-29) |
| A compromised core swaps the file after Check | The host copies and hashes in one pass into a root-only folder, and apt only sees the copy (INV-26) |
| Two writers corrupt the audit chain | The applier never opens it; phases go through the journal (INV-30) |
| The old host's run files read by the new host | The run and journal formats are a contract: a new host reads the previous release's files (N−1 test with stored fixtures) |
| apt state: a stale list, or the dependency mirror is offline | `apt-get update` when the snapshot is older than 24 h, and a simulation before any change (`dependencies_unavailable`) |
| Dependencies installed by a self-update are not removed by `install.sh --uninstall` | Deferred line (`.ai/deferred/feat-host-self-update.md`) |
| The host's write lock is held up to 130 min in the worst case (two applier runs) | Normal runs take minutes; the bound is fixed in the journal and does not restart with the host; the GUI says the helper is busy (story (a) wording: deferred line) |
| `systemd-run` unit name collision | `--collect`; a leftover active unit gives `409 busy` at Check; lab check 7 |
| arm64 is untested | Same path; `feat-multiarch-images.md` lab on real arm64 |

## 3. What does not change

- `deploy/deb/postinst` keeps `restart_after_upgrade`: it is what restarts the host, from outside the cgroup when the
  applier runs dpkg.
- `deploy/systemd/vedette-host.service` does not change (`KillMode=control-group` stays; the transient unit has no
  hardening, like `apt-daily-upgrade.service`).
- No new outbound host and no new cookie, setting or button.
