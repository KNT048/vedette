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
`vedette-host-upgrade.service` with `systemd-run`. That unit runs the old binary in `-self-update-apply` mode (the
"applier"), outside the host unit's cgroup. The applier runs `apt-get install <file>`. The package's postinst restarts the
host, the new host writes `started.json` after READY, and the applier checks that it is healthy (right version,
`MainPID`, stable for 30 s). If it is not, the applier reinstalls the kept previous `.deb`. Whichever host is running reads
the journal and settles the run, and it holds the write lock across the restart (`Options.Resume`). Only upgrades are
allowed, and there is no rollback by hand. In core's software run, the host step comes first: a host step that fails stops
the run before any image changes.

## 1. Slices

GUI-first order (`rules/gui-first.md`): the host command is below core's API, so it comes first, as `container.*` did.
The core API and the GUI follow: mock and GUI before the core backend. Each slice is one PR, has its own branch and gets an
Opus review (host code, D-255).

### Slice 1: the framework keeps a running run across a host restart (`host/server`)

- `Options.Resume` today keeps only `awaiting_confirm` runs (D-100). Extend it to keep a `running` run when the callback
  says so, keep the write lock held by that run, and add a `Settle` path for a resumed running run: exactly once, and the
  audit line, the final event and the lock release happen in that order, as in the awaiting run.
- A resumed run's events go on from the stored ones (`seq` continues; `Last-Event-ID` still works).
- Files: `host/server/{server,awaiting,registry}.go` (or a new `resume.go`), `host/server/*_test.go`, and
  `modules/host/contract_test.go` for the INV-3 rows.
- Tests: a running run of a test-only command survives `New` with Resume and keeps `409 busy` for other writes; Settle
  ends it once; a Resume that panics counts as "no" (`failed host_restarted`); Settle after Shutdown is refused.

### Slice 2: the host command, the applier, the reader (`host/ops`, `cmd/vedette-host`)

- `host/ops/selfupdate.go`: `Check` (order of host-api §6.14), `Run` (stage, `dpkg-deb --field`, `apt-get -s`, journal,
  `systemd-run`, wait). `selfupdatestate.go`: `versions.json`, `journal.json`, `started.json` with strict readers and
  atomic writes, adoption at `Start`, keeping `packages/` at two files. `selfupdateapply.go`: the applier, with phases,
  effect checks and rollback. `selfupdateargv.go`: builders and validators for `systemd-run`, `dpkg-deb`, `dpkg-query`,
  the `apt-get` forms and `systemctl show|restart|is-active` (two runners: the host runner never accepts `install <file>`,
  `dpkg -i` or a restart of its own unit). `Ops.Start`/`AfterReady`: read the journal before Listen, write `started.json`
  after READY, then start the settle goroutine, and dispatch the applier again when the run is not ended and the applier
  is dead (`attempt` ≤ 2).
- `os.install` drops `vedette-host` from its upgrade list as a second layer (no apt repository carries it, D-81).
- `host/api/selfupdate.go`: args, result and codes. `host/client`: `SelfUpdate`, `StateHost`. `GET /v1/state/host`
  goes through `server.Readers`.
- `cmd/vedette-host`: the `-self-update-apply rn_<16 hex>` flag. It refuses when it is not root, and it opens no socket,
  no `host.lock` and no audit file.
- `host/ops/opstest`: a `SelfUpdate` fake world. The fake `systemd-run` runs the applier in a goroutine. The fake
  `apt-get` changes the "installed version" and calls a hook that simulates postinst `try-restart`: it stops the `Ops` and
  starts a new one from the same state dir. Fakes for `dpkg-query` and `systemctl show`. Markers for "new host never
  writes started.json", "crash-loops (NRestarts grows)", "apt fails", "rollback apt fails", "policy-rc.d (no restart)",
  "applier dies at phase X".
- Tests, all in `modules/host/contract_selfupdate_test.go` and `host/ops/selfupdate*_test.go`: the contract tests named in
  host-api §6.14 "Đề xuất cho CONTRACT.md" (INV-26 … INV-30, POST-5, FORBID-7). Also
  `TestTimeLimitsAreConsistent` (60 min command ≥ applier 45 min + slack), fuzz for every new validator and for the journal
  and started readers, and the real `internal/release` vectors under `-tags releasetestkeys` (a manifest with a `host`
  part).
- Docs in the same PR: add INV-26 … INV-30, POST-5 and FORBID-7 to `modules/host/CONTRACT.md` and the allowlist row, update
  `modules/host/IMPACT.md`, and turn host-api §6.14 "Trạng thái: thiết kế" into "Đã xây". Add a RUNBOOK section
  "vedette-host self-update stopped half way" (what is in `selfupdate/`, `apt-get install --allow-downgrades` of the kept
  `.deb`, deleting `journal.json`).
- Timing in tests: `testing/synctest` or waiting on state, never wall-clock deadlines (D-373 (3)). The 120 s health and
  30 s stability windows are `Deps` seams.

### Slice 3: ship the first kept package (`install.sh`, release builder)

- `install.sh` `install_deb`: after the install is verified, put the `.deb` at
  `/var/lib/vedette-host/selfupdate/packages/vedette-host_<debver>_<arch>.deb` (0600 root, `install -d -m 0700` for the
  folders). This runs on every install and every repair or upgrade by `install.sh`. The host adopts the file at its next
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
  busy) and `rollback_failed`. Each has the exact sentence of the story.
- `UpdatesSection.tsx`: the System helper row (no Rollback), "Includes system helper <v>." on the available release, the
  `host` step label and its in-progress sentence, run errors. `locales/en/core.json`: the strings.
- Tests: vitest for each scenario (row, step, end sentence, buttons disabled while running, no Rollback on the host row),
  and the e2e spec of the Updates page (desktop) for success, reverted and one refusal. QA per `docs/QA.md`: an
  independent reviewer, the persona walkthrough, light and dark themes, and phone width.
- `PRIVACY.md` flow 6 and the Settings → Privacy text (`core.json`): add "and the package of the system helper
  `vedette-host`" to the GitHub releases item. There is no new destination, but the text must stay exact (rules/legal.md).

### Slice 5: core backend

- `modules/core/updates_run.go`: the plan gets a first call `host.self_update` when `manifest.host.version` is above
  `/v1/info.host_version` and `commands[]` has the command. The download goes to `<core_data>/host-packages/<hex32>.deb`
  (`O_EXCL` 0600). The size is capped at the manifest `size` and the SHA-256 is checked before the call. The redirects use
  `releaseHosts`, as in the check. The call uses its own idempotency key stored before sending, and the wait is 65 min
  (60 at the host). A step that is not `succeeded` stops the run with the mapped error. On success the plan goes on to
  the image pulls.
- Reconnect: the host socket drops while the host restarts. Use the same lookup-by-key path that core's own restart uses.
- `updates_check.go`: the `host` component (version from `/v1/info`), and "Includes system helper" on the offered release.
  History rows with `component: host`. Sweep `host-packages/` at start (files older than 1 hour), as with snapshots.
- Map the host codes to the API error sentences of the story (core CONTRACT INV-21 table).
- Tests: `updates_run_test.go` with a fake host for success, reverted (run stops, no `container.pull` call), refusal, a
  host restart in the middle (`ErrUnreachable` then the run found by key), a download that does not match the hash (no
  host call), and a host without the command (no step). `modules/core/CONTRACT.md` / `IMPACT.md`.

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
4. Reboot the VM while the applier is in `installing`: the next boot finishes or rolls back, `attempt` is 2, and nothing
   loops.
5. `policy-rc.d` that forbids starts (exit 101): the applier restarts the host itself.
6. unattended-upgrades holding the dpkg lock: `409 dpkg_locked` at Check, or `not_started dpkg_locked` after 10 min.
7. A leftover `vedette-host-upgrade.service` (failed, not collected) on the second run: `--collect` prevents it; confirm
   what `systemd-run` says when the name is taken.
8. `postinst try-restart` with the new host's `TimeoutStartSec` (Type=notify): no deadlock, because the new host
   sends READY before it waits for the journal.

## 2. Risks

| Risk | What guards it |
|---|---|
| Deadlock: postinst `try-restart` waits for READY, and a new host that waits for the applier before READY | The host reads the journal before Listen but waits for it only after READY (same lesson as UNIT-2/D-123 H1); lab check 8 |
| The new host crash-loops and the box reboots during the applier window, so nobody restarts the applier | Accepted limit (D-316); RUNBOOK; the GUI shows the host unreachable with its last known version |
| A compromised core forces a downgrade of the root helper | Only upgrades; no manual rollback command; the automatic rollback goes only to the recorded previous with its hash checked again (INV-29) |
| A compromised core swaps the file after Check | The host copies and hashes in one pass into a root-only folder, and apt only sees the copy (INV-26) |
| Two writers corrupt the audit chain | The applier never opens it; phases go through the journal (INV-30) |
| The old host's run files read by the new host | The run and journal formats are a contract: a new host reads the previous release's files (N−1 test with stored fixtures) |
| apt state: a stale list, or the dependency mirror is offline | `apt-get update` when the snapshot is older than 24 h, and a simulation before any change (`dependencies_unavailable`) |
| Dependencies installed by a self-update are not removed by `install.sh --uninstall` | Deferred line (`.ai/deferred/feat-host-self-update.md`) |
| The host's write lock is held up to 60 min | The same scale as `container.start` (45 min); the GUI says the helper is busy |
| `systemd-run` unit name collision | `--collect`; a leftover active unit gives `409 busy` at Check; lab check 7 |
| arm64 is untested | Same path; `feat-multiarch-images.md` lab on real arm64 |

## 3. What does not change

- `deploy/deb/postinst` keeps `restart_after_upgrade`: it is what restarts the host, from outside the cgroup when the
  applier runs dpkg.
- `deploy/systemd/vedette-host.service` does not change (`KillMode=control-group` stays; the transient unit has no
  hardening, like `apt-daily-upgrade.service`).
- No new outbound host and no new cookie, setting or button.
