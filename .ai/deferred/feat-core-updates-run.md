# Deferred: feat/core-updates-run (run side of the software update, D-342)

- [x] Merge with the check side: delete `modules/core/updates_check_stub.go` (offered, runningRestoresData, setManual, updatesView, CoreGetCoreUpdates) when `updates_check.go` lands; keep `updRun.seam` + `export_updates_test.go` for the run side's tests, or switch them to the check side's signed fixtures. Check that `setManual` runs inside the caller's transaction (rollback and the rebuilt rollback of D-342 (4)). — **Done** (2026-11-12, before-v1 Mac recheck): #432: modules/core/updates_check_stub.go is gone; `setManual(ctx, tx, by)` (updates_check.go:151) runs in the caller's transaction (updates_run.go:243 rollback plan, :957 rebuilt rollback).
- [ ] Automatic mode: install the offered release by itself inside the maintenance window (`os.settings` window, user "system"), through the same `beginUpdate` plan (no admin check, audit user "system").
- [ ] Bundle (`POST/GET /core/updates/bundle`): still 501; needs host `source=bundle` (host answers `bundle_unsupported`, `.ai/deferred/feat-host-net-containers.md`).
- [ ] A service that was off during an update stays on the old image: when its module is turned on, `cmd/vedette/modulecontainer.go` (OnGuard) starts the pinned (old) version. Send `version` = core's running version there (D-342 (2)).
- [ ] Events `core.update.applied|rolled_back` (CONTRACT Events) are not published: `OSHandlers` has no bus; wire one when a receiver exists (notify).
- [ ] `index_expired` from `container.pull`/`start` results is not shown on the page yet (D-130 says the caller shows it).
- [ ] e2e-real: one apply and one rollback against the real host on the Ubuntu box (needs a signed test release).
