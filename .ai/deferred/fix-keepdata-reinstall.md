# Deferred: fix/keepdata-reinstall (W2-9, W2-10, D-418)

- [ ] Keep-data reinstall with a NEWER release: take a backup of the kept core data (DB + key) before the new core migrates it, as Settings -> Updates does with its pre_update backup (Opus review M4; today only a warning and RUNBOOK §1.3). Also check the manifest's min_upgrade_from against the release that last ran.
- [ ] kept_release reads only `current` of versions-core.json; a core transition that took effect but was not completed (transition-core.json newer) under-reports the release that ran (Opus review L3). Take the higher of the two.
- [ ] install.sh skips the bootstrap when core has its record and unit; a bootstrap that died after core's unit but before another service's leaves that service without a unit on every re-run (pre-existing, Opus review L5). Skip only when every versions-<svc>.json has its vedette-<svc>.container.
- [ ] Run `make install-check` (needs a Linux box with rootless podman and dist/install) for the new keep-data / W2-10 case: not runnable on the Mac; the supervisor tests on the real box.
