# fix/privacy-accuracy (WP-08j, D-153)
- [ ] Before release: `PATCH /core/privacy` (modules/core/handlers_privacy.go) still accepts `telemetry: true` and stores it (unset counts as on, `telemetry()` returns true); the GUI no longer offers it (D-153). Refuse a PATCH that turns it on (and make GET report `enabled: false`) before release, with a contract test and CONTRACT INV-10 update.
