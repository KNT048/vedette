# Deferred: fix/honey-token-fires (W1-28, D-507)

- [x] Done (#717, D-468): `POST /honeypot/tokens` still accepts `type=dns` (only the GUI disables it): refuse it with 409 `dns_unavailable` in `AddToken` (`modules/honeypot/mutate.go`, owned by the b2-trapip branch right now; do after that merges), contract.ts enum note + mock.
- [x] Done (#717, D-468: type dropped from create, old rows list as "Cannot alert"): Existing DNS tokens on a box stay listed with the "cannot alert yet" text; decide whether to drop the type entirely or build a DNS listener (needs a story, D-74).
- [ ] `core/server` `secretSegments` does not mask `/t/<id>` in the panic log line of the Envelope (the honeytoken handler itself never logs the path).
- [ ] (2026-11-13, review L4 of #679) `ingestBatch` sets `s.hourNew = env.hourNew` (`modules/honeypot/ingest.go`) from its own snapshot, overwriting URL token opens counted meanwhile: the per-hour cap under-counts a little (never a breach of the dedupe). Fix to `s.hourNew += len(created)` with the hour check once b2-trapip (which edits `ingest.go`) has merged.
