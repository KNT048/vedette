# Deferred: fix/honey-token-fires (W1-28, D-507)

- [ ] `POST /honeypot/tokens` still accepts `type=dns` (only the GUI disables it): refuse it with 409 `dns_unavailable` in `AddToken` (`modules/honeypot/mutate.go`, owned by the b2-trapip branch right now; do after that merges), contract.ts enum note + mock.
- [ ] Existing DNS tokens on a box stay listed with the "cannot alert yet" text; decide whether to drop the type entirely or build a DNS listener (needs a story, D-74).
- [ ] `core/server` `secretSegments` does not mask `/t/<id>` in the panic log line of the Envelope (the honeytoken handler itself never logs the path).
