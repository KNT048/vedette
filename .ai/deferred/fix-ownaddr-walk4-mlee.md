# Deferred: fix/ownaddr-walk4-mlee (walk 4, one rule for Vedette itself, D-446)

- [ ] 2026-11-13 — `core/conn` (connections) and the `response` webhook still refuse the machine's addresses on every port, while feeds, notify, logs and ai now refuse only Vedette's own ports there (D-446) — vì sao để sau: Kiên's area (core/, response), out of this branch's scope — ở đâu: core/conn/validate.go, modules/response/webhook.go
- [ ] 2026-11-13 — the GUI mock seeds the AI profile "Company Ollama server" at `http://localhost:11434/v1`, which D-446 refuses at save (a profile saved before D-446 still loads); a mock user who edits it gets the "Vedette itself" sentence — vì sao để sau: web/src/mocks/stores.ts is Kiên-side (seed data, no new field) — ở đâu: web/src/mocks/stores.ts:111
