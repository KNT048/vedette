# Deferred from feat/conn-read (core/conn/read, D-127)

- [ ] **Emily (WP-25)**: PRIVACY flow 3 (device data goes only to internal AI profiles) must be enforced when `ai` is wired to `core/conn/read`: device output now enters the AI context, so a provider that is not an internal profile must never receive a tool result of a connection. `ai_activity` should record `connection_id` and `tool` of every read tool call (the reader's own log line is not the audit trail).
