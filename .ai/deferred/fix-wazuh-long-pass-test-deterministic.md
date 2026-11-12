# Deferred — fix/wazuh-long-pass-test-deterministic

- [ ] 2026-11-12 — LOW (Sonnet review): in `TestWazuh_ALongPassGoesOnAtTheNextTick` the fake's handler waits on the request context while holding the fake's lock; if net/http ever stopped noticing a client abort, the test would hang until the package timeout instead of failing fast. Theoretical (a client abort closes the connection, which the server sees); a safety timer would bring back real time — vì sao để sau: no failure seen, fix would reintroduce wall-clock waits — ở đâu: modules/agent-intake/wazuh_test.go
