# Deferred: feat/connections-gui (slice 13b-1)

- [ ] 13b-4: real `core/conn` store and endpoints (routes answer 501 until then); `privacyFacts.ConnectionsConfigured` then reads the store; `in_use` through `response.ChangesInForce`.
- [ ] 13b-4/5: the mock accepts `http://` targets and pins in a simplified way (TLS pin only for LAN-like hosts); the real box refuses plain HTTP (D-94) and pins per its rules. Align the mock messages when the backend lands.
- [ ] Mock-only additions beyond the brief: error `pin_mismatch` (502) on Test; a changed address, kind or sign-in forgets the pin. Confirm both in D-94 wording at 13b-4.
- [ ] `modules/ai` CONTRACT/MANIFEST still mention `ai_connectors` and the 5 `/ai/connections*` endpoints: handled by PR #84 (13b-0); check after it merges. Emily's ai contract loses the 5 endpoints.
- [ ] Mock `automation` read tool is `list_jobs`; DATA_MODEL names `get_job`. Align at 13b-4.
