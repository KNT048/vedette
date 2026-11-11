# Deferred — fix/response-e2e-bugs (2026-11-11)
- [ ] D-285 (1): check whether `core_audit` (`/core/audit`?) and `ai_activity` serve their chained `ts` as `date-time` (ogen drops the milliseconds, #308 pattern); if so, same fix (string as stored) + a handler-level re-hash test. Owner: core = Kiên, ai = Emily.
- [ ] D-286 (3): `switch_port` of the honeypot trigger is empty until a real switch-port source exists.
