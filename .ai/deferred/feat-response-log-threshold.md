# Deferred — feat/response-log-threshold (2026-11-12)
- [ ] D-287 (4): bring back the address-ban templates (tpl-vpn-ban, tpl-ssh-acl) and fill `source_ip` once logs has the per-address port (#338, owner:emily).
- [ ] GUI: the trigger catalog has no per-trigger "module off" flag; the log_threshold description says it needs the Logs module. A real flag (`available`, `unavailable_reason` on TriggerInfo) needs a story.
- [ ] logs IMPACT.md (Emily's module) still says `Counts` has "1 caller (later)": the caller is now response PollLogs (#332). Ask Mlee to update.
- [ ] Review r1 (M2): `responseLogCounts.Sources` uses `logs.Service.Sources`, the full Logs page view (it also reads the inventory), once a minute while a log rule is on. Ask Mlee for a narrow ids-and-names read in logs.
- [ ] Review r1 (L7): dev databases may hold log_threshold rules saved with the old template conditions (`signature eq`, `count gte`); they load but never poll. No release is tagged; re-save them or drop them.
