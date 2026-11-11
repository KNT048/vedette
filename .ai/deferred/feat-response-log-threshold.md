# Deferred — feat/response-log-threshold (2026-11-12)
- [x] D-287 (4): Done in #348 (D-288): tpl-vpn-ban, tpl-ssh-acl ban by address again; `source_ip` filled from `logs.TopAddresses`.
- [ ] GUI: the trigger catalog has no per-trigger "module off" flag; the log_threshold description says it needs the Logs module. A real flag (`available`, `unavailable_reason` on TriggerInfo) needs a story.
- [x] logs IMPACT.md: `Counts` names response PollLogs; `TopAddresses` caller updated in #348.
- [x] Review r1 (M2): Done in #348: `responseLogCounts.Sources` reads `logs.Service.SourceNames`.
- [ ] Review r1 (L7): dev databases may hold log_threshold rules saved with the old template conditions (`signature eq`, `count gte`); they load but never poll. No release is tagged; re-save them or drop them.
