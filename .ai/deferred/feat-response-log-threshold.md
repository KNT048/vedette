# Deferred — feat/response-log-threshold (2026-11-12)
- [x] D-287 (4): Done in #348 (D-288): tpl-vpn-ban, tpl-ssh-acl ban by address again; `source_ip` filled from `logs.TopAddresses`.
- [x] logs IMPACT.md: `Counts` names response PollLogs; `TopAddresses` caller updated in #348.
- [x] Review r1 (M2): Done in #348: `responseLogCounts.Sources` reads `logs.Service.SourceNames`.
- [ ] Review r1 (L7): dev databases may hold log_threshold rules saved with the old template conditions (`signature eq`, `count gte`); they load but never poll. No release is tagged; re-save them or drop them.
- [ ] #348 review r1 (L5): log events stored before #348 have ids `…:N:<unix>`, not matched by the new `…/` keys: a burst in progress at the upgrade fires once more. No release tagged; accepted.
