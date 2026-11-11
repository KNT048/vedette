# Deferred — feat/response-log-threshold (2026-11-12)
- [x] D-287 (4): Done in #348 (D-288): tpl-vpn-ban, tpl-ssh-acl ban by address again; `source_ip` filled from `logs.TopAddresses`.
- [ ] GUI: the trigger catalog has no per-trigger "module off" flag; the log_threshold description says it needs the Logs module. A real flag (`available`, `unavailable_reason` on TriggerInfo) needs a story.
- [x] logs IMPACT.md: `Counts` names response PollLogs; `TopAddresses` caller updated in #348.
- [x] Review r1 (M2): Done in #348: `responseLogCounts.Sources` reads `logs.Service.SourceNames`.
- [ ] Review r1 (L7): dev databases may hold log_threshold rules saved with the old template conditions (`signature eq`, `count gte`); they load but never poll. No release is tagged; re-save them or drop them.
- [ ] #348 review r1 (L3): more than 50 addresses over N, or all hits already quiet while new addresses under the top 50 reach N: those never fire, and the source-only event does not either (a missed detection, never a wrong ban). Fix: also make the source event when every hit is quiet and 50 came back - where: modules/response/logthreshold.go PollLogs.
- [ ] #348 review r1 (L4): one burst can make an address event and later, as that address's lines leave the window while others keep the total at N, a source-only event (a second notice, the ban is refused) - where: logthreshold.go.
- [ ] #348 review r1 (L5): log events stored before #348 have ids `…:N:<unix>`, not matched by the new `…/` keys: a burst in progress at the upgrade fires once more. No release tagged; accepted.
- [ ] #348 review r1 (M1 residual): a ban rule on a connectionless deny signature can ban a forged source; today only the trigger description and D-288 (6) say so. A real guard (logs marks session-backed signatures, response refuses address bans on others, or asks approval) needs a story.
