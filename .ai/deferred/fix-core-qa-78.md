# fix/core-qa-78 deferred

- [x] Privacy flows 3, 10, 11: `cmd/vedette/wiring.go` `privacyFacts` answers today's truth (no AI provider, default NTP, no OIDC issuer). When `ai`, `host` (NTP) and `auth-oidc` get backends, read their real settings through their services. — **Done** (sweep): flows 3 and 11 read the ai and auth-oidc services; flow 10 stays on by D-166 (the distribution's chrony sources are kept), D-289 (4).
- [ ] Issue #78 item 3 (temporary password of `POST /core/users` rejected at first sign-in) did not reproduce: HTTP tests and a real binary sign in with the returned password for operator, viewer and admin. If Emily still sees it, get the exact request/response pair (and `.dev/vedette.db` age) of her run.
- [ ] D-73: ogen body-decode errors carry no field path (core/server/errors.go:63) — all endpoints; separate PR.
- [ ] prod bundle includes msw + mock stores via features/core/logExport.ts — separate PR (lead).
