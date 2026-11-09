# fix/core-qa-78 deferred

- [ ] Privacy flows 3, 10, 11: `cmd/vedette/wiring.go` `privacyFacts` answers today's truth (no AI provider, default NTP, no OIDC issuer). When `ai`, `host` (NTP) and `auth-oidc` get backends, read their real settings through their services.
- [ ] Issue #78 item 3 (temporary password of `POST /core/users` rejected at first sign-in) did not reproduce: HTTP tests and a real binary sign in with the returned password for operator, viewer and admin. If Emily still sees it, get the exact request/response pair (and `.dev/vedette.db` age) of her run.
