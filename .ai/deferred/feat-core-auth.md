# Deferred — feat/core-auth (WP-04b part 1)

- [ ] Host allowlist (anti DNS-rebinding), the HTTP handlers, `GET /me` and `/auth/*` wiring, `Retry-After` on rate-limit responses (done in `apierr.Write`): WP-04b part 2.

## From the independent security review (2026-11-09)

- [ ] Handlers (part 2): parse the client address with `netip.ParseAddrPort(r.RemoteAddr)` (or the trusted proxy header once there is a proxy decision) and refuse the request when it fails; pass the `netip.Addr` to `LoginRequest.IP`, `ResendCode`. Map `auth` errors with `apierr.Write` (503 `server_busy` carries `Retry-After`). `POST /core/account/2fa/{confirm,email/confirm,disable}` must pass the current session id (`Sessions.CurrentID`) as `keepSessionID`.
- [ ] Self email change does not exist in the library yet (L2 listed it); when it is added it must reject control characters with `hasControl` and answer 400 `invalid_email`.
- [ ] L4 (concurrent duplicate `CreateUser`) could not be reproduced as a failure before the fix: the single writer (`BEGIN IMMEDIATE`) serialises the existence check and the insert. The unique-constraint mapping (`store.IsUniqueViolation`) is defence in depth for callers that insert outside that serialisation; test added anyway.
- [ ] Argon2 gate sizing: `MaxHashing` defaults to `max(1, NumCPU/2)` at 64 MiB each; the installer/`DEPLOYMENT` §2.5 should state the memory this implies (4 CPUs: 128 MiB) and whether `Config.MaxHashing` is exposed in core's own config file.

## From the verifier round (2026-11-09)

- [ ] D-76: enabling two-step sign-in (`ConfirmTOTP`, `ConfirmEmail2FA`, i.e. `POST /core/account/2fa/confirm` and `/email/confirm`) must require the current password; with the M4 rule (enabling ends the other sessions) a stolen session could otherwise lock the owner out. Done in WP-04b part 2 (it changes the API contract, so not in this branch).
- [x] 2026-11-10 DONE in WP-08c (D-150: `Environment=GOMEMLIMIT=1800MiB`, gate test in core/auth) — WP-08: set `GOMEMLIMIT` in the core Quadlet unit (DEPLOYMENT 2.5: 2 CPU, 2 GiB). The argon2 gate default is `min(GOMAXPROCS/2, GOMEMLIMIT/4/64 MiB)`, so without the memory limit only the CPU count (cgroup-aware in Go 1.26) bounds it.
