# Deferred — feat/core-auth (WP-04b part 1)

- [ ] Host allowlist (anti DNS-rebinding), the HTTP handlers, `GET /me` and `/auth/*` wiring, `Retry-After` on rate-limit responses (done in `apierr.Write`): WP-04b part 2.

## From the independent security review (2026-11-09)

- [ ] Handlers (part 2): parse the client address with `netip.ParseAddrPort(r.RemoteAddr)` (or the trusted proxy header once there is a proxy decision) and refuse the request when it fails; pass the `netip.Addr` to `LoginRequest.IP`, `ResendCode`. Map `auth` errors with `apierr.Write` (503 `server_busy` carries `Retry-After`). `POST /core/account/2fa/{confirm,email/confirm,disable}` must pass the current session id (`Sessions.CurrentID`) as `keepSessionID`.
- [ ] Argon2 gate sizing: `MaxHashing` defaults to `max(1, NumCPU/2)` at 64 MiB each; the installer/`DEPLOYMENT` §2.5 should state the memory this implies (4 CPUs: 128 MiB) and whether `Config.MaxHashing` is exposed in core's own config file.

## From the verifier round (2026-11-09)

- [x] 2026-11-10 DONE in WP-08c (D-150: `Environment=GOMEMLIMIT=1800MiB`, gate test in core/auth) — WP-08: set `GOMEMLIMIT` in the core Quadlet unit (DEPLOYMENT 2.5: 2 CPU, 2 GiB). The argon2 gate default is `min(GOMAXPROCS/2, GOMEMLIMIT/4/64 MiB)`, so without the memory limit only the CPU count (cgroup-aware in Go 1.26) bounds it.
