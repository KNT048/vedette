# Deferred — feat/core-auth (WP-04b part 1)

- [ ] Pending TOTP rows (`core_user_totp.confirmed = 0`) expire when confirmed (10 min) but are never deleted by a job; add a `core` job that removes them, and old `core_email_code_send` rows of users who never send again (WP-04b part 2, with the other jobs).
- [ ] Login rate limit is in memory (resets on restart, per process, 10,000 keys): a `core_login_failure` table pruned by a job if it matters. There is no per-IP cap across emails; API_CONVENTIONS §8 lists 60 req/min per IP for public endpoints as an HTTP-level limit (part 2).
- [ ] `core_session` rows stay for ever: DATA_MODEL says delete 30 days after `expires_at`/`revoked_at`; the pruning job is not written (part 2).
- [ ] `ai_activity` (module ai) and `resp_log` (module response) must call `chain.AdvanceHead` in their appends and verify with `chain.NewVerifierWithHead` (issue #17); `modules/ai` should drop its local `ChainHead`. Tell Emily when this merges.
- [ ] Retention prune of any hash chain must lower `core_chain_head.count` in the same transaction (prune is not built yet): add to the prune WP's acceptance.
- [ ] `notify` must implement `auth.CodeMailer` (`Available`, `SendCode`) and `main` must pass it in `auth.Config.Mailer`; until then email two-step reports "unavailable".
- [ ] Host allowlist (anti DNS-rebinding), the HTTP handlers, `GET /me` and `/auth/*` wiring, `Retry-After` on rate-limit responses (done in `apierr.Write`): WP-04b part 2.

## From the independent security review (2026-11-09)

- [ ] Handlers (part 2): parse the client address with `netip.ParseAddrPort(r.RemoteAddr)` (or the trusted proxy header once there is a proxy decision) and refuse the request when it fails; pass the `netip.Addr` to `LoginRequest.IP`, `ResendCode`. Map `auth` errors with `apierr.Write` (503 `server_busy` carries `Retry-After`). `POST /core/account/2fa/{confirm,email/confirm,disable}` must pass the current session id (`Sessions.CurrentID`) as `keepSessionID`.
- [ ] Unknown-email sign-in failures now write one `auth.login_failed` row each (L1: same writer work as a real account, so timing does not show which emails exist). The audit chain can grow with attacker-chosen volume, bounded only by the login limiter and the 60 req/min/IP public limit of part 2: the audit retention prune (not built) should treat `auth.login_failed` rows with target `unknown email …` as the first to go; decide a cap if the volume matters.
- [ ] The per-account two-step limiter (10 wrong codes / 15 min) lets someone who knows a password lock that account's two-step sign-in out for the wait (up to 10 min); an administrator reset or waiting clears it. Accepted trade-off against code guessing from rotating addresses; revisit if it is abused.
- [ ] Self email change does not exist in the library yet (L2 listed it); when it is added it must reject control characters with `hasControl` and answer 400 `invalid_email`.
- [ ] L4 (concurrent duplicate `CreateUser`) could not be reproduced as a failure before the fix: the single writer (`BEGIN IMMEDIATE`) serialises the existence check and the insert. The unique-constraint mapping (`store.IsUniqueViolation`) is defence in depth for callers that insert outside that serialisation; test added anyway.
- [ ] Argon2 gate sizing: `MaxHashing` defaults to `max(1, NumCPU/2)` at 64 MiB each; the installer/`DEPLOYMENT` §2.5 should state the memory this implies (4 CPUs: 128 MiB) and whether `Config.MaxHashing` is exposed in core's own config file.
