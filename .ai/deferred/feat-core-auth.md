# Deferred — feat/core-auth (WP-04b part 1)

- [ ] Pending TOTP rows (`core_user_totp.confirmed = 0`) expire when confirmed (10 min) but are never deleted by a job; add a `core` job that removes them, and old `core_email_code_send` rows of users who never send again (WP-04b part 2, with the other jobs).
- [ ] Login rate limit is in memory (resets on restart, per process, 10,000 keys): a `core_login_failure` table pruned by a job if it matters. There is no per-IP cap across emails; API_CONVENTIONS §8 lists 60 req/min per IP for public endpoints as an HTTP-level limit (part 2).
- [ ] `core_session` rows stay for ever: DATA_MODEL says delete 30 days after `expires_at`/`revoked_at`; the pruning job is not written (part 2).
- [ ] `ai_activity` (module ai) and `resp_log` (module response) must call `chain.AdvanceHead` in their appends and verify with `chain.NewVerifierWithHead` (issue #17); `modules/ai` should drop its local `ChainHead`. Tell Emily when this merges.
- [ ] Retention prune of any hash chain must lower `core_chain_head.count` in the same transaction (prune is not built yet): add to the prune WP's acceptance.
- [ ] `notify` must implement `auth.CodeMailer` (`Available`, `SendCode`) and `main` must pass it in `auth.Config.Mailer`; until then email two-step reports "unavailable".
- [ ] Host allowlist (anti DNS-rebinding), the HTTP handlers, `GET /me` and `/auth/*` wiring, `Retry-After` on rate-limit responses (done in `apierr.Write`): WP-04b part 2.
