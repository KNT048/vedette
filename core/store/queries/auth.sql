-- name: InsertUser :exec
INSERT INTO core_user (id, name, email, role, password_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetUserByEmail :one
SELECT id, name, email, role, password_hash, twofa_method, disabled, created_at, last_login
FROM core_user WHERE email = ?;

-- name: GetUserByID :one
SELECT id, name, email, role, password_hash, twofa_method, disabled, created_at, last_login
FROM core_user WHERE id = ?;

-- name: CountOtherActiveAdmins :one
SELECT count(*) FROM core_user WHERE role = 'admin' AND disabled = 0 AND id <> ?;

-- name: UpdateUserPassword :execrows
UPDATE core_user SET password_hash = ? WHERE id = ?;

-- name: UpdateUserRole :execrows
UPDATE core_user SET role = ? WHERE id = ?;

-- name: UpdateUserDisabled :execrows
UPDATE core_user SET disabled = ? WHERE id = ?;

-- name: UpdateUserLastLogin :exec
UPDATE core_user SET last_login = ? WHERE id = ?;

-- name: UpdateUserTwofaMethod :execrows
UPDATE core_user SET twofa_method = ? WHERE id = ?;

-- name: EnableUserTwofaMethod :execrows
UPDATE core_user SET twofa_method = ? WHERE id = ? AND twofa_method IS NULL;

-- name: RehashUserPassword :execrows
UPDATE core_user SET password_hash = ? WHERE id = ? AND password_hash = ?;

-- name: UpsertTotp :exec
INSERT INTO core_user_totp (user_id, secret_id, confirmed, last_step, created_at)
VALUES (?, ?, 0, NULL, ?)
ON CONFLICT (user_id) DO UPDATE SET secret_id = excluded.secret_id, confirmed = 0, last_step = NULL, created_at = excluded.created_at;

-- name: GetTotp :one
SELECT user_id, secret_id, confirmed, last_step, created_at
FROM core_user_totp
WHERE user_id = ?;

-- name: ConfirmTotp :execrows
UPDATE core_user_totp SET confirmed = 1, last_step = ? WHERE user_id = ? AND confirmed = 0;

-- name: AdvanceTotpStep :execrows
UPDATE core_user_totp SET last_step = ?
WHERE user_id = ? AND confirmed = 1 AND (last_step IS NULL OR last_step < ?);

-- name: DeleteTotp :exec
DELETE FROM core_user_totp WHERE user_id = ?;

-- name: UpsertEmailCode :exec
INSERT INTO core_email_code (user_id, code_hash, expires_at, tries, sent_at)
VALUES (?, ?, ?, 0, ?)
ON CONFLICT (user_id) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, tries = 0, sent_at = excluded.sent_at;

-- name: GetEmailCode :one
SELECT user_id, code_hash, expires_at, tries, sent_at FROM core_email_code WHERE user_id = ?;

-- name: DeleteEmailCode :exec
DELETE FROM core_email_code WHERE user_id = ?;

-- name: DeleteEmailCodeIfHash :exec
DELETE FROM core_email_code WHERE user_id = ? AND code_hash = ?;

-- name: SetEmailCodeTries :exec
UPDATE core_email_code SET tries = ? WHERE user_id = ?;

-- name: InsertEmailCodeSend :exec
INSERT INTO core_email_code_send (user_id, sent_at) VALUES (?, ?);

-- name: DeleteEmailCodeSend :exec
DELETE FROM core_email_code_send WHERE user_id = ? AND sent_at = ?;

-- name: CountEmailCodeSendsSince :one
SELECT count(*) FROM core_email_code_send WHERE user_id = ? AND sent_at > ?;

-- name: PruneEmailCodeSends :exec
DELETE FROM core_email_code_send WHERE user_id = ? AND sent_at <= ?;

-- name: InsertSession :exec
INSERT INTO core_session (id, user_id, token_hash, csrf_hash, device, ip, started_at, last_seen, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSessionByTokenHash :one
SELECT s.id, s.user_id, s.csrf_hash, s.started_at, s.last_seen, s.expires_at, s.revoked_at,
       u.email, u.role, u.disabled
FROM core_session s JOIN core_user u ON u.id = s.user_id
WHERE s.token_hash = ?;

-- name: TouchSession :exec
UPDATE core_session SET last_seen = ? WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeSession :execrows
UPDATE core_session SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;

-- name: RevokeOtherSessions :execrows
UPDATE core_session SET revoked_at = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL;

-- name: RevokeAllSessions :execrows
UPDATE core_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL;

-- name: ListSessions :many
SELECT id, user_id, device, ip, started_at, last_seen, expires_at
FROM core_session
WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? AND last_seen > ?
ORDER BY started_at DESC, id;

-- name: GetChainHead :one
SELECT chain, last_hash, count, updated_at FROM core_chain_head WHERE chain = ?;

-- name: AdvanceChainHead :exec
INSERT INTO core_chain_head (chain, last_hash, count, updated_at)
VALUES (?, ?, 1, ?)
ON CONFLICT (chain) DO UPDATE SET last_hash = excluded.last_hash, count = core_chain_head.count + 1, updated_at = excluded.updated_at;
