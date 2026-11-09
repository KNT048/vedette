-- name: InsertSecret :exec
INSERT INTO core_secret (id, purpose, nonce, ciphertext, key_version, last4, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSecret :one
SELECT id, purpose, nonce, ciphertext, key_version, last4, created_at, rotated_at
FROM core_secret
WHERE id = ?;

-- name: ReplaceSecret :execrows
UPDATE core_secret
SET nonce = ?, ciphertext = ?, key_version = ?, last4 = ?, rotated_at = ?
WHERE id = ? AND purpose = ?;

-- name: DeleteSecret :execrows
DELETE FROM core_secret WHERE id = ?;

-- name: GetSecretIDByPurpose :one
SELECT id FROM core_secret WHERE purpose = ? ORDER BY created_at, id LIMIT 1;
