-- name: GetOrg :one
SELECT id, name, timezone, setup_complete, data_mode, install_id FROM core_org WHERE id = 1;

-- name: InsertOrg :exec
INSERT INTO core_org (id, name, timezone, setup_complete, data_mode, install_id)
VALUES (1, ?, ?, 1, ?, ?);

-- name: UpdateOrgGeneral :execrows
UPDATE core_org SET name = ?, timezone = ? WHERE id = 1;

-- name: UpsertSetting :exec
INSERT INTO core_setting (key, value, updated_at, updated_by)
VALUES (?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by;

-- name: UpdateUserName :execrows
UPDATE core_user SET name = ? WHERE id = ?;

-- name: ListUsers :many
SELECT id, name, email, role, password_hash, cred_version, twofa_method, disabled, created_at, last_login, temp_password_expires_at
FROM core_user
ORDER BY created_at, id;

-- name: GetSetting :one
SELECT value FROM core_setting WHERE key = ?;
