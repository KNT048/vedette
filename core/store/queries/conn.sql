-- name: InsertConnection :exec
INSERT INTO core_connection (id, name, name_key, kind, target, asset_id, auth_type, username, secret_id, key_fp, pin, pin_seen, allow, enabled, status, last_test, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateConnection :execrows
UPDATE core_connection
SET name = ?, name_key = ?, kind = ?, target = ?, asset_id = ?, auth_type = ?, username = ?, secret_id = ?, key_fp = ?, pin = ?, pin_seen = ?, allow = ?, enabled = ?, status = ?, last_test = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteConnection :execrows
DELETE FROM core_connection WHERE id = ?;

-- name: CountConnections :one
SELECT count(*) FROM core_connection;

-- name: ConnectionNameTaken :one
SELECT EXISTS (SELECT 1 FROM core_connection WHERE name_key = ? AND id <> ?);

-- name: AnyEnabledConnection :one
SELECT EXISTS (SELECT 1 FROM core_connection WHERE enabled = 1);

-- name: GetConnection :one
SELECT c.id, c.name, c.kind, c.target, c.asset_id, c.auth_type, c.username, c.secret_id, c.key_fp, c.pin, c.pin_seen, c.allow, c.enabled, c.status, c.last_test, c.updated_at, s.last4
FROM core_connection c LEFT JOIN core_secret s ON s.id = c.secret_id
WHERE c.id = ?;

-- name: ListConnections :many
SELECT c.id, c.name, c.kind, c.target, c.asset_id, c.auth_type, c.username, c.secret_id, c.key_fp, c.pin, c.pin_seen, c.allow, c.enabled, c.status, c.last_test, c.updated_at, s.last4
FROM core_connection c LEFT JOIN core_secret s ON s.id = c.secret_id
ORDER BY c.rowid;

-- name: InsertConnectionTool :exec
INSERT INTO core_connection_tool (connection_id, name, pos, access, description, enabled) VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteConnectionTools :exec
DELETE FROM core_connection_tool WHERE connection_id = ?;

-- name: ListConnectionTools :many
SELECT connection_id, name, pos, access, description, enabled FROM core_connection_tool ORDER BY connection_id, pos;

-- name: ListToolsOfConnection :many
SELECT connection_id, name, pos, access, description, enabled FROM core_connection_tool WHERE connection_id = ? ORDER BY pos;
