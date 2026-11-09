-- name: InsertModuleIfMissing :exec
INSERT INTO core_module (id, enabled, enabled_at, disabled_at, version)
VALUES (?, ?, ?, NULL, ?)
ON CONFLICT (id) DO NOTHING;

-- name: ListModules :many
SELECT id, enabled, enabled_at, disabled_at, version
FROM core_module
ORDER BY id;

-- name: SetModuleState :execrows
UPDATE core_module
SET enabled = ?, enabled_at = ?, disabled_at = ?
WHERE id = ?;
