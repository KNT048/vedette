-- name: InsertAudit :exec
INSERT INTO core_audit (id, prev_hash, hash, ts, user, action, target, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: LastAuditHash :one
SELECT hash FROM core_audit ORDER BY seq DESC LIMIT 1;

-- name: ListAuditAfter :many
SELECT seq, id, prev_hash, hash, ts, user, action, target, detail
FROM core_audit
WHERE seq > ?
ORDER BY seq
LIMIT ?;

-- name: GetChainAnchor :one
SELECT chain, last_pruned_id, last_pruned_hash, pruned_at
FROM core_chain_anchor
WHERE chain = ?;

-- name: MaxAuditSeq :one
SELECT CAST(COALESCE(MAX(seq), 0) AS INTEGER) FROM core_audit;

-- The audit screen and its CSV export (GET /core/audit, /core/audit/export): newest first, keyset on seq
-- (seq < before_seq), every filter optional. The text filter is a case-insensitive substring over the
-- same four columns the screen shows; lower() folds ASCII only. The group is the part of the action before
-- the first dot. people (D-416), when set, leaves out the automatic lines: user "system" or "system:<part>".
-- name: ListAuditFiltered :many
SELECT seq, id, ts, user, action, target, detail
FROM core_audit
WHERE seq < sqlc.arg('before_seq')
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
  AND (sqlc.narg('who') IS NULL OR user = sqlc.narg('who'))
  AND (sqlc.narg('grp') IS NULL OR substr(action, 1, instr(action, '.') - 1) = sqlc.narg('grp'))
  AND (sqlc.narg('people') IS NULL OR (user <> 'system' AND substr(user, 1, 7) <> 'system:'))
  AND (sqlc.narg('needle') IS NULL OR instr(lower(action || ' ' || target || ' ' || COALESCE(detail, '') || ' ' || user), sqlc.narg('needle')) > 0)
ORDER BY seq DESC
LIMIT sqlc.arg('max_rows');

-- name: CountAuditFiltered :one
SELECT count(*)
FROM core_audit
WHERE seq <= sqlc.arg('upto_seq')
  AND (sqlc.narg('from_ts') IS NULL OR ts >= sqlc.narg('from_ts'))
  AND (sqlc.narg('to_ts') IS NULL OR ts <= sqlc.narg('to_ts'))
  AND (sqlc.narg('who') IS NULL OR user = sqlc.narg('who'))
  AND (sqlc.narg('grp') IS NULL OR substr(action, 1, instr(action, '.') - 1) = sqlc.narg('grp'))
  AND (sqlc.narg('people') IS NULL OR (user <> 'system' AND substr(user, 1, 7) <> 'system:'))
  AND (sqlc.narg('needle') IS NULL OR instr(lower(action || ' ' || target || ' ' || COALESCE(detail, '') || ' ' || user), sqlc.narg('needle')) > 0);

-- name: ListAuditUsers :many
SELECT DISTINCT user FROM core_audit ORDER BY user;

-- name: ListAuditGroups :many
SELECT DISTINCT substr(action, 1, instr(action, '.') - 1) AS grp FROM core_audit ORDER BY grp;
