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
