-- name: InsertJobRun :exec
INSERT INTO core_job_run (id, module, job, started_at, finished_at, status, error)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: PruneJobRuns :exec
DELETE FROM core_job_run
WHERE core_job_run.module = ? AND core_job_run.job = ?
  AND core_job_run.rowid NOT IN (
    SELECT r.rowid FROM core_job_run r
    WHERE r.module = ? AND r.job = ?
    ORDER BY r.started_at DESC, r.rowid DESC
    LIMIT ?
  );

-- name: ListJobRuns :many
SELECT id, module, job, started_at, finished_at, status, error
FROM core_job_run
WHERE module = ? AND job = ?
ORDER BY started_at DESC, rowid DESC
LIMIT ?;
