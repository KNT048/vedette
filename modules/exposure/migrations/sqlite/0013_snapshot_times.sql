-- +goose Up
-- A scan is named by when it started, with when it ended next to it, on every page that shows one (the target's header, the
-- snapshot and compare pickers, Settings › Scanning › History). started_at is when the run started (before the port scan);
-- finished_at is when its last step ended (OpenVAS, an hour or more after the other results are stored), NULL while that step runs.
-- exp_target.last_scan_at becomes the start of the newest scan. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_snapshot ADD COLUMN started_at TEXT CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
ALTER TABLE exp_snapshot ADD COLUMN finished_at TEXT CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');

-- A snapshot stored before this version: the closest known start is when its results were stored.
UPDATE exp_snapshot SET started_at = scanned_at;

-- Its end: the time of its OpenVAS check line when it has one; else, when OpenVAS did not run, when its results were stored.
UPDATE exp_snapshot SET finished_at = (
    SELECT max(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(exp_snapshot.checks) AS c
    WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.kind') = 'greenbone'
      AND json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at') GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
UPDATE exp_snapshot SET finished_at = scanned_at
WHERE finished_at IS NULL AND coalesce(json_extract(greenbone_run, '$.state'), 'not_run') = 'not_run'
  AND NOT EXISTS (SELECT 1 FROM json_each(exp_snapshot.not_checked) AS n
      WHERE json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.kind') = 'greenbone'
        AND json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.text') LIKE 'OpenVAS%stopped%');

-- The newest snapshot of a target ended when the target's last_scan_at says: until this version it was set when the scan's last
-- step ended (also an OpenVAS step that was stopped).
UPDATE exp_snapshot SET finished_at = (SELECT t.last_scan_at FROM exp_target AS t WHERE t.id = exp_snapshot.target_id)
WHERE date = (SELECT max(s2.date) FROM exp_snapshot AS s2 WHERE s2.target_id = exp_snapshot.target_id)
  AND coalesce(json_extract(greenbone_run, '$.state'), '') <> 'running'
  AND (SELECT t.last_scan_at FROM exp_target AS t WHERE t.id = exp_snapshot.target_id) >= scanned_at;

-- "Last scanned" is the start of the newest scan, like every other label of a scan.
UPDATE exp_target SET last_scan_at = (SELECT s.started_at FROM exp_snapshot AS s WHERE s.target_id = exp_target.id ORDER BY s.date DESC LIMIT 1)
WHERE EXISTS (SELECT 1 FROM exp_snapshot AS s WHERE s.target_id = exp_target.id);
