-- +goose Up
-- #861 (INV-30): the newest external scan in which each engine step actually ran (nuclei's templates, ZAP's passive web scan,
-- OpenVAS), with how it ended and a short text: Settings › Scanning's nuclei, zap and openvas cards read their last run here. A run
-- that skipped the step leaves the row as it was; a scan of the same target later the same day replaces the snapshot, never this row.
-- Kept when a target is deleted, like the audit row of the scan. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_engine_run (
    engine  TEXT NOT NULL PRIMARY KEY CHECK (engine IN ('nuclei', 'zap', 'openvas')),
    run_id  TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 96),
    target  TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
    at      TEXT NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'partial', 'failed', 'stopped')),
    text    TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 300)
);

-- The scans stored before this version: the newest snapshot in which the step ran, from what the snapshot says (its check line, the
-- OpenVAS state of 0011). The run id is the snapshot's. A row whose time is not a timestamp of the box is left out, never refused.
INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'openvas', id, value, at, outcome, substr(text, 1, 300) FROM (
    SELECT s.id, t.value,
        coalesce((SELECT max(json_extract(c.value, '$.at')) FROM json_each(s.checks) AS c WHERE json_extract(c.value, '$.kind') = 'greenbone'),
            json_extract(s.greenbone_run, '$.started_at'), s.scanned_at) AS at,
        CASE json_extract(s.greenbone_run, '$.state')
            WHEN 'done' THEN 'ok' WHEN 'partial' THEN 'partial' WHEN 'ended' THEN 'partial' WHEN 'failed' THEN 'failed' ELSE 'stopped' END AS outcome,
        'External scan of ' || t.value || ': ' || CASE
            WHEN json_extract(s.greenbone_run, '$.state') IN ('done', 'partial', 'ended') THEN 'OpenVAS found ' || json_array_length(s.greenbone) ||
                CASE json_array_length(s.greenbone) WHEN 1 THEN ' result' ELSE ' results' END
            WHEN json_extract(s.greenbone_run, '$.state') = 'failed' THEN 'OpenVAS failed (the scan''s Not checked list says why)'
            ELSE 'stopped while OpenVAS ran' END AS text
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
    WHERE json_extract(s.greenbone_run, '$.state') IN ('done', 'partial', 'ended', 'failed', 'stopped', 'running')
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;

INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'zap', id, value, at, outcome, substr(text, 1, 300) FROM (
    SELECT s.id, t.value,
        (SELECT max(json_extract(c.value, '$.at')) FROM json_each(s.checks) AS c WHERE json_extract(c.value, '$.kind') = 'web') AS at,
        CASE WHEN EXISTS (SELECT 1 FROM json_each(s.not_checked) AS n WHERE json_extract(n.value, '$.kind') = 'web' AND (
                json_extract(n.value, '$.text') LIKE '%(ZAP) failed%' OR json_extract(n.value, '$.text') LIKE '%(ZAP) did not finish%' OR
                json_extract(n.value, '$.text') LIKE '%(ZAP) returned a report that could not be read%'))
            THEN 'partial' ELSE 'ok' END AS outcome,
        'External scan of ' || t.value || ': ZAP found ' || json_array_length(s.web_findings) ||
            CASE json_array_length(s.web_findings) WHEN 1 THEN ' alert' ELSE ' alerts' END AS text
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;

INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'nuclei', id, value, at, 'ok', substr('External scan of ' || value || ': safe templates ran', 1, 300) FROM (
    SELECT s.id, t.value,
        (SELECT max(json_extract(c.value, '$.at')) FROM json_each(s.checks) AS c WHERE json_extract(c.value, '$.kind') = 'templates'
            AND json_extract(c.value, '$.text') NOT LIKE '%none needed%') AS at
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;
