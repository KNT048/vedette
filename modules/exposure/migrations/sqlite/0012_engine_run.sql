-- +goose Up
-- #861 (INV-30): the newest external scan in which each engine step actually ran (nuclei's templates, ZAP's passive web scan,
-- OpenVAS), with how it ended and a short text: Settings › Scanning's nuclei, zap and openvas cards read their last run here. A run
-- that skipped the step leaves the row as it was; a scan of the same target later the same day replaces the snapshot, never this row.
-- Deleting (or ignoring) the target deletes its rows. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_engine_run (
    engine  TEXT NOT NULL PRIMARY KEY CHECK (engine IN ('nuclei', 'zap', 'openvas')),
    run_id  TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 96),
    target  TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
    at      TEXT NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'partial', 'failed', 'stopped')),
    text    TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 300)
);

-- The scans stored before this version: the newest snapshot in which the step ran, from what the snapshot says (its check line, the
-- OpenVAS state of 0011). The run id is the snapshot's; the time is the step's check line, the only end time a snapshot keeps, so a
-- step without one (OpenVAS failed or stopped) is not taken. Only object elements of the lists are read (CASE … 'object'): any other
-- element is passed over, and a row whose time is not a timestamp of the box is left out, never refused.
INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'openvas', id, value, at, outcome, substr(text, 1, 300) FROM (
    SELECT s.id, t.value,
        (SELECT max(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(s.checks) AS c
            WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.kind') = 'greenbone') AS at,
        CASE json_extract(s.greenbone_run, '$.state') WHEN 'done' THEN 'ok' ELSE 'partial' END AS outcome,
        'External scan of ' || t.value || ': ' || CASE json_extract(s.greenbone_run, '$.state')
            WHEN 'done' THEN 'OpenVAS found '
            WHEN 'partial' THEN 'OpenVAS stopped at its 90-minute limit, '
            ELSE 'OpenVAS ended the task before it finished, ' END ||
            json_array_length(s.greenbone) || CASE json_array_length(s.greenbone) WHEN 1 THEN ' result' ELSE ' results' END AS text
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
    WHERE json_extract(s.greenbone_run, '$.state') IN ('done', 'partial', 'ended')
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;

INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'zap', id, value, at, outcome, substr(text, 1, 300) FROM (
    SELECT s.id, t.value,
        (SELECT max(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(s.checks) AS c
            WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.kind') = 'web') AS at,
        CASE WHEN EXISTS (SELECT 1 FROM json_each(s.not_checked) AS n
                WHERE json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.kind') = 'web' AND (
                    json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.text') LIKE '%(ZAP) failed%' OR
                    json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.text') LIKE '%(ZAP) did not finish%' OR
                    json_extract(CASE n.type WHEN 'object' THEN n.value END, '$.text') LIKE '%(ZAP) returned a report that could not be read%'))
            THEN 'partial' ELSE 'ok' END AS outcome,
        'External scan of ' || t.value || ': ZAP found ' || json_array_length(s.web_findings) ||
            CASE json_array_length(s.web_findings) WHEN 1 THEN ' alert' ELSE ' alerts' END AS text
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;

INSERT INTO exp_engine_run (engine, run_id, target, at, outcome, text)
SELECT 'nuclei', id, value, at, 'ok', substr('External scan of ' || value || ': ' || kind || ' ran', 1, 300) FROM (
    SELECT s.id, t.value,
        (SELECT max(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(s.checks) AS c
            WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.kind') = 'templates'
            AND json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.text') NOT LIKE '%none needed%') AS at,
        CASE WHEN EXISTS (SELECT 1 FROM json_each(s.checks) AS c
                WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.kind') = 'templates'
                AND json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.text') LIKE 'Deep templates%')
            THEN 'deep templates' ELSE 'safe templates' END AS kind
    FROM exp_snapshot AS s JOIN exp_target AS t ON t.id = s.target_id
)
WHERE at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
ORDER BY at DESC LIMIT 1;
