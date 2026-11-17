-- +goose Up
-- A scan stored before 0013 got its store time as its start: the moment the steps before OpenVAS (port scan, service
-- identification, templates, the passive web scan) had all ended, often half an hour after the scan began, so the scan's own steps
-- read as earlier than its start. Its start is the earliest time it recorded: the time of its first check line, stamped when that
-- step ended (the port scan of an IP, the name lookups of a domain), never later than the store time. Only the starts 0013 filled are changed (started_at = scanned_at): a scan stored since then has
-- its real start, earlier than every line. The snapshot keeps its day. Forward-only (DATA_MODEL 6, rule 1).
UPDATE exp_snapshot SET started_at = (
    SELECT min(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(exp_snapshot.checks) AS c
    WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at') GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
WHERE started_at = scanned_at AND (
    SELECT min(json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at')) FROM json_each(exp_snapshot.checks) AS c
    WHERE json_extract(CASE c.type WHEN 'object' THEN c.value END, '$.at') GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z') < started_at;

-- "Last scanned" is the start of the newest scan.
UPDATE exp_target SET last_scan_at = (SELECT s.started_at FROM exp_snapshot AS s WHERE s.target_id = exp_target.id ORDER BY s.date DESC LIMIT 1)
WHERE EXISTS (SELECT 1 FROM exp_snapshot AS s WHERE s.target_id = exp_target.id AND s.started_at IS NOT NULL);
