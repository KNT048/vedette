-- +goose Up
-- D-501 (walk 2 W2-4): the discovery window starts at 22:00 like the vulnerability-scan window (modules/scan 0001), so the box
-- shows one window by default instead of 22:00 on Vulnerability scans and 23:00 under Scope and sensors. Only the untouched
-- default row moves; a window someone saved stays. Forward-only (DATA_MODEL 6, rule 1).
UPDATE inv_setting SET value = json_set(value, '$.from', '22:00')
WHERE key = 'active' AND updated_by = 'system' AND json_extract(value, '$.from') = '23:00';
