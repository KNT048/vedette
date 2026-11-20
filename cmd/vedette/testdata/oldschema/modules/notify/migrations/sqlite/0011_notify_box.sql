-- +goose Up
-- D-483: when notify first ran on this box (the first discovery of devices is summarised for 36 hours from then) and when the
-- summary incident last told people. A box upgraded to this version takes the earliest notify record it has, so an old box never
-- opens a first-discovery window; a new box starts now.
CREATE TABLE notify_box (
    id                   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    first_run_at         TEXT    NOT NULL CHECK (first_run_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    discovery_told_at    TEXT    CHECK (discovery_told_at IS NULL OR discovery_told_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    discovery_told_count INTEGER NOT NULL DEFAULT 0 CHECK (discovery_told_count >= 0)
);
INSERT INTO notify_box (id, first_run_at)
SELECT 1, COALESCE(MIN(t), strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) FROM (
    SELECT MIN(first_seen) AS t FROM notify_incident
    UNION ALL SELECT MIN(at) FROM notify_send
    UNION ALL SELECT MIN(seen_at) FROM notify_kev
    UNION ALL SELECT MIN(updated_at) FROM notify_channel
    UNION ALL SELECT MIN(updated_at) FROM notify_setting
    UNION ALL SELECT MIN(created_at) FROM notify_pending
);
