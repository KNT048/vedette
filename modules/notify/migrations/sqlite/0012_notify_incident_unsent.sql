-- +goose Up
-- Why an incident reached no channel (INV-24, D-551): the decision Publish made when it was opened, kept so the Incidents page can say
-- "Not sent: …" instead of a bare "Not sent". unsent is queued (a channel took it), quiet_hours (held until quiet hours end), no_channel,
-- channels_off, below_min_severity (unsent_floor: the lowest minimum of the channels that were on, unsent_channel: that channel),
-- channel_off / channel_removed (unsent_channel: the channel a held or rate-limited message waited for was turned off or removed),
-- or dropped_stale. NULL: an incident opened by an older binary (the page then reads the channels as they are now).
ALTER TABLE notify_incident ADD COLUMN unsent TEXT CHECK (unsent IS NULL OR length(unsent) BETWEEN 1 AND 40);
ALTER TABLE notify_incident ADD COLUMN unsent_floor TEXT CHECK (unsent_floor IS NULL OR unsent_floor IN ('critical', 'high', 'medium', 'low'));
ALTER TABLE notify_incident ADD COLUMN unsent_channel TEXT CHECK (unsent_channel IS NULL OR unsent_channel IN ('telegram', 'slack', 'zalo', 'zalo-personal', 'email', 'webhook'));
