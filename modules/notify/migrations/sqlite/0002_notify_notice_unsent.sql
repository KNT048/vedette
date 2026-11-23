-- +goose Up
-- What a vulnerability notice said and why no channel took it, so the History page can name every notice that was not sent.
-- Forward-only: there is no Down section.

-- title: the notice's one-line title as it was queued (a snapshot: the finding or its device may be gone later). severity: the
-- severity the channels judged it at (its CVSS band raised to the floor of its urgency layer). NULL on a notice written by an earlier
-- build.
ALTER TABLE notify_notice ADD COLUMN title TEXT CHECK (title IS NULL OR length(title) <= 400);
ALTER TABLE notify_notice ADD COLUMN severity TEXT CHECK (severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'info'));

-- The decision taken when the notice was queued, or when the queue dropped it, like notify_incident.unsent: queued (a channel took
-- it), quiet_hours, no_channel, channels_off, below_min_severity, channel_off, channel_removed, dropped_stale (an open vocabulary,
-- notify.NotSentReason); unsent_floor is the lowest minimum severity of the channels that skipped it, unsent_channel the channel to fix
-- (a channel type, channel.Type: shape checked only, so a new channel type needs no table change).
ALTER TABLE notify_notice ADD COLUMN unsent TEXT CHECK (unsent IS NULL OR (length(unsent) BETWEEN 1 AND 40 AND unsent NOT GLOB '*[^a-z0-9_]*'));
ALTER TABLE notify_notice ADD COLUMN unsent_floor TEXT CHECK (unsent_floor IS NULL OR unsent_floor IN ('critical', 'high', 'medium', 'low'));
ALTER TABLE notify_notice ADD COLUMN unsent_channel TEXT CHECK (unsent_channel IS NULL OR (length(unsent_channel) BETWEEN 1 AND 40 AND unsent_channel NOT GLOB '*[^a-z-]*'));
