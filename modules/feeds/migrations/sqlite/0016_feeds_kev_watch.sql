-- +goose Up
-- kien G13 (D-629): Home says which copy of the CISA list answered and why. answered_why is why cisa.gov did not, when CISA's GitHub
-- copy answered the last good pull ("cisa.gov refused this box (HTTP 403)"); NULL when cisa.gov answered, for every other feed and
-- before the next pull of a box that ran an older version.
-- stale_watch_from and stale_alerted_at keep the stale alert of the CISA list (one alert after six missed checks, one when it is up to
-- date again), so a restart neither sends it twice nor forgets it was sent: stale_watch_from is when the watch first saw the list on
-- (the six hours count from it at the latest, so turning the list on does not raise an old staleness), stale_alerted_at when the stale
-- alert went out (NULL: none open). Both NULL for every other feed. Forward-only.
ALTER TABLE feeds_source ADD COLUMN answered_why TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_watch_from TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_alerted_at TEXT;
