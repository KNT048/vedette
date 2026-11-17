-- +goose Up
-- kien G13 (D-91 as amended 2026-11-17, D-629): every check of the CISA list asks both copies, cisa.gov and CISA's GitHub copy
-- (cisagov/kev-data), each with its own validators (etag/last_modified are cisa.gov's, mirror_etag/mirror_last_modified the copy's),
-- and keeps the newer catalog; it never rolls back.
-- kev_copies: what each copy said at its last check, JSON {"cisa": {...}, "mirror": {...}} with version (catalogVersion), released
-- (dateReleased, RFC 3339), checked_at and error (one clause, "" when it answered). A copy whose version is not known is asked without
-- validators, so a box that ran an older version reads each copy in full once. NULL for every other feed.
-- catalog_released: the dateReleased of the catalog the box holds, the tie-breaker of two copies with the same catalogVersion.
-- stale_watch_from, stale_alerted_at, stale_failed_since and stale_failed_checks keep the alert of the CISA list (one when both copies
-- fail at two scheduled checks in a row about an hour apart, or the list is six checks old; one when it is up to date again), so a
-- restart neither sends it twice nor forgets it was sent: when the watch first saw the list on, when the alert was recorded, when the
-- current run of scheduled checks where both copies failed began, and how many there were. Forward-only.
ALTER TABLE feeds_source ADD COLUMN kev_copies TEXT;
ALTER TABLE feeds_source ADD COLUMN catalog_released TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_watch_from TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_alerted_at TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_failed_since TEXT;
ALTER TABLE feeds_source ADD COLUMN stale_failed_checks INTEGER NOT NULL DEFAULT 0;
