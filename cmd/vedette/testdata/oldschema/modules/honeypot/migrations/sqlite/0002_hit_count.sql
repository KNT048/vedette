-- +goose Up
-- One hit per (source, service, trap IP) per 10 minutes (WP-14 review, D-89 amendment): later connections of the same
-- window raise `conn_count` and add a line to `events` instead of making a new row. Existing rows are one connection each.
-- Forward-only: no Down section.
ALTER TABLE hp_hits ADD COLUMN conn_count INTEGER NOT NULL DEFAULT 1 CHECK (conn_count >= 1);
