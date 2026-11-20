-- +goose Up
-- When the signatures of a source started to mean what they mean now: set when a source is edited and its kind or its sender address
-- changes (a different kind is read by a different profile, a different sender is a different device). The digest restarts the
-- 24 hour warm-up of the source from this time. NULL = never changed.
ALTER TABLE logs_sources ADD COLUMN signatures_since TEXT CHECK (signatures_since IS NULL OR signatures_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
