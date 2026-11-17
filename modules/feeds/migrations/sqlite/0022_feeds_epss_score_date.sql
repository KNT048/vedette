-- +goose Up
-- The day FIRST gives its scores for (the score_date of the file's first line, YYYY-MM-DD) next to the last good pull of epss-all: the
-- plan's "EPSS scores of <day>" and Settings › Feeds name the same publisher's day, not the day the box happened to download it. NULL
-- until the next pull (the epss-all code version moves with this column, so every box reads the file again at its next check).
-- Forward-only.
ALTER TABLE feeds_epss_baseline ADD COLUMN score_date TEXT CHECK (score_date IS NULL OR score_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]');
