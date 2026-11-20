-- +goose Up
-- D-617 (review r1 #6 of #804): NVD's "running on" condition of each vulnerable entry of nvd-recent (an AND configuration with
-- non-vulnerable operating-system entries: a flaw of an application only when it runs on Windows), as a JSON array of
-- "vendor:product" ('[]' = no condition). NULL = stored before this column: not known, and findings' plan never counts such an entry.
-- The cursor goes, so the next pull of nvd-recent loads the 12 months again (about 105 requests) and every row gets its condition;
-- meanwhile the feed says it is loading and the plan lists nothing from it. Forward-only.
ALTER TABLE feeds_recent_affected ADD COLUMN platforms TEXT CHECK (platforms IS NULL OR (json_valid(platforms) AND json_type(platforms) = 'array'));
DELETE FROM feeds_recent_cursor;
