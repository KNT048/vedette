-- +goose Up
-- Why the provider stopped writing the answer the row is about (the stop reason of the last response): 'end', 'max_tokens' (cut at
-- the output limit), 'tool_use' or 'other'; NULL when no answer came (blocked, capped, failed) and for rows written before this column.
-- It tells a cut-off answer from one in the wrong format. Like outcome it is not part of the hash: the chain and an export of it are
-- unchanged. Add-only, forward-only.
ALTER TABLE ai_activity ADD COLUMN stop TEXT CHECK (stop IS NULL OR stop IN ('end', 'max_tokens', 'tool_use', 'other'));
