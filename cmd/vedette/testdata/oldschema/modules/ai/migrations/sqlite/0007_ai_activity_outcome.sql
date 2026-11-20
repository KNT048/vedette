-- +goose Up
-- How a call that got no answer ended, as a stable marker beside the activity row (POST-5, S-AI-4): 'capped' (the shared daily cap, or
-- the profile's own cap, stopped it before anything was sent), 'not_sent' (no profile could take it: the privacy rule, changed settings
-- or settings a client cannot be built from; nothing left the box); NULL for every other row. GET /ai/runs reads its status from it, never
-- from the summary text. Like profile_id it is not part of the hash: the chain and an export of it are unchanged. Add-only, forward-only.
ALTER TABLE ai_activity ADD COLUMN outcome TEXT CHECK (outcome IS NULL OR outcome IN ('capped', 'not_sent'));
