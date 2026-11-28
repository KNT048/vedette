-- +goose Up
-- How the AI researched one release line (findings P-12): the reading itself is the fnd_line_statement row of the same key (verdict,
-- quote, page, model); this row keeps the research behind it: the layer whose answer stands (quick, or strong after an escalation),
-- where the box found the quote (in text the AI's tools returned, in the box's own digest of the CVE, on a live fetch of the cited
-- page, not found, or no quote), the tokens of every layer, and detail: the mode, the AI's confidence, the trap it checked, and per
-- layer the model, profile, tokens in and out, web searches and the pages it read. Deleted with its reading. No device data.
-- Add-only, forward-only: there is no Down section.
CREATE TABLE fnd_line_research (
    statement_key TEXT NOT NULL PRIMARY KEY REFERENCES fnd_line_statement (statement_key) ON DELETE CASCADE,
    layer TEXT NOT NULL CHECK (layer IN ('quick', 'strong')), quote_check TEXT NOT NULL CHECK (quote_check IN ('tool', 'digest', 'live', 'not_found', 'none')),
    tokens INTEGER NOT NULL CHECK (tokens >= 0), detail TEXT NOT NULL CHECK (json_valid(detail)));
