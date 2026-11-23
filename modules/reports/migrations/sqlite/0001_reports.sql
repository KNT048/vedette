-- +goose Up
-- The whole schema of the reports module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- The report definitions: one template with section switches (options), its recipients (at most 20). The send schedule is a
-- core_schedule row keyed 'reports.def:<id>'. A row is made on the first save; before it the definition is the default one.
-- send_due_at is a send the schedule asked for (its due time; send_by the person who pressed "Run once now", NULL for the
-- schedule): the schedule's transaction sets it, and the send job clears it before it sends, so a due time is sent at most once.
CREATE TABLE rep_definition (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64 AND id NOT GLOB '*[^A-Za-z0-9._-]*'),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
    kind        TEXT NOT NULL CHECK (kind = 'security'),
    options     TEXT NOT NULL CHECK (json_valid(options) AND json_type(options) = 'object'),
    recipients  TEXT NOT NULL CHECK (json_valid(recipients) AND json_type(recipients) = 'array' AND json_array_length(recipients) <= 20),
    updated_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 254),
    send_due_at TEXT,
    send_by     TEXT CHECK (send_by IS NULL OR length(send_by) BETWEEN 1 AND 254),
    CHECK (send_by IS NULL OR send_due_at IS NOT NULL)
);

-- One row per send attempt; document is the report exactly as it was made and sent (INV-2), never recomputed. Title and period
-- are copies of the document's, so the list does not read the documents.
CREATE TABLE rep_history (
    id            TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    definition_id TEXT NOT NULL CHECK (length(definition_id) BETWEEN 1 AND 64),
    ts            TEXT NOT NULL,
    title         TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    period_from   TEXT NOT NULL,
    period_to     TEXT NOT NULL,
    trigger       TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule')),
    recipients    TEXT NOT NULL CHECK (json_valid(recipients) AND json_type(recipients) = 'array'),
    status        TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
    error         TEXT CHECK (error IS NULL OR length(error) <= 500),
    sent_by       TEXT CHECK (sent_by IS NULL OR length(sent_by) BETWEEN 1 AND 254),
    document      TEXT NOT NULL CHECK (json_valid(document) AND json_type(document) = 'object'),
    CHECK ((status = 'failed') = (error IS NOT NULL))
);

-- The personal-data-protection self-assessment: the organisation's details and the last generated report; one row (id = 1).
CREATE TABLE rep_pdpl (
    id     INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    org    TEXT CHECK (org IS NULL OR (json_valid(org) AND json_type(org) = 'object')),
    report TEXT CHECK (report IS NULL OR (json_valid(report) AND json_type(report) = 'object'))
);

CREATE INDEX rep_history_ts ON rep_history (ts DESC);
