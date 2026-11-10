-- +goose Up
-- The volume of the logs module, in its own database file (logs.db) with its own writer, so that a flood of syslog never
-- waits for, or holds, the writer of the main database (the findings events lost to a busy writer, #159/#160).
-- Nothing here references another table or another database: a source is named by its id only, and a line outlives the
-- source it came from (INV-4: deleting a source keeps its lines until retention). Forward-only.

-- Received lines. ts is the receive time (device clocks drift, RFC 3164 has no year); "newest first" walks the ts index backwards. A
-- purge of the oldest is a range delete by ts, and ids (handed out in receive order) bound the number of rows kept.
CREATE TABLE logs_events (
    id        INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    line      TEXT NOT NULL CHECK (length(line) <= 8192)
);
CREATE INDEX logs_events_ts ON logs_events (ts);
CREATE INDEX logs_events_source_ts ON logs_events (source_id, ts);

-- Lines per source per 5 minutes: feeds lines_per_hour and lines_24h without counting events.
CREATE TABLE logs_source_buckets (
    source_id TEXT    NOT NULL,
    bucket    INTEGER NOT NULL, -- unix seconds / 300
    lines     INTEGER NOT NULL CHECK (lines >= 0),
    PRIMARY KEY (source_id, bucket)
) WITHOUT ROWID;

-- The last time a line arrived from a source.
CREATE TABLE logs_source_seen (
    source_id     TEXT NOT NULL PRIMARY KEY,
    last_received TEXT NOT NULL CHECK (last_received GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) WITHOUT ROWID;
