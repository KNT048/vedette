-- +goose Up
-- ai_read of slice 7 (D-311, D-119): one row per read the box itself made through a connection read tool (core/conn/read), written by
-- the tool runner after the read answered, never from text the model produced. response looks a row up by id as config_read evidence
-- of an AI proposal; only rows at most 24 hours old count. Rows older than that are removed when a new read is recorded, and at most
-- the newest 500 are kept. The output of the read is not stored: only which connection and which tool, and when. Forward-only.
CREATE TABLE ai_read (
    id              TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts              TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    connection_id   TEXT NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 96),
    connection_name TEXT NOT NULL CHECK (length(connection_name) <= 60),
    tool            TEXT NOT NULL CHECK (length(tool) BETWEEN 1 AND 60),
    job             TEXT NOT NULL CHECK (length(job) BETWEEN 1 AND 32)
);
CREATE INDEX ai_read_ts ON ai_read (ts);
