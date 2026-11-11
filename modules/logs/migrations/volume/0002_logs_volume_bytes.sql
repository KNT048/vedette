-- +goose Up
-- How many bytes of line text logs_events holds: the byte bound of the purge (M2) is checked by Ingest on every batch, and a
-- sum over millions of rows is not something a batch can afford. Ingest adds to it in the batch's own transaction, the purge
-- subtracts in the transaction that deletes. One row. Add-only (D-151): an older binary ignores the table.
CREATE TABLE logs_volume (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    line_bytes INTEGER NOT NULL CHECK (line_bytes >= 0)
);
INSERT INTO logs_volume (id, line_bytes) SELECT 1, coalesce(sum(length(CAST(line AS BLOB))), 0) FROM logs_events;
